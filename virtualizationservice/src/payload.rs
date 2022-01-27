// Copyright 2021, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Payload disk image

use android_system_virtualizationservice::aidl::android::system::virtualizationservice::{
    DiskImage::DiskImage, Partition::Partition, VirtualMachineAppConfig::DebugLevel::DebugLevel,
    VirtualMachineAppConfig::VirtualMachineAppConfig,
    VirtualMachineRawConfig::VirtualMachineRawConfig,
};
use android_system_virtualizationservice::binder::ParcelFileDescriptor;
use anyhow::{anyhow, bail, Context, Result};
use binder::wait_for_interface;
use log::{info, warn};
use microdroid_metadata::{ApexPayload, ApkPayload, Metadata};
use microdroid_payload_config::{ApexConfig, VmPayloadConfig};
use once_cell::sync::OnceCell;
use packagemanager_aidl::aidl::android::content::pm::IPackageManagerNative::IPackageManagerNative;
use regex::Regex;
use serde::Deserialize;
use serde_xml_rs::from_reader;
use std::collections::HashSet;
use std::fs::{metadata, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;
use vmconfig::open_parcel_file;

/// The list of APEXes which microdroid requires.
// TODO(b/192200378) move this to microdroid.json?
const MICRODROID_REQUIRED_APEXES: [&str; 1] = ["com.android.os.statsd"];
const MICRODROID_REQUIRED_APEXES_DEBUG: [&str; 1] = ["com.android.adbd"];

const APEX_INFO_LIST_PATH: &str = "/apex/apex-info-list.xml";

const PACKAGE_MANAGER_NATIVE_SERVICE: &str = "package_native";

/// Represents the list of APEXes
#[derive(Clone, Debug, Deserialize)]
struct ApexInfoList {
    #[serde(rename = "apex-info")]
    list: Vec<ApexInfo>,
}

#[derive(Clone, Debug, Deserialize)]
struct ApexInfo {
    #[serde(rename = "moduleName")]
    name: String,
    #[serde(rename = "modulePath")]
    path: PathBuf,

    #[serde(default)]
    has_classpath_jar: bool,

    // The field claims to be milliseconds but is actually seconds.
    #[serde(rename = "lastUpdateMillis")]
    last_update_seconds: u64,

    #[serde(rename = "isFactory")]
    is_factory: bool,
}

impl ApexInfoList {
    /// Loads ApexInfoList
    fn load() -> Result<&'static ApexInfoList> {
        static INSTANCE: OnceCell<ApexInfoList> = OnceCell::new();
        INSTANCE.get_or_try_init(|| {
            let apex_info_list = File::open(APEX_INFO_LIST_PATH)
                .context(format!("Failed to open {}", APEX_INFO_LIST_PATH))?;
            let mut apex_info_list: ApexInfoList = from_reader(apex_info_list)
                .context(format!("Failed to parse {}", APEX_INFO_LIST_PATH))?;

            // For active APEXes, we run derive_classpath and parse its output to see if it
            // contributes to the classpath(s). (This allows us to handle any new classpath env
            // vars seamlessly.)
            let classpath_vars = run_derive_classpath()?;
            let classpath_apexes = find_apex_names_in_classpath(&classpath_vars)?;

            for apex_info in apex_info_list.list.iter_mut() {
                apex_info.has_classpath_jar = classpath_apexes.contains(&apex_info.name);
            }

            Ok(apex_info_list)
        })
    }

    /// Returns the list of apex names matching with the predicate
    fn get_matching(&self, predicate: fn(&ApexInfo) -> bool) -> Vec<String> {
        self.list.iter().filter(|info| predicate(info)).map(|info| info.name.clone()).collect()
    }

    fn get(&self, apex_name: &str) -> Result<&ApexInfo> {
        self.list
            .iter()
            .find(|apex| apex.name == apex_name)
            .ok_or_else(|| anyhow!("{} not found.", apex_name))
    }

    fn get_path_for(&self, apex_name: &str) -> Result<PathBuf> {
        Ok(self.get(apex_name)?.path.clone())
    }
}

struct PackageManager {
    apex_info_list: &'static ApexInfoList,
}

impl PackageManager {
    fn new() -> Result<Self> {
        let apex_info_list = ApexInfoList::load()?;
        Ok(Self { apex_info_list })
    }

    fn get_apex_list(&self, prefer_staged: bool) -> Result<ApexInfoList> {
        // get the list of active apexes
        let mut list = self.apex_info_list.clone();
        // When prefer_staged, we override ApexInfo by consulting "package_native"
        if prefer_staged {
            let pm =
                wait_for_interface::<dyn IPackageManagerNative>(PACKAGE_MANAGER_NATIVE_SERVICE)
                    .context("Failed to get service when prefer_staged is set.")?;
            let staged = pm.getStagedApexModuleNames()?;
            for apex_info in list.list.iter_mut() {
                if staged.contains(&apex_info.name) {
                    if let Some(staged_apex_info) = pm.getStagedApexInfo(&apex_info.name)? {
                        apex_info.path = PathBuf::from(staged_apex_info.diskImagePath);
                        apex_info.has_classpath_jar = staged_apex_info.hasClassPathJars;
                        let metadata = metadata(&apex_info.path)?;
                        apex_info.last_update_seconds =
                            metadata.modified()?.duration_since(SystemTime::UNIX_EPOCH)?.as_secs();
                        // by definition, staged apex can't be a factory apex.
                        apex_info.is_factory = false;
                    }
                }
            }
        }
        Ok(list)
    }
}

fn make_metadata_file(
    config_path: &str,
    apex_names: &[String],
    temporary_directory: &Path,
    apex_list: &ApexInfoList,
) -> Result<ParcelFileDescriptor> {
    let metadata_path = temporary_directory.join("metadata");
    let metadata = Metadata {
        version: 1,
        apexes: apex_names
            .iter()
            .enumerate()
            .map(|(i, apex_name)| {
                let apex_info = apex_list.get(apex_name)?;
                Ok(ApexPayload {
                    name: apex_name.clone(),
                    partition_name: format!("microdroid-apex-{}", i),
                    last_update_seconds: apex_info.last_update_seconds,
                    is_factory: apex_info.is_factory,
                    ..Default::default()
                })
            })
            .collect::<Result<_>>()?,
        apk: Some(ApkPayload {
            name: "apk".to_owned(),
            payload_partition_name: "microdroid-apk".to_owned(),
            idsig_partition_name: "microdroid-apk-idsig".to_owned(),
            ..Default::default()
        })
        .into(),
        payload_config_path: format!("/mnt/apk/{}", config_path),
        ..Default::default()
    };

    // Write metadata to file.
    let mut metadata_file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&metadata_path)
        .with_context(|| format!("Failed to open metadata file {:?}", metadata_path))?;
    microdroid_metadata::write_metadata(&metadata, &mut metadata_file)?;

    // Re-open the metadata file as read-only.
    open_parcel_file(&metadata_path, false)
}

/// Creates a DiskImage with partitions:
///   metadata: metadata
///   microdroid-apex-0: apex 0
///   microdroid-apex-1: apex 1
///   ..
///   microdroid-apk: apk
///   microdroid-apk-idsig: idsig
///   extra-apk-0:   additional apk 0
///   extra-idsig-0: additional idsig 0
///   extra-apk-1:   additional apk 1
///   extra-idsig-1: additional idsig 1
///   ..
fn make_payload_disk(
    app_config: &VirtualMachineAppConfig,
    apk_file: File,
    idsig_file: File,
    vm_payload_config: &VmPayloadConfig,
    temporary_directory: &Path,
) -> Result<DiskImage> {
    if vm_payload_config.extra_apks.len() != app_config.extraIdsigs.len() {
        bail!(
            "payload config has {} apks, but app config has {} idsigs",
            vm_payload_config.extra_apks.len(),
            app_config.extraIdsigs.len()
        );
    }

    let pm = PackageManager::new()?;
    let apex_list = pm.get_apex_list(vm_payload_config.prefer_staged)?;

    // collect APEX names from config
    let apexes = collect_apex_names(&apex_list, &vm_payload_config.apexes, app_config.debugLevel);
    info!("Microdroid payload APEXes: {:?}", apexes);

    let metadata_file =
        make_metadata_file(&app_config.configPath, &apexes, temporary_directory, &apex_list)?;
    // put metadata at the first partition
    let mut partitions = vec![Partition {
        label: "payload-metadata".to_owned(),
        image: Some(metadata_file),
        writable: false,
    }];

    for (i, apex) in apexes.iter().enumerate() {
        let apex_path = apex_list.get_path_for(apex)?;
        let apex_file = open_parcel_file(&apex_path, false)?;
        partitions.push(Partition {
            label: format!("microdroid-apex-{}", i),
            image: Some(apex_file),
            writable: false,
        });
    }
    partitions.push(Partition {
        label: "microdroid-apk".to_owned(),
        image: Some(ParcelFileDescriptor::new(apk_file)),
        writable: false,
    });
    partitions.push(Partition {
        label: "microdroid-apk-idsig".to_owned(),
        image: Some(ParcelFileDescriptor::new(idsig_file)),
        writable: false,
    });

    // we've already checked that extra_apks and extraIdsigs are in the same size.
    let extra_apks = &vm_payload_config.extra_apks;
    let extra_idsigs = &app_config.extraIdsigs;
    for (i, (extra_apk, extra_idsig)) in extra_apks.iter().zip(extra_idsigs.iter()).enumerate() {
        partitions.push(Partition {
            label: format!("extra-apk-{}", i),
            image: Some(ParcelFileDescriptor::new(File::open(PathBuf::from(&extra_apk.path))?)),
            writable: false,
        });

        partitions.push(Partition {
            label: format!("extra-idsig-{}", i),
            image: Some(ParcelFileDescriptor::new(extra_idsig.as_ref().try_clone()?)),
            writable: false,
        });
    }

    Ok(DiskImage { image: None, partitions, writable: false })
}

fn run_derive_classpath() -> Result<String> {
    let result = Command::new("/apex/com.android.sdkext/bin/derive_classpath")
        .arg("/proc/self/fd/1")
        .output()
        .context("Failed to run derive_classpath")?;

    if !result.status.success() {
        bail!("derive_classpath returned {}", result.status);
    }

    String::from_utf8(result.stdout).context("Converting derive_classpath output")
}

fn find_apex_names_in_classpath(classpath_vars: &str) -> Result<HashSet<String>> {
    // Each line should be in the format "export <var name> <paths>", where <paths> is a
    // colon-separated list of paths to JARs. We don't care about the var names, and we're only
    // interested in paths that look like "/apex/<apex name>/<anything>" so we know which APEXes
    // contribute to at least one var.
    let mut apexes = HashSet::new();

    let pattern = Regex::new(r"^export [^ ]+ ([^ ]+)$").context("Failed to construct Regex")?;
    for line in classpath_vars.lines() {
        if let Some(captures) = pattern.captures(line) {
            if let Some(paths) = captures.get(1) {
                apexes.extend(paths.as_str().split(':').filter_map(|path| {
                    let path = path.strip_prefix("/apex/")?;
                    Some(path[..path.find('/')?].to_owned())
                }));
                continue;
            }
        }
        warn!("Malformed line from derive_classpath: {}", line);
    }

    Ok(apexes)
}

// Collect APEX names from config
fn collect_apex_names(
    apex_list: &ApexInfoList,
    apexes: &[ApexConfig],
    debug_level: DebugLevel,
) -> Vec<String> {
    // Process pseudo names like "{CLASSPATH}".
    // For now we have following pseudo APEX names:
    // - {CLASSPATH}: represents APEXes contributing to any derive_classpath environment variable
    let mut apex_names: Vec<String> = apexes
        .iter()
        .flat_map(|apex| match apex.name.as_str() {
            "{CLASSPATH}" => apex_list.get_matching(|apex| apex.has_classpath_jar),
            _ => vec![apex.name.clone()],
        })
        .collect();
    // Add required APEXes
    apex_names.extend(MICRODROID_REQUIRED_APEXES.iter().map(|name| name.to_string()));
    if debug_level != DebugLevel::NONE {
        apex_names.extend(MICRODROID_REQUIRED_APEXES_DEBUG.iter().map(|name| name.to_string()));
    }
    apex_names.sort();
    apex_names.dedup();
    apex_names
}

pub fn add_microdroid_images(
    config: &VirtualMachineAppConfig,
    temporary_directory: &Path,
    apk_file: File,
    idsig_file: File,
    instance_file: File,
    vm_payload_config: &VmPayloadConfig,
    vm_config: &mut VirtualMachineRawConfig,
) -> Result<()> {
    vm_config.disks.push(make_payload_disk(
        config,
        apk_file,
        idsig_file,
        vm_payload_config,
        temporary_directory,
    )?);

    vm_config.disks[1].partitions.push(Partition {
        label: "vbmeta".to_owned(),
        image: Some(open_parcel_file(
            Path::new("/apex/com.android.virt/etc/fs/microdroid_vbmeta_bootconfig.img"),
            false,
        )?),
        writable: false,
    });
    let bootconfig_image = "/apex/com.android.virt/etc/microdroid_bootconfig.".to_owned()
        + match config.debugLevel {
            DebugLevel::NONE => "normal",
            DebugLevel::APP_ONLY => "app_debuggable",
            DebugLevel::FULL => "full_debuggable",
            _ => return Err(anyhow!("unsupported debug level: {:?}", config.debugLevel)),
        };
    vm_config.disks[1].partitions.push(Partition {
        label: "bootconfig".to_owned(),
        image: Some(open_parcel_file(Path::new(&bootconfig_image), false)?),
        writable: false,
    });

    // instance image is at the second partition in the second disk.
    vm_config.disks[1].partitions.push(Partition {
        label: "vm-instance".to_owned(),
        image: Some(ParcelFileDescriptor::new(instance_file)),
        writable: true,
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_apex_names_in_classpath() {
        let vars = r#"
export FOO /apex/unterminated
export BAR /apex/valid.apex/something
wrong
export EMPTY
export OTHER /foo/bar:/baz:/apex/second.valid.apex/:gibberish:"#;
        let expected = vec!["valid.apex", "second.valid.apex"];
        let expected: HashSet<_> = expected.into_iter().map(ToString::to_string).collect();

        assert_eq!(find_apex_names_in_classpath(vars).unwrap(), expected);
    }

    #[test]
    fn test_collect_apex_names() {
        let apex_list = ApexInfoList {
            list: vec![
                ApexInfo {
                    name: "hasnt_classpath".to_string(),
                    path: PathBuf::from("path0"),
                    has_classpath_jar: false,
                    last_update_seconds: 12345678,
                    is_factory: true,
                },
                ApexInfo {
                    name: "has_classpath".to_string(),
                    path: PathBuf::from("path1"),
                    has_classpath_jar: true,
                    last_update_seconds: 87654321,
                    is_factory: false,
                },
            ],
        };
        let apexes = vec![
            ApexConfig { name: "config_name".to_string() },
            ApexConfig { name: "{CLASSPATH}".to_string() },
        ];
        assert_eq!(
            collect_apex_names(&apex_list, &apexes, DebugLevel::FULL),
            vec![
                "com.android.adbd".to_string(),
                "com.android.os.statsd".to_string(),
                "config_name".to_string(),
                "has_classpath".to_string(),
            ]
        );
    }
}
