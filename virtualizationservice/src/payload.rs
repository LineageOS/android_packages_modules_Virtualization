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

use anyhow::{anyhow, Context, Result};
use microdroid_metadata::{ApexPayload, ApkPayload, Metadata};
use microdroid_payload_config::ApexConfig;
use once_cell::sync::OnceCell;
use serde::Deserialize;
use serde_xml_rs::from_reader;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use vmconfig::{DiskImage, Partition};

const APEX_INFO_LIST_PATH: &str = "/apex/apex-info-list.xml";

/// Represents the list of APEXes
#[derive(Debug, Deserialize)]
struct ApexInfoList {
    #[serde(rename = "apex-info")]
    list: Vec<ApexInfo>,
}

#[derive(Debug, Deserialize)]
struct ApexInfo {
    #[serde(rename = "moduleName")]
    name: String,
    #[serde(rename = "modulePath")]
    path: PathBuf,
}

impl ApexInfoList {
    /// Loads ApexInfoList
    fn load() -> Result<&'static ApexInfoList> {
        static INSTANCE: OnceCell<ApexInfoList> = OnceCell::new();
        INSTANCE.get_or_try_init(|| {
            let apex_info_list = File::open(APEX_INFO_LIST_PATH)
                .context(format!("Failed to open {}", APEX_INFO_LIST_PATH))?;
            let apex_info_list: ApexInfoList = from_reader(apex_info_list)
                .context(format!("Failed to parse {}", APEX_INFO_LIST_PATH))?;
            Ok(apex_info_list)
        })
    }

    fn get_path_for(&self, apex_name: &str) -> Result<PathBuf> {
        Ok(self
            .list
            .iter()
            .find(|apex| apex.name == apex_name)
            .ok_or_else(|| anyhow!("{} not found.", apex_name))?
            .path
            .clone())
    }
}

/// Creates a DiskImage with partitions:
///   metadata: metadata
///   microdroid-apex-0: apex 0
///   microdroid-apex-1: apex 1
///   ..
///   microdroid-apk: apk
///   microdroid-apk-idsig: idsig
pub fn make_payload_disk(
    apk_file: PathBuf,
    idsig_file: PathBuf,
    config_path: &str,
    apexes: &[ApexConfig],
    temporary_directory: &Path,
) -> Result<DiskImage> {
    let metadata_path = temporary_directory.join("metadata");
    let metadata = Metadata {
        version: 1u32,
        apexes: apexes
            .iter()
            .map(|apex| ApexPayload { name: apex.name.clone(), ..Default::default() })
            .collect(),
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
    let mut metadata_file =
        OpenOptions::new().create_new(true).read(true).write(true).open(&metadata_path)?;
    microdroid_metadata::write_metadata(&metadata, &mut metadata_file)?;

    // put metadata at the first partition
    let mut partitions = vec![Partition {
        label: "payload-metadata".to_owned(),
        paths: vec![metadata_path],
        writable: false,
    }];

    let apex_info_list = ApexInfoList::load()?;
    for (i, apex) in apexes.iter().enumerate() {
        partitions.push(Partition {
            label: format!("microdroid-apex-{}", i),
            paths: vec![apex_info_list.get_path_for(&apex.name)?],
            writable: false,
        });
    }
    partitions.push(Partition {
        label: "microdroid-apk".to_owned(),
        paths: vec![apk_file],
        writable: false,
    });
    partitions.push(Partition {
        label: "microdroid-apk-idsig".to_owned(),
        paths: vec![idsig_file],
        writable: false,
    });

    Ok(DiskImage { image: None, partitions, writable: false })
}
