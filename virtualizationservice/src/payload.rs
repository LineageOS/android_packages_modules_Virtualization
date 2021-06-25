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

use crate::composite::align_to_partition_size;

use anyhow::{Error, Result};
use microdroid_metadata::{ApexPayload, ApkPayload, Metadata};
use microdroid_payload_config::ApexConfig;
use std::fs;
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use vmconfig::{DiskImage, Partition};

// TODO(b/191601801): look up /apex/apex-info-list.xml
fn get_path(package_name: &str) -> Result<PathBuf> {
    let output = Command::new("pm").arg("path").arg(package_name).output()?;
    let output = String::from_utf8(output.stdout)?;
    Ok(PathBuf::from(output.strip_prefix("package:").unwrap().trim()))
}

/// When passing a host APEX file as a block device in a payload disk image,
/// the size of the original file needs to be stored in the last 4 bytes so that
/// other programs (e.g. apexd) can read it as a zip.
fn make_size_filler(size: u64, filler_path: &Path) -> Result<bool> {
    let partition_size = align_to_partition_size(size + 4);
    let mut file = OpenOptions::new().create_new(true).write(true).open(filler_path)?;
    file.set_len(partition_size - size)?;
    file.seek(SeekFrom::End(-4))?;
    file.write_all(&(size as i32).to_be_bytes())?;
    Ok(true)
}

/// When passing a host APK file as a block device in a payload disk image and it is
/// mounted via dm-verity, we need to make the device zero-padded up to 4K boundary.
/// Otherwise, intergrity checks via hashtree will fail.
fn make_zero_filler(size: u64, filler_path: &Path) -> Result<bool> {
    let partition_size = align_to_partition_size(size);
    if partition_size <= size {
        return Ok(false);
    }
    let file = OpenOptions::new().create_new(true).write(true).open(filler_path)?;
    file.set_len(partition_size - size)?;
    Ok(true)
}

/// When passing a host idsig file as a block device, we don't need any filler because it is read
/// in length-prefixed way.
fn make_no_filler(_size: u64, _filler_path: &Path) -> Result<bool> {
    Ok(false)
}

/// Creates a DiskImage with partitions:
///   metadata: metadata
///   microdroid-apex-0: [apex 0, size filler]
///   microdroid-apex-1: [apex 1, size filler]
///   ..
///   microdroid-apk: [apk, zero filler]
///   microdroid-apk-idsig: idsig
pub fn make_disk_image(
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
            .map(|apex| ApexPayload { name: String::from(&apex.name), ..Default::default() })
            .collect(),
        apk: Some(ApkPayload {
            name: String::from("apk"),
            payload_partition_name: String::from("microdroid-apk"),
            idsig_partition_name: String::from("microdroid-apk-idsig"),
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
        label: String::from("metadata"),
        path: Some(metadata_path),
        paths: vec![],
        writable: false,
    }];

    let mut filler_count = 0;
    let mut make_partition = |label: String,
                              path: PathBuf,
                              make_filler: &dyn Fn(u64, &Path) -> Result<bool, Error>|
     -> Result<Partition> {
        let filler_path = temporary_directory.join(format!("filler-{}", filler_count));
        let size = fs::metadata(&path)?.len();

        if make_filler(size, &filler_path)? {
            filler_count += 1;
            Ok(Partition { label, path: None, paths: vec![path, filler_path], writable: false })
        } else {
            Ok(Partition { label, path: Some(path), paths: vec![], writable: false })
        }
    };
    for (i, apex) in apexes.iter().enumerate() {
        partitions.push(make_partition(
            format!("microdroid-apex-{}", i),
            get_path(&apex.name)?,
            &make_size_filler,
        )?);
    }
    partitions.push(make_partition(String::from("microdroid-apk"), apk_file, &make_zero_filler)?);
    partitions.push(make_partition(
        String::from("microdroid-apk-idsig"),
        idsig_file,
        &make_no_filler,
    )?);

    Ok(DiskImage { image: None, partitions, writable: false })
}
