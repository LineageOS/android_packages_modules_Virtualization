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

//! Routines for handling payload

use crate::instance::ApexData;
use crate::ioutil::wait_for_file;
use anyhow::Result;
use log::info;
use microdroid_metadata::{read_metadata, ApexPayload, Metadata};
use std::fs::File;
use std::io::Read;
use std::time::Duration;
use zip::ZipArchive;

const APEX_PUBKEY_ENTRY: &str = "apex_pubkey";
const PAYLOAD_METADATA_PATH: &str = "/dev/block/by-name/payload-metadata";
const WAIT_TIMEOUT: Duration = Duration::from_secs(10);

/// Loads payload metadata from /dev/block/by-name/payload-metadata
pub fn load_metadata() -> Result<Metadata> {
    info!("loading payload metadata...");
    let file = wait_for_file(PAYLOAD_METADATA_PATH, WAIT_TIMEOUT)?;
    read_metadata(file)
}

/// Loads (name, pubkey) from payload APEXes
pub fn get_apex_data_from_payload(metadata: &Metadata) -> Result<Vec<ApexData>> {
    metadata
        .apexes
        .iter()
        .map(|apex| {
            let name = apex.name.clone();
            let partition = format!("/dev/block/by-name/{}", apex.partition_name);
            let pubkey = get_pubkey_from_apex(&partition)?;
            Ok(ApexData { name, pubkey })
        })
        .collect()
}

fn get_pubkey_from_apex(path: &str) -> Result<Vec<u8>> {
    let f = File::open(path)?;
    let mut z = ZipArchive::new(f)?;
    let mut pubkey_file = z.by_name(APEX_PUBKEY_ENTRY)?;
    let mut pubkey = Vec::new();
    pubkey_file.read_to_end(&mut pubkey)?;
    Ok(pubkey)
}

/// Convert vector of ApexData into Metadata
pub fn to_metadata(apex_data: &[ApexData]) -> Metadata {
    Metadata {
        apexes: apex_data
            .iter()
            .map(|data| ApexPayload {
                name: data.name.clone(),
                public_key: data.pubkey.clone(),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    }
}
