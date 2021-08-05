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

//! Android VirtualizationService

mod aidl;
mod composite;
mod crosvm;
mod payload;

use crate::aidl::{VirtualizationService, BINDER_SERVICE_IDENTIFIER, TEMPORARY_DIRECTORY};
use android_system_virtualizationservice::aidl::android::system::virtualizationservice::IVirtualizationService::BnVirtualizationService;
use android_system_virtualizationservice::binder::{add_service, BinderFeatures, ProcessState};
use anyhow::Error;
use log::{info, Level};
use std::fs::{remove_dir_all, remove_file, read_dir};

/// The first CID to assign to a guest VM managed by the VirtualizationService. CIDs lower than this
/// are reserved for the host or other usage.
const FIRST_GUEST_CID: Cid = 10;

const LOG_TAG: &str = "VirtualizationService";

/// The unique ID of a VM used (together with a port number) for vsock communication.
type Cid = u32;

fn main() {
    android_logger::init_once(
        android_logger::Config::default().with_tag(LOG_TAG).with_min_level(Level::Trace),
    );

    clear_temporary_files().expect("Failed to delete old temporary files");

    let service = VirtualizationService::init();
    let service = BnVirtualizationService::new_binder(
        service,
        BinderFeatures { set_requesting_sid: true, ..BinderFeatures::default() },
    );
    add_service(BINDER_SERVICE_IDENTIFIER, service.as_binder()).unwrap();
    info!("Registered Binder service, joining threadpool.");
    ProcessState::join_thread_pool();
}

/// Remove any files under `TEMPORARY_DIRECTORY`.
fn clear_temporary_files() -> Result<(), Error> {
    for dir_entry in read_dir(TEMPORARY_DIRECTORY)? {
        let dir_entry = dir_entry?;
        let path = dir_entry.path();
        if dir_entry.file_type()?.is_dir() {
            remove_dir_all(path)?;
        } else {
            remove_file(path)?;
        }
    }
    Ok(())
}
