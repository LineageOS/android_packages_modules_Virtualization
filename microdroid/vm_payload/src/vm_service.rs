// Copyright 2022, The Android Open Source Project
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

//! This module handles the interaction with virtual machine payload service.

use android_system_virtualization_payload::aidl::android::system::virtualization::payload::IVmPayloadService::IVmPayloadService;
use anyhow::{Context, Result};
use binder::{wait_for_interface, Strong};
use log::{error, info, Level};

/// The CID representing the host VM
const VM_PAYLOAD_SERVICE_NAME: &str = "virtual_machine_payload_service";

/// Notifies the host that the payload is ready.
/// Returns true if the notification succeeds else false.
#[no_mangle]
pub extern "C" fn notify_payload_ready() -> bool {
    android_logger::init_once(
        android_logger::Config::default().with_tag("vm_payload").with_min_level(Level::Debug),
    );
    if let Err(e) = try_notify_payload_ready() {
        error!("Failed to notify ready: {}", e);
        false
    } else {
        info!("Notified host payload ready successfully");
        true
    }
}

/// Notifies the host that the payload is ready.
/// Returns a `Result` containing error information if failed.
fn try_notify_payload_ready() -> Result<()> {
    get_vm_payload_service()?.notifyPayloadReady().context("Cannot notify payload ready")
}

fn get_vm_payload_service() -> Result<Strong<dyn IVmPayloadService>> {
    wait_for_interface(VM_PAYLOAD_SERVICE_NAME)
        .context(format!("Failed to connect to service: {}", VM_PAYLOAD_SERVICE_NAME))
}
