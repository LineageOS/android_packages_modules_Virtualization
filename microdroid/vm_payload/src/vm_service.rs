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

//! This module handles the interaction with virtual machine service.

use android_system_virtualmachineservice::aidl::android::system::virtualmachineservice::IVirtualMachineService::{
    VM_BINDER_SERVICE_PORT, IVirtualMachineService};
use anyhow::{Context, Result};
use binder::Strong;
use log::{error, info, Level};
use rpcbinder::get_vsock_rpc_interface;

/// The CID representing the host VM
const VMADDR_CID_HOST: u32 = 2;

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
    get_vm_service()?.notifyPayloadReady().context("Cannot notify payload ready")
}

fn get_vm_service() -> Result<Strong<dyn IVirtualMachineService>> {
    get_vsock_rpc_interface(VMADDR_CID_HOST, VM_BINDER_SERVICE_PORT as u32)
        .context("Connecting to IVirtualMachineService")
}
