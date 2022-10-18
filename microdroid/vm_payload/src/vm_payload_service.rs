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

use android_system_virtualization_payload::aidl::android::system::virtualization::payload::IVmPayloadService::{
    IVmPayloadService, VM_PAYLOAD_SERVICE_NAME};
use anyhow::{Context, Result};
use binder::{wait_for_interface, Strong};
use log::{error, info, Level};

/// Notifies the host that the payload is ready.
/// Returns true if the notification succeeds else false.
#[no_mangle]
pub extern "C" fn AVmPayload_notifyPayloadReady() -> bool {
    android_logger::init_once(
        android_logger::Config::default().with_tag("vm_payload").with_min_level(Level::Debug),
    );
    if let Err(e) = try_notify_payload_ready() {
        error!("{:?}", e);
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

/// Get a secret that is uniquely bound to this VM instance.
///
/// # Safety
///
/// Behavior is undefined if any of the following conditions are violated:
///
/// * `identifier` must be [valid] for reads of `identifier_size` bytes.
/// * `secret` must be [valid] for writes of `size` bytes.
///
/// [valid]: std::ptr#safety
#[no_mangle]
pub unsafe extern "C" fn AVmPayload_getVmInstanceSecret(
    identifier: *const u8,
    identifier_size: usize,
    secret: *mut u8,
    size: usize,
) -> bool {
    let identifier = std::slice::from_raw_parts(identifier, identifier_size);
    match try_get_vm_instance_secret(identifier, size) {
        Err(e) => {
            error!("{:?}", e);
            false
        }
        Ok(vm_secret) => {
            if vm_secret.len() != size {
                return false;
            }
            std::ptr::copy_nonoverlapping(vm_secret.as_ptr(), secret, size);
            true
        }
    }
}

fn try_get_vm_instance_secret(identifier: &[u8], size: usize) -> Result<Vec<u8>> {
    get_vm_payload_service()?
        .getVmInstanceSecret(identifier, i32::try_from(size)?)
        .context("Cannot get VM instance secret")
}

/// Get the VM's attestation chain.
/// Returns true on success, else false.
///
/// # Safety
///
/// Behavior is undefined if any of the following conditions are violated:
///
/// * `data` must be [valid] for writes of `size` bytes.
/// * `total` must be [valid] for writes.
///
/// [valid]: std::ptr#safety
#[no_mangle]
pub unsafe extern "C" fn AVmPayload_getDiceAttestationChain(
    data: *mut u8,
    size: usize,
    total: *mut usize,
) -> bool {
    match try_get_dice_attestation_chain() {
        Err(e) => {
            error!("{:?}", e);
            false
        }
        Ok(chain) => {
            total.write(chain.len());
            std::ptr::copy_nonoverlapping(chain.as_ptr(), data, std::cmp::min(chain.len(), size));
            true
        }
    }
}

fn try_get_dice_attestation_chain() -> Result<Vec<u8>> {
    get_vm_payload_service()?.getDiceAttestationChain().context("Cannot get attestation chain")
}

/// Get the VM's attestation CDI.
/// Returns true on success, else false.
///
/// # Safety
///
/// Behavior is undefined if any of the following conditions are violated:
///
/// * `data` must be [valid] for writes of `size` bytes.
/// * `total` must be [valid] for writes.
///
/// [valid]: std::ptr#safety
#[no_mangle]
pub unsafe extern "C" fn AVmPayload_getDiceAttestationCdi(
    data: *mut u8,
    size: usize,
    total: *mut usize,
) -> bool {
    match try_get_dice_attestation_cdi() {
        Err(e) => {
            error!("{:?}", e);
            false
        }
        Ok(cdi) => {
            total.write(cdi.len());
            std::ptr::copy_nonoverlapping(cdi.as_ptr(), data, std::cmp::min(cdi.len(), size));
            true
        }
    }
}

fn try_get_dice_attestation_cdi() -> Result<Vec<u8>> {
    get_vm_payload_service()?.getDiceAttestationCdi().context("Cannot get attestation CDI")
}

fn get_vm_payload_service() -> Result<Strong<dyn IVmPayloadService>> {
    wait_for_interface(VM_PAYLOAD_SERVICE_NAME)
        .context(format!("Failed to connect to service: {}", VM_PAYLOAD_SERVICE_NAME))
}
