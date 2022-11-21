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
    IVmPayloadService, VM_PAYLOAD_SERVICE_SOCKET_NAME, VM_APK_CONTENTS_PATH};
use anyhow::{Context, Result};
use binder::{Strong, unstable_api::{AIBinder, new_spibinder}};
use lazy_static::lazy_static;
use log::{error, info, Level};
use rpcbinder::{get_unix_domain_rpc_interface, run_vsock_rpc_server};
use std::ffi::CString;
use std::os::raw::{c_char, c_void};
use std::ptr;
use std::sync::Mutex;

lazy_static! {
    static ref VM_APK_CONTENTS_PATH_C: CString =
        CString::new(VM_APK_CONTENTS_PATH).expect("CString::new failed");
    static ref PAYLOAD_CONNECTION: Mutex<Option<Strong<dyn IVmPayloadService>>> = Mutex::default();
}

/// Return a connection to the payload service in Microdroid Manager. Uses the existing connection
/// if there is one, otherwise attempts to create a new one.
fn get_vm_payload_service() -> Result<Strong<dyn IVmPayloadService>> {
    let mut connection = PAYLOAD_CONNECTION.lock().unwrap();
    if let Some(strong) = &*connection {
        Ok(strong.clone())
    } else {
        let new_connection: Strong<dyn IVmPayloadService> = get_unix_domain_rpc_interface(
            VM_PAYLOAD_SERVICE_SOCKET_NAME,
        )
        .context(format!("Failed to connect to service: {}", VM_PAYLOAD_SERVICE_SOCKET_NAME))?;
        *connection = Some(new_connection.clone());
        Ok(new_connection)
    }
}

/// Make sure our logging goes to logcat. It is harmless to call this more than once.
fn initialize_logging() {
    android_logger::init_once(
        android_logger::Config::default().with_tag("vm_payload").with_min_level(Level::Debug),
    );
}

/// Notifies the host that the payload is ready.
/// Returns true if the notification succeeds else false.
#[no_mangle]
pub extern "C" fn AVmPayload_notifyPayloadReady() -> bool {
    initialize_logging();

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

/// Runs a binder RPC server, serving the supplied binder service implementation on the given vsock
/// port.
///
/// If and when the server is ready for connections (it is listening on the port), `on_ready` is
/// called to allow appropriate action to be taken - e.g. to notify clients that they may now
/// attempt to connect.
///
/// The current thread is joined to the binder thread pool to handle incoming messages.
///
/// Returns true if the server has shutdown normally, false if it failed in some way.
///
/// # Safety
///
/// The `on_ready` callback is only called inside `run_vsock_rpc_server`, within the lifetime of
/// `ReadyNotifier` (the last parameter of `run_vsock_rpc_server`). If `on_ready` is called with
/// wrong param, the callback execution could go wrong.
#[no_mangle]
pub unsafe extern "C" fn AVmPayload_runVsockRpcServer(
    service: *mut AIBinder,
    port: u32,
    on_ready: Option<unsafe extern "C" fn(param: *mut c_void)>,
    param: *mut c_void,
) -> bool {
    initialize_logging();

    // SAFETY: AIBinder returned has correct reference count, and the ownership can
    // safely be taken by new_spibinder.
    let service = new_spibinder(service);
    if let Some(service) = service {
        run_vsock_rpc_server(service, port, || {
            if let Some(on_ready) = on_ready {
                on_ready(param);
            }
        })
    } else {
        error!("Failed to convert the given service from AIBinder to SpIBinder.");
        false
    }
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
    initialize_logging();

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
    initialize_logging();

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
    initialize_logging();

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

/// Gets the path to the APK contents.
#[no_mangle]
pub extern "C" fn AVmPayload_getApkContentsPath() -> *const c_char {
    (*VM_APK_CONTENTS_PATH_C).as_ptr()
}

/// Gets the path to the VM's encrypted storage.
#[no_mangle]
pub extern "C" fn AVmPayload_getEncryptedStoragePath() -> *const c_char {
    // TODO(b/254454578): Return a real path if storage is present
    ptr::null()
}

fn try_get_dice_attestation_cdi() -> Result<Vec<u8>> {
    get_vm_payload_service()?.getDiceAttestationCdi().context("Cannot get attestation CDI")
}
