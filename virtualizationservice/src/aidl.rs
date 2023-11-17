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

//! Implementation of the AIDL interface of the VirtualizationService.

use crate::{get_calling_pid, get_calling_uid, REMOTELY_PROVISIONED_COMPONENT_SERVICE_NAME};
use crate::atom::{forward_vm_booted_atom, forward_vm_creation_atom, forward_vm_exited_atom};
use crate::rkpvm::request_attestation;
use android_os_permissions_aidl::aidl::android::os::IPermissionController;
use android_system_virtualizationcommon::aidl::android::system::virtualizationcommon::Certificate::Certificate;
use android_system_virtualizationservice::{
    aidl::android::system::virtualizationservice::AssignableDevice::AssignableDevice,
    aidl::android::system::virtualizationservice::VirtualMachineDebugInfo::VirtualMachineDebugInfo,
    binder::ParcelFileDescriptor,
};
use android_system_virtualizationservice_internal::aidl::android::system::virtualizationservice_internal::{
    AtomVmBooted::AtomVmBooted,
    AtomVmCreationRequested::AtomVmCreationRequested,
    AtomVmExited::AtomVmExited,
    IGlobalVmContext::{BnGlobalVmContext, IGlobalVmContext},
    IVirtualizationServiceInternal::BoundDevice::BoundDevice,
    IVirtualizationServiceInternal::IVirtualizationServiceInternal,
    IVfioHandler::{BpVfioHandler, IVfioHandler},
};
use android_system_virtualmachineservice::aidl::android::system::virtualmachineservice::IVirtualMachineService::VM_TOMBSTONES_SERVICE_PORT;
use anyhow::{anyhow, ensure, Context, Result};
use avflog::LogResult;
use binder::{self, wait_for_interface, BinderFeatures, ExceptionCode, Interface, LazyServiceGuard, Status, Strong, IntoBinderResult};
use libc::VMADDR_CID_HOST;
use log::{error, info, warn};
use rkpd_client::get_rkpd_attestation_key;
use rustutils::system_properties;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs::{self, create_dir, remove_dir_all, set_permissions, File, Permissions};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::raw::{pid_t, uid_t};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use tombstoned_client::{DebuggerdDumpType, TombstonedConnection};
use vsock::{VsockListener, VsockStream};
use nix::unistd::{chown, Uid};

/// The unique ID of a VM used (together with a port number) for vsock communication.
pub type Cid = u32;

pub const BINDER_SERVICE_IDENTIFIER: &str = "android.system.virtualizationservice";

/// Directory in which to write disk image files used while running VMs.
pub const TEMPORARY_DIRECTORY: &str = "/data/misc/virtualizationservice";

/// The first CID to assign to a guest VM managed by the VirtualizationService. CIDs lower than this
/// are reserved for the host or other usage.
const GUEST_CID_MIN: Cid = 2048;
const GUEST_CID_MAX: Cid = 65535;

const SYSPROP_LAST_CID: &str = "virtualizationservice.state.last_cid";

const CHUNK_RECV_MAX_LEN: usize = 1024;

fn is_valid_guest_cid(cid: Cid) -> bool {
    (GUEST_CID_MIN..=GUEST_CID_MAX).contains(&cid)
}

/// Singleton service for allocating globally-unique VM resources, such as the CID, and running
/// singleton servers, like tombstone receiver.
#[derive(Debug, Default)]
pub struct VirtualizationServiceInternal {
    state: Arc<Mutex<GlobalState>>,
}

impl VirtualizationServiceInternal {
    pub fn init() -> VirtualizationServiceInternal {
        let service = VirtualizationServiceInternal::default();

        std::thread::spawn(|| {
            if let Err(e) = handle_stream_connection_tombstoned() {
                warn!("Error receiving tombstone from guest or writing them. Error: {:?}", e);
            }
        });

        service
    }
}

impl Interface for VirtualizationServiceInternal {}

impl IVirtualizationServiceInternal for VirtualizationServiceInternal {
    fn removeMemlockRlimit(&self) -> binder::Result<()> {
        let pid = get_calling_pid();
        let lim = libc::rlimit { rlim_cur: libc::RLIM_INFINITY, rlim_max: libc::RLIM_INFINITY };

        // SAFETY: borrowing the new limit struct only
        let ret = unsafe { libc::prlimit(pid, libc::RLIMIT_MEMLOCK, &lim, std::ptr::null_mut()) };

        match ret {
            0 => Ok(()),
            -1 => Err(std::io::Error::last_os_error().into()),
            n => Err(anyhow!("Unexpected return value from prlimit(): {n}")),
        }
        .or_binder_exception(ExceptionCode::ILLEGAL_STATE)
    }

    fn allocateGlobalVmContext(
        &self,
        requester_debug_pid: i32,
    ) -> binder::Result<Strong<dyn IGlobalVmContext>> {
        check_manage_access()?;

        let requester_uid = get_calling_uid();
        let requester_debug_pid = requester_debug_pid as pid_t;
        let state = &mut *self.state.lock().unwrap();
        state
            .allocate_vm_context(requester_uid, requester_debug_pid)
            .or_binder_exception(ExceptionCode::ILLEGAL_STATE)
    }

    fn atomVmBooted(&self, atom: &AtomVmBooted) -> Result<(), Status> {
        forward_vm_booted_atom(atom);
        Ok(())
    }

    fn atomVmCreationRequested(&self, atom: &AtomVmCreationRequested) -> Result<(), Status> {
        forward_vm_creation_atom(atom);
        Ok(())
    }

    fn atomVmExited(&self, atom: &AtomVmExited) -> Result<(), Status> {
        forward_vm_exited_atom(atom);
        Ok(())
    }

    fn debugListVms(&self) -> binder::Result<Vec<VirtualMachineDebugInfo>> {
        check_debug_access()?;

        let state = &mut *self.state.lock().unwrap();
        let cids = state
            .held_contexts
            .iter()
            .filter_map(|(_, inst)| Weak::upgrade(inst))
            .map(|vm| VirtualMachineDebugInfo {
                cid: vm.cid as i32,
                temporaryDirectory: vm.get_temp_dir().to_string_lossy().to_string(),
                requesterUid: vm.requester_uid as i32,
                requesterPid: vm.requester_debug_pid,
            })
            .collect();
        Ok(cids)
    }

    fn requestAttestation(
        &self,
        csr: &[u8],
        requester_uid: i32,
    ) -> binder::Result<Vec<Certificate>> {
        check_manage_access()?;
        info!("Received csr. Requestting attestation...");
        if cfg!(remote_attestation) {
            let attestation_key = get_rkpd_attestation_key(
                REMOTELY_PROVISIONED_COMPONENT_SERVICE_NAME,
                requester_uid as u32,
            )
            .context("Failed to retrieve the remotely provisioned keys")
            .with_log()
            .or_service_specific_exception(-1)?;
            let certificate = request_attestation(csr, &attestation_key.keyBlob)
                .context("Failed to request attestation")
                .with_log()
                .or_service_specific_exception(-1)?;
            // TODO(b/309780089): Parse the remotely provisioned certificate chain into
            // individual certificates.
            let mut certificate_chain =
                vec![Certificate { encodedCertificate: attestation_key.encodedCertChain }];
            certificate_chain.push(Certificate { encodedCertificate: certificate });
            Ok(certificate_chain)
        } else {
            Err(Status::new_exception_str(
                ExceptionCode::UNSUPPORTED_OPERATION,
                Some(
                    "requestAttestation is not supported with the remote_attestation feature \
                     disabled",
                ),
            ))
            .with_log()
        }
    }

    fn getAssignableDevices(&self) -> binder::Result<Vec<AssignableDevice>> {
        check_use_custom_virtual_machine()?;

        Ok(get_assignable_devices()?
            .device
            .into_iter()
            .map(|x| AssignableDevice { node: x.sysfs_path, kind: x.kind })
            .collect::<Vec<_>>())
    }

    fn bindDevicesToVfioDriver(&self, devices: &[String]) -> binder::Result<Vec<BoundDevice>> {
        check_use_custom_virtual_machine()?;

        let vfio_service: Strong<dyn IVfioHandler> =
            wait_for_interface(<BpVfioHandler as IVfioHandler>::get_descriptor())?;

        vfio_service.bindDevicesToVfioDriver(devices)?;

        let dtbo_path = Path::new(TEMPORARY_DIRECTORY).join("common").join("dtbo");
        if !dtbo_path.exists() {
            // open a writable file descriptor for vfio_handler
            let dtbo = File::create(&dtbo_path)
                .context("Failed to create VM DTBO file")
                .or_service_specific_exception(-1)?;
            vfio_service.writeVmDtbo(&ParcelFileDescriptor::new(dtbo))?;
        }

        Ok(get_assignable_devices()?
            .device
            .into_iter()
            .filter_map(|x| {
                if devices.contains(&x.sysfs_path) {
                    Some(BoundDevice { sysfsPath: x.sysfs_path, dtboLabel: x.dtbo_label })
                } else {
                    None
                }
            })
            .collect::<Vec<_>>())
    }
}

// KEEP IN SYNC WITH assignable_devices.xsd
#[derive(Debug, Deserialize)]
struct Device {
    kind: String,
    dtbo_label: String,
    sysfs_path: String,
}

#[derive(Debug, Default, Deserialize)]
struct Devices {
    device: Vec<Device>,
}

fn get_assignable_devices() -> binder::Result<Devices> {
    let xml_path = Path::new("/vendor/etc/avf/assignable_devices.xml");
    if !xml_path.exists() {
        return Ok(Devices { ..Default::default() });
    }

    let xml = fs::read(xml_path)
        .context("Failed to read assignable_devices.xml")
        .with_log()
        .or_service_specific_exception(-1)?;

    let xml = String::from_utf8(xml)
        .context("assignable_devices.xml is not a valid UTF-8 file")
        .with_log()
        .or_service_specific_exception(-1)?;

    let mut devices: Devices = serde_xml_rs::from_str(&xml)
        .context("can't parse assignable_devices.xml")
        .with_log()
        .or_service_specific_exception(-1)?;

    let mut device_set = HashSet::new();
    devices.device.retain(move |device| {
        if device_set.contains(&device.sysfs_path) {
            warn!("duplicated assignable device {device:?}; ignoring...");
            return false;
        }

        if !Path::new(&device.sysfs_path).exists() {
            warn!("assignable device {device:?} doesn't exist; ignoring...");
            return false;
        }

        device_set.insert(device.sysfs_path.clone());
        true
    });
    Ok(devices)
}

#[derive(Debug, Default)]
struct GlobalVmInstance {
    /// The unique CID assigned to the VM for vsock communication.
    cid: Cid,
    /// UID of the client who requested this VM instance.
    requester_uid: uid_t,
    /// PID of the client who requested this VM instance.
    requester_debug_pid: pid_t,
}

impl GlobalVmInstance {
    fn get_temp_dir(&self) -> PathBuf {
        let cid = self.cid;
        format!("{TEMPORARY_DIRECTORY}/{cid}").into()
    }
}

/// The mutable state of the VirtualizationServiceInternal. There should only be one instance
/// of this struct.
#[derive(Debug, Default)]
struct GlobalState {
    /// VM contexts currently allocated to running VMs. A CID is never recycled as long
    /// as there is a strong reference held by a GlobalVmContext.
    held_contexts: HashMap<Cid, Weak<GlobalVmInstance>>,
}

impl GlobalState {
    /// Get the next available CID, or an error if we have run out. The last CID used is stored in
    /// a system property so that restart of virtualizationservice doesn't reuse CID while the host
    /// Android is up.
    fn get_next_available_cid(&mut self) -> Result<Cid> {
        // Start trying to find a CID from the last used CID + 1. This ensures
        // that we do not eagerly recycle CIDs. It makes debugging easier but
        // also means that retrying to allocate a CID, eg. because it is
        // erroneously occupied by a process, will not recycle the same CID.
        let last_cid_prop =
            system_properties::read(SYSPROP_LAST_CID)?.and_then(|val| match val.parse::<Cid>() {
                Ok(num) => {
                    if is_valid_guest_cid(num) {
                        Some(num)
                    } else {
                        error!("Invalid value '{}' of property '{}'", num, SYSPROP_LAST_CID);
                        None
                    }
                }
                Err(_) => {
                    error!("Invalid value '{}' of property '{}'", val, SYSPROP_LAST_CID);
                    None
                }
            });

        let first_cid = if let Some(last_cid) = last_cid_prop {
            if last_cid == GUEST_CID_MAX {
                GUEST_CID_MIN
            } else {
                last_cid + 1
            }
        } else {
            GUEST_CID_MIN
        };

        let cid = self
            .find_available_cid(first_cid..=GUEST_CID_MAX)
            .or_else(|| self.find_available_cid(GUEST_CID_MIN..first_cid))
            .ok_or_else(|| anyhow!("Could not find an available CID."))?;

        system_properties::write(SYSPROP_LAST_CID, &format!("{}", cid))?;
        Ok(cid)
    }

    fn find_available_cid<I>(&self, mut range: I) -> Option<Cid>
    where
        I: Iterator<Item = Cid>,
    {
        range.find(|cid| !self.held_contexts.contains_key(cid))
    }

    fn allocate_vm_context(
        &mut self,
        requester_uid: uid_t,
        requester_debug_pid: pid_t,
    ) -> Result<Strong<dyn IGlobalVmContext>> {
        // Garbage collect unused VM contexts.
        self.held_contexts.retain(|_, instance| instance.strong_count() > 0);

        let cid = self.get_next_available_cid()?;
        let instance = Arc::new(GlobalVmInstance { cid, requester_uid, requester_debug_pid });
        create_temporary_directory(&instance.get_temp_dir(), requester_uid)?;

        self.held_contexts.insert(cid, Arc::downgrade(&instance));
        let binder = GlobalVmContext { instance, ..Default::default() };
        Ok(BnGlobalVmContext::new_binder(binder, BinderFeatures::default()))
    }
}

fn create_temporary_directory(path: &PathBuf, requester_uid: uid_t) -> Result<()> {
    if path.as_path().exists() {
        remove_temporary_dir(path).unwrap_or_else(|e| {
            warn!("Could not delete temporary directory {:?}: {}", path, e);
        });
    }
    // Create a directory that is owned by client's UID but system's GID, and permissions 0700.
    // If the chown() fails, this will leave behind an empty directory that will get removed
    // at the next attempt, or if virtualizationservice is restarted.
    create_dir(path).with_context(|| format!("Could not create temporary directory {:?}", path))?;
    chown(path, Some(Uid::from_raw(requester_uid)), None)
        .with_context(|| format!("Could not set ownership of temporary directory {:?}", path))?;
    Ok(())
}

/// Removes a directory owned by a different user by first changing its owner back
/// to VirtualizationService.
pub fn remove_temporary_dir(path: &PathBuf) -> Result<()> {
    ensure!(path.as_path().is_dir(), "Path {:?} is not a directory", path);
    chown(path, Some(Uid::current()), None)?;
    set_permissions(path, Permissions::from_mode(0o700))?;
    remove_dir_all(path)?;
    Ok(())
}

/// Implementation of the AIDL `IGlobalVmContext` interface.
#[derive(Debug, Default)]
struct GlobalVmContext {
    /// Strong reference to the context's instance data structure.
    instance: Arc<GlobalVmInstance>,
    /// Keeps our service process running as long as this VM context exists.
    #[allow(dead_code)]
    lazy_service_guard: LazyServiceGuard,
}

impl Interface for GlobalVmContext {}

impl IGlobalVmContext for GlobalVmContext {
    fn getCid(&self) -> binder::Result<i32> {
        Ok(self.instance.cid as i32)
    }

    fn getTemporaryDirectory(&self) -> binder::Result<String> {
        Ok(self.instance.get_temp_dir().to_string_lossy().to_string())
    }
}

fn handle_stream_connection_tombstoned() -> Result<()> {
    // Should not listen for tombstones on a guest VM's port.
    assert!(!is_valid_guest_cid(VM_TOMBSTONES_SERVICE_PORT as Cid));
    let listener =
        VsockListener::bind_with_cid_port(VMADDR_CID_HOST, VM_TOMBSTONES_SERVICE_PORT as Cid)?;
    for incoming_stream in listener.incoming() {
        let mut incoming_stream = match incoming_stream {
            Err(e) => {
                warn!("invalid incoming connection: {:?}", e);
                continue;
            }
            Ok(s) => s,
        };
        std::thread::spawn(move || {
            if let Err(e) = handle_tombstone(&mut incoming_stream) {
                error!("Failed to write tombstone- {:?}", e);
            }
        });
    }
    Ok(())
}

fn handle_tombstone(stream: &mut VsockStream) -> Result<()> {
    if let Ok(addr) = stream.peer_addr() {
        info!("Vsock Stream connected to cid={} for tombstones", addr.cid());
    }
    let tb_connection =
        TombstonedConnection::connect(std::process::id() as i32, DebuggerdDumpType::Tombstone)
            .context("Failed to connect to tombstoned")?;
    let mut text_output = tb_connection
        .text_output
        .as_ref()
        .ok_or_else(|| anyhow!("Could not get file to write the tombstones on"))?;
    let mut num_bytes_read = 0;
    loop {
        let mut chunk_recv = [0; CHUNK_RECV_MAX_LEN];
        let n = stream
            .read(&mut chunk_recv)
            .context("Failed to read tombstone data from Vsock stream")?;
        if n == 0 {
            break;
        }
        num_bytes_read += n;
        text_output.write_all(&chunk_recv[0..n]).context("Failed to write guests tombstones")?;
    }
    info!("Received {} bytes from guest & wrote to tombstone file", num_bytes_read);
    tb_connection.notify_completion()?;
    Ok(())
}

/// Checks whether the caller has a specific permission
fn check_permission(perm: &str) -> binder::Result<()> {
    let calling_pid = get_calling_pid();
    let calling_uid = get_calling_uid();
    // Root can do anything
    if calling_uid == 0 {
        return Ok(());
    }
    let perm_svc: Strong<dyn IPermissionController::IPermissionController> =
        binder::get_interface("permission")?;
    if perm_svc.checkPermission(perm, calling_pid, calling_uid as i32)? {
        Ok(())
    } else {
        Err(anyhow!("does not have the {} permission", perm))
            .or_binder_exception(ExceptionCode::SECURITY)
    }
}

/// Check whether the caller of the current Binder method is allowed to call debug methods.
fn check_debug_access() -> binder::Result<()> {
    check_permission("android.permission.DEBUG_VIRTUAL_MACHINE")
}

/// Check whether the caller of the current Binder method is allowed to manage VMs
fn check_manage_access() -> binder::Result<()> {
    check_permission("android.permission.MANAGE_VIRTUAL_MACHINE")
}

/// Check whether the caller of the current Binder method is allowed to use custom VMs
fn check_use_custom_virtual_machine() -> binder::Result<()> {
    check_permission("android.permission.USE_CUSTOM_VIRTUAL_MACHINE")
}
