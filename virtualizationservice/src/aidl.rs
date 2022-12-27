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

use crate::{get_calling_pid, get_calling_uid};
use crate::atom::{
    forward_vm_booted_atom, forward_vm_creation_atom, forward_vm_exited_atom,
    write_vm_booted_stats, write_vm_creation_stats};
use crate::composite::make_composite_image;
use crate::crosvm::{CrosvmConfig, DiskFile, PayloadState, VmContext, VmInstance, VmState};
use crate::payload::{add_microdroid_payload_images, add_microdroid_system_images};
use crate::selinux::{getfilecon, SeContext};
use android_os_permissions_aidl::aidl::android::os::IPermissionController;
use android_system_virtualizationcommon::aidl::android::system::virtualizationcommon::{
    DeathReason::DeathReason,
    ErrorCode::ErrorCode,
};
use android_system_virtualizationservice::aidl::android::system::virtualizationservice::{
    DiskImage::DiskImage,
    IVirtualMachine::{BnVirtualMachine, IVirtualMachine},
    IVirtualMachineCallback::IVirtualMachineCallback,
    IVirtualizationService::IVirtualizationService,
    MemoryTrimLevel::MemoryTrimLevel,
    Partition::Partition,
    PartitionType::PartitionType,
    VirtualMachineAppConfig::{DebugLevel::DebugLevel, Payload::Payload, VirtualMachineAppConfig},
    VirtualMachineConfig::VirtualMachineConfig,
    VirtualMachineDebugInfo::VirtualMachineDebugInfo,
    VirtualMachinePayloadConfig::VirtualMachinePayloadConfig,
    VirtualMachineRawConfig::VirtualMachineRawConfig,
    VirtualMachineState::VirtualMachineState,
};
use android_system_virtualizationservice_internal::aidl::android::system::virtualizationservice_internal::{
    AtomVmBooted::AtomVmBooted,
    AtomVmCreationRequested::AtomVmCreationRequested,
    AtomVmExited::AtomVmExited,
    IGlobalVmContext::{BnGlobalVmContext, IGlobalVmContext},
    IVirtualizationServiceInternal::IVirtualizationServiceInternal,
};
use android_system_virtualmachineservice::aidl::android::system::virtualmachineservice::IVirtualMachineService::{
        BnVirtualMachineService, IVirtualMachineService, VM_TOMBSTONES_SERVICE_PORT,
};
use anyhow::{anyhow, bail, Context, Result};
use apkverify::{HashAlgorithm, V4Signature};
use binder::{
    self, wait_for_interface, BinderFeatures, ExceptionCode, Interface, LazyServiceGuard,
    ParcelFileDescriptor, Status, StatusCode, Strong,
};
use disk::QcowFile;
use lazy_static::lazy_static;
use libc::VMADDR_CID_HOST;
use log::{debug, error, info, warn};
use microdroid_payload_config::{OsConfig, Task, TaskType, VmPayloadConfig};
use nix::unistd::pipe;
use rpcbinder::RpcServer;
use rustutils::system_properties;
use semver::VersionReq;
use std::collections::HashMap;
use std::convert::TryInto;
use std::ffi::CStr;
use std::fs::{create_dir, read_dir, remove_dir, remove_file, set_permissions, File, OpenOptions, Permissions};
use std::io::{BufRead, BufReader, Error, ErrorKind, Read, Write};
use std::num::NonZeroU32;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::os::unix::raw::{pid_t, uid_t};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use tombstoned_client::{DebuggerdDumpType, TombstonedConnection};
use vmconfig::VmConfig;
use vsock::{VsockListener, VsockStream};
use zip::ZipArchive;
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

/// The size of zero.img.
/// Gaps in composite disk images are filled with a shared zero.img.
const ZERO_FILLER_SIZE: u64 = 4096;

/// Magic string for the instance image
const ANDROID_VM_INSTANCE_MAGIC: &str = "Android-VM-instance";

/// Version of the instance image format
const ANDROID_VM_INSTANCE_VERSION: u16 = 1;

const CHUNK_RECV_MAX_LEN: usize = 1024;

const MICRODROID_OS_NAME: &str = "microdroid";

const UNFORMATTED_STORAGE_MAGIC: &str = "UNFORMATTED-STORAGE";

lazy_static! {
    pub static ref GLOBAL_SERVICE: Strong<dyn IVirtualizationServiceInternal> =
        wait_for_interface(BINDER_SERVICE_IDENTIFIER)
            .expect("Could not connect to VirtualizationServiceInternal");
}

fn is_valid_guest_cid(cid: Cid) -> bool {
    (GUEST_CID_MIN..=GUEST_CID_MAX).contains(&cid)
}

fn create_or_update_idsig_file(
    input_fd: &ParcelFileDescriptor,
    idsig_fd: &ParcelFileDescriptor,
) -> Result<()> {
    let mut input = clone_file(input_fd)?;
    let metadata = input.metadata().context("failed to get input metadata")?;
    if !metadata.is_file() {
        bail!("input is not a regular file");
    }
    let mut sig = V4Signature::create(&mut input, 4096, &[], HashAlgorithm::SHA256)
        .context("failed to create idsig")?;

    let mut output = clone_file(idsig_fd)?;
    output.set_len(0).context("failed to set_len on the idsig output")?;
    sig.write_into(&mut output).context("failed to write idsig")?;
    Ok(())
}

/// Singleton service for allocating globally-unique VM resources, such as the CID, and running
/// singleton servers, like tombstone receiver.
#[derive(Debug, Default)]
pub struct VirtualizationServiceInternal {
    state: Arc<Mutex<GlobalState>>,
}

impl VirtualizationServiceInternal {
    // TODO(b/245727626): Remove after the source files for virtualizationservice
    // and virtmgr binaries are split from each other.
    #[allow(dead_code)]
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

        // SAFETY - borrowing the new limit struct only
        let ret = unsafe { libc::prlimit(pid, libc::RLIMIT_MEMLOCK, &lim, std::ptr::null_mut()) };

        match ret {
            0 => Ok(()),
            -1 => Err(Status::new_exception_str(
                ExceptionCode::ILLEGAL_STATE,
                Some(std::io::Error::last_os_error().to_string()),
            )),
            n => Err(Status::new_exception_str(
                ExceptionCode::ILLEGAL_STATE,
                Some(format!("Unexpected return value from prlimit(): {n}")),
            )),
        }
    }

    fn allocateGlobalVmContext(
        &self,
        requester_debug_pid: i32,
    ) -> binder::Result<Strong<dyn IGlobalVmContext>> {
        let requester_uid = get_calling_uid();
        let requester_debug_pid = requester_debug_pid as pid_t;
        let state = &mut *self.state.lock().unwrap();
        state.allocate_vm_context(requester_uid, requester_debug_pid).map_err(|e| {
            Status::new_exception_str(ExceptionCode::ILLEGAL_STATE, Some(e.to_string()))
        })
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
        let state = &mut *self.state.lock().unwrap();
        let cids = state
            .held_contexts
            .iter()
            .filter_map(|(_, inst)| Weak::upgrade(inst))
            .map(|vm| VirtualMachineDebugInfo {
                cid: vm.cid as i32,
                temporaryDirectory: vm.get_temp_dir().to_string_lossy().to_string(),
                requesterUid: vm.requester_uid as i32,
                requesterPid: vm.requester_debug_pid as i32,
            })
            .collect();
        Ok(cids)
    }
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
    if !path.as_path().is_dir() {
        bail!("Path {:?} is not a directory", path);
    }
    chown(path, Some(Uid::current()), None)?;
    set_permissions(path, Permissions::from_mode(0o700))?;
    remove_temporary_files(path)?;
    remove_dir(path)?;
    Ok(())
}

pub fn remove_temporary_files(path: &PathBuf) -> Result<()> {
    for dir_entry in read_dir(path)? {
        remove_file(dir_entry?.path())?;
    }
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

/// Implementation of `IVirtualizationService`, the entry point of the AIDL service.
#[derive(Debug, Default)]
pub struct VirtualizationService {
    state: Arc<Mutex<State>>,
}

impl Interface for VirtualizationService {
    fn dump(&self, mut file: &File, _args: &[&CStr]) -> Result<(), StatusCode> {
        check_permission("android.permission.DUMP").or(Err(StatusCode::PERMISSION_DENIED))?;
        let state = &mut *self.state.lock().unwrap();
        let vms = state.vms();
        writeln!(file, "Running {0} VMs:", vms.len()).or(Err(StatusCode::UNKNOWN_ERROR))?;
        for vm in vms {
            writeln!(file, "VM CID: {}", vm.cid).or(Err(StatusCode::UNKNOWN_ERROR))?;
            writeln!(file, "\tState: {:?}", vm.vm_state.lock().unwrap())
                .or(Err(StatusCode::UNKNOWN_ERROR))?;
            writeln!(file, "\tPayload state {:?}", vm.payload_state())
                .or(Err(StatusCode::UNKNOWN_ERROR))?;
            writeln!(file, "\tProtected: {}", vm.protected).or(Err(StatusCode::UNKNOWN_ERROR))?;
            writeln!(file, "\ttemporary_directory: {}", vm.temporary_directory.to_string_lossy())
                .or(Err(StatusCode::UNKNOWN_ERROR))?;
            writeln!(file, "\trequester_uid: {}", vm.requester_uid)
                .or(Err(StatusCode::UNKNOWN_ERROR))?;
            writeln!(file, "\trequester_debug_pid: {}", vm.requester_debug_pid)
                .or(Err(StatusCode::UNKNOWN_ERROR))?;
        }
        Ok(())
    }
}

impl IVirtualizationService for VirtualizationService {
    /// Creates (but does not start) a new VM with the given configuration, assigning it the next
    /// available CID.
    ///
    /// Returns a binder `IVirtualMachine` object referring to it, as a handle for the client.
    fn createVm(
        &self,
        config: &VirtualMachineConfig,
        console_fd: Option<&ParcelFileDescriptor>,
        log_fd: Option<&ParcelFileDescriptor>,
    ) -> binder::Result<Strong<dyn IVirtualMachine>> {
        let mut is_protected = false;
        let ret = self.create_vm_internal(config, console_fd, log_fd, &mut is_protected);
        write_vm_creation_stats(config, is_protected, &ret);
        ret
    }

    /// Initialise an empty partition image of the given size to be used as a writable partition.
    fn initializeWritablePartition(
        &self,
        image_fd: &ParcelFileDescriptor,
        size: i64,
        partition_type: PartitionType,
    ) -> binder::Result<()> {
        check_manage_access()?;
        let size = size.try_into().map_err(|e| {
            Status::new_exception_str(
                ExceptionCode::ILLEGAL_ARGUMENT,
                Some(format!("Invalid size {}: {:?}", size, e)),
            )
        })?;
        let image = clone_file(image_fd)?;
        // initialize the file. Any data in the file will be erased.
        image.set_len(0).map_err(|e| {
            Status::new_service_specific_error_str(
                -1,
                Some(format!("Failed to reset a file: {:?}", e)),
            )
        })?;
        let mut part = QcowFile::new(image, size).map_err(|e| {
            Status::new_service_specific_error_str(
                -1,
                Some(format!("Failed to create QCOW2 image: {:?}", e)),
            )
        })?;

        match partition_type {
            PartitionType::RAW => Ok(()),
            PartitionType::ANDROID_VM_INSTANCE => format_as_android_vm_instance(&mut part),
            PartitionType::ENCRYPTEDSTORE => format_as_encryptedstore(&mut part),
            _ => Err(Error::new(
                ErrorKind::Unsupported,
                format!("Unsupported partition type {:?}", partition_type),
            )),
        }
        .map_err(|e| {
            Status::new_service_specific_error_str(
                -1,
                Some(format!("Failed to initialize partition as {:?}: {:?}", partition_type, e)),
            )
        })?;

        Ok(())
    }

    /// Creates or update the idsig file by digesting the input APK file.
    fn createOrUpdateIdsigFile(
        &self,
        input_fd: &ParcelFileDescriptor,
        idsig_fd: &ParcelFileDescriptor,
    ) -> binder::Result<()> {
        // TODO(b/193504400): do this only when (1) idsig_fd is empty or (2) the APK digest in
        // idsig_fd is different from APK digest in input_fd

        check_manage_access()?;

        create_or_update_idsig_file(input_fd, idsig_fd)
            .map_err(|e| Status::new_service_specific_error_str(-1, Some(format!("{:?}", e))))?;
        Ok(())
    }

    /// Get a list of all currently running VMs. This method is only intended for debug purposes,
    /// and as such is only permitted from the shell user.
    fn debugListVms(&self) -> binder::Result<Vec<VirtualMachineDebugInfo>> {
        check_debug_access()?;
        GLOBAL_SERVICE.debugListVms()
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

impl VirtualizationService {
    // TODO(b/245727626): Remove after the source files for virtualizationservice
    // and virtmgr binaries are split from each other.
    #[allow(dead_code)]
    pub fn init() -> VirtualizationService {
        VirtualizationService::default()
    }

    fn create_vm_context(&self, requester_debug_pid: pid_t) -> Result<(VmContext, Cid, PathBuf)> {
        const NUM_ATTEMPTS: usize = 5;

        for _ in 0..NUM_ATTEMPTS {
            let vm_context = GLOBAL_SERVICE.allocateGlobalVmContext(requester_debug_pid as i32)?;
            let cid = vm_context.getCid()? as Cid;
            let temp_dir: PathBuf = vm_context.getTemporaryDirectory()?.into();
            let service = VirtualMachineService::new_binder(self.state.clone(), cid).as_binder();

            // Start VM service listening for connections from the new CID on port=CID.
            let port = cid;
            match RpcServer::new_vsock(service, cid, port) {
                Ok(vm_server) => {
                    vm_server.start();
                    return Ok((VmContext::new(vm_context, vm_server), cid, temp_dir));
                }
                Err(err) => {
                    warn!("Could not start RpcServer on port {}: {}", port, err);
                }
            }
        }
        bail!("Too many attempts to create VM context failed.");
    }

    fn create_vm_internal(
        &self,
        config: &VirtualMachineConfig,
        console_fd: Option<&ParcelFileDescriptor>,
        log_fd: Option<&ParcelFileDescriptor>,
        is_protected: &mut bool,
    ) -> binder::Result<Strong<dyn IVirtualMachine>> {
        check_manage_access()?;

        let is_custom = match config {
            VirtualMachineConfig::RawConfig(_) => true,
            VirtualMachineConfig::AppConfig(config) => {
                // Some features are reserved for platform apps only, even when using
                // VirtualMachineAppConfig:
                // - controlling CPUs;
                // - specifying a config file in the APK.
                !config.taskProfiles.is_empty() || matches!(config.payload, Payload::ConfigPath(_))
            }
        };
        if is_custom {
            check_use_custom_virtual_machine()?;
        }

        let requester_uid = get_calling_uid();
        let requester_debug_pid = get_calling_pid();

        let (vm_context, cid, temporary_directory) =
            self.create_vm_context(requester_debug_pid).map_err(|e| {
                error!("Failed to create VmContext: {:?}", e);
                Status::new_service_specific_error_str(
                    -1,
                    Some(format!("Failed to create VmContext: {:?}", e)),
                )
            })?;

        let state = &mut *self.state.lock().unwrap();
        let console_fd =
            clone_or_prepare_logger_fd(config, console_fd, format!("Console({})", cid))?;
        let log_fd = clone_or_prepare_logger_fd(config, log_fd, format!("Log({})", cid))?;

        // Counter to generate unique IDs for temporary image files.
        let mut next_temporary_image_id = 0;
        // Files which are referred to from composite images. These must be mapped to the crosvm
        // child process, and not closed before it is started.
        let mut indirect_files = vec![];

        let (is_app_config, config) = match config {
            VirtualMachineConfig::RawConfig(config) => (false, BorrowedOrOwned::Borrowed(config)),
            VirtualMachineConfig::AppConfig(config) => {
                let config = load_app_config(config, &temporary_directory).map_err(|e| {
                    *is_protected = config.protectedVm;
                    let message = format!("Failed to load app config: {:?}", e);
                    error!("{}", message);
                    Status::new_service_specific_error_str(-1, Some(message))
                })?;
                (true, BorrowedOrOwned::Owned(config))
            }
        };
        let config = config.as_ref();
        *is_protected = config.protectedVm;

        // Check if partition images are labeled incorrectly. This is to prevent random images
        // which are not protected by the Android Verified Boot (e.g. bits downloaded by apps) from
        // being loaded in a pVM. This applies to everything in the raw config, and everything but
        // the non-executable, generated partitions in the app config.
        config
            .disks
            .iter()
            .flat_map(|disk| disk.partitions.iter())
            .filter(|partition| {
                if is_app_config {
                    !is_safe_app_partition(&partition.label)
                } else {
                    true // all partitions are checked
                }
            })
            .try_for_each(check_label_for_partition)
            .map_err(|e| Status::new_service_specific_error_str(-1, Some(format!("{:?}", e))))?;

        let kernel = maybe_clone_file(&config.kernel)?;
        let initrd = maybe_clone_file(&config.initrd)?;

        // In a protected VM, we require custom kernels to come from a trusted source (b/237054515).
        if config.protectedVm {
            check_label_for_kernel_files(&kernel, &initrd).map_err(|e| {
                Status::new_service_specific_error_str(-1, Some(format!("{:?}", e)))
            })?;
        }

        let zero_filler_path = temporary_directory.join("zero.img");
        write_zero_filler(&zero_filler_path).map_err(|e| {
            error!("Failed to make composite image: {:?}", e);
            Status::new_service_specific_error_str(
                -1,
                Some(format!("Failed to make composite image: {:?}", e)),
            )
        })?;

        // Assemble disk images if needed.
        let disks = config
            .disks
            .iter()
            .map(|disk| {
                assemble_disk_image(
                    disk,
                    &zero_filler_path,
                    &temporary_directory,
                    &mut next_temporary_image_id,
                    &mut indirect_files,
                )
            })
            .collect::<Result<Vec<DiskFile>, _>>()?;

        // Creating this ramdump file unconditionally is not harmful as ramdump will be created
        // only when the VM is configured as such. `ramdump_write` is sent to crosvm and will
        // be the backing store for the /dev/hvc1 where VM will emit ramdump to. `ramdump_read`
        // will be sent back to the client (i.e. the VM owner) for readout.
        let ramdump_path = temporary_directory.join("ramdump");
        let ramdump = prepare_ramdump_file(&ramdump_path).map_err(|e| {
            error!("Failed to prepare ramdump file: {:?}", e);
            Status::new_service_specific_error_str(
                -1,
                Some(format!("Failed to prepare ramdump file: {:?}", e)),
            )
        })?;

        // Actually start the VM.
        let crosvm_config = CrosvmConfig {
            cid,
            name: config.name.clone(),
            bootloader: maybe_clone_file(&config.bootloader)?,
            kernel,
            initrd,
            disks,
            params: config.params.to_owned(),
            protected: *is_protected,
            memory_mib: config.memoryMib.try_into().ok().and_then(NonZeroU32::new),
            cpus: config.numCpus.try_into().ok().and_then(NonZeroU32::new),
            task_profiles: config.taskProfiles.clone(),
            console_fd,
            log_fd,
            ramdump: Some(ramdump),
            indirect_files,
            platform_version: parse_platform_version_req(&config.platformVersion)?,
            detect_hangup: is_app_config,
        };
        let instance = Arc::new(
            VmInstance::new(
                crosvm_config,
                temporary_directory,
                requester_uid,
                requester_debug_pid,
                vm_context,
            )
            .map_err(|e| {
                error!("Failed to create VM with config {:?}: {:?}", config, e);
                Status::new_service_specific_error_str(
                    -1,
                    Some(format!("Failed to create VM: {:?}", e)),
                )
            })?,
        );
        state.add_vm(Arc::downgrade(&instance));
        Ok(VirtualMachine::create(instance))
    }
}

fn write_zero_filler(zero_filler_path: &Path) -> Result<()> {
    let file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(zero_filler_path)
        .with_context(|| "Failed to create zero.img")?;
    file.set_len(ZERO_FILLER_SIZE)?;
    Ok(())
}

fn format_as_android_vm_instance(part: &mut dyn Write) -> std::io::Result<()> {
    part.write_all(ANDROID_VM_INSTANCE_MAGIC.as_bytes())?;
    part.write_all(&ANDROID_VM_INSTANCE_VERSION.to_le_bytes())?;
    part.flush()
}

fn format_as_encryptedstore(part: &mut dyn Write) -> std::io::Result<()> {
    part.write_all(UNFORMATTED_STORAGE_MAGIC.as_bytes())?;
    part.flush()
}

fn prepare_ramdump_file(ramdump_path: &Path) -> Result<File> {
    File::create(ramdump_path).context(format!("Failed to create ramdump file {:?}", &ramdump_path))
}

/// Given the configuration for a disk image, assembles the `DiskFile` to pass to crosvm.
///
/// This may involve assembling a composite disk from a set of partition images.
fn assemble_disk_image(
    disk: &DiskImage,
    zero_filler_path: &Path,
    temporary_directory: &Path,
    next_temporary_image_id: &mut u64,
    indirect_files: &mut Vec<File>,
) -> Result<DiskFile, Status> {
    let image = if !disk.partitions.is_empty() {
        if disk.image.is_some() {
            warn!("DiskImage {:?} contains both image and partitions.", disk);
            return Err(Status::new_exception_str(
                ExceptionCode::ILLEGAL_ARGUMENT,
                Some("DiskImage contains both image and partitions."),
            ));
        }

        let composite_image_filenames =
            make_composite_image_filenames(temporary_directory, next_temporary_image_id);
        let (image, partition_files) = make_composite_image(
            &disk.partitions,
            zero_filler_path,
            &composite_image_filenames.composite,
            &composite_image_filenames.header,
            &composite_image_filenames.footer,
        )
        .map_err(|e| {
            error!("Failed to make composite image with config {:?}: {:?}", disk, e);
            Status::new_service_specific_error_str(
                -1,
                Some(format!("Failed to make composite image: {:?}", e)),
            )
        })?;

        // Pass the file descriptors for the various partition files to crosvm when it
        // is run.
        indirect_files.extend(partition_files);

        image
    } else if let Some(image) = &disk.image {
        clone_file(image)?
    } else {
        warn!("DiskImage {:?} didn't contain image or partitions.", disk);
        return Err(Status::new_exception_str(
            ExceptionCode::ILLEGAL_ARGUMENT,
            Some("DiskImage didn't contain image or partitions."),
        ));
    };

    Ok(DiskFile { image, writable: disk.writable })
}

fn load_app_config(
    config: &VirtualMachineAppConfig,
    temporary_directory: &Path,
) -> Result<VirtualMachineRawConfig> {
    let apk_file = clone_file(config.apk.as_ref().unwrap())?;
    let idsig_file = clone_file(config.idsig.as_ref().unwrap())?;
    let instance_file = clone_file(config.instanceImage.as_ref().unwrap())?;

    let storage_image = if let Some(file) = config.encryptedStorageImage.as_ref() {
        Some(clone_file(file)?)
    } else {
        None
    };

    let vm_payload_config = match &config.payload {
        Payload::ConfigPath(config_path) => {
            load_vm_payload_config_from_file(&apk_file, config_path.as_str())
                .with_context(|| format!("Couldn't read config from {}", config_path))?
        }
        Payload::PayloadConfig(payload_config) => create_vm_payload_config(payload_config)?,
    };

    // For now, the only supported OS is Microdroid
    let os_name = vm_payload_config.os.name.as_str();
    if os_name != MICRODROID_OS_NAME {
        bail!("Unknown OS \"{}\"", os_name);
    }

    // It is safe to construct a filename based on the os_name because we've already checked that it
    // is one of the allowed values.
    let vm_config_path = PathBuf::from(format!("/apex/com.android.virt/etc/{}.json", os_name));
    let vm_config_file = File::open(vm_config_path)?;
    let mut vm_config = VmConfig::load(&vm_config_file)?.to_parcelable()?;

    if config.memoryMib > 0 {
        vm_config.memoryMib = config.memoryMib;
    }

    vm_config.name = config.name.clone();
    vm_config.protectedVm = config.protectedVm;
    vm_config.numCpus = config.numCpus;
    vm_config.taskProfiles = config.taskProfiles.clone();

    // Microdroid takes additional init ramdisk & (optionally) storage image
    add_microdroid_system_images(config, instance_file, storage_image, &mut vm_config)?;

    // Include Microdroid payload disk (contains apks, idsigs) in vm config
    add_microdroid_payload_images(
        config,
        temporary_directory,
        apk_file,
        idsig_file,
        &vm_payload_config,
        &mut vm_config,
    )?;

    Ok(vm_config)
}

fn load_vm_payload_config_from_file(apk_file: &File, config_path: &str) -> Result<VmPayloadConfig> {
    let mut apk_zip = ZipArchive::new(apk_file)?;
    let config_file = apk_zip.by_name(config_path)?;
    Ok(serde_json::from_reader(config_file)?)
}

fn create_vm_payload_config(
    payload_config: &VirtualMachinePayloadConfig,
) -> Result<VmPayloadConfig> {
    // There isn't an actual config file. Construct a synthetic VmPayloadConfig from the explicit
    // parameters we've been given. Microdroid will do something equivalent inside the VM using the
    // payload config that we send it via the metadata file.

    let payload_binary_name = &payload_config.payloadBinaryName;
    if payload_binary_name.contains('/') {
        bail!("Payload binary name must not specify a path: {payload_binary_name}");
    }

    let task = Task { type_: TaskType::MicrodroidLauncher, command: payload_binary_name.clone() };
    Ok(VmPayloadConfig {
        os: OsConfig { name: MICRODROID_OS_NAME.to_owned() },
        task: Some(task),
        apexes: vec![],
        extra_apks: vec![],
        prefer_staged: false,
        export_tombstones: false,
        enable_authfs: false,
    })
}

/// Generates a unique filename to use for a composite disk image.
fn make_composite_image_filenames(
    temporary_directory: &Path,
    next_temporary_image_id: &mut u64,
) -> CompositeImageFilenames {
    let id = *next_temporary_image_id;
    *next_temporary_image_id += 1;
    CompositeImageFilenames {
        composite: temporary_directory.join(format!("composite-{}.img", id)),
        header: temporary_directory.join(format!("composite-{}-header.img", id)),
        footer: temporary_directory.join(format!("composite-{}-footer.img", id)),
    }
}

/// Filenames for a composite disk image, including header and footer partitions.
#[derive(Clone, Debug, Eq, PartialEq)]
struct CompositeImageFilenames {
    /// The composite disk image itself.
    composite: PathBuf,
    /// The header partition image.
    header: PathBuf,
    /// The footer partition image.
    footer: PathBuf,
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
        Err(Status::new_exception_str(
            ExceptionCode::SECURITY,
            Some(format!("does not have the {} permission", perm)),
        ))
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

/// Check whether the caller of the current Binder method is allowed to create custom VMs
fn check_use_custom_virtual_machine() -> binder::Result<()> {
    check_permission("android.permission.USE_CUSTOM_VIRTUAL_MACHINE")
}

/// Return whether a partition is exempt from selinux label checks, because we know that it does
/// not contain code and is likely to be generated in an app-writable directory.
fn is_safe_app_partition(label: &str) -> bool {
    // See add_microdroid_system_images & add_microdroid_payload_images in payload.rs.
    label == "vm-instance"
        || label == "encryptedstore"
        || label == "microdroid-apk-idsig"
        || label == "payload-metadata"
        || label.starts_with("extra-idsig-")
}

/// Check that a file SELinux label is acceptable.
///
/// We only want to allow code in a VM to be sourced from places that apps, and the
/// system, do not have write access to.
///
/// Note that sepolicy must also grant read access for these types to both virtualization
/// service and crosvm.
///
/// App private data files are deliberately excluded, to avoid arbitrary payloads being run on
/// user devices (W^X).
fn check_label_is_allowed(context: &SeContext) -> Result<()> {
    match context.selinux_type()? {
        | "system_file" // immutable dm-verity protected partition
        | "apk_data_file" // APKs of an installed app
        | "staging_data_file" // updated/staged APEX images
        | "shell_data_file" // test files created via adb shell
         => Ok(()),
        _ => bail!("Label {} is not allowed", context),
    }
}

fn check_label_for_partition(partition: &Partition) -> Result<()> {
    let file = partition.image.as_ref().unwrap().as_ref();
    check_label_is_allowed(&getfilecon(file)?)
        .with_context(|| format!("Partition {} invalid", &partition.label))
}

fn check_label_for_kernel_files(kernel: &Option<File>, initrd: &Option<File>) -> Result<()> {
    if let Some(f) = kernel {
        check_label_for_file(f, "kernel")?;
    }
    if let Some(f) = initrd {
        check_label_for_file(f, "initrd")?;
    }
    Ok(())
}
fn check_label_for_file(file: &File, name: &str) -> Result<()> {
    check_label_is_allowed(&getfilecon(file)?).with_context(|| format!("{} file invalid", name))
}

/// Implementation of the AIDL `IVirtualMachine` interface. Used as a handle to a VM.
#[derive(Debug)]
struct VirtualMachine {
    instance: Arc<VmInstance>,
}

impl VirtualMachine {
    fn create(instance: Arc<VmInstance>) -> Strong<dyn IVirtualMachine> {
        BnVirtualMachine::new_binder(VirtualMachine { instance }, BinderFeatures::default())
    }
}

impl Interface for VirtualMachine {}

impl IVirtualMachine for VirtualMachine {
    fn getCid(&self) -> binder::Result<i32> {
        // Don't check permission. The owner of the VM might have passed this binder object to
        // others.
        Ok(self.instance.cid as i32)
    }

    fn getState(&self) -> binder::Result<VirtualMachineState> {
        // Don't check permission. The owner of the VM might have passed this binder object to
        // others.
        Ok(get_state(&self.instance))
    }

    fn registerCallback(
        &self,
        callback: &Strong<dyn IVirtualMachineCallback>,
    ) -> binder::Result<()> {
        // Don't check permission. The owner of the VM might have passed this binder object to
        // others.
        //
        // TODO: Should this give an error if the VM is already dead?
        self.instance.callbacks.add(callback.clone());
        Ok(())
    }

    fn start(&self) -> binder::Result<()> {
        self.instance.start().map_err(|e| {
            error!("Error starting VM with CID {}: {:?}", self.instance.cid, e);
            Status::new_service_specific_error_str(-1, Some(e.to_string()))
        })
    }

    fn stop(&self) -> binder::Result<()> {
        self.instance.kill().map_err(|e| {
            error!("Error stopping VM with CID {}: {:?}", self.instance.cid, e);
            Status::new_service_specific_error_str(-1, Some(e.to_string()))
        })
    }

    fn onTrimMemory(&self, level: MemoryTrimLevel) -> binder::Result<()> {
        self.instance.trim_memory(level).map_err(|e| {
            error!("Error trimming VM with CID {}: {:?}", self.instance.cid, e);
            Status::new_service_specific_error_str(-1, Some(e.to_string()))
        })
    }

    fn connectVsock(&self, port: i32) -> binder::Result<ParcelFileDescriptor> {
        if !matches!(&*self.instance.vm_state.lock().unwrap(), VmState::Running { .. }) {
            return Err(Status::new_service_specific_error_str(-1, Some("VM is not running")));
        }
        let port = port as u32;
        if port < 1024 {
            return Err(Status::new_service_specific_error_str(
                -1,
                Some(format!("Can't connect to privileged port {port}")),
            ));
        }
        let stream = VsockStream::connect_with_cid_port(self.instance.cid, port).map_err(|e| {
            Status::new_service_specific_error_str(-1, Some(format!("Failed to connect: {:?}", e)))
        })?;
        Ok(vsock_stream_to_pfd(stream))
    }
}

impl Drop for VirtualMachine {
    fn drop(&mut self) {
        debug!("Dropping {:?}", self);
        if let Err(e) = self.instance.kill() {
            debug!("Error stopping dropped VM with CID {}: {:?}", self.instance.cid, e);
        }
    }
}

/// A set of Binders to be called back in response to various events on the VM, such as when it
/// dies.
#[derive(Debug, Default)]
pub struct VirtualMachineCallbacks(Mutex<Vec<Strong<dyn IVirtualMachineCallback>>>);

impl VirtualMachineCallbacks {
    /// Call all registered callbacks to notify that the payload has started.
    pub fn notify_payload_started(&self, cid: Cid) {
        let callbacks = &*self.0.lock().unwrap();
        for callback in callbacks {
            if let Err(e) = callback.onPayloadStarted(cid as i32) {
                error!("Error notifying payload start event from VM CID {}: {:?}", cid, e);
            }
        }
    }

    /// Call all registered callbacks to notify that the payload is ready to serve.
    pub fn notify_payload_ready(&self, cid: Cid) {
        let callbacks = &*self.0.lock().unwrap();
        for callback in callbacks {
            if let Err(e) = callback.onPayloadReady(cid as i32) {
                error!("Error notifying payload ready event from VM CID {}: {:?}", cid, e);
            }
        }
    }

    /// Call all registered callbacks to notify that the payload has finished.
    pub fn notify_payload_finished(&self, cid: Cid, exit_code: i32) {
        let callbacks = &*self.0.lock().unwrap();
        for callback in callbacks {
            if let Err(e) = callback.onPayloadFinished(cid as i32, exit_code) {
                error!("Error notifying payload finish event from VM CID {}: {:?}", cid, e);
            }
        }
    }

    /// Call all registered callbacks to say that the VM encountered an error.
    pub fn notify_error(&self, cid: Cid, error_code: ErrorCode, message: &str) {
        let callbacks = &*self.0.lock().unwrap();
        for callback in callbacks {
            if let Err(e) = callback.onError(cid as i32, error_code, message) {
                error!("Error notifying error event from VM CID {}: {:?}", cid, e);
            }
        }
    }

    /// Call all registered callbacks to say that the VM has died.
    pub fn callback_on_died(&self, cid: Cid, reason: DeathReason) {
        let callbacks = &*self.0.lock().unwrap();
        for callback in callbacks {
            if let Err(e) = callback.onDied(cid as i32, reason) {
                error!("Error notifying exit of VM CID {}: {:?}", cid, e);
            }
        }
    }

    /// Add a new callback to the set.
    fn add(&self, callback: Strong<dyn IVirtualMachineCallback>) {
        self.0.lock().unwrap().push(callback);
    }
}

/// The mutable state of the VirtualizationService. There should only be one instance of this
/// struct.
#[derive(Debug, Default)]
struct State {
    /// The VMs which have been started. When VMs are started a weak reference is added to this list
    /// while a strong reference is returned to the caller over Binder. Once all copies of the
    /// Binder client are dropped the weak reference here will become invalid, and will be removed
    /// from the list opportunistically the next time `add_vm` is called.
    vms: Vec<Weak<VmInstance>>,
}

impl State {
    /// Get a list of VMs which still have Binder references to them.
    fn vms(&self) -> Vec<Arc<VmInstance>> {
        // Attempt to upgrade the weak pointers to strong pointers.
        self.vms.iter().filter_map(Weak::upgrade).collect()
    }

    /// Add a new VM to the list.
    fn add_vm(&mut self, vm: Weak<VmInstance>) {
        // Garbage collect any entries from the stored list which no longer exist.
        self.vms.retain(|vm| vm.strong_count() > 0);

        // Actually add the new VM.
        self.vms.push(vm);
    }

    /// Get a VM that corresponds to the given cid
    fn get_vm(&self, cid: Cid) -> Option<Arc<VmInstance>> {
        self.vms().into_iter().find(|vm| vm.cid == cid)
    }
}

/// Gets the `VirtualMachineState` of the given `VmInstance`.
fn get_state(instance: &VmInstance) -> VirtualMachineState {
    match &*instance.vm_state.lock().unwrap() {
        VmState::NotStarted { .. } => VirtualMachineState::NOT_STARTED,
        VmState::Running { .. } => match instance.payload_state() {
            PayloadState::Starting => VirtualMachineState::STARTING,
            PayloadState::Started => VirtualMachineState::STARTED,
            PayloadState::Ready => VirtualMachineState::READY,
            PayloadState::Finished => VirtualMachineState::FINISHED,
            PayloadState::Hangup => VirtualMachineState::DEAD,
        },
        VmState::Dead => VirtualMachineState::DEAD,
        VmState::Failed => VirtualMachineState::DEAD,
    }
}

/// Converts a `&ParcelFileDescriptor` to a `File` by cloning the file.
pub fn clone_file(file: &ParcelFileDescriptor) -> Result<File, Status> {
    file.as_ref().try_clone().map_err(|e| {
        Status::new_exception_str(
            ExceptionCode::BAD_PARCELABLE,
            Some(format!("Failed to clone File from ParcelFileDescriptor: {:?}", e)),
        )
    })
}

/// Converts an `&Option<ParcelFileDescriptor>` to an `Option<File>` by cloning the file.
fn maybe_clone_file(file: &Option<ParcelFileDescriptor>) -> Result<Option<File>, Status> {
    file.as_ref().map(clone_file).transpose()
}

/// Converts a `VsockStream` to a `ParcelFileDescriptor`.
fn vsock_stream_to_pfd(stream: VsockStream) -> ParcelFileDescriptor {
    // SAFETY: ownership is transferred from stream to f
    let f = unsafe { File::from_raw_fd(stream.into_raw_fd()) };
    ParcelFileDescriptor::new(f)
}

/// Parses the platform version requirement string.
fn parse_platform_version_req(s: &str) -> Result<VersionReq, Status> {
    VersionReq::parse(s).map_err(|e| {
        Status::new_exception_str(
            ExceptionCode::BAD_PARCELABLE,
            Some(format!("Invalid platform version requirement {}: {:?}", s, e)),
        )
    })
}

fn is_debuggable(config: &VirtualMachineConfig) -> bool {
    match config {
        VirtualMachineConfig::AppConfig(config) => config.debugLevel != DebugLevel::NONE,
        _ => false,
    }
}

fn clone_or_prepare_logger_fd(
    config: &VirtualMachineConfig,
    fd: Option<&ParcelFileDescriptor>,
    tag: String,
) -> Result<Option<File>, Status> {
    if let Some(fd) = fd {
        return Ok(Some(clone_file(fd)?));
    }

    if !is_debuggable(config) {
        return Ok(None);
    }

    let (raw_read_fd, raw_write_fd) = pipe().map_err(|e| {
        Status::new_service_specific_error_str(-1, Some(format!("Failed to create pipe: {:?}", e)))
    })?;

    // SAFETY: We are the sole owners of these fds as they were just created.
    let mut reader = BufReader::new(unsafe { File::from_raw_fd(raw_read_fd) });
    let write_fd = unsafe { File::from_raw_fd(raw_write_fd) };

    std::thread::spawn(move || loop {
        let mut buf = vec![];
        match reader.read_until(b'\n', &mut buf) {
            Ok(0) => {
                // EOF
                return;
            }
            Ok(size) => {
                if buf[size - 1] == b'\n' {
                    buf.pop();
                }
                info!("{}: {}", &tag, &String::from_utf8_lossy(&buf));
            }
            Err(e) => {
                error!("Could not read console pipe: {:?}", e);
                return;
            }
        };
    });

    Ok(Some(write_fd))
}

/// Simple utility for referencing Borrowed or Owned. Similar to std::borrow::Cow, but
/// it doesn't require that T implements Clone.
enum BorrowedOrOwned<'a, T> {
    Borrowed(&'a T),
    Owned(T),
}

impl<'a, T> AsRef<T> for BorrowedOrOwned<'a, T> {
    fn as_ref(&self) -> &T {
        match self {
            Self::Borrowed(b) => b,
            Self::Owned(o) => o,
        }
    }
}

/// Implementation of `IVirtualMachineService`, the entry point of the AIDL service.
#[derive(Debug, Default)]
struct VirtualMachineService {
    state: Arc<Mutex<State>>,
    cid: Cid,
}

impl Interface for VirtualMachineService {}

impl IVirtualMachineService for VirtualMachineService {
    fn notifyPayloadStarted(&self) -> binder::Result<()> {
        let cid = self.cid;
        if let Some(vm) = self.state.lock().unwrap().get_vm(cid) {
            info!("VM with CID {} started payload", cid);
            vm.update_payload_state(PayloadState::Started).map_err(|e| {
                Status::new_exception_str(ExceptionCode::ILLEGAL_STATE, Some(e.to_string()))
            })?;
            vm.callbacks.notify_payload_started(cid);

            let vm_start_timestamp = vm.vm_metric.lock().unwrap().start_timestamp;
            write_vm_booted_stats(vm.requester_uid as i32, &vm.name, vm_start_timestamp);
            Ok(())
        } else {
            error!("notifyPayloadStarted is called from an unknown CID {}", cid);
            Err(Status::new_service_specific_error_str(
                -1,
                Some(format!("cannot find a VM with CID {}", cid)),
            ))
        }
    }

    fn notifyPayloadReady(&self) -> binder::Result<()> {
        let cid = self.cid;
        if let Some(vm) = self.state.lock().unwrap().get_vm(cid) {
            info!("VM with CID {} reported payload is ready", cid);
            vm.update_payload_state(PayloadState::Ready).map_err(|e| {
                Status::new_exception_str(ExceptionCode::ILLEGAL_STATE, Some(e.to_string()))
            })?;
            vm.callbacks.notify_payload_ready(cid);
            Ok(())
        } else {
            error!("notifyPayloadReady is called from an unknown CID {}", cid);
            Err(Status::new_service_specific_error_str(
                -1,
                Some(format!("cannot find a VM with CID {}", cid)),
            ))
        }
    }

    fn notifyPayloadFinished(&self, exit_code: i32) -> binder::Result<()> {
        let cid = self.cid;
        if let Some(vm) = self.state.lock().unwrap().get_vm(cid) {
            info!("VM with CID {} finished payload", cid);
            vm.update_payload_state(PayloadState::Finished).map_err(|e| {
                Status::new_exception_str(ExceptionCode::ILLEGAL_STATE, Some(e.to_string()))
            })?;
            vm.callbacks.notify_payload_finished(cid, exit_code);
            Ok(())
        } else {
            error!("notifyPayloadFinished is called from an unknown CID {}", cid);
            Err(Status::new_service_specific_error_str(
                -1,
                Some(format!("cannot find a VM with CID {}", cid)),
            ))
        }
    }

    fn notifyError(&self, error_code: ErrorCode, message: &str) -> binder::Result<()> {
        let cid = self.cid;
        if let Some(vm) = self.state.lock().unwrap().get_vm(cid) {
            info!("VM with CID {} encountered an error", cid);
            vm.update_payload_state(PayloadState::Finished).map_err(|e| {
                Status::new_exception_str(ExceptionCode::ILLEGAL_STATE, Some(e.to_string()))
            })?;
            vm.callbacks.notify_error(cid, error_code, message);
            Ok(())
        } else {
            error!("notifyError is called from an unknown CID {}", cid);
            Err(Status::new_service_specific_error_str(
                -1,
                Some(format!("cannot find a VM with CID {}", cid)),
            ))
        }
    }
}

impl VirtualMachineService {
    fn new_binder(state: Arc<Mutex<State>>, cid: Cid) -> Strong<dyn IVirtualMachineService> {
        BnVirtualMachineService::new_binder(
            VirtualMachineService { state, cid },
            BinderFeatures::default(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_allowed_label_for_partition() -> Result<()> {
        let expected_results = vec![
            ("u:object_r:system_file:s0", true),
            ("u:object_r:apk_data_file:s0", true),
            ("u:object_r:app_data_file:s0", false),
            ("u:object_r:app_data_file:s0:c512,c768", false),
            ("u:object_r:privapp_data_file:s0:c512,c768", false),
            ("invalid", false),
            ("user:role:apk_data_file:severity:categories", true),
            ("user:role:apk_data_file:severity:categories:extraneous", false),
        ];

        for (label, expected_valid) in expected_results {
            let context = SeContext::new(label)?;
            let result = check_label_is_allowed(&context);
            if expected_valid {
                assert!(result.is_ok(), "Expected label {} to be allowed, got {:?}", label, result);
            } else if result.is_ok() {
                bail!("Expected label {} to be disallowed", label);
            }
        }
        Ok(())
    }

    #[test]
    fn test_create_or_update_idsig_file_empty_apk() -> Result<()> {
        let apk = tempfile::tempfile().unwrap();
        let idsig = tempfile::tempfile().unwrap();

        let ret = create_or_update_idsig_file(
            &ParcelFileDescriptor::new(apk),
            &ParcelFileDescriptor::new(idsig),
        );
        assert!(ret.is_err(), "should fail");
        Ok(())
    }

    #[test]
    fn test_create_or_update_idsig_dir_instead_of_file_for_apk() -> Result<()> {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let apk = File::open(tmp_dir.path()).unwrap();
        let idsig = tempfile::tempfile().unwrap();

        let ret = create_or_update_idsig_file(
            &ParcelFileDescriptor::new(apk),
            &ParcelFileDescriptor::new(idsig),
        );
        assert!(ret.is_err(), "should fail");
        Ok(())
    }

    /// Verifies that create_or_update_idsig_file won't oom if a fd that corresponds to a directory
    /// on ext4 filesystem is passed.
    /// On ext4 lseek on a directory fd will return (off_t)-1 (see:
    /// https://bugzilla.kernel.org/show_bug.cgi?id=200043), which will result in
    /// create_or_update_idsig_file ooming while attempting to allocate petabytes of memory.
    #[test]
    fn test_create_or_update_idsig_does_not_crash_dir_on_ext4() -> Result<()> {
        // APEXes are backed by the ext4.
        let apk = File::open("/apex/com.android.virt/").unwrap();
        let idsig = tempfile::tempfile().unwrap();

        let ret = create_or_update_idsig_file(
            &ParcelFileDescriptor::new(apk),
            &ParcelFileDescriptor::new(idsig),
        );
        assert!(ret.is_err(), "should fail");
        Ok(())
    }
}
