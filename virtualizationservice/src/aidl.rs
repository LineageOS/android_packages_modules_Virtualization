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

use crate::composite::make_composite_image;
use crate::crosvm::{CrosvmConfig, DiskFile, VmInstance};
use crate::payload::add_microdroid_images;
use crate::{Cid, FIRST_GUEST_CID};

use android_os_permissions_aidl::aidl::android::os::IPermissionController;
use android_system_virtualizationservice::aidl::android::system::virtualizationservice::DiskImage::DiskImage;
use android_system_virtualizationservice::aidl::android::system::virtualizationservice::IVirtualizationService::IVirtualizationService;
use android_system_virtualizationservice::aidl::android::system::virtualizationservice::IVirtualMachine::{
    BnVirtualMachine, IVirtualMachine,
};
use android_system_virtualizationservice::aidl::android::system::virtualizationservice::IVirtualMachineCallback::IVirtualMachineCallback;
use android_system_virtualizationservice::aidl::android::system::virtualizationservice::{
    VirtualMachineAppConfig::VirtualMachineAppConfig,
    VirtualMachineConfig::VirtualMachineConfig,
    VirtualMachineRawConfig::VirtualMachineRawConfig,
};
use android_system_virtualizationservice::aidl::android::system::virtualizationservice::VirtualMachineDebugInfo::VirtualMachineDebugInfo;
use android_system_virtualizationservice::aidl::android::system::virtualizationservice::PartitionType::PartitionType;
use android_system_virtualizationservice::binder::{
    self, BinderFeatures, ExceptionCode, Interface, ParcelFileDescriptor, Status, Strong, ThreadState,
};
use android_system_virtualmachineservice::aidl::android::system::virtualmachineservice::IVirtualMachineService::{
    BnVirtualMachineService, IVirtualMachineService,
};
use anyhow::{bail, Context, Result};
use ::binder::unstable_api::AsNative;
use disk::QcowFile;
use idsig::{V4Signature, HashAlgorithm};
use log::{debug, error, warn, info};
use microdroid_payload_config::VmPayloadConfig;
use std::convert::TryInto;
use std::ffi::CString;
use std::fs::{File, OpenOptions, create_dir};
use std::io::{Error, ErrorKind, Write};
use std::num::NonZeroU32;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use vmconfig::VmConfig;
use vsock::{SockAddr, VsockListener, VsockStream};
use zip::ZipArchive;

pub const BINDER_SERVICE_IDENTIFIER: &str = "android.system.virtualizationservice";

/// Directory in which to write disk image files used while running VMs.
pub const TEMPORARY_DIRECTORY: &str = "/data/misc/virtualizationservice";

/// The CID representing the host VM
const VMADDR_CID_HOST: u32 = 2;

/// Port number that virtualizationservice listens on connections from the guest VMs for the
/// payload input and output
const PORT_VIRT_STREAM_SERVICE: u32 = 3000;

/// Port number that virtualizationservice listens on connections from the guest VMs for the
/// VirtualMachineService binder service
/// Sync with microdroid_manager/src/main.rs
const PORT_VM_BINDER_SERVICE: u32 = 5000;

/// The size of zero.img.
/// Gaps in composite disk images are filled with a shared zero.img.
const ZERO_FILLER_SIZE: u64 = 4096;

/// Magic string for the instance image
const ANDROID_VM_INSTANCE_MAGIC: &str = "Android-VM-instance";

/// Version of the instance image format
const ANDROID_VM_INSTANCE_VERSION: u16 = 1;

/// Implementation of `IVirtualizationService`, the entry point of the AIDL service.
#[derive(Debug, Default)]
pub struct VirtualizationService {
    state: Arc<Mutex<State>>,
}

impl Interface for VirtualizationService {}

impl IVirtualizationService for VirtualizationService {
    /// Create and start a new VM with the given configuration, assigning it the next available CID.
    ///
    /// Returns a binder `IVirtualMachine` object referring to it, as a handle for the client.
    fn startVm(
        &self,
        config: &VirtualMachineConfig,
        log_fd: Option<&ParcelFileDescriptor>,
    ) -> binder::Result<Strong<dyn IVirtualMachine>> {
        check_manage_access()?;
        let state = &mut *self.state.lock().unwrap();
        let log_fd = log_fd.map(clone_file).transpose()?;
        let requester_uid = ThreadState::get_calling_uid();
        let requester_sid = get_calling_sid()?;
        let requester_debug_pid = ThreadState::get_calling_pid();
        let cid = state.allocate_cid()?;

        // Counter to generate unique IDs for temporary image files.
        let mut next_temporary_image_id = 0;
        // Files which are referred to from composite images. These must be mapped to the crosvm
        // child process, and not closed before it is started.
        let mut indirect_files = vec![];

        // Make directory for temporary files.
        let temporary_directory: PathBuf = format!("{}/{}", TEMPORARY_DIRECTORY, cid).into();
        create_dir(&temporary_directory).map_err(|e| {
            error!(
                "Failed to create temporary directory {:?} for VM files: {}",
                temporary_directory, e
            );
            new_binder_exception(
                ExceptionCode::SERVICE_SPECIFIC,
                format!(
                    "Failed to create temporary directory {:?} for VM files: {}",
                    temporary_directory, e
                ),
            )
        })?;

        let config = match config {
            VirtualMachineConfig::AppConfig(config) => BorrowedOrOwned::Owned(
                load_app_config(config, &temporary_directory).map_err(|e| {
                    error!("Failed to load app config from {}: {}", &config.configPath, e);
                    new_binder_exception(
                        ExceptionCode::SERVICE_SPECIFIC,
                        format!("Failed to load app config from {}: {}", &config.configPath, e),
                    )
                })?,
            ),
            VirtualMachineConfig::RawConfig(config) => BorrowedOrOwned::Borrowed(config),
        };
        let config = config.as_ref();

        let zero_filler_path = temporary_directory.join("zero.img");
        write_zero_filler(&zero_filler_path).map_err(|e| {
            error!("Failed to make composite image: {}", e);
            new_binder_exception(
                ExceptionCode::SERVICE_SPECIFIC,
                format!("Failed to make composite image: {}", e),
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

        // Actually start the VM.
        let crosvm_config = CrosvmConfig {
            cid,
            bootloader: as_asref(&config.bootloader),
            kernel: as_asref(&config.kernel),
            initrd: as_asref(&config.initrd),
            disks,
            params: config.params.to_owned(),
            protected: config.protectedVm,
            memory_mib: config.memoryMib.try_into().ok().and_then(NonZeroU32::new),
        };
        let composite_disk_fds: Vec<_> =
            indirect_files.iter().map(|file| file.as_raw_fd()).collect();
        let instance = VmInstance::start(
            &crosvm_config,
            log_fd,
            &composite_disk_fds,
            temporary_directory,
            requester_uid,
            requester_sid,
            requester_debug_pid,
        )
        .map_err(|e| {
            error!("Failed to start VM with config {:?}: {}", config, e);
            new_binder_exception(
                ExceptionCode::SERVICE_SPECIFIC,
                format!("Failed to start VM: {}", e),
            )
        })?;
        state.add_vm(Arc::downgrade(&instance));
        Ok(VirtualMachine::create(instance))
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
            new_binder_exception(
                ExceptionCode::ILLEGAL_ARGUMENT,
                format!("Invalid size {}: {}", size, e),
            )
        })?;
        let image = clone_file(image_fd)?;

        let mut part = QcowFile::new(image, size).map_err(|e| {
            new_binder_exception(
                ExceptionCode::SERVICE_SPECIFIC,
                format!("Failed to create QCOW2 image: {}", e),
            )
        })?;

        match partition_type {
            PartitionType::RAW => Ok(()),
            PartitionType::ANDROID_VM_INSTANCE => format_as_android_vm_instance(&mut part),
            _ => Err(Error::new(
                ErrorKind::Unsupported,
                format!("Unsupported partition type {:?}", partition_type),
            )),
        }
        .map_err(|e| {
            new_binder_exception(
                ExceptionCode::SERVICE_SPECIFIC,
                format!("Failed to initialize partition as {:?}: {}", partition_type, e),
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

        let mut input = clone_file(input_fd)?;
        let mut sig = V4Signature::create(&mut input, 4096, &[], HashAlgorithm::SHA256).unwrap();

        let mut output = clone_file(idsig_fd)?;
        output.set_len(0).unwrap();
        sig.write_into(&mut output).unwrap();
        Ok(())
    }

    /// Get a list of all currently running VMs. This method is only intended for debug purposes,
    /// and as such is only permitted from the shell user.
    fn debugListVms(&self) -> binder::Result<Vec<VirtualMachineDebugInfo>> {
        check_debug_access()?;

        let state = &mut *self.state.lock().unwrap();
        let vms = state.vms();
        let cids = vms
            .into_iter()
            .map(|vm| VirtualMachineDebugInfo {
                cid: vm.cid as i32,
                temporaryDirectory: vm.temporary_directory.to_string_lossy().to_string(),
                requesterUid: vm.requester_uid as i32,
                requesterSid: vm.requester_sid.clone(),
                requesterPid: vm.requester_debug_pid,
                running: vm.running(),
            })
            .collect();
        Ok(cids)
    }

    /// Hold a strong reference to a VM in VirtualizationService. This method is only intended for
    /// debug purposes, and as such is only permitted from the shell user.
    fn debugHoldVmRef(&self, vmref: &Strong<dyn IVirtualMachine>) -> binder::Result<()> {
        check_debug_access()?;

        let state = &mut *self.state.lock().unwrap();
        state.debug_hold_vm(vmref.clone());
        Ok(())
    }

    /// Drop reference to a VM that is being held by VirtualizationService. Returns the reference if
    /// the VM was found and None otherwise. This method is only intended for debug purposes, and as
    /// such is only permitted from the shell user.
    fn debugDropVmRef(&self, cid: i32) -> binder::Result<Option<Strong<dyn IVirtualMachine>>> {
        check_debug_access()?;

        let state = &mut *self.state.lock().unwrap();
        Ok(state.debug_drop_vm(cid))
    }
}

impl VirtualizationService {
    pub fn init() -> VirtualizationService {
        let service = VirtualizationService::default();

        // server for payload output
        let state = service.state.clone(); // reference to state (not the state itself) is copied
        std::thread::spawn(move || {
            handle_stream_connection_from_vm(state).unwrap();
        });

        // binder server for vm
        let state = service.state.clone(); // reference to state (not the state itself) is copied
        std::thread::spawn(move || {
            let mut service = VirtualMachineService::new_binder(state).as_binder();
            debug!("virtual machine service is starting as an RPC service.");
            // SAFETY: Service ownership is transferring to the server and won't be valid afterward.
            // Plus the binder objects are threadsafe.
            let retval = unsafe {
                binder_rpc_unstable_bindgen::RunRpcServer(
                    service.as_native_mut() as *mut binder_rpc_unstable_bindgen::AIBinder,
                    PORT_VM_BINDER_SERVICE,
                )
            };
            if retval {
                debug!("RPC server has shut down gracefully");
            } else {
                bail!("Premature termination of RPC server");
            }

            Ok(retval)
        });
        service
    }
}

/// Waits for incoming connections from VM. If a new connection is made, notify the event to the
/// client via the callback (if registered).
fn handle_stream_connection_from_vm(state: Arc<Mutex<State>>) -> Result<()> {
    let listener = VsockListener::bind_with_cid_port(VMADDR_CID_HOST, PORT_VIRT_STREAM_SERVICE)?;
    for stream in listener.incoming() {
        let stream = match stream {
            Err(e) => {
                warn!("invalid incoming connection: {}", e);
                continue;
            }
            Ok(s) => s,
        };
        if let Ok(SockAddr::Vsock(addr)) = stream.peer_addr() {
            let cid = addr.cid();
            let port = addr.port();
            info!("payload stream connected from cid={}, port={}", cid, port);
            if let Some(vm) = state.lock().unwrap().get_vm(cid) {
                vm.stream.lock().unwrap().insert(stream);
            } else {
                error!("connection from cid={} is not from a guest VM", cid);
            }
        }
    }
    Ok(())
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
            return Err(new_binder_exception(
                ExceptionCode::ILLEGAL_ARGUMENT,
                "DiskImage contains both image and partitions.",
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
            error!("Failed to make composite image with config {:?}: {}", disk, e);
            new_binder_exception(
                ExceptionCode::SERVICE_SPECIFIC,
                format!("Failed to make composite image: {}", e),
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
        return Err(new_binder_exception(
            ExceptionCode::ILLEGAL_ARGUMENT,
            "DiskImage didn't contain image or partitions.",
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
    let config_path = &config.configPath;

    let mut apk_zip = ZipArchive::new(&apk_file)?;
    let config_file = apk_zip.by_name(config_path)?;
    let vm_payload_config: VmPayloadConfig = serde_json::from_reader(config_file)?;

    let os_name = &vm_payload_config.os.name;

    // For now, the only supported "os" value is "microdroid"
    if os_name != "microdroid" {
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

    // Microdroid requires an additional payload disk image and the bootconfig partition.
    if os_name == "microdroid" {
        let apexes = vm_payload_config.apexes.clone();
        add_microdroid_images(
            config,
            temporary_directory,
            apk_file,
            idsig_file,
            instance_file,
            apexes,
            &mut vm_config,
        )?;
    }

    Ok(vm_config)
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

/// Gets the calling SID of the current Binder thread.
fn get_calling_sid() -> Result<String, Status> {
    ThreadState::with_calling_sid(|sid| {
        if let Some(sid) = sid {
            match sid.to_str() {
                Ok(sid) => Ok(sid.to_owned()),
                Err(e) => {
                    error!("SID was not valid UTF-8: {}", e);
                    Err(new_binder_exception(
                        ExceptionCode::ILLEGAL_ARGUMENT,
                        format!("SID was not valid UTF-8: {}", e),
                    ))
                }
            }
        } else {
            error!("Missing SID on startVm");
            Err(new_binder_exception(ExceptionCode::SECURITY, "Missing SID on startVm"))
        }
    })
}

/// Checks whether the caller has a specific permission
fn check_permission(perm: &str) -> binder::Result<()> {
    let calling_pid = ThreadState::get_calling_pid();
    let calling_uid = ThreadState::get_calling_uid();
    // Root can do anything
    if calling_uid == 0 {
        return Ok(());
    }
    let perm_svc: Strong<dyn IPermissionController::IPermissionController> =
        binder::get_interface("permission")?;
    if perm_svc.checkPermission(perm, calling_pid, calling_uid as i32)? {
        Ok(())
    } else {
        Err(new_binder_exception(
            ExceptionCode::SECURITY,
            format!("does not have the {} permission", perm),
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

/// Implementation of the AIDL `IVirtualMachine` interface. Used as a handle to a VM.
#[derive(Debug)]
struct VirtualMachine {
    instance: Arc<VmInstance>,
}

impl VirtualMachine {
    fn create(instance: Arc<VmInstance>) -> Strong<dyn IVirtualMachine> {
        let binder = VirtualMachine { instance };
        BnVirtualMachine::new_binder(binder, BinderFeatures::default())
    }
}

impl Interface for VirtualMachine {}

impl IVirtualMachine for VirtualMachine {
    fn getCid(&self) -> binder::Result<i32> {
        // Don't check permission. The owner of the VM might have passed this binder object to
        // others.
        Ok(self.instance.cid as i32)
    }

    fn isRunning(&self) -> binder::Result<bool> {
        // Don't check permission. The owner of the VM might have passed this binder object to
        // others.
        Ok(self.instance.running())
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

    fn connectVsock(&self, port: i32) -> binder::Result<ParcelFileDescriptor> {
        if !self.instance.running() {
            return Err(new_binder_exception(
                ExceptionCode::SERVICE_SPECIFIC,
                "VM is no longer running",
            ));
        }
        let stream =
            VsockStream::connect_with_cid_port(self.instance.cid, port as u32).map_err(|e| {
                new_binder_exception(
                    ExceptionCode::SERVICE_SPECIFIC,
                    format!("Failed to connect: {}", e),
                )
            })?;
        Ok(vsock_stream_to_pfd(stream))
    }
}

impl Drop for VirtualMachine {
    fn drop(&mut self) {
        debug!("Dropping {:?}", self);
        self.instance.kill();
    }
}

/// A set of Binders to be called back in response to various events on the VM, such as when it
/// dies.
#[derive(Debug, Default)]
pub struct VirtualMachineCallbacks(Mutex<Vec<Strong<dyn IVirtualMachineCallback>>>);

impl VirtualMachineCallbacks {
    /// Call all registered callbacks to notify that the payload has started.
    pub fn notify_payload_started(&self, cid: Cid, stream: Option<VsockStream>) {
        let callbacks = &*self.0.lock().unwrap();
        let pfd = stream.map(vsock_stream_to_pfd);
        for callback in callbacks {
            if let Err(e) = callback.onPayloadStarted(cid as i32, pfd.as_ref()) {
                error!("Error notifying payload start event from VM CID {}: {}", cid, e);
            }
        }
    }

    /// Call all registered callbacks to say that the VM has died.
    pub fn callback_on_died(&self, cid: Cid) {
        let callbacks = &*self.0.lock().unwrap();
        for callback in callbacks {
            if let Err(e) = callback.onDied(cid as i32) {
                error!("Error notifying exit of VM CID {}: {}", cid, e);
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
#[derive(Debug)]
struct State {
    /// The next available unused CID.
    next_cid: Cid,

    /// The VMs which have been started. When VMs are started a weak reference is added to this list
    /// while a strong reference is returned to the caller over Binder. Once all copies of the
    /// Binder client are dropped the weak reference here will become invalid, and will be removed
    /// from the list opportunistically the next time `add_vm` is called.
    vms: Vec<Weak<VmInstance>>,

    /// Vector of strong VM references held on behalf of users that cannot hold them themselves.
    /// This is only used for debugging purposes.
    debug_held_vms: Vec<Strong<dyn IVirtualMachine>>,
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

    /// Store a strong VM reference.
    fn debug_hold_vm(&mut self, vm: Strong<dyn IVirtualMachine>) {
        self.debug_held_vms.push(vm);
    }

    /// Retrieve and remove a strong VM reference.
    fn debug_drop_vm(&mut self, cid: i32) -> Option<Strong<dyn IVirtualMachine>> {
        let pos = self.debug_held_vms.iter().position(|vm| vm.getCid() == Ok(cid))?;
        Some(self.debug_held_vms.swap_remove(pos))
    }

    /// Get the next available CID, or an error if we have run out.
    fn allocate_cid(&mut self) -> binder::Result<Cid> {
        // TODO(qwandor): keep track of which CIDs are currently in use so that we can reuse them.
        let cid = self.next_cid;
        self.next_cid = self.next_cid.checked_add(1).ok_or(ExceptionCode::ILLEGAL_STATE)?;
        Ok(cid)
    }
}

impl Default for State {
    fn default() -> Self {
        State { next_cid: FIRST_GUEST_CID, vms: vec![], debug_held_vms: vec![] }
    }
}

/// Converts an `&Option<T>` to an `Option<U>` where `T` implements `AsRef<U>`.
fn as_asref<T: AsRef<U>, U>(option: &Option<T>) -> Option<&U> {
    option.as_ref().map(|t| t.as_ref())
}

/// Converts a `&ParcelFileDescriptor` to a `File` by cloning the file.
fn clone_file(file: &ParcelFileDescriptor) -> Result<File, Status> {
    file.as_ref().try_clone().map_err(|e| {
        new_binder_exception(
            ExceptionCode::BAD_PARCELABLE,
            format!("Failed to clone File from ParcelFileDescriptor: {}", e),
        )
    })
}

/// Converts a `VsockStream` to a `ParcelFileDescriptor`.
fn vsock_stream_to_pfd(stream: VsockStream) -> ParcelFileDescriptor {
    // SAFETY: ownership is transferred from stream to f
    let f = unsafe { File::from_raw_fd(stream.into_raw_fd()) };
    ParcelFileDescriptor::new(f)
}

/// Constructs a new Binder error `Status` with the given `ExceptionCode` and message.
fn new_binder_exception<T: AsRef<str>>(exception: ExceptionCode, message: T) -> Status {
    Status::new_exception(exception, CString::new(message.as_ref()).ok().as_deref())
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
}

impl Interface for VirtualMachineService {}

impl IVirtualMachineService for VirtualMachineService {
    fn notifyPayloadStarted(&self, cid: i32) -> binder::Result<()> {
        let cid = cid as Cid;
        if let Some(vm) = self.state.lock().unwrap().get_vm(cid) {
            info!("VM having CID {} started payload", cid);
            let stream = vm.stream.lock().unwrap().take();
            vm.callbacks.notify_payload_started(cid, stream);
            Ok(())
        } else {
            error!("notifyPayloadStarted is called from an unknown cid {}", cid);
            Err(new_binder_exception(
                ExceptionCode::SERVICE_SPECIFIC,
                format!("cannot find a VM with cid {}", cid),
            ))
        }
    }
}

impl VirtualMachineService {
    fn new_binder(state: Arc<Mutex<State>>) -> Strong<dyn IVirtualMachineService> {
        BnVirtualMachineService::new_binder(
            VirtualMachineService { state },
            BinderFeatures::default(),
        )
    }
}
