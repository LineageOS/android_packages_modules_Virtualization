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
    write_vm_booted_stats, write_vm_creation_stats};
use crate::composite::make_composite_image;
use crate::crosvm::{CrosvmConfig, DiskFile, PayloadState, VmContext, VmInstance, VmState};
use crate::debug_config::DebugConfig;
use crate::payload::{add_microdroid_payload_images, add_microdroid_system_images, add_microdroid_vendor_image};
use crate::selinux::{getfilecon, SeContext};
use android_os_permissions_aidl::aidl::android::os::IPermissionController;
use android_system_virtualizationcommon::aidl::android::system::virtualizationcommon::{
    DeathReason::DeathReason,
    ErrorCode::ErrorCode,
};
use android_system_virtualizationservice::aidl::android::system::virtualizationservice::{
    AssignableDevice::AssignableDevice,
    CpuTopology::CpuTopology,
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
use android_system_virtualizationservice_internal::aidl::android::system::virtualizationservice_internal::IVirtualizationServiceInternal::IVirtualizationServiceInternal;
use android_system_virtualmachineservice::aidl::android::system::virtualmachineservice::IVirtualMachineService::{
        BnVirtualMachineService, IVirtualMachineService,
};
use anyhow::{anyhow, bail, Context, Result};
use apkverify::{HashAlgorithm, V4Signature};
use avfutil::LogResult;
use binder::{
    self, wait_for_interface, BinderFeatures, ExceptionCode, Interface, ParcelFileDescriptor,
    Status, StatusCode, Strong,
    IntoBinderResult,
};
use disk::QcowFile;
use lazy_static::lazy_static;
use log::{debug, error, info, warn};
use microdroid_payload_config::{OsConfig, Task, TaskType, VmPayloadConfig};
use nix::unistd::pipe;
use rpcbinder::RpcServer;
use rustutils::system_properties;
use semver::VersionReq;
use std::collections::HashSet;
use std::convert::TryInto;
use std::ffi::CStr;
use std::fs::{canonicalize, read_dir, remove_file, File, OpenOptions};
use std::io::{BufRead, BufReader, Error, ErrorKind, Write};
use std::num::{NonZeroU16, NonZeroU32};
use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::os::unix::raw::pid_t;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use vmconfig::VmConfig;
use vsock::VsockStream;
use zip::ZipArchive;

/// The unique ID of a VM used (together with a port number) for vsock communication.
pub type Cid = u32;

pub const BINDER_SERVICE_IDENTIFIER: &str = "android.system.virtualizationservice";

/// The size of zero.img.
/// Gaps in composite disk images are filled with a shared zero.img.
const ZERO_FILLER_SIZE: u64 = 4096;

/// Magic string for the instance image
const ANDROID_VM_INSTANCE_MAGIC: &str = "Android-VM-instance";

/// Version of the instance image format
const ANDROID_VM_INSTANCE_VERSION: u16 = 1;

const MICRODROID_OS_NAME: &str = "microdroid";

const UNFORMATTED_STORAGE_MAGIC: &str = "UNFORMATTED-STORAGE";

/// crosvm requires all partitions to be a multiple of 4KiB.
const PARTITION_GRANULARITY_BYTES: u64 = 4096;

lazy_static! {
    pub static ref GLOBAL_SERVICE: Strong<dyn IVirtualizationServiceInternal> =
        wait_for_interface(BINDER_SERVICE_IDENTIFIER)
            .expect("Could not connect to VirtualizationServiceInternal");
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
    let mut sig =
        V4Signature::create(&mut input, get_current_sdk()?, 4096, &[], HashAlgorithm::SHA256)
            .context("failed to create idsig")?;

    let mut output = clone_file(idsig_fd)?;

    // Optimization. We don't have to update idsig file whenever a VM is started. Don't update it,
    // if the idsig file already has the same APK digest.
    if output.metadata()?.len() > 0 {
        if let Ok(out_sig) = V4Signature::from_idsig(&mut output) {
            if out_sig.signing_info.apk_digest == sig.signing_info.apk_digest {
                debug!("idsig {:?} is up-to-date with apk {:?}.", output, input);
                return Ok(());
            }
        }
        // if we fail to read v4signature from output, that's fine. User can pass a random file.
        // We will anyway overwrite the file to the v4signature generated from input_fd.
    }

    output.set_len(0).context("failed to set_len on the idsig output")?;
    sig.write_into(&mut output).context("failed to write idsig")?;
    Ok(())
}

fn get_current_sdk() -> Result<u32> {
    let current_sdk = system_properties::read("ro.build.version.sdk")?;
    let current_sdk = current_sdk.ok_or_else(|| anyhow!("SDK version missing"))?;
    current_sdk.parse().context("Malformed SDK version")
}

pub fn remove_temporary_files(path: &PathBuf) -> Result<()> {
    for dir_entry in read_dir(path)? {
        remove_file(dir_entry?.path())?;
    }
    Ok(())
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
        console_out_fd: Option<&ParcelFileDescriptor>,
        console_in_fd: Option<&ParcelFileDescriptor>,
        log_fd: Option<&ParcelFileDescriptor>,
    ) -> binder::Result<Strong<dyn IVirtualMachine>> {
        let mut is_protected = false;
        let ret = self.create_vm_internal(
            config,
            console_out_fd,
            console_in_fd,
            log_fd,
            &mut is_protected,
        );
        write_vm_creation_stats(config, is_protected, &ret);
        ret
    }

    /// Initialise an empty partition image of the given size to be used as a writable partition.
    fn initializeWritablePartition(
        &self,
        image_fd: &ParcelFileDescriptor,
        size_bytes: i64,
        partition_type: PartitionType,
    ) -> binder::Result<()> {
        check_manage_access()?;
        let size_bytes = size_bytes
            .try_into()
            .with_context(|| format!("Invalid size: {}", size_bytes))
            .or_binder_exception(ExceptionCode::ILLEGAL_ARGUMENT)?;
        let size_bytes = round_up(size_bytes, PARTITION_GRANULARITY_BYTES);
        let image = clone_file(image_fd)?;
        // initialize the file. Any data in the file will be erased.
        image.set_len(0).context("Failed to reset a file").or_service_specific_exception(-1)?;
        let mut part = QcowFile::new(image, size_bytes)
            .context("Failed to create QCOW2 image")
            .or_service_specific_exception(-1)?;

        match partition_type {
            PartitionType::RAW => Ok(()),
            PartitionType::ANDROID_VM_INSTANCE => format_as_android_vm_instance(&mut part),
            PartitionType::ENCRYPTEDSTORE => format_as_encryptedstore(&mut part),
            _ => Err(Error::new(
                ErrorKind::Unsupported,
                format!("Unsupported partition type {:?}", partition_type),
            )),
        }
        .with_context(|| format!("Failed to initialize partition as {:?}", partition_type))
        .or_service_specific_exception(-1)?;

        Ok(())
    }

    /// Creates or update the idsig file by digesting the input APK file.
    fn createOrUpdateIdsigFile(
        &self,
        input_fd: &ParcelFileDescriptor,
        idsig_fd: &ParcelFileDescriptor,
    ) -> binder::Result<()> {
        check_manage_access()?;

        create_or_update_idsig_file(input_fd, idsig_fd).or_service_specific_exception(-1)?;
        Ok(())
    }

    /// Get a list of all currently running VMs. This method is only intended for debug purposes,
    /// and as such is only permitted from the shell user.
    fn debugListVms(&self) -> binder::Result<Vec<VirtualMachineDebugInfo>> {
        // Delegate to the global service, including checking the debug permission.
        GLOBAL_SERVICE.debugListVms()
    }

    /// Get a list of assignable device types.
    fn getAssignableDevices(&self) -> binder::Result<Vec<AssignableDevice>> {
        // Delegate to the global service, including checking the permission.
        GLOBAL_SERVICE.getAssignableDevices()
    }
}

impl VirtualizationService {
    pub fn init() -> VirtualizationService {
        VirtualizationService::default()
    }

    fn create_vm_context(
        &self,
        requester_debug_pid: pid_t,
    ) -> binder::Result<(VmContext, Cid, PathBuf)> {
        const NUM_ATTEMPTS: usize = 5;

        for _ in 0..NUM_ATTEMPTS {
            let vm_context = GLOBAL_SERVICE.allocateGlobalVmContext(requester_debug_pid)?;
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
        Err(anyhow!("Too many attempts to create VM context failed"))
            .or_service_specific_exception(-1)
    }

    fn create_vm_internal(
        &self,
        config: &VirtualMachineConfig,
        console_out_fd: Option<&ParcelFileDescriptor>,
        console_in_fd: Option<&ParcelFileDescriptor>,
        log_fd: Option<&ParcelFileDescriptor>,
        is_protected: &mut bool,
    ) -> binder::Result<Strong<dyn IVirtualMachine>> {
        let requester_uid = get_calling_uid();
        let requester_debug_pid = get_calling_pid();

        // Allocating VM context checks the MANAGE_VIRTUAL_MACHINE permission.
        let (vm_context, cid, temporary_directory) = self.create_vm_context(requester_debug_pid)?;

        let is_custom = match config {
            VirtualMachineConfig::RawConfig(_) => true,
            VirtualMachineConfig::AppConfig(config) => {
                // Some features are reserved for platform apps only, even when using
                // VirtualMachineAppConfig. Almost all of these features are grouped in the
                // CustomConfig struct:
                // - controlling CPUs;
                // - specifying a config file in the APK; (this one is not part of CustomConfig)
                // - gdbPort is set, meaning that crosvm will start a gdb server;
                // - using anything other than the default kernel;
                // - specifying devices to be assigned.
                config.customConfig.is_some() || matches!(config.payload, Payload::ConfigPath(_))
            }
        };
        if is_custom {
            check_use_custom_virtual_machine()?;
        }

        let gdb_port = extract_gdb_port(config);

        // Additional permission checks if caller request gdb.
        if gdb_port.is_some() {
            check_gdb_allowed(config)?;
        }

        let debug_level = match config {
            VirtualMachineConfig::AppConfig(config) => config.debugLevel,
            _ => DebugLevel::NONE,
        };
        let debug_config = DebugConfig::new(debug_level);

        let ramdump = if debug_config.is_ramdump_needed() {
            Some(prepare_ramdump_file(&temporary_directory)?)
        } else {
            None
        };

        let state = &mut *self.state.lock().unwrap();
        let console_out_fd =
            clone_or_prepare_logger_fd(&debug_config, console_out_fd, format!("Console({})", cid))?;
        let console_in_fd = console_in_fd.map(clone_file).transpose()?;
        let log_fd = clone_or_prepare_logger_fd(&debug_config, log_fd, format!("Log({})", cid))?;

        // Counter to generate unique IDs for temporary image files.
        let mut next_temporary_image_id = 0;
        // Files which are referred to from composite images. These must be mapped to the crosvm
        // child process, and not closed before it is started.
        let mut indirect_files = vec![];

        let (is_app_config, config) = match config {
            VirtualMachineConfig::RawConfig(config) => (false, BorrowedOrOwned::Borrowed(config)),
            VirtualMachineConfig::AppConfig(config) => {
                let config = load_app_config(config, &debug_config, &temporary_directory)
                    .or_service_specific_exception_with(-1, |e| {
                        *is_protected = config.protectedVm;
                        let message = format!("Failed to load app config: {:?}", e);
                        error!("{}", message);
                        message
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
            .or_service_specific_exception(-1)?;

        let kernel = maybe_clone_file(&config.kernel)?;
        let initrd = maybe_clone_file(&config.initrd)?;

        // In a protected VM, we require custom kernels to come from a trusted source (b/237054515).
        if config.protectedVm {
            check_label_for_kernel_files(&kernel, &initrd).or_service_specific_exception(-1)?;
        }

        let zero_filler_path = temporary_directory.join("zero.img");
        write_zero_filler(&zero_filler_path)
            .context("Failed to make composite image")
            .with_log()
            .or_service_specific_exception(-1)?;

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

        let (cpus, host_cpu_topology) = match config.cpuTopology {
            CpuTopology::MATCH_HOST => (None, true),
            CpuTopology::ONE_CPU => (NonZeroU32::new(1), false),
            val => {
                return Err(anyhow!("Failed to parse CPU topology value {:?}", val))
                    .with_log()
                    .or_service_specific_exception(-1);
            }
        };

        let devices_dtbo = if !config.devices.is_empty() {
            let mut set = HashSet::new();
            for device in config.devices.iter() {
                let path = canonicalize(device)
                    .with_context(|| format!("can't canonicalize {device}"))
                    .or_service_specific_exception(-1)?;
                if !set.insert(path) {
                    return Err(anyhow!("duplicated device {device}"))
                        .or_binder_exception(ExceptionCode::ILLEGAL_ARGUMENT);
                }
            }
            let dtbo_path = temporary_directory.join("dtbo");
            // open a writable file descriptor for vfio_handler
            let dtbo = File::create(&dtbo_path).map_err(|e| {
                error!("Failed to create VM DTBO file {dtbo_path:?}: {e:?}");
                Status::new_service_specific_error_str(
                    -1,
                    Some(format!("Failed to create VM DTBO file {dtbo_path:?}: {e:?}")),
                )
            })?;
            GLOBAL_SERVICE
                .bindDevicesToVfioDriver(&config.devices, &ParcelFileDescriptor::new(dtbo))?;

            // open (again) a readable file descriptor for crosvm
            let dtbo = File::open(&dtbo_path).map_err(|e| {
                error!("Failed to open VM DTBO file {dtbo_path:?}: {e:?}");
                Status::new_service_specific_error_str(
                    -1,
                    Some(format!("Failed to open VM DTBO file {dtbo_path:?}: {e:?}")),
                )
            })?;
            Some(dtbo)
        } else {
            None
        };

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
            debug_config,
            memory_mib: config.memoryMib.try_into().ok().and_then(NonZeroU32::new),
            cpus,
            host_cpu_topology,
            task_profiles: config.taskProfiles.clone(),
            console_out_fd,
            console_in_fd,
            log_fd,
            ramdump,
            indirect_files,
            platform_version: parse_platform_version_req(&config.platformVersion)?,
            detect_hangup: is_app_config,
            gdb_port,
            vfio_devices: config.devices.iter().map(PathBuf::from).collect(),
            devices_dtbo,
        };
        let instance = Arc::new(
            VmInstance::new(
                crosvm_config,
                temporary_directory,
                requester_uid,
                requester_debug_pid,
                vm_context,
            )
            .with_context(|| format!("Failed to create VM with config {:?}", config))
            .with_log()
            .or_service_specific_exception(-1)?,
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

fn round_up(input: u64, granularity: u64) -> u64 {
    if granularity == 0 {
        return input;
    }
    // If the input is absurdly large we round down instead of up; it's going to fail anyway.
    let result = input.checked_add(granularity - 1).unwrap_or(input);
    (result / granularity) * granularity
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
            return Err(anyhow!("DiskImage contains both image and partitions"))
                .or_binder_exception(ExceptionCode::ILLEGAL_ARGUMENT);
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
        .with_context(|| format!("Failed to make composite disk image with config {:?}", disk))
        .with_log()
        .or_service_specific_exception(-1)?;

        // Pass the file descriptors for the various partition files to crosvm when it
        // is run.
        indirect_files.extend(partition_files);

        image
    } else if let Some(image) = &disk.image {
        clone_file(image)?
    } else {
        warn!("DiskImage {:?} didn't contain image or partitions.", disk);
        return Err(anyhow!("DiskImage didn't contain image or partitions."))
            .or_binder_exception(ExceptionCode::ILLEGAL_ARGUMENT);
    };

    Ok(DiskFile { image, writable: disk.writable })
}

fn append_kernel_param(param: &str, vm_config: &mut VirtualMachineRawConfig) {
    if let Some(ref mut params) = vm_config.params {
        params.push(' ');
        params.push_str(param)
    } else {
        vm_config.params = Some(param.to_owned())
    }
}

fn load_app_config(
    config: &VirtualMachineAppConfig,
    debug_config: &DebugConfig,
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

    if let Some(custom_config) = &config.customConfig {
        if let Some(file) = custom_config.customKernelImage.as_ref() {
            vm_config.kernel = Some(ParcelFileDescriptor::new(clone_file(file)?))
        }
        vm_config.taskProfiles = custom_config.taskProfiles.clone();
        vm_config.gdbPort = custom_config.gdbPort;

        if let Some(file) = custom_config.vendorImage.as_ref() {
            add_microdroid_vendor_image(clone_file(file)?, &mut vm_config);
            append_kernel_param("androidboot.microdroid.mount_vendor=1", &mut vm_config)
        }

        vm_config.devices = custom_config.devices.clone();
    }

    if config.memoryMib > 0 {
        vm_config.memoryMib = config.memoryMib;
    }

    vm_config.name = config.name.clone();
    vm_config.protectedVm = config.protectedVm;
    vm_config.cpuTopology = config.cpuTopology;

    // Microdroid takes additional init ramdisk & (optionally) storage image
    add_microdroid_system_images(config, instance_file, storage_image, &mut vm_config)?;

    // Include Microdroid payload disk (contains apks, idsigs) in vm config
    add_microdroid_payload_images(
        config,
        debug_config,
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
        export_tombstones: None,
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
        Err(anyhow!("does not have the {} permission", perm))
            .or_binder_exception(ExceptionCode::SECURITY)
    }
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
        | "apk_data_file" // APKs of an installed app
        | "shell_data_file" // test files created via adb shell
        | "staging_data_file" // updated/staged APEX images
        | "system_file" // immutable dm-verity protected partition
        | "virtualizationservice_data_file" // files created by VS / VirtMgr
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
        self.instance
            .start()
            .with_context(|| format!("Error starting VM with CID {}", self.instance.cid))
            .with_log()
            .or_service_specific_exception(-1)
    }

    fn stop(&self) -> binder::Result<()> {
        self.instance
            .kill()
            .with_context(|| format!("Error stopping VM with CID {}", self.instance.cid))
            .with_log()
            .or_service_specific_exception(-1)
    }

    fn onTrimMemory(&self, level: MemoryTrimLevel) -> binder::Result<()> {
        self.instance
            .trim_memory(level)
            .with_context(|| format!("Error trimming VM with CID {}", self.instance.cid))
            .with_log()
            .or_service_specific_exception(-1)
    }

    fn connectVsock(&self, port: i32) -> binder::Result<ParcelFileDescriptor> {
        if !matches!(&*self.instance.vm_state.lock().unwrap(), VmState::Running { .. }) {
            return Err(anyhow!("VM is not running")).or_service_specific_exception(-1);
        }
        let port = port as u32;
        if port < 1024 {
            return Err(anyhow!("Can't connect to privileged port {port}"))
                .or_service_specific_exception(-1);
        }
        let stream = VsockStream::connect_with_cid_port(self.instance.cid, port)
            .context("Failed to connect")
            .or_service_specific_exception(-1)?;
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
pub fn clone_file(file: &ParcelFileDescriptor) -> binder::Result<File> {
    file.as_ref()
        .try_clone()
        .context("Failed to clone File from ParcelFileDescriptor")
        .or_binder_exception(ExceptionCode::BAD_PARCELABLE)
}

/// Converts an `&Option<ParcelFileDescriptor>` to an `Option<File>` by cloning the file.
fn maybe_clone_file(file: &Option<ParcelFileDescriptor>) -> binder::Result<Option<File>> {
    file.as_ref().map(clone_file).transpose()
}

/// Converts a `VsockStream` to a `ParcelFileDescriptor`.
fn vsock_stream_to_pfd(stream: VsockStream) -> ParcelFileDescriptor {
    // SAFETY: ownership is transferred from stream to f
    let f = unsafe { File::from_raw_fd(stream.into_raw_fd()) };
    ParcelFileDescriptor::new(f)
}

/// Parses the platform version requirement string.
fn parse_platform_version_req(s: &str) -> binder::Result<VersionReq> {
    VersionReq::parse(s)
        .with_context(|| format!("Invalid platform version requirement {}", s))
        .or_binder_exception(ExceptionCode::BAD_PARCELABLE)
}

/// Create the empty ramdump file
fn prepare_ramdump_file(temporary_directory: &Path) -> binder::Result<File> {
    // `ramdump_write` is sent to crosvm and will be the backing store for the /dev/hvc1 where
    // VM will emit ramdump to. `ramdump_read` will be sent back to the client (i.e. the VM
    // owner) for readout.
    let ramdump_path = temporary_directory.join("ramdump");
    let ramdump = File::create(ramdump_path)
        .context("Failed to prepare ramdump file")
        .with_log()
        .or_service_specific_exception(-1)?;
    Ok(ramdump)
}

fn is_protected(config: &VirtualMachineConfig) -> bool {
    match config {
        VirtualMachineConfig::RawConfig(config) => config.protectedVm,
        VirtualMachineConfig::AppConfig(config) => config.protectedVm,
    }
}

fn check_gdb_allowed(config: &VirtualMachineConfig) -> binder::Result<()> {
    if is_protected(config) {
        return Err(anyhow!("Can't use gdb with protected VMs"))
            .or_binder_exception(ExceptionCode::SECURITY);
    }

    match config {
        VirtualMachineConfig::RawConfig(_) => Ok(()),
        VirtualMachineConfig::AppConfig(config) => {
            if config.debugLevel != DebugLevel::FULL {
                Err(anyhow!("Can't use gdb with non-debuggable VMs"))
                    .or_binder_exception(ExceptionCode::SECURITY)
            } else {
                Ok(())
            }
        }
    }
}

fn extract_gdb_port(config: &VirtualMachineConfig) -> Option<NonZeroU16> {
    match config {
        VirtualMachineConfig::RawConfig(config) => NonZeroU16::new(config.gdbPort as u16),
        VirtualMachineConfig::AppConfig(config) => {
            NonZeroU16::new(config.customConfig.as_ref().map(|c| c.gdbPort).unwrap_or(0) as u16)
        }
    }
}

fn clone_or_prepare_logger_fd(
    debug_config: &DebugConfig,
    fd: Option<&ParcelFileDescriptor>,
    tag: String,
) -> Result<Option<File>, Status> {
    if let Some(fd) = fd {
        return Ok(Some(clone_file(fd)?));
    }

    if !debug_config.should_prepare_console_output() {
        return Ok(None);
    };

    let (raw_read_fd, raw_write_fd) =
        pipe().context("Failed to create pipe").or_service_specific_exception(-1)?;

    // SAFETY: We are the sole owner of this FD as we just created it, and it is valid and open.
    let mut reader = BufReader::new(unsafe { File::from_raw_fd(raw_read_fd) });
    // SAFETY: We are the sole owner of this FD as we just created it, and it is valid and open.
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
            vm.update_payload_state(PayloadState::Started)
                .or_binder_exception(ExceptionCode::ILLEGAL_STATE)?;
            vm.callbacks.notify_payload_started(cid);

            let vm_start_timestamp = vm.vm_metric.lock().unwrap().start_timestamp;
            write_vm_booted_stats(vm.requester_uid as i32, &vm.name, vm_start_timestamp);
            Ok(())
        } else {
            error!("notifyPayloadStarted is called from an unknown CID {}", cid);
            Err(anyhow!("cannot find a VM with CID {}", cid)).or_service_specific_exception(-1)
        }
    }

    fn notifyPayloadReady(&self) -> binder::Result<()> {
        let cid = self.cid;
        if let Some(vm) = self.state.lock().unwrap().get_vm(cid) {
            info!("VM with CID {} reported payload is ready", cid);
            vm.update_payload_state(PayloadState::Ready)
                .or_binder_exception(ExceptionCode::ILLEGAL_STATE)?;
            vm.callbacks.notify_payload_ready(cid);
            Ok(())
        } else {
            error!("notifyPayloadReady is called from an unknown CID {}", cid);
            Err(anyhow!("cannot find a VM with CID {}", cid)).or_service_specific_exception(-1)
        }
    }

    fn notifyPayloadFinished(&self, exit_code: i32) -> binder::Result<()> {
        let cid = self.cid;
        if let Some(vm) = self.state.lock().unwrap().get_vm(cid) {
            info!("VM with CID {} finished payload", cid);
            vm.update_payload_state(PayloadState::Finished)
                .or_binder_exception(ExceptionCode::ILLEGAL_STATE)?;
            vm.callbacks.notify_payload_finished(cid, exit_code);
            Ok(())
        } else {
            error!("notifyPayloadFinished is called from an unknown CID {}", cid);
            Err(anyhow!("cannot find a VM with CID {}", cid)).or_service_specific_exception(-1)
        }
    }

    fn notifyError(&self, error_code: ErrorCode, message: &str) -> binder::Result<()> {
        let cid = self.cid;
        if let Some(vm) = self.state.lock().unwrap().get_vm(cid) {
            info!("VM with CID {} encountered an error", cid);
            vm.update_payload_state(PayloadState::Finished)
                .or_binder_exception(ExceptionCode::ILLEGAL_STATE)?;
            vm.callbacks.notify_error(cid, error_code, message);
            Ok(())
        } else {
            error!("notifyError is called from an unknown CID {}", cid);
            Err(anyhow!("cannot find a VM with CID {}", cid)).or_service_specific_exception(-1)
        }
    }

    fn requestCertificate(&self, csr: &[u8]) -> binder::Result<Vec<u8>> {
        let cid = self.cid;
        let Some(vm) = self.state.lock().unwrap().get_vm(cid) else {
            error!("requestCertificate is called from an unknown CID {cid}");
            return Err(anyhow!("cannot find a VM with CID {}", cid))
                .or_service_specific_exception(-1);
        };
        let instance_img_path = vm.temporary_directory.join("rkpvm_instance.img");
        let instance_img = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(instance_img_path)
            .context("Failed to create rkpvm_instance.img file")
            .with_log()
            .or_service_specific_exception(-1)?;
        GLOBAL_SERVICE.requestCertificate(csr, &ParcelFileDescriptor::new(instance_img))
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

    #[test]
    fn test_create_or_update_idsig_does_not_update_if_already_valid() -> Result<()> {
        use std::io::Seek;

        // Pick any APK
        let mut apk = File::open("/system/priv-app/Shell/Shell.apk").unwrap();
        let mut idsig = tempfile::tempfile().unwrap();

        create_or_update_idsig_file(
            &ParcelFileDescriptor::new(apk.try_clone()?),
            &ParcelFileDescriptor::new(idsig.try_clone()?),
        )?;
        let modified_orig = idsig.metadata()?.modified()?;
        apk.rewind()?;
        idsig.rewind()?;

        // Call the function again
        create_or_update_idsig_file(
            &ParcelFileDescriptor::new(apk.try_clone()?),
            &ParcelFileDescriptor::new(idsig.try_clone()?),
        )?;
        let modified_new = idsig.metadata()?.modified()?;
        assert!(modified_orig == modified_new, "idsig file was updated unnecessarily");
        Ok(())
    }

    #[test]
    fn test_append_kernel_param_first_param() {
        let mut vm_config = VirtualMachineRawConfig { ..Default::default() };
        append_kernel_param("foo=1", &mut vm_config);
        assert_eq!(vm_config.params, Some("foo=1".to_owned()))
    }

    #[test]
    fn test_append_kernel_param() {
        let mut vm_config =
            VirtualMachineRawConfig { params: Some("foo=5".to_owned()), ..Default::default() };
        append_kernel_param("bar=42", &mut vm_config);
        assert_eq!(vm_config.params, Some("foo=5 bar=42".to_owned()))
    }
}
