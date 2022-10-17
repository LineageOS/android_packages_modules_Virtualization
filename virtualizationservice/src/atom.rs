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

//! Functions for creating and collecting atoms.

use crate::aidl::clone_file;
use android_system_virtualizationservice::aidl::android::system::virtualizationservice::{
    DeathReason::DeathReason,
    IVirtualMachine::IVirtualMachine,
    VirtualMachineAppConfig::{Payload::Payload, VirtualMachineAppConfig},
    VirtualMachineConfig::VirtualMachineConfig,
};
use android_system_virtualizationservice::binder::{Status, Strong};
use android_system_virtualmachineservice::aidl::android::system::virtualmachineservice::{
    VirtualMachineCpuStatus::VirtualMachineCpuStatus,
    VirtualMachineMemStatus::VirtualMachineMemStatus,
};
use anyhow::{anyhow, Result};
use binder::{ParcelFileDescriptor, ThreadState};
use log::{trace, warn};
use microdroid_payload_config::VmPayloadConfig;
use statslog_virtualization_rust::{
    vm_booted, vm_cpu_status_reported, vm_creation_requested, vm_exited, vm_mem_status_reported,
};
use std::time::{Duration, SystemTime};
use zip::ZipArchive;

fn get_apex_list(config: &VirtualMachineAppConfig) -> String {
    match &config.payload {
        Payload::PayloadConfig(_) => String::new(),
        Payload::ConfigPath(config_path) => {
            let vm_payload_config = get_vm_payload_config(&config.apk, config_path);
            if let Ok(vm_payload_config) = vm_payload_config {
                vm_payload_config
                    .apexes
                    .iter()
                    .map(|x| x.name.clone())
                    .collect::<Vec<String>>()
                    .join(":")
            } else {
                "INFO: Can't get VmPayloadConfig".to_owned()
            }
        }
    }
}

fn get_vm_payload_config(
    apk_fd: &Option<ParcelFileDescriptor>,
    config_path: &str,
) -> Result<VmPayloadConfig> {
    let apk = apk_fd.as_ref().ok_or_else(|| anyhow!("APK is none"))?;
    let apk_file = clone_file(apk)?;
    let mut apk_zip = ZipArchive::new(&apk_file)?;
    let config_file = apk_zip.by_name(config_path)?;
    let vm_payload_config: VmPayloadConfig = serde_json::from_reader(config_file)?;
    Ok(vm_payload_config)
}

fn get_duration(vm_start_timestamp: Option<SystemTime>) -> Duration {
    match vm_start_timestamp {
        Some(vm_start_timestamp) => vm_start_timestamp.elapsed().unwrap_or_default(),
        None => Duration::default(),
    }
}

/// Write the stats of VMCreation to statsd
pub fn write_vm_creation_stats(
    config: &VirtualMachineConfig,
    is_protected: bool,
    ret: &binder::Result<Strong<dyn IVirtualMachine>>,
) {
    let creation_succeeded;
    let binder_exception_code;
    match ret {
        Ok(_) => {
            creation_succeeded = true;
            binder_exception_code = Status::ok().exception_code() as i32;
        }
        Err(ref e) => {
            creation_succeeded = false;
            binder_exception_code = e.exception_code() as i32;
        }
    }

    let (vm_identifier, config_type, num_cpus, memory_mib, apexes) = match config {
        VirtualMachineConfig::AppConfig(config) => (
            &config.name,
            vm_creation_requested::ConfigType::VirtualMachineAppConfig,
            config.numCpus,
            config.memoryMib,
            get_apex_list(config),
        ),
        VirtualMachineConfig::RawConfig(config) => (
            &config.name,
            vm_creation_requested::ConfigType::VirtualMachineRawConfig,
            config.numCpus,
            config.memoryMib,
            String::new(),
        ),
    };

    let vm_creation_requested = vm_creation_requested::VmCreationRequested {
        uid: ThreadState::get_calling_uid() as i32,
        vm_identifier,
        hypervisor: vm_creation_requested::Hypervisor::Pkvm,
        is_protected,
        creation_succeeded,
        binder_exception_code,
        config_type,
        num_cpus,
        cpu_affinity: "", // deprecated
        memory_mib,
        apexes: &apexes,
        // TODO(seungjaeyoo) Fill information about task_profile
        // TODO(seungjaeyoo) Fill information about disk_image for raw config
    };

    match vm_creation_requested.stats_write() {
        Err(e) => {
            warn!("statslog_rust failed with error: {}", e);
        }
        Ok(_) => trace!("statslog_rust succeeded for virtualization service"),
    }
}

/// Write the stats of VM boot to statsd
pub fn write_vm_booted_stats(
    uid: i32,
    vm_identifier: &String,
    vm_start_timestamp: Option<SystemTime>,
) {
    let duration = get_duration(vm_start_timestamp);
    let vm_booted = vm_booted::VmBooted {
        uid,
        vm_identifier,
        elapsed_time_millis: duration.as_millis() as i64,
    };
    match vm_booted.stats_write() {
        Err(e) => {
            warn!("statslog_rust failed with error: {}", e);
        }
        Ok(_) => trace!("statslog_rust succeeded for virtualization service"),
    }
}

/// Write the stats of VM exit to statsd
pub fn write_vm_exited_stats(
    uid: i32,
    vm_identifier: &String,
    reason: DeathReason,
    vm_start_timestamp: Option<SystemTime>,
) {
    let duration = get_duration(vm_start_timestamp);
    let vm_exited = vm_exited::VmExited {
        uid,
        vm_identifier,
        elapsed_time_millis: duration.as_millis() as i64,
        death_reason: match reason {
            DeathReason::INFRASTRUCTURE_ERROR => vm_exited::DeathReason::InfrastructureError,
            DeathReason::KILLED => vm_exited::DeathReason::Killed,
            DeathReason::UNKNOWN => vm_exited::DeathReason::Unknown,
            DeathReason::SHUTDOWN => vm_exited::DeathReason::Shutdown,
            DeathReason::ERROR => vm_exited::DeathReason::Error,
            DeathReason::REBOOT => vm_exited::DeathReason::Reboot,
            DeathReason::CRASH => vm_exited::DeathReason::Crash,
            DeathReason::PVM_FIRMWARE_PUBLIC_KEY_MISMATCH => {
                vm_exited::DeathReason::PvmFirmwarePublicKeyMismatch
            }
            DeathReason::PVM_FIRMWARE_INSTANCE_IMAGE_CHANGED => {
                vm_exited::DeathReason::PvmFirmwareInstanceImageChanged
            }
            DeathReason::BOOTLOADER_PUBLIC_KEY_MISMATCH => {
                vm_exited::DeathReason::BootloaderPublicKeyMismatch
            }
            DeathReason::BOOTLOADER_INSTANCE_IMAGE_CHANGED => {
                vm_exited::DeathReason::BootloaderInstanceImageChanged
            }
            DeathReason::MICRODROID_FAILED_TO_CONNECT_TO_VIRTUALIZATION_SERVICE => {
                vm_exited::DeathReason::MicrodroidFailedToConnectToVirtualizationService
            }
            DeathReason::MICRODROID_PAYLOAD_HAS_CHANGED => {
                vm_exited::DeathReason::MicrodroidPayloadHasChanged
            }
            DeathReason::MICRODROID_PAYLOAD_VERIFICATION_FAILED => {
                vm_exited::DeathReason::MicrodroidPayloadVerificationFailed
            }
            DeathReason::MICRODROID_INVALID_PAYLOAD_CONFIG => {
                vm_exited::DeathReason::MicrodroidInvalidPayloadConfig
            }
            DeathReason::MICRODROID_UNKNOWN_RUNTIME_ERROR => {
                vm_exited::DeathReason::MicrodroidUnknownRuntimeError
            }
            DeathReason::HANGUP => vm_exited::DeathReason::Hangup,
            _ => vm_exited::DeathReason::Unknown,
        },
    };
    match vm_exited.stats_write() {
        Err(e) => {
            warn!("statslog_rust failed with error: {}", e);
        }
        Ok(_) => trace!("statslog_rust succeeded for virtualization service"),
    }
}

/// Write the stats of VM cpu status to statsd
pub fn write_vm_cpu_status_stats(
    uid: i32,
    vm_identifier: &String,
    cpu_status: &VirtualMachineCpuStatus,
) {
    let vm_cpu_status_reported = vm_cpu_status_reported::VmCpuStatusReported {
        uid,
        vm_identifier,
        cpu_time_user_millis: cpu_status.cpu_time_user,
        cpu_time_nice_millis: cpu_status.cpu_time_nice,
        cpu_time_sys_millis: cpu_status.cpu_time_sys,
        cpu_time_idle_millis: cpu_status.cpu_time_idle,
    };
    match vm_cpu_status_reported.stats_write() {
        Err(e) => {
            warn!("statslog_rust failed with error: {}", e);
        }
        Ok(_) => trace!("statslog_rust succeeded for virtualization service"),
    }
}

/// Write the stats of VM memory status to statsd
pub fn write_vm_mem_status_stats(
    uid: i32,
    vm_identifier: &String,
    mem_status: &VirtualMachineMemStatus,
) {
    let vm_mem_status_reported = vm_mem_status_reported::VmMemStatusReported {
        uid,
        vm_identifier,
        mem_total_kb: mem_status.mem_total,
        mem_free_kb: mem_status.mem_free,
        mem_available_kb: mem_status.mem_available,
        mem_buffer_kb: mem_status.mem_buffer,
        mem_cached_kb: mem_status.mem_cached,
    };
    match vm_mem_status_reported.stats_write() {
        Err(e) => {
            warn!("statslog_rust failed with error: {}", e);
        }
        Ok(_) => trace!("statslog_rust succeeded for virtualization service"),
    }
}
