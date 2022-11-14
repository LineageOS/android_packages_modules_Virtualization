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
use anyhow::{anyhow, Result};
use binder::{ParcelFileDescriptor, ThreadState};
use log::{trace, warn};
use microdroid_payload_config::VmPayloadConfig;
use rustutils::system_properties;
use statslog_virtualization_rust::{vm_booted, vm_creation_requested, vm_exited};
use std::thread;
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
            config.name.clone(),
            vm_creation_requested::ConfigType::VirtualMachineAppConfig,
            config.numCpus,
            config.memoryMib,
            get_apex_list(config),
        ),
        VirtualMachineConfig::RawConfig(config) => (
            config.name.clone(),
            vm_creation_requested::ConfigType::VirtualMachineRawConfig,
            config.numCpus,
            config.memoryMib,
            String::new(),
        ),
    };

    let uid = ThreadState::get_calling_uid() as i32;
    thread::spawn(move || {
        let vm_creation_requested = vm_creation_requested::VmCreationRequested {
            uid,
            vm_identifier: &vm_identifier,
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

        wait_for_statsd().unwrap_or_else(|e| warn!("failed to wait for statsd with error: {}", e));
        match vm_creation_requested.stats_write() {
            Err(e) => {
                warn!("statslog_rust failed with error: {}", e);
            }
            Ok(_) => trace!("statslog_rust succeeded for virtualization service"),
        }
    });
}

/// Write the stats of VM boot to statsd
/// The function creates a separate thread which waits fro statsd to start to push atom
pub fn write_vm_booted_stats(
    uid: i32,
    vm_identifier: &str,
    vm_start_timestamp: Option<SystemTime>,
) {
    let vm_identifier = vm_identifier.to_owned();
    let duration = get_duration(vm_start_timestamp);
    thread::spawn(move || {
        let vm_booted = vm_booted::VmBooted {
            uid,
            vm_identifier: &vm_identifier,
            elapsed_time_millis: duration.as_millis() as i64,
        };
        wait_for_statsd().unwrap_or_else(|e| warn!("failed to wait for statsd with error: {}", e));
        match vm_booted.stats_write() {
            Err(e) => {
                warn!("statslog_rust failed with error: {}", e);
            }
            Ok(_) => trace!("statslog_rust succeeded for virtualization service"),
        }
    });
}

/// Write the stats of VM exit to statsd
/// The function creates a separate thread which waits fro statsd to start to push atom
pub fn write_vm_exited_stats(
    uid: i32,
    vm_identifier: &str,
    reason: DeathReason,
    vm_start_timestamp: Option<SystemTime>,
) {
    let vm_identifier = vm_identifier.to_owned();
    let duration = get_duration(vm_start_timestamp);
    thread::spawn(move || {
        let vm_exited = vm_exited::VmExited {
            uid,
            vm_identifier: &vm_identifier,
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
        wait_for_statsd().unwrap_or_else(|e| warn!("failed to wait for statsd with error: {}", e));
        match vm_exited.stats_write() {
            Err(e) => {
                warn!("statslog_rust failed with error: {}", e);
            }
            Ok(_) => trace!("statslog_rust succeeded for virtualization service"),
        }
    });
}

fn wait_for_statsd() -> Result<()> {
    let mut prop = system_properties::PropertyWatcher::new("init.svc.statsd")?;
    loop {
        prop.wait()?;
        match system_properties::read("init.svc.statsd")? {
            Some(s) => {
                if s == "running" {
                    break;
                }
            }
            None => {
                // This case never really happens because
                // prop.wait() waits for property to be non-null.
                break;
            }
        }
    }
    Ok(())
}
