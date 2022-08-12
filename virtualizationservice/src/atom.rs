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
    IVirtualMachine::IVirtualMachine, VirtualMachineAppConfig::VirtualMachineAppConfig,
    VirtualMachineConfig::VirtualMachineConfig,
};
use android_system_virtualizationservice::binder::{Status, Strong};
use anyhow::{anyhow, Result};
use log::{trace, warn};
use microdroid_payload_config::VmPayloadConfig;
use statslog_virtualization_rust::{vm_booted, vm_creation_requested};
use zip::ZipArchive;

fn get_vm_payload_config(config: &VirtualMachineAppConfig) -> Result<VmPayloadConfig> {
    let apk = config.apk.as_ref().ok_or_else(|| anyhow!("APK is none"))?;
    let apk_file = clone_file(apk)?;
    let mut apk_zip = ZipArchive::new(&apk_file)?;
    let config_file = apk_zip.by_name(&config.configPath)?;
    let vm_payload_config: VmPayloadConfig = serde_json::from_reader(config_file)?;
    Ok(vm_payload_config)
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

    let config_type;
    let num_cpus;
    let cpu_affinity;
    let memory_mib;
    let apexes;
    match config {
        VirtualMachineConfig::AppConfig(config) => {
            config_type = vm_creation_requested::ConfigType::VirtualMachineAppConfig;
            num_cpus = config.numCpus;
            cpu_affinity = config.cpuAffinity.clone().unwrap_or_default();
            memory_mib = config.memoryMib;

            let vm_payload_config = get_vm_payload_config(config);
            if let Ok(vm_payload_config) = vm_payload_config {
                apexes = vm_payload_config
                    .apexes
                    .iter()
                    .map(|x| x.name.clone())
                    .collect::<Vec<String>>()
                    .join(":");
            } else {
                apexes = "INFO: Can't get VmPayloadConfig".into();
            }
        }
        VirtualMachineConfig::RawConfig(config) => {
            config_type = vm_creation_requested::ConfigType::VirtualMachineRawConfig;
            num_cpus = config.numCpus;
            cpu_affinity = config.cpuAffinity.clone().unwrap_or_default();
            memory_mib = config.memoryMib;
            apexes = String::new();
        }
    }

    let empty_string = String::new();
    let vm_creation_requested = vm_creation_requested::VmCreationRequested {
        // TODO(seungjaeyoo) Implement sending proper data about uid & vm_identifier
        uid: -1,
        vm_identifier: &empty_string,
        hypervisor: vm_creation_requested::Hypervisor::Pkvm,
        is_protected,
        creation_succeeded,
        binder_exception_code,
        config_type,
        num_cpus,
        cpu_affinity: &cpu_affinity,
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
pub fn write_vm_booted_stats() {
    let empty_string = String::new();
    let vm_booted = vm_booted::VmBooted {
        // TODO(seungjaeyoo) Implement sending proper data about uid & vm_identifier
        uid: -1,
        vm_identifier: &empty_string,
    };
    match vm_booted.stats_write() {
        Err(e) => {
            warn!("statslog_rust failed with error: {}", e);
        }
        Ok(_) => trace!("statslog_rust succeeded for virtualization service"),
    }
}
