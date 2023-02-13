// Copyright 2023, The Android Open Source Project
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

//! Functions for AVF debug policy and debug level

use android_system_virtualizationservice::aidl::android::system::virtualizationservice::{
    VirtualMachineAppConfig::DebugLevel::DebugLevel, VirtualMachineConfig::VirtualMachineConfig,
};
use std::fs::File;
use std::io::Read;

/// Get debug policy value in bool. It's true iff the value is explicitly set to <1>.
fn get_debug_policy_bool(path: &'static str) -> Option<bool> {
    let mut file = File::open(path).ok()?;
    let mut log: [u8; 4] = Default::default();
    file.read_exact(&mut log).ok()?;
    // DT spec uses big endian although Android is always little endian.
    Some(u32::from_be_bytes(log) == 1)
}

/// Get whether console output should be configred for VM to leave console and adb log.
/// Caller should create pipe and prepare for receiving VM log with it.
pub fn should_prepare_console_output(debug_level: DebugLevel) -> bool {
    debug_level != DebugLevel::NONE
        || get_debug_policy_bool("/proc/device-tree/avf/guest/common/log").unwrap_or_default()
        || get_debug_policy_bool("/proc/device-tree/avf/guest/microdroid/adb").unwrap_or_default()
}

/// Get whether debug apexes (MICRODROID_REQUIRED_APEXES_DEBUG) are required.
pub fn should_include_debug_apexes(debug_level: DebugLevel) -> bool {
    debug_level != DebugLevel::NONE
        || get_debug_policy_bool("/proc/device-tree/avf/guest/microdroid/adb").unwrap_or_default()
}

/// Decision to support ramdump
pub fn is_ramdump_needed(config: &VirtualMachineConfig) -> bool {
    let enabled_in_dp =
        get_debug_policy_bool("/proc/device-tree/avf/guest/common/ramdump").unwrap_or_default();
    let (protected, debuggable) = match config {
        VirtualMachineConfig::RawConfig(config) => {
            // custom VMs are considered debuggable for flexibility
            (config.protectedVm, true)
        }
        VirtualMachineConfig::AppConfig(config) => {
            (config.protectedVm, config.debugLevel == DebugLevel::FULL)
        }
    };

    if protected {
        enabled_in_dp
    } else {
        enabled_in_dp || debuggable
    }
}
