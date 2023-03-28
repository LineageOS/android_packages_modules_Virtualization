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
    VirtualMachineAppConfig::DebugLevel::DebugLevel,
};
use std::fs::File;
use std::io::Read;
use log::info;
use rustutils::system_properties;

const DEBUG_POLICY_LOG_PATH: &str = "/proc/device-tree/avf/guest/common/log";
const DEBUG_POLICY_RAMDUMP_PATH: &str = "/proc/device-tree/avf/guest/common/ramdump";
const DEBUG_POLICY_ADB_PATH: &str = "/proc/device-tree/avf/guest/microdroid/adb";

const SYSPROP_CUSTOM_DEBUG_POLICY_PATH: &str = "hypervisor.virtualizationmanager.debug_policy.path";

/// Debug configurations for both debug level and debug policy
#[derive(Debug)]
pub struct DebugConfig {
    pub debug_level: DebugLevel,
    debug_policy_log: bool,
    debug_policy_ramdump: bool,
    debug_policy_adb: bool,
}

/// Get debug policy value in bool. It's true iff the value is explicitly set to <1>.
fn get_debug_policy_bool(path: &'static str) -> Option<bool> {
    let mut file = File::open(path).ok()?;
    let mut log: [u8; 4] = Default::default();
    file.read_exact(&mut log).ok()?;
    // DT spec uses big endian although Android is always little endian.
    Some(u32::from_be_bytes(log) == 1)
}

impl DebugConfig {
    pub fn new(debug_level: DebugLevel) -> Self {
        match system_properties::read(SYSPROP_CUSTOM_DEBUG_POLICY_PATH).unwrap_or_default() {
            Some(debug_policy_path) if !debug_policy_path.is_empty() => {
                // TODO: Read debug policy file and override log, adb, ramdump for testing.
                info!("Debug policy is disabled by sysprop");
                Self {
                    debug_level,
                    debug_policy_log: false,
                    debug_policy_ramdump: false,
                    debug_policy_adb: false,
                }
            }
            _ => {
                let debug_config = Self {
                    debug_level,
                    debug_policy_log: get_debug_policy_bool(DEBUG_POLICY_LOG_PATH)
                        .unwrap_or_default(),
                    debug_policy_ramdump: get_debug_policy_bool(DEBUG_POLICY_RAMDUMP_PATH)
                        .unwrap_or_default(),
                    debug_policy_adb: get_debug_policy_bool(DEBUG_POLICY_ADB_PATH)
                        .unwrap_or_default(),
                };
                info!("Loaded debug policy from host OS: {:?}", debug_config);

                debug_config
            }
        }
    }

    /// Get whether console output should be configred for VM to leave console and adb log.
    /// Caller should create pipe and prepare for receiving VM log with it.
    pub fn should_prepare_console_output(&self) -> bool {
        self.debug_level != DebugLevel::NONE || self.debug_policy_log || self.debug_policy_adb
    }

    /// Get whether debug apexes (MICRODROID_REQUIRED_APEXES_DEBUG) are required.
    pub fn should_include_debug_apexes(&self) -> bool {
        self.debug_level != DebugLevel::NONE || self.debug_policy_adb
    }

    /// Decision to support ramdump
    pub fn is_ramdump_needed(&self) -> bool {
        self.debug_level != DebugLevel::NONE || self.debug_policy_ramdump
    }
}
