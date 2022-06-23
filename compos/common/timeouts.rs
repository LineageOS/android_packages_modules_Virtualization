/*
 * Copyright 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Timeouts for common situations, with support for longer timeouts when using nested
//! virtualization.

use anyhow::Result;
use std::time::Duration;

/// Holder for the various timeouts we use.
#[derive(Debug, Copy, Clone)]
pub struct Timeouts {
    /// Total time that odrefresh may take to perform compilation
    pub odrefresh_max_execution_time: Duration,
    /// Time allowed for the CompOS VM to start up and become ready.
    pub vm_max_time_to_ready: Duration,
}

/// Return the timeouts that are appropriate on the current platform.
pub fn timeouts() -> Result<&'static Timeouts> {
    // Nested virtualization is slow.
    if nested_virt::is_nested_virtualization()? {
        Ok(&EXTENDED_TIMEOUTS)
    } else {
        Ok(&NORMAL_TIMEOUTS)
    }
}

/// The timeouts that we use normally.
const NORMAL_TIMEOUTS: Timeouts = Timeouts {
    // Note: the source of truth for these odrefresh timeouts is art/odrefresh/odr_config.h.
    odrefresh_max_execution_time: Duration::from_secs(300),
    vm_max_time_to_ready: Duration::from_secs(15),
};

/// The timeouts that we use when need_extra_time() returns true.
const EXTENDED_TIMEOUTS: Timeouts = Timeouts {
    odrefresh_max_execution_time: Duration::from_secs(480),
    vm_max_time_to_ready: Duration::from_secs(120),
};
