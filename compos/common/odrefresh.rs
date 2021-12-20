/*
 * Copyright (C) 2021 The Android Open Source Project
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

//! Helpers for running odrefresh

use anyhow::{anyhow, Result};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

/// The path to the odrefresh binary
pub const ODREFRESH_PATH: &str = "/apex/com.android.art/bin/odrefresh";

// The highest "standard" exit code defined in sysexits.h (as EX__MAX); odrefresh error codes
// start above here to avoid clashing.
// TODO: What if this changes?
const EX_MAX: i8 = 78;

/// The defined odrefresh exit codes - see art/odrefresh/include/odrefresh/odrefresh.h
#[derive(Debug, PartialEq, Eq, FromPrimitive)]
#[repr(i8)]
pub enum ExitCode {
    /// No compilation required, all artifacts look good
    Okay = 0,
    /// Compilation required
    CompilationRequired = EX_MAX + 1,
    /// New artifacts successfully generated
    CompilationSuccess = EX_MAX + 2,
    /// Compilation failed
    CompilationFailed = EX_MAX + 3,
    /// Removal of existing invalid artifacts failed
    CleanupFailed = EX_MAX + 4,
}

impl ExitCode {
    /// Map an integer to the corresponding ExitCode enum, if there is one
    pub fn from_i32(exit_code: i32) -> Result<Self> {
        FromPrimitive::from_i32(exit_code)
            .ok_or_else(|| anyhow!("Unexpected odrefresh exit code: {}", exit_code))
    }
}
