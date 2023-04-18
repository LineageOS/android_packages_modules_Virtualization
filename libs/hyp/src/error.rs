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

//! Error and Result types for hypervisor.

use core::{fmt, result};

/// Result type with hypervisor error.
pub type Result<T> = result::Result<T, Error>;

/// Hypervisor error.
#[derive(Debug, Clone)]
pub enum Error {
    /// MMIO guard is not supported.
    MmioGuardNotsupported,
    /// Failed to invoke a certain HVC function.
    HvcError(smccc::Error, u32),
    /// The MMIO_GUARD granule used by the hypervisor is not supported.
    UnsupportedMmioGuardGranule(usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::MmioGuardNotsupported => write!(f, "MMIO guard is not supported"),
            Self::HvcError(e, function_id) => {
                write!(f, "Failed to invoke the HVC function with function ID {function_id}: {e}")
            }
            Self::UnsupportedMmioGuardGranule(g) => {
                write!(f, "Unsupported MMIO guard granule: {g}")
            }
        }
    }
}
