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

use core::{fmt, result};
use psci::smccc::hvc64;

/// Standard SMCCC error values as described in DEN 0028E.
#[derive(Debug, Clone)]
pub enum Error {
    /// The call is not supported by the implementation.
    NotSupported,
    /// The call is deemed not required by the implementation.
    NotRequired,
    /// One of the call parameters has a non-supported value.
    InvalidParameter,
    /// Negative values indicate error.
    Unknown(i64),
    /// The call returned a positive value when 0 was expected.
    Unexpected(u64),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::NotSupported => write!(f, "SMCCC call not supported"),
            Self::NotRequired => write!(f, "SMCCC call not required"),
            Self::InvalidParameter => write!(f, "SMCCC call received non-supported value"),
            Self::Unexpected(v) => write!(f, "Unexpected SMCCC return value {} ({0:#x})", v),
            Self::Unknown(e) => write!(f, "Unknown SMCCC return value {} ({0:#x})", e),
        }
    }
}

pub type Result<T> = result::Result<T, Error>;

pub fn checked_hvc64_expect_zero(function: u32, args: [u64; 17]) -> Result<()> {
    match checked_hvc64(function, args)? {
        0 => Ok(()),
        v => Err(Error::Unexpected(v)),
    }
}

pub fn checked_hvc64(function: u32, args: [u64; 17]) -> Result<u64> {
    match hvc64(function, args)[0] as i64 {
        ret if ret >= 0 => Ok(ret as u64),
        -1 => Err(Error::NotSupported),
        -2 => Err(Error::NotRequired),
        -3 => Err(Error::InvalidParameter),
        ret => Err(Error::Unknown(ret)),
    }
}
