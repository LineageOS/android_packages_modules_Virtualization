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

use crate::smccc;
use core::fmt;
use core::result;

/// Standard SMCCC TRNG error values as described in DEN 0098 1.0 REL0.
#[derive(Debug, Clone)]
pub enum Error {
    /// The call is not supported by the implementation.
    NotSupported,
    /// One of the call parameters has a non-supported value.
    InvalidParameter,
    /// Call returned without the requested entropy bits.
    NoEntropy,
    /// Negative values indicate error.
    Unknown(i64),
    /// The call returned a positive value when 0 was expected.
    Unexpected(u64),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::NotSupported => write!(f, "SMCCC TRNG call not supported"),
            Self::InvalidParameter => write!(f, "SMCCC TRNG call received non-supported value"),
            Self::NoEntropy => write!(f, "SMCCC TRNG call returned no entropy"),
            Self::Unexpected(v) => write!(f, "Unexpected SMCCC TRNG return value {} ({0:#x})", v),
            Self::Unknown(e) => write!(f, "Unknown SMCCC TRNG return value {} ({0:#x})", e),
        }
    }
}

pub type Result<T> = result::Result<T, Error>;

pub fn hvc64(function: u32, args: [u64; 17]) -> Result<[u64; 18]> {
    let res = smccc::hvc64(function, args);
    match res[0] as i64 {
        ret if ret >= 0 => Ok(res),
        -1 => Err(Error::NotSupported),
        -2 => Err(Error::InvalidParameter),
        -3 => Err(Error::NoEntropy),
        ret => Err(Error::Unknown(ret)),
    }
}

pub fn hvc64_expect_zero(function: u32, args: [u64; 17]) -> Result<[u64; 18]> {
    let res = hvc64(function, args)?;
    match res[0] {
        0 => Ok(res),
        v => Err(Error::Unexpected(v)),
    }
}
