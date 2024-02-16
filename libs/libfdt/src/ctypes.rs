// Copyright 2024, The Android Open Source Project
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

//! Safe zero-cost wrappers around integer values used by libfdt.

use crate::result::FdtRawResult;
use crate::{FdtError, Result};

/// Wrapper guaranteed to contain a valid phandle.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct Phandle(u32);

impl Phandle {
    /// Minimum valid value for device tree phandles.
    pub const MIN: Self = Self(1);
    /// Maximum valid value for device tree phandles.
    pub const MAX: Self = Self(libfdt_bindgen::FDT_MAX_PHANDLE);

    /// Creates a new Phandle
    pub const fn new(value: u32) -> Option<Self> {
        if Self::MIN.0 <= value && value <= Self::MAX.0 {
            Some(Self(value))
        } else {
            None
        }
    }
}

impl From<Phandle> for u32 {
    fn from(phandle: Phandle) -> u32 {
        phandle.0
    }
}

impl TryFrom<u32> for Phandle {
    type Error = FdtError;

    fn try_from(value: u32) -> Result<Self> {
        Self::new(value).ok_or(FdtError::BadPhandle)
    }
}

impl TryFrom<FdtRawResult> for Phandle {
    type Error = FdtError;

    fn try_from(res: FdtRawResult) -> Result<Self> {
        Self::new(res.try_into()?).ok_or(FdtError::BadPhandle)
    }
}
