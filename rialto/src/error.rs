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

//! This module contains the error thrown by Rialto.

use aarch64_paging::MapError;
use core::{fmt, result};
use hyp::mmio_guard::Error as MmioError;

pub type Result<T> = result::Result<T, Error>;

#[derive(Clone, Debug)]
pub enum Error {
    /// MMIO guard failed.
    MmioGuard(MmioError),
    /// Failed when attempting to map some range in the page table.
    PageTableMapping(MapError),
    /// Failed to initialize the logger.
    LoggerInit,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::MmioGuard(e) => write!(f, "MMIO guard failed: {e}."),
            Self::PageTableMapping(e) => {
                write!(f, "Failed when attempting to map some range in the page table: {e}.")
            }
            Self::LoggerInit => write!(f, "Failed to initialize the logger."),
        }
    }
}

impl From<MmioError> for Error {
    fn from(e: MmioError) -> Self {
        Self::MmioGuard(e)
    }
}

impl From<MapError> for Error {
    fn from(e: MapError) -> Self {
        Self::PageTableMapping(e)
    }
}
