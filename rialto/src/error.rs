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
use fdtpci::PciError;
use hyp::Error as HypervisorError;
use libfdt::FdtError;
use vmbase::{memory::MemoryTrackerError, virtio::pci};

pub type Result<T> = result::Result<T, Error>;

#[derive(Clone, Debug)]
pub enum Error {
    /// Hypervisor error.
    Hypervisor(HypervisorError),
    /// Failed when attempting to map some range in the page table.
    PageTableMapping(MapError),
    /// Invalid FDT.
    InvalidFdt(FdtError),
    /// Invalid PCI.
    InvalidPci(PciError),
    /// Failed memory operation.
    MemoryOperationFailed(MemoryTrackerError),
    /// Failed to initialize PCI.
    PciInitializationFailed(pci::PciError),
    /// Failed to create VirtIO Socket device.
    VirtIOSocketCreationFailed(virtio_drivers::Error),
    /// Missing socket device.
    MissingVirtIOSocketDevice,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Hypervisor(e) => write!(f, "Hypervisor error: {e}."),
            Self::PageTableMapping(e) => {
                write!(f, "Failed when attempting to map some range in the page table: {e}.")
            }
            Self::InvalidFdt(e) => write!(f, "Invalid FDT: {e}"),
            Self::InvalidPci(e) => write!(f, "Invalid PCI: {e}"),
            Self::MemoryOperationFailed(e) => write!(f, "Failed memory operation: {e}"),
            Self::PciInitializationFailed(e) => write!(f, "Failed to initialize PCI: {e}"),
            Self::VirtIOSocketCreationFailed(e) => {
                write!(f, "Failed to create VirtIO Socket device: {e}")
            }
            Self::MissingVirtIOSocketDevice => write!(f, "Missing VirtIO Socket device."),
        }
    }
}

impl From<HypervisorError> for Error {
    fn from(e: HypervisorError) -> Self {
        Self::Hypervisor(e)
    }
}

impl From<MapError> for Error {
    fn from(e: MapError) -> Self {
        Self::PageTableMapping(e)
    }
}

impl From<FdtError> for Error {
    fn from(e: FdtError) -> Self {
        Self::InvalidFdt(e)
    }
}

impl From<PciError> for Error {
    fn from(e: PciError) -> Self {
        Self::InvalidPci(e)
    }
}

impl From<MemoryTrackerError> for Error {
    fn from(e: MemoryTrackerError) -> Self {
        Self::MemoryOperationFailed(e)
    }
}
