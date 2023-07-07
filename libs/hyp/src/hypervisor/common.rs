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

//! This module regroups some common traits shared by all the hypervisors.

use crate::error::Result;
use crate::util::SIZE_4KB;

/// Expected MMIO guard granule size, validated during MMIO guard initialization.
pub const MMIO_GUARD_GRANULE_SIZE: usize = SIZE_4KB;

/// Trait for the hypervisor.
pub trait Hypervisor {
    /// Returns the hypervisor's MMIO_GUARD implementation, if any.
    fn as_mmio_guard(&self) -> Option<&dyn MmioGuardedHypervisor> {
        None
    }

    /// Returns the hypervisor's dynamic memory sharing implementation, if any.
    fn as_mem_sharer(&self) -> Option<&dyn MemSharingHypervisor> {
        None
    }
}

pub trait MmioGuardedHypervisor {
    /// Initializes the hypervisor by enrolling a MMIO guard and checking the memory granule size.
    /// By enrolling, all MMIO will be blocked unless allow-listed with `mmio_guard_map`.
    /// Protected VMs are auto-enrolled.
    fn init(&self) -> Result<()>;

    /// Maps a page containing the given memory address to the hypervisor MMIO guard.
    /// The page size corresponds to the MMIO guard granule size.
    fn map(&self, addr: usize) -> Result<()>;

    /// Unmaps a page containing the given memory address from the hypervisor MMIO guard.
    /// The page size corresponds to the MMIO guard granule size.
    fn unmap(&self, addr: usize) -> Result<()>;
}

pub trait MemSharingHypervisor {
    /// Shares a region of memory with host, granting it read, write and execute permissions.
    /// The size of the region is equal to the memory protection granule returned by
    /// [`hyp_meminfo`].
    fn share(&self, base_ipa: u64) -> Result<()>;

    /// Revokes access permission from host to a memory region previously shared with
    /// [`mem_share`]. The size of the region is equal to the memory protection granule returned by
    /// [`hyp_meminfo`].
    fn unshare(&self, base_ipa: u64) -> Result<()>;

    /// Returns the memory protection granule size in bytes.
    fn granule(&self) -> Result<usize>;
}
