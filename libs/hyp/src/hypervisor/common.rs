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

use smccc::Result;

/// Trait for the hypervisor.
pub trait Hypervisor {
    /// Returns MMIO guard granule size in bytes.
    fn mmio_guard_granule(&self) -> Result<usize>;

    /// Registers to use MMIO guard APIs.
    /// By enrolling, all MMIO will be blocked unless allow-listed with `mmio_guard_map`.
    /// Protected VMs are auto-enrolled.
    fn mmio_guard_enroll(&self) -> Result<()>;

    /// Maps a memory address to the hypervisor MMIO guard.
    fn mmio_guard_map(&self, ipa: u64) -> Result<()>;

    /// Unmaps a memory address from the hypervisor MMIO guard.
    fn mmio_guard_unmap(&self, ipa: u64) -> Result<()>;

    /// Shares a region of memory with host, granting it read, write and execute permissions.
    /// The size of the region is equal to the memory protection granule returned by
    /// [`hyp_meminfo`].
    fn mem_share(&self, base_ipa: u64) -> Result<()>;

    /// Revokes access permission from host to a memory region previously shared with
    /// [`mem_share`]. The size of the region is equal to the memory protection granule returned by
    /// [`hyp_meminfo`].
    fn mem_unshare(&self, base_ipa: u64) -> Result<()>;

    /// Returns the memory protection granule size in bytes.
    fn memory_protection_granule(&self) -> Result<usize>;
}
