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

//! Wrappers around hypervisor back-ends.

mod kvm;

/// Queries the memory protection parameters for a protected virtual machine.
///
/// Returns the memory protection granule size in bytes.
pub fn hyp_meminfo() -> smccc::Result<u64> {
    kvm::hyp_meminfo()
}

/// Shares a region of memory with the host, granting it read, write and execute permissions.
/// The size of the region is equal to the memory protection granule returned by [`hyp_meminfo`].
pub fn mem_share(base_ipa: u64) -> smccc::Result<()> {
    kvm::mem_share(base_ipa)
}

/// Revokes access permission from the host to a memory region previously shared with
/// [`mem_share`]. The size of the region is equal to the memory protection granule returned by
/// [`hyp_meminfo`].
pub fn mem_unshare(base_ipa: u64) -> smccc::Result<()> {
    kvm::mem_unshare(base_ipa)
}

pub(crate) fn mmio_guard_info() -> smccc::Result<u64> {
    kvm::mmio_guard_info()
}

pub(crate) fn mmio_guard_enroll() -> smccc::Result<()> {
    kvm::mmio_guard_enroll()
}

pub(crate) fn mmio_guard_map(ipa: u64) -> smccc::Result<()> {
    kvm::mmio_guard_map(ipa)
}

pub(crate) fn mmio_guard_unmap(ipa: u64) -> smccc::Result<()> {
    kvm::mmio_guard_unmap(ipa)
}
