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

use crate::hvc;

pub fn hyp_meminfo() -> smccc::Result<u64> {
    hvc::kvm_hyp_meminfo()
}

pub fn mem_share(base_ipa: u64) -> smccc::Result<()> {
    hvc::kvm_mem_share(base_ipa)
}

pub fn mem_unshare(base_ipa: u64) -> smccc::Result<()> {
    hvc::kvm_mem_unshare(base_ipa)
}

pub fn mmio_guard_info() -> smccc::Result<u64> {
    hvc::kvm_mmio_guard_info()
}

pub fn mmio_guard_enroll() -> smccc::Result<()> {
    hvc::kvm_mmio_guard_enroll()
}

pub fn mmio_guard_map(ipa: u64) -> smccc::Result<()> {
    hvc::kvm_mmio_guard_map(ipa)
}

pub fn mmio_guard_unmap(ipa: u64) -> smccc::Result<()> {
    hvc::kvm_mmio_guard_unmap(ipa)
}
