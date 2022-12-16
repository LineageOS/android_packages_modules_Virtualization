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

//! Wrappers around calls to the hypervisor.

use crate::smccc::{self, checked_hvc64, checked_hvc64_expect_zero};
use log::info;

const VENDOR_HYP_KVM_MMIO_GUARD_INFO_FUNC_ID: u32 = 0xc6000005;
const VENDOR_HYP_KVM_MMIO_GUARD_ENROLL_FUNC_ID: u32 = 0xc6000006;
const VENDOR_HYP_KVM_MMIO_GUARD_MAP_FUNC_ID: u32 = 0xc6000007;
const VENDOR_HYP_KVM_MMIO_GUARD_UNMAP_FUNC_ID: u32 = 0xc6000008;

pub fn mmio_guard_info() -> smccc::Result<u64> {
    let args = [0u64; 17];

    checked_hvc64(VENDOR_HYP_KVM_MMIO_GUARD_INFO_FUNC_ID, args)
}

pub fn mmio_guard_enroll() -> smccc::Result<()> {
    let args = [0u64; 17];

    checked_hvc64_expect_zero(VENDOR_HYP_KVM_MMIO_GUARD_ENROLL_FUNC_ID, args)
}

pub fn mmio_guard_map(ipa: u64) -> smccc::Result<()> {
    let mut args = [0u64; 17];
    args[0] = ipa;

    // TODO(b/253586500): pKVM currently returns a i32 instead of a i64.
    let is_i32_error_code = |n| u32::try_from(n).ok().filter(|v| (*v as i32) < 0).is_some();
    match checked_hvc64_expect_zero(VENDOR_HYP_KVM_MMIO_GUARD_MAP_FUNC_ID, args) {
        Err(smccc::Error::Unexpected(e)) if is_i32_error_code(e) => {
            info!("Handled a pKVM bug by interpreting the MMIO_GUARD_MAP return value as i32");
            match e as u32 as i32 {
                -1 => Err(smccc::Error::NotSupported),
                -2 => Err(smccc::Error::NotRequired),
                -3 => Err(smccc::Error::InvalidParameter),
                ret => Err(smccc::Error::Unknown(ret as i64)),
            }
        }
        res => res,
    }
}

pub fn mmio_guard_unmap(ipa: u64) -> smccc::Result<()> {
    let mut args = [0u64; 17];
    args[0] = ipa;

    // TODO(b/251426790): pKVM currently returns NOT_SUPPORTED for SUCCESS.
    match checked_hvc64_expect_zero(VENDOR_HYP_KVM_MMIO_GUARD_UNMAP_FUNC_ID, args) {
        Err(smccc::Error::NotSupported) | Ok(_) => Ok(()),
        x => x,
    }
}
