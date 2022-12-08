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

//! Safe MMIO_GUARD support.

use crate::helpers;
use crate::smccc;
use core::{fmt, result};
use log::info;

#[derive(Debug, Clone)]
pub enum Error {
    /// Failed the necessary MMIO_GUARD_ENROLL call.
    EnrollFailed(smccc::Error),
    /// Failed to obtain the MMIO_GUARD granule size.
    InfoFailed(smccc::Error),
    /// Failed to MMIO_GUARD_MAP a page.
    MapFailed(smccc::Error),
    /// Failed to MMIO_GUARD_UNMAP a page.
    UnmapFailed(smccc::Error),
    /// The MMIO_GUARD granule used by the hypervisor is not supported.
    UnsupportedGranule(usize),
}

type Result<T> = result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::EnrollFailed(e) => write!(f, "Failed to enroll into MMIO_GUARD: {e}"),
            Self::InfoFailed(e) => write!(f, "Failed to get the MMIO_GUARD granule: {e}"),
            Self::MapFailed(e) => write!(f, "Failed to MMIO_GUARD map: {e}"),
            Self::UnmapFailed(e) => write!(f, "Failed to MMIO_GUARD unmap: {e}"),
            Self::UnsupportedGranule(g) => write!(f, "Unsupported MMIO_GUARD granule: {g}"),
        }
    }
}

pub fn init() -> Result<()> {
    mmio_guard_enroll().map_err(Error::EnrollFailed)?;
    let mmio_granule = mmio_guard_info().map_err(Error::InfoFailed)? as usize;
    if mmio_granule != helpers::SIZE_4KB {
        return Err(Error::UnsupportedGranule(mmio_granule));
    }
    Ok(())
}

pub fn map(addr: usize) -> Result<()> {
    mmio_guard_map(helpers::page_4kb_of(addr) as u64).map_err(Error::MapFailed)
}

pub fn unmap(addr: usize) -> Result<()> {
    mmio_guard_unmap(helpers::page_4kb_of(addr) as u64).map_err(Error::UnmapFailed)
}

fn mmio_guard_info() -> smccc::Result<u64> {
    const VENDOR_HYP_KVM_MMIO_GUARD_INFO_FUNC_ID: u32 = 0xc6000005;
    let args = [0u64; 17];

    smccc::checked_hvc64(VENDOR_HYP_KVM_MMIO_GUARD_INFO_FUNC_ID, args)
}

fn mmio_guard_enroll() -> smccc::Result<()> {
    const VENDOR_HYP_KVM_MMIO_GUARD_ENROLL_FUNC_ID: u32 = 0xc6000006;
    let args = [0u64; 17];

    smccc::checked_hvc64_expect_zero(VENDOR_HYP_KVM_MMIO_GUARD_ENROLL_FUNC_ID, args)
}

fn mmio_guard_map(ipa: u64) -> smccc::Result<()> {
    const VENDOR_HYP_KVM_MMIO_GUARD_MAP_FUNC_ID: u32 = 0xc6000007;
    let mut args = [0u64; 17];
    args[0] = ipa;

    // TODO(b/253586500): pKVM currently returns a i32 instead of a i64.
    let is_i32_error_code = |n| u32::try_from(n).ok().filter(|v| (*v as i32) < 0).is_some();
    match smccc::checked_hvc64_expect_zero(VENDOR_HYP_KVM_MMIO_GUARD_MAP_FUNC_ID, args) {
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

fn mmio_guard_unmap(ipa: u64) -> smccc::Result<()> {
    const VENDOR_HYP_KVM_MMIO_GUARD_UNMAP_FUNC_ID: u32 = 0xc6000008;
    let mut args = [0u64; 17];
    args[0] = ipa;

    // TODO(b/251426790): pKVM currently returns NOT_SUPPORTED for SUCCESS.
    match smccc::checked_hvc64_expect_zero(VENDOR_HYP_KVM_MMIO_GUARD_UNMAP_FUNC_ID, args) {
        Err(smccc::Error::NotSupported) | Ok(_) => Ok(()),
        x => x,
    }
}
