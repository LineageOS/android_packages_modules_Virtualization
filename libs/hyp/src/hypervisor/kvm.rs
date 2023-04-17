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

//! Wrappers around calls to the KVM hypervisor.

use super::common::Hypervisor;
use crate::error::{Error, Result};
use crate::util::{page_address, SIZE_4KB};

const ARM_SMCCC_KVM_FUNC_HYP_MEMINFO: u32 = 0xc6000002;
const ARM_SMCCC_KVM_FUNC_MEM_SHARE: u32 = 0xc6000003;
const ARM_SMCCC_KVM_FUNC_MEM_UNSHARE: u32 = 0xc6000004;

const VENDOR_HYP_KVM_MMIO_GUARD_INFO_FUNC_ID: u32 = 0xc6000005;
const VENDOR_HYP_KVM_MMIO_GUARD_ENROLL_FUNC_ID: u32 = 0xc6000006;
const VENDOR_HYP_KVM_MMIO_GUARD_MAP_FUNC_ID: u32 = 0xc6000007;
const VENDOR_HYP_KVM_MMIO_GUARD_UNMAP_FUNC_ID: u32 = 0xc6000008;

pub(super) struct KvmHypervisor;

impl Hypervisor for KvmHypervisor {
    fn mmio_guard_init(&self) -> Result<()> {
        mmio_guard_enroll()?;
        let mmio_granule = mmio_guard_granule()?;
        if mmio_granule != SIZE_4KB {
            return Err(Error::UnsupportedMmioGuardGranule(mmio_granule));
        }
        Ok(())
    }

    fn mmio_guard_map(&self, addr: usize) -> Result<()> {
        let mut args = [0u64; 17];
        args[0] = page_address(addr);

        // TODO(b/277859415): pKVM returns a i32 instead of a i64 in T.
        // Drop this hack once T reaches EoL.
        let is_i32_error_code = |n| u32::try_from(n).ok().filter(|v| (*v as i32) < 0).is_some();
        match smccc::checked_hvc64_expect_zero(VENDOR_HYP_KVM_MMIO_GUARD_MAP_FUNC_ID, args) {
            Err(smccc::Error::Unexpected(e)) if is_i32_error_code(e) => match e as u32 as i32 {
                -1 => Err(smccc::Error::NotSupported),
                -2 => Err(smccc::Error::NotRequired),
                -3 => Err(smccc::Error::InvalidParameter),
                ret => Err(smccc::Error::Unknown(ret as i64)),
            },
            res => res,
        }
        .map_err(|e| Error::HvcError(e, VENDOR_HYP_KVM_MMIO_GUARD_MAP_FUNC_ID))
    }

    fn mmio_guard_unmap(&self, addr: usize) -> Result<()> {
        let mut args = [0u64; 17];
        args[0] = page_address(addr);

        // TODO(b/277860860): pKVM returns NOT_SUPPORTED for SUCCESS in T.
        // Drop this hack once T reaches EoL.
        match smccc::checked_hvc64_expect_zero(VENDOR_HYP_KVM_MMIO_GUARD_UNMAP_FUNC_ID, args) {
            Err(smccc::Error::NotSupported) | Ok(_) => Ok(()),
            Err(e) => Err(Error::HvcError(e, VENDOR_HYP_KVM_MMIO_GUARD_UNMAP_FUNC_ID)),
        }
    }

    fn mem_share(&self, base_ipa: u64) -> Result<()> {
        let mut args = [0u64; 17];
        args[0] = base_ipa;

        checked_hvc64_expect_zero(ARM_SMCCC_KVM_FUNC_MEM_SHARE, args)
    }

    fn mem_unshare(&self, base_ipa: u64) -> Result<()> {
        let mut args = [0u64; 17];
        args[0] = base_ipa;

        checked_hvc64_expect_zero(ARM_SMCCC_KVM_FUNC_MEM_UNSHARE, args)
    }

    fn memory_protection_granule(&self) -> Result<usize> {
        let args = [0u64; 17];
        let granule = checked_hvc64(ARM_SMCCC_KVM_FUNC_HYP_MEMINFO, args)?;
        Ok(granule.try_into().unwrap())
    }
}

fn mmio_guard_granule() -> Result<usize> {
    let args = [0u64; 17];

    let granule = checked_hvc64(VENDOR_HYP_KVM_MMIO_GUARD_INFO_FUNC_ID, args)?;
    Ok(granule.try_into().unwrap())
}

fn mmio_guard_enroll() -> Result<()> {
    let args = [0u64; 17];
    match smccc::checked_hvc64_expect_zero(VENDOR_HYP_KVM_MMIO_GUARD_ENROLL_FUNC_ID, args) {
        Ok(_) => Ok(()),
        Err(smccc::Error::NotSupported) => Err(Error::MmioGuardNotsupported),
        Err(e) => Err(Error::HvcError(e, VENDOR_HYP_KVM_MMIO_GUARD_ENROLL_FUNC_ID)),
    }
}

fn checked_hvc64_expect_zero(function: u32, args: [u64; 17]) -> Result<()> {
    smccc::checked_hvc64_expect_zero(function, args).map_err(|e| Error::HvcError(e, function))
}

fn checked_hvc64(function: u32, args: [u64; 17]) -> Result<u64> {
    smccc::checked_hvc64(function, args).map_err(|e| Error::HvcError(e, function))
}
