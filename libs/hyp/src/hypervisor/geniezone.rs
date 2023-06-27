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

//! Wrappers around calls to the GenieZone hypervisor.

use super::common::{Hypervisor, HypervisorCap, MMIO_GUARD_GRANULE_SIZE};
use crate::error::{Error, Result};
use crate::util::page_address;
use core::fmt::{self, Display, Formatter};
use smccc::{
    error::{positive_or_error_64, success_or_error_64},
    hvc64,
};
use uuid::{uuid, Uuid};

pub(super) struct GeniezoneHypervisor;

const ARM_SMCCC_GZVM_FUNC_HYP_MEMINFO: u32 = 0xc6000002;
const ARM_SMCCC_GZVM_FUNC_MEM_SHARE: u32 = 0xc6000003;
const ARM_SMCCC_GZVM_FUNC_MEM_UNSHARE: u32 = 0xc6000004;

const VENDOR_HYP_GZVM_MMIO_GUARD_INFO_FUNC_ID: u32 = 0xc6000005;
const VENDOR_HYP_GZVM_MMIO_GUARD_ENROLL_FUNC_ID: u32 = 0xc6000006;
const VENDOR_HYP_GZVM_MMIO_GUARD_MAP_FUNC_ID: u32 = 0xc6000007;
const VENDOR_HYP_GZVM_MMIO_GUARD_UNMAP_FUNC_ID: u32 = 0xc6000008;

impl GeniezoneHypervisor {
    // We generate this uuid by ourselves to identify GenieZone hypervisor
    // and share the same identification along with guest VMs.
    // The previous uuid was removed due to duplication elsewhere.
    pub const UUID: Uuid = uuid!("7e134ed0-3b82-488d-8cee-69c19211dbe7");
    const CAPABILITIES: HypervisorCap = HypervisorCap::DYNAMIC_MEM_SHARE;
}

/// Error from a GenieZone HVC call.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum GeniezoneError {
    /// The call is not supported by the implementation.
    NotSupported,
    /// The call is not required to implement.
    NotRequired,
    /// One of the call parameters has a invalid value.
    InvalidParameter,
    /// There was an unexpected return value.
    Unknown(i64),
}

impl From<i64> for GeniezoneError {
    fn from(value: i64) -> Self {
        match value {
            -1 => GeniezoneError::NotSupported,
            -2 => GeniezoneError::NotRequired,
            -3 => GeniezoneError::InvalidParameter,
            _ => GeniezoneError::Unknown(value),
        }
    }
}

impl From<i32> for GeniezoneError {
    fn from(value: i32) -> Self {
        i64::from(value).into()
    }
}

impl Display for GeniezoneError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::NotSupported => write!(f, "GenieZone call not supported"),
            Self::NotRequired => write!(f, "GenieZone call not required"),
            Self::InvalidParameter => write!(f, "GenieZone call received invalid value"),
            Self::Unknown(e) => write!(f, "Unknown return value from GenieZone {} ({0:#x})", e),
        }
    }
}

impl Hypervisor for GeniezoneHypervisor {
    fn mmio_guard_init(&self) -> Result<()> {
        mmio_guard_enroll()?;
        let mmio_granule = mmio_guard_granule()?;
        if mmio_granule != MMIO_GUARD_GRANULE_SIZE {
            return Err(Error::UnsupportedMmioGuardGranule(mmio_granule));
        }
        Ok(())
    }

    fn mmio_guard_map(&self, addr: usize) -> Result<()> {
        let mut args = [0u64; 17];
        args[0] = page_address(addr);

        checked_hvc64_expect_zero(VENDOR_HYP_GZVM_MMIO_GUARD_MAP_FUNC_ID, args)
    }

    fn mmio_guard_unmap(&self, addr: usize) -> Result<()> {
        let mut args = [0u64; 17];
        args[0] = page_address(addr);

        checked_hvc64_expect_zero(VENDOR_HYP_GZVM_MMIO_GUARD_UNMAP_FUNC_ID, args)
    }

    fn mem_share(&self, base_ipa: u64) -> Result<()> {
        let mut args = [0u64; 17];
        args[0] = base_ipa;

        checked_hvc64_expect_zero(ARM_SMCCC_GZVM_FUNC_MEM_SHARE, args)
    }

    fn mem_unshare(&self, base_ipa: u64) -> Result<()> {
        let mut args = [0u64; 17];
        args[0] = base_ipa;

        checked_hvc64_expect_zero(ARM_SMCCC_GZVM_FUNC_MEM_UNSHARE, args)
    }

    fn memory_protection_granule(&self) -> Result<usize> {
        let args = [0u64; 17];
        let granule = checked_hvc64(ARM_SMCCC_GZVM_FUNC_HYP_MEMINFO, args)?;
        Ok(granule.try_into().unwrap())
    }

    fn has_cap(&self, cap: HypervisorCap) -> bool {
        Self::CAPABILITIES.contains(cap)
    }
}

fn mmio_guard_granule() -> Result<usize> {
    let args = [0u64; 17];

    let granule = checked_hvc64(VENDOR_HYP_GZVM_MMIO_GUARD_INFO_FUNC_ID, args)?;
    Ok(granule.try_into().unwrap())
}

fn mmio_guard_enroll() -> Result<()> {
    let args = [0u64; 17];
    match success_or_error_64(hvc64(VENDOR_HYP_GZVM_MMIO_GUARD_ENROLL_FUNC_ID, args)[0]) {
        Ok(_) => Ok(()),
        Err(GeniezoneError::NotSupported) => Err(Error::MmioGuardNotsupported),
        Err(GeniezoneError::NotRequired) => Err(Error::MmioGuardNotsupported),
        Err(e) => Err(Error::GeniezoneError(e, VENDOR_HYP_GZVM_MMIO_GUARD_ENROLL_FUNC_ID)),
    }
}

fn checked_hvc64_expect_zero(function: u32, args: [u64; 17]) -> Result<()> {
    success_or_error_64(hvc64(function, args)[0]).map_err(|e| Error::GeniezoneError(e, function))
}

fn checked_hvc64(function: u32, args: [u64; 17]) -> Result<u64> {
    positive_or_error_64(hvc64(function, args)[0]).map_err(|e| Error::GeniezoneError(e, function))
}
