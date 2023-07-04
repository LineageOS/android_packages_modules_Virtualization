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

//! Project Rialto main source file.

#![no_main]
#![no_std]

mod error;
mod exceptions;

extern crate alloc;

use crate::error::{Error, Result};
use core::num::NonZeroUsize;
use core::result;
use core::slice;
use fdtpci::PciInfo;
use hyp::{get_hypervisor, HypervisorCap, KvmError};
use libfdt::FdtError;
use log::{debug, error, info};
use vmbase::{
    configure_heap,
    fdt::SwiotlbInfo,
    layout::{self, crosvm},
    main,
    memory::{MemoryTracker, PageTable, MEMORY, PAGE_SIZE, SIZE_64KB},
    power::reboot,
    virtio::pci,
};

fn new_page_table() -> Result<PageTable> {
    let mut page_table = PageTable::default();

    page_table.map_data(&layout::scratch_range())?;
    page_table.map_data(&layout::stack_range(40 * PAGE_SIZE))?;
    page_table.map_code(&layout::text_range())?;
    page_table.map_rodata(&layout::rodata_range())?;
    page_table.map_device(&layout::console_uart_range())?;

    Ok(page_table)
}

fn try_init_logger() -> Result<bool> {
    let mmio_guard_supported = match get_hypervisor().mmio_guard_init() {
        // pKVM blocks MMIO by default, we need to enable MMIO guard to support logging.
        Ok(()) => {
            get_hypervisor().mmio_guard_map(vmbase::console::BASE_ADDRESS)?;
            true
        }
        // MMIO guard enroll is not supported in unprotected VM.
        Err(hyp::Error::MmioGuardNotsupported) => false,
        Err(e) => return Err(e.into()),
    };
    vmbase::logger::init(log::LevelFilter::Debug).map_err(|_| Error::LoggerInit)?;
    Ok(mmio_guard_supported)
}

/// # Safety
///
/// Behavior is undefined if any of the following conditions are violated:
/// * The `fdt_addr` must be a valid pointer and points to a valid `Fdt`.
unsafe fn try_main(fdt_addr: usize) -> Result<()> {
    info!("Welcome to Rialto!");
    let page_table = new_page_table()?;

    MEMORY.lock().replace(MemoryTracker::new(
        page_table,
        crosvm::MEM_START..layout::MAX_VIRT_ADDR,
        crosvm::MMIO_RANGE,
        None, // Rialto doesn't have any payload for now.
    ));

    let fdt_range = MEMORY
        .lock()
        .as_mut()
        .unwrap()
        .alloc(fdt_addr, NonZeroUsize::new(crosvm::FDT_MAX_SIZE).unwrap())?;
    // SAFETY: The tracker validated the range to be in main memory, mapped, and not overlap.
    let fdt = unsafe { slice::from_raw_parts(fdt_range.start as *mut u8, fdt_range.len()) };
    // We do not need to validate the DT since it is already validated in pvmfw.
    let fdt = libfdt::Fdt::from_slice(fdt)?;

    let memory_range = fdt.first_memory_range()?;
    MEMORY.lock().as_mut().unwrap().shrink(&memory_range).map_err(|e| {
        error!("Failed to use memory range value from DT: {memory_range:#x?}");
        e
    })?;

    if get_hypervisor().has_cap(HypervisorCap::DYNAMIC_MEM_SHARE) {
        let granule = memory_protection_granule()?;
        MEMORY.lock().as_mut().unwrap().init_dynamic_shared_pool(granule).map_err(|e| {
            error!("Failed to initialize dynamically shared pool.");
            e
        })?;
    } else {
        let range = SwiotlbInfo::new_from_fdt(fdt)?.fixed_range().ok_or_else(|| {
            error!("Pre-shared pool range not specified in swiotlb node");
            Error::from(FdtError::BadValue)
        })?;
        MEMORY.lock().as_mut().unwrap().init_static_shared_pool(range).map_err(|e| {
            error!("Failed to initialize pre-shared pool.");
            e
        })?;
    }

    let pci_info = PciInfo::from_fdt(fdt)?;
    debug!("PCI: {pci_info:#x?}");
    let pci_root = pci::initialise(pci_info, MEMORY.lock().as_mut().unwrap())
        .map_err(Error::PciInitializationFailed)?;
    debug!("PCI root: {pci_root:#x?}");
    Ok(())
}

fn memory_protection_granule() -> result::Result<usize, hyp::Error> {
    match get_hypervisor().memory_protection_granule() {
        Ok(granule) => Ok(granule),
        // Take the default page size when KVM call is not supported in non-protected VMs.
        Err(hyp::Error::KvmError(KvmError::NotSupported, _)) => Ok(PAGE_SIZE),
        Err(e) => Err(e),
    }
}

fn try_unshare_all_memory(mmio_guard_supported: bool) -> Result<()> {
    info!("Starting unsharing memory...");

    // No logging after unmapping UART.
    if mmio_guard_supported {
        get_hypervisor().mmio_guard_unmap(vmbase::console::BASE_ADDRESS)?;
    }
    // Unshares all memory and deactivates page table.
    drop(MEMORY.lock().take());
    Ok(())
}

fn unshare_all_memory(mmio_guard_supported: bool) {
    if let Err(e) = try_unshare_all_memory(mmio_guard_supported) {
        error!("Failed to unshare the memory: {e}");
    }
}

/// Entry point for Rialto.
pub fn main(fdt_addr: u64, _a1: u64, _a2: u64, _a3: u64) {
    let Ok(mmio_guard_supported) = try_init_logger() else {
        // Don't log anything if the logger initialization fails.
        reboot();
    };
    // SAFETY: `fdt_addr` is supposed to be a valid pointer and points to
    // a valid `Fdt`.
    match unsafe { try_main(fdt_addr as usize) } {
        Ok(()) => unshare_all_memory(mmio_guard_supported),
        Err(e) => {
            error!("Rialto failed with {e}");
            unshare_all_memory(mmio_guard_supported);
            reboot()
        }
    }
}

main!(main);
configure_heap!(SIZE_64KB);
