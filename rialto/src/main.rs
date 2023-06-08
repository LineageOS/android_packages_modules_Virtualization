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
use buddy_system_allocator::LockedHeap;
use core::slice;
use fdtpci::PciInfo;
use hyp::get_hypervisor;
use log::{debug, error, info};
use vmbase::{
    layout, main,
    memory::{PageTable, PAGE_SIZE},
    power::reboot,
};

const SZ_1K: usize = 1024;
const SZ_64K: usize = 64 * SZ_1K;
const SZ_1M: usize = 1024 * SZ_1K;
const SZ_1G: usize = 1024 * SZ_1M;

#[global_allocator]
static HEAP_ALLOCATOR: LockedHeap<32> = LockedHeap::<32>::new();

static mut HEAP: [u8; SZ_64K] = [0; SZ_64K];

fn init_heap() {
    // SAFETY: Allocator set to otherwise unused, static memory.
    unsafe {
        HEAP_ALLOCATOR.lock().init(&mut HEAP as *mut u8 as usize, HEAP.len());
    }
}

fn init_page_table() -> Result<()> {
    let mut page_table = PageTable::default();

    // The first 1 GiB of address space is used by crosvm for MMIO.
    page_table.map_device(&(0..SZ_1G))?;
    page_table.map_data(&layout::scratch_range())?;
    page_table.map_data(&layout::stack_range(40 * PAGE_SIZE))?;
    page_table.map_code(&layout::text_range())?;
    page_table.map_rodata(&layout::rodata_range())?;
    page_table.map_device(&layout::console_uart_range())?;

    // SAFETY: It is safe to activate the page table by setting `TTBR0_EL1` to point to
    // it as this is the first time we activate the page table.
    unsafe { page_table.activate() }
    info!("Activated kernel page table.");
    Ok(())
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
    // SAFETY: The caller ensures that `fdt_addr` is valid.
    let fdt = unsafe { slice::from_raw_parts(fdt_addr as *mut u8, SZ_1M) };
    let fdt = libfdt::Fdt::from_slice(fdt)?;
    let pci_info = PciInfo::from_fdt(fdt)?;
    debug!("PCI: {:#x?}", pci_info);

    init_page_table()?;
    Ok(())
}

fn try_unshare_all_memory(mmio_guard_supported: bool) -> Result<()> {
    if !mmio_guard_supported {
        return Ok(());
    }
    info!("Starting unsharing memory...");

    // TODO(b/284462758): Unshare all the memory here.

    // No logging after unmapping UART.
    get_hypervisor().mmio_guard_unmap(vmbase::console::BASE_ADDRESS)?;
    Ok(())
}

fn unshare_all_memory(mmio_guard_supported: bool) {
    if let Err(e) = try_unshare_all_memory(mmio_guard_supported) {
        error!("Failed to unshare the memory: {e}");
    }
}

/// Entry point for Rialto.
pub fn main(fdt_addr: u64, _a1: u64, _a2: u64, _a3: u64) {
    init_heap();
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
