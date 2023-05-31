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
use aarch64_paging::idmap::IdMap;
use buddy_system_allocator::LockedHeap;
use core::slice;
use fdtpci::PciInfo;
use hyp::get_hypervisor;
use log::{debug, error, info};
use vmbase::{layout, main, memory::PageTable, power::reboot};

const SZ_1K: usize = 1024;
const SZ_4K: usize = 4 * SZ_1K;
const SZ_64K: usize = 64 * SZ_1K;
const SZ_1M: usize = 1024 * SZ_1K;
const SZ_1G: usize = 1024 * SZ_1M;

// Root level is given by the value of TCR_EL1.TG0 and TCR_EL1.T0SZ, set in
// entry.S. For 4KB granule and 39-bit VA, the root level is 1.
const PT_ROOT_LEVEL: usize = 1;
const PT_ASID: usize = 1;

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
    let mut page_table: PageTable = IdMap::new(PT_ASID, PT_ROOT_LEVEL).into();

    // The first 1 GiB of address space is used by crosvm for MMIO.
    page_table.map_device(&(0..SZ_1G))?;
    page_table.map_data(&layout::scratch_range())?;
    page_table.map_data(&layout::stack_range(40 * SZ_4K))?;
    page_table.map_code(&layout::text_range())?;
    page_table.map_rodata(&layout::rodata_range())?;

    // SAFETY: It is safe to activate the page table by setting `TTBR0_EL1` to point to
    // it as this is the first time we activate the page table.
    unsafe { page_table.activate() }
    info!("Activated kernel page table.");
    Ok(())
}

fn try_init_logger() -> Result<()> {
    match get_hypervisor().mmio_guard_init() {
        // pKVM blocks MMIO by default, we need to enable MMIO guard to support logging.
        Ok(()) => get_hypervisor().mmio_guard_map(vmbase::console::BASE_ADDRESS)?,
        // MMIO guard enroll is not supported in unprotected VM.
        Err(hyp::Error::MmioGuardNotsupported) => {}
        Err(e) => return Err(e.into()),
    };
    vmbase::logger::init(log::LevelFilter::Debug).map_err(|_| Error::LoggerInit)
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

/// Entry point for Rialto.
pub fn main(fdt_addr: u64, _a1: u64, _a2: u64, _a3: u64) {
    init_heap();
    if try_init_logger().is_err() {
        // Don't log anything if the logger initialization fails.
        reboot();
    }
    // SAFETY: `fdt_addr` is supposed to be a valid pointer and points to
    // a valid `Fdt`.
    match unsafe { try_main(fdt_addr as usize) } {
        Ok(()) => info!("Rialto ends successfully."),
        Err(e) => {
            error!("Rialto failed with {e}");
            reboot()
        }
    }
}

main!(main);
