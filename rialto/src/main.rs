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
#![feature(default_alloc_error_handler)]

mod exceptions;

extern crate alloc;

use aarch64_paging::{
    idmap::IdMap,
    paging::{Attributes, MemoryRegion},
    AddressRangeError,
};
use buddy_system_allocator::LockedHeap;
use log::{debug, info};
use vmbase::main;

const SZ_1K: usize = 1024;
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

unsafe fn kimg_ptr(sym: &u8) -> *const u8 {
    sym as *const u8
}

unsafe fn kimg_addr(sym: &u8) -> usize {
    kimg_ptr(sym) as usize
}

unsafe fn kimg_region(begin: &u8, end: &u8) -> MemoryRegion {
    MemoryRegion::new(kimg_addr(begin), kimg_addr(end))
}

fn init_heap() {
    // SAFETY: Allocator set to otherwise unused, static memory.
    unsafe {
        HEAP_ALLOCATOR.lock().init(&mut HEAP as *mut u8 as usize, HEAP.len());
    }
    info!("Initialized heap.");
}

fn init_kernel_pgt(pgt: &mut IdMap) -> Result<(), AddressRangeError> {
    // The first 1 GiB of address space is used by crosvm for MMIO.
    let reg_dev = MemoryRegion::new(0, SZ_1G);
    // SAFETY: Taking addresses of kernel image sections to set up page table
    // mappings. Not taking ownerhip of the memory.
    let reg_text = unsafe { kimg_region(&text_begin, &text_end) };
    let reg_rodata = unsafe { kimg_region(&rodata_begin, &rodata_end) };
    let reg_data = unsafe { kimg_region(&data_begin, &boot_stack_end) };

    debug!("Preparing kernel page tables.");
    debug!("  dev:    {}-{}", reg_dev.start(), reg_dev.end());
    debug!("  text:   {}-{}", reg_text.start(), reg_text.end());
    debug!("  rodata: {}-{}", reg_rodata.start(), reg_rodata.end());
    debug!("  data:   {}-{}", reg_data.start(), reg_data.end());

    let prot_dev = Attributes::DEVICE_NGNRE | Attributes::EXECUTE_NEVER;
    let prot_rx = Attributes::NORMAL | Attributes::NON_GLOBAL | Attributes::READ_ONLY;
    let prot_ro = Attributes::NORMAL
        | Attributes::NON_GLOBAL
        | Attributes::READ_ONLY
        | Attributes::EXECUTE_NEVER;
    let prot_rw = Attributes::NORMAL | Attributes::NON_GLOBAL | Attributes::EXECUTE_NEVER;

    pgt.map_range(&reg_dev, prot_dev)?;
    pgt.map_range(&reg_text, prot_rx)?;
    pgt.map_range(&reg_rodata, prot_ro)?;
    pgt.map_range(&reg_data, prot_rw)?;

    info!("Finished preparing kernel page table.");
    Ok(())
}

fn activate_kernel_pgt(pgt: &mut IdMap) {
    pgt.activate();
    info!("Activated kernel page table.");
}

/// Entry point for Rialto.
pub fn main(_a0: u64, _a1: u64, _a2: u64, _a3: u64) {
    vmbase::logger::init(log::LevelFilter::Debug).unwrap();

    info!("Welcome to Rialto!");
    init_heap();

    let mut pgt = IdMap::new(PT_ASID, PT_ROOT_LEVEL);
    init_kernel_pgt(&mut pgt).unwrap();
    activate_kernel_pgt(&mut pgt);
}

extern "C" {
    static text_begin: u8;
    static text_end: u8;
    static rodata_begin: u8;
    static rodata_end: u8;
    static data_begin: u8;
    static boot_stack_end: u8;
}

main!(main);
