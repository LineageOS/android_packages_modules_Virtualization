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

//! Memory layout.

use aarch64_paging::paging::{MemoryRegion, VirtualAddress};
use core::arch::asm;
use core::ops::Range;
use vmbase::println;

/// The first 1 GiB of memory are used for MMIO.
pub const DEVICE_REGION: MemoryRegion = MemoryRegion::new(0, 0x40000000);

/// Memory reserved for the DTB.
pub fn dtb_range() -> Range<VirtualAddress> {
    unsafe {
        VirtualAddress(&dtb_begin as *const u8 as usize)
            ..VirtualAddress(&dtb_end as *const u8 as usize)
    }
}

/// Executable code.
pub fn text_range() -> Range<VirtualAddress> {
    unsafe {
        VirtualAddress(&text_begin as *const u8 as usize)
            ..VirtualAddress(&text_end as *const u8 as usize)
    }
}

/// Read-only data.
pub fn rodata_range() -> Range<VirtualAddress> {
    unsafe {
        VirtualAddress(&rodata_begin as *const u8 as usize)
            ..VirtualAddress(&rodata_end as *const u8 as usize)
    }
}

/// Initialised writable data.
pub fn data_range() -> Range<VirtualAddress> {
    unsafe {
        VirtualAddress(&data_begin as *const u8 as usize)
            ..VirtualAddress(&data_end as *const u8 as usize)
    }
}

/// Zero-initialised writable data.
pub fn bss_range() -> Range<VirtualAddress> {
    unsafe {
        VirtualAddress(&bss_begin as *const u8 as usize)
            ..VirtualAddress(&bss_end as *const u8 as usize)
    }
}

/// Writable data region for the stack.
pub fn boot_stack_range() -> Range<VirtualAddress> {
    unsafe {
        VirtualAddress(&boot_stack_begin as *const u8 as usize)
            ..VirtualAddress(&boot_stack_end as *const u8 as usize)
    }
}

/// Writable data, including the stack.
pub fn writable_region() -> MemoryRegion {
    unsafe {
        MemoryRegion::new(&data_begin as *const u8 as usize, &boot_stack_end as *const u8 as usize)
    }
}

fn data_load_address() -> VirtualAddress {
    unsafe { VirtualAddress(&data_lma as *const u8 as usize) }
}

fn binary_end() -> VirtualAddress {
    unsafe { VirtualAddress(&bin_end as *const u8 as usize) }
}

pub fn print_addresses() {
    let dtb = dtb_range();
    println!("dtb:        {}..{} ({} bytes)", dtb.start, dtb.end, dtb.end - dtb.start);
    let text = text_range();
    println!("text:       {}..{} ({} bytes)", text.start, text.end, text.end - text.start);
    let rodata = rodata_range();
    println!("rodata:     {}..{} ({} bytes)", rodata.start, rodata.end, rodata.end - rodata.start);
    println!("binary end: {}", binary_end());
    let data = data_range();
    println!(
        "data:       {}..{} ({} bytes, loaded at {})",
        data.start,
        data.end,
        data.end - data.start,
        data_load_address(),
    );
    let bss = bss_range();
    println!("bss:        {}..{} ({} bytes)", bss.start, bss.end, bss.end - bss.start);
    let boot_stack = boot_stack_range();
    println!(
        "boot_stack: {}..{} ({} bytes)",
        boot_stack.start,
        boot_stack.end,
        boot_stack.end - boot_stack.start
    );
}

/// Bionic-compatible thread-local storage entry, at the given offset from TPIDR_EL0.
pub fn bionic_tls(off: usize) -> u64 {
    let mut base: usize;
    unsafe {
        asm!("mrs {base}, tpidr_el0", base = out(reg) base);
        let ptr = (base + off) as *const u64;
        *ptr
    }
}

/// Value of __stack_chk_guard.
pub fn stack_chk_guard() -> u64 {
    unsafe { __stack_chk_guard }
}

extern "C" {
    static dtb_begin: u8;
    static dtb_end: u8;
    static text_begin: u8;
    static text_end: u8;
    static rodata_begin: u8;
    static rodata_end: u8;
    static data_begin: u8;
    static data_end: u8;
    static data_lma: u8;
    static bin_end: u8;
    static bss_begin: u8;
    static bss_end: u8;
    static boot_stack_begin: u8;
    static boot_stack_end: u8;
    static __stack_chk_guard: u64;
}
