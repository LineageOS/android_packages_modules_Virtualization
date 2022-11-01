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
use vmbase::layout;
use vmbase::println;
use vmbase::STACK_CHK_GUARD;

/// The first 1 GiB of memory are used for MMIO.
pub const DEVICE_REGION: MemoryRegion = MemoryRegion::new(0, 0x40000000);

fn into_va_range(r: Range<usize>) -> Range<VirtualAddress> {
    VirtualAddress(r.start)..VirtualAddress(r.end)
}

/// Memory reserved for the DTB.
pub fn dtb_range() -> Range<VirtualAddress> {
    into_va_range(layout::dtb_range())
}

/// Executable code.
pub fn text_range() -> Range<VirtualAddress> {
    into_va_range(layout::text_range())
}

/// Read-only data.
pub fn rodata_range() -> Range<VirtualAddress> {
    into_va_range(layout::rodata_range())
}

/// Initialised writable data.
pub fn data_range() -> Range<VirtualAddress> {
    into_va_range(layout::data_range())
}

/// Zero-initialised writable data.
pub fn bss_range() -> Range<VirtualAddress> {
    into_va_range(layout::bss_range())
}

/// Writable data region for the stack.
pub fn boot_stack_range() -> Range<VirtualAddress> {
    into_va_range(layout::boot_stack_range())
}

/// Writable data, including the stack.
pub fn writable_region() -> MemoryRegion {
    let r = layout::writable_region();
    MemoryRegion::new(r.start, r.end)
}

fn data_load_address() -> VirtualAddress {
    VirtualAddress(layout::data_load_address())
}

fn binary_end() -> VirtualAddress {
    VirtualAddress(layout::binary_end())
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
    *STACK_CHK_GUARD
}
