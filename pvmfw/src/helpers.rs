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

//! Miscellaneous helper functions.

use core::arch::asm;
use zeroize::Zeroize;

pub const SIZE_4KB: usize = 4 << 10;
pub const SIZE_2MB: usize = 2 << 20;

/// Computes the largest multiple of the provided alignment smaller or equal to the address.
///
/// Note: the result is undefined if alignment isn't a power of two.
pub const fn unchecked_align_down(addr: usize, alignment: usize) -> usize {
    addr & !(alignment - 1)
}

/// Computes the smallest multiple of the provided alignment larger or equal to the address.
///
/// Note: the result is undefined if alignment isn't a power of two and may wrap to 0.
pub const fn unchecked_align_up(addr: usize, alignment: usize) -> usize {
    unchecked_align_down(addr + alignment - 1, alignment)
}

/// Safe wrapper around unchecked_align_up() that validates its assumptions and doesn't wrap.
pub const fn align_up(addr: usize, alignment: usize) -> Option<usize> {
    if !alignment.is_power_of_two() {
        None
    } else if let Some(s) = addr.checked_add(alignment - 1) {
        Some(unchecked_align_down(s, alignment))
    } else {
        None
    }
}

/// Computes the address of the 4KiB page containing a given address.
pub const fn page_4kb_of(addr: usize) -> usize {
    unchecked_align_down(addr, SIZE_4KB)
}

#[inline]
fn min_dcache_line_size() -> usize {
    const DMINLINE_SHIFT: usize = 16;
    const DMINLINE_MASK: usize = 0xf;
    let ctr_el0: usize;

    unsafe { asm!("mrs {x}, ctr_el0", x = out(reg) ctr_el0) }

    // DminLine: log2 of the number of words in the smallest cache line of all the data caches.
    let dminline = (ctr_el0 >> DMINLINE_SHIFT) & DMINLINE_MASK;

    1 << dminline
}

/// Flush `size` bytes of data cache by virtual address.
#[inline]
pub fn flush_region(start: usize, size: usize) {
    let line_size = min_dcache_line_size();
    let end = start + size;
    let start = unchecked_align_down(start, line_size);

    for line in (start..end).step_by(line_size) {
        // SAFETY - Clearing cache lines shouldn't have Rust-visible side effects.
        unsafe { asm!("dc cvau, {x}", x = in(reg) line) }
    }
}

#[inline]
/// Overwrites the slice with zeroes, to the point of unification.
pub fn flushed_zeroize(reg: &mut [u8]) {
    reg.zeroize();
    flush_region(reg.as_ptr() as usize, reg.len())
}
