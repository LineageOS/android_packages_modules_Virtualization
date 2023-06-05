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
use core::ops::Range;
use vmbase::memory::SIZE_4KB;
use vmbase::read_sysreg;
use vmbase::util::unchecked_align_down;
use zeroize::Zeroize;

pub const GUEST_PAGE_SIZE: usize = SIZE_4KB;
pub const PVMFW_PAGE_SIZE: usize = SIZE_4KB;

#[inline]
/// Read the number of words in the smallest cache line of all the data caches and unified caches.
pub fn min_dcache_line_size() -> usize {
    const DMINLINE_SHIFT: usize = 16;
    const DMINLINE_MASK: usize = 0xf;
    let ctr_el0 = read_sysreg!("ctr_el0");

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
        unsafe {
            asm!(
                "dc cvau, {x}",
                x = in(reg) line,
                options(nomem, nostack, preserves_flags),
            )
        }
    }
}

#[inline]
/// Flushes the slice to the point of unification.
pub fn flush(reg: &[u8]) {
    flush_region(reg.as_ptr() as usize, reg.len())
}

#[inline]
/// Overwrites the slice with zeroes, to the point of unification.
pub fn flushed_zeroize(reg: &mut [u8]) {
    reg.zeroize();
    flush(reg)
}

/// Trait to check containment of one range within another.
pub(crate) trait RangeExt {
    /// Returns true if `self` is contained within the `other` range.
    fn is_within(&self, other: &Self) -> bool;
}

impl<T: PartialOrd> RangeExt for Range<T> {
    fn is_within(&self, other: &Self) -> bool {
        self.start >= other.start && self.end <= other.end
    }
}

/// Create &CStr out of &str literal
#[macro_export]
macro_rules! cstr {
    ($str:literal) => {{
        core::ffi::CStr::from_bytes_with_nul(concat!($str, "\0").as_bytes()).unwrap()
    }};
}
