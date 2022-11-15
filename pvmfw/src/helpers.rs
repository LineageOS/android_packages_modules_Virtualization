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

pub const SIZE_4KB: usize = 4 << 10;
pub const SIZE_2MB: usize = 2 << 20;

/// Computes the largest multiple of the provided alignment smaller or equal to the address.
///
/// Note: the result is undefined if alignment isn't a power of two.
pub const fn unchecked_align_down(addr: usize, alignment: usize) -> usize {
    addr & !(alignment - 1)
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
