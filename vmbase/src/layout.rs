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

use crate::linker;
use core::ops::Range;
use core::ptr::addr_of;

/// Memory reserved for the DTB.
pub fn dtb_range() -> Range<usize> {
    unsafe { (addr_of!(linker::dtb_begin) as usize)..(addr_of!(linker::dtb_end) as usize) }
}

/// Executable code.
pub fn text_range() -> Range<usize> {
    unsafe { (addr_of!(linker::text_begin) as usize)..(addr_of!(linker::text_end) as usize) }
}

/// Read-only data.
pub fn rodata_range() -> Range<usize> {
    unsafe { (addr_of!(linker::rodata_begin) as usize)..(addr_of!(linker::rodata_end) as usize) }
}

/// Initialised writable data.
pub fn data_range() -> Range<usize> {
    unsafe { (addr_of!(linker::data_begin) as usize)..(addr_of!(linker::data_end) as usize) }
}

/// Zero-initialised writable data.
pub fn bss_range() -> Range<usize> {
    unsafe { (addr_of!(linker::bss_begin) as usize)..(addr_of!(linker::bss_end) as usize) }
}

/// Writable data region for the stack.
pub fn boot_stack_range() -> Range<usize> {
    unsafe {
        (addr_of!(linker::boot_stack_begin) as usize)..(addr_of!(linker::boot_stack_end) as usize)
    }
}

/// Writable data, including the stack.
pub fn writable_region() -> Range<usize> {
    data_range().start..boot_stack_range().end
}

/// Read-write data (original).
pub fn data_load_address() -> usize {
    unsafe { addr_of!(linker::data_lma) as usize }
}

/// End of the binary image.
pub fn binary_end() -> usize {
    unsafe { addr_of!(linker::bin_end) as usize }
}
