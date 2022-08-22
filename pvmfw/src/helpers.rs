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

/// Computes the address of the page containing a given address.
pub const fn page_of(addr: u64, page_size: u64) -> u64 {
    addr & !(page_size - 1)
}

/// Validates a page size and computes the address of the page containing a given address.
pub const fn checked_page_of(addr: u64, page_size: u64) -> Option<u64> {
    if page_size.is_power_of_two() {
        Some(page_of(addr, page_size))
    } else {
        None
    }
}

/// Computes the address of the 4KiB page containing a given address.
pub const fn page_4kb_of(addr: u64) -> u64 {
    const PAGE_SIZE: u64 = 4 << 10;

    page_of(addr, PAGE_SIZE)
}
