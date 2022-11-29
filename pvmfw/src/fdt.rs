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

//! High-level FDT functions.

use core::ffi::CStr;
use core::ops::Range;

/// Extract from /chosen the address range containing the pre-loaded ramdisk.
pub fn initrd_range(fdt: &libfdt::Fdt) -> libfdt::Result<Option<Range<usize>>> {
    let start = CStr::from_bytes_with_nul(b"linux,initrd-start\0").unwrap();
    let end = CStr::from_bytes_with_nul(b"linux,initrd-end\0").unwrap();

    if let Some(chosen) = fdt.chosen()? {
        if let (Some(start), Some(end)) = (chosen.getprop_u32(start)?, chosen.getprop_u32(end)?) {
            return Ok(Some((start as usize)..(end as usize)));
        }
    }

    Ok(None)
}
