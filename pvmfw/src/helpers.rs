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

use core::ops::Range;
use vmbase::memory::{PAGE_SIZE, SIZE_4KB};

pub const GUEST_PAGE_SIZE: usize = SIZE_4KB;
pub const PVMFW_PAGE_SIZE: usize = PAGE_SIZE;

/// Trait to check containment of one range within another.
pub(crate) trait RangeExt {
    /// Returns true if `self` is contained within the `other` range.
    fn is_within(&self, other: &Self) -> bool;

    /// Returns true if `self` overlaps with the `other` range.
    fn overlaps(&self, other: &Self) -> bool;
}

impl<T: PartialOrd> RangeExt for Range<T> {
    fn is_within(&self, other: &Self) -> bool {
        self.start >= other.start && self.end <= other.end
    }

    fn overlaps(&self, other: &Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

/// Create &CStr out of &str literal
#[macro_export]
macro_rules! cstr {
    ($str:literal) => {{
        core::ffi::CStr::from_bytes_with_nul(concat!($str, "\0").as_bytes()).unwrap()
    }};
}
