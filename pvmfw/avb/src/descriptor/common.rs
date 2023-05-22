// Copyright 2023, The Android Open Source Project
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

//! Structs and functions used by all the descriptors.

use crate::error::AvbIOError;
use crate::utils::{self, is_not_null};
use core::mem::MaybeUninit;

/// # Safety
///
/// Behavior is undefined if any of the following conditions are violated:
/// * The `descriptor_ptr` pointer must be non-null and point to a valid `AvbDescriptor`.
pub(super) unsafe fn get_valid_descriptor<T>(
    descriptor_ptr: *const T,
    descriptor_validate_and_byteswap: unsafe extern "C" fn(src: *const T, dest: *mut T) -> bool,
) -> utils::Result<T> {
    is_not_null(descriptor_ptr)?;
    // SAFETY: It is safe because the caller ensures that `descriptor_ptr` is a non-null pointer
    // pointing to a valid struct.
    let descriptor = unsafe {
        let mut desc = MaybeUninit::uninit();
        if !descriptor_validate_and_byteswap(descriptor_ptr, desc.as_mut_ptr()) {
            return Err(AvbIOError::Io);
        }
        desc.assume_init()
    };
    Ok(descriptor)
}
