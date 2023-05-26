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

//! Structs and functions relating to the property descriptor.

use super::common::get_valid_descriptor;
use crate::error::AvbIOError;
use crate::utils::{self, to_usize, usize_checked_add};
use avb_bindgen::{
    avb_property_descriptor_validate_and_byteswap, AvbDescriptor, AvbPropertyDescriptor,
};
use core::mem::size_of;

pub(super) struct PropertyDescriptor<'a> {
    pub(super) key: &'a [u8],
    pub(super) value: &'a [u8],
}

impl<'a> PropertyDescriptor<'a> {
    /// # Safety
    ///
    /// Behavior is undefined if any of the following conditions are violated:
    /// * The `descriptor` pointer must be non-null and point to a valid `AvbDescriptor`.
    pub(super) unsafe fn from_descriptor_ptr(
        descriptor: *const AvbDescriptor,
        data: &'a [u8],
    ) -> utils::Result<Self> {
        // SAFETY: It is safe as the raw pointer `descriptor` is non-null and points to
        // a valid `AvbDescriptor`.
        let h = unsafe { PropertyDescriptorHeader::from_descriptor_ptr(descriptor)? };
        let key = Self::get_valid_slice(data, h.key_start(), h.key_end()?)?;
        let value = Self::get_valid_slice(data, h.value_start()?, h.value_end()?)?;
        Ok(Self { key, value })
    }

    fn get_valid_slice(data: &[u8], start: usize, end: usize) -> utils::Result<&[u8]> {
        const NUL_BYTE: u8 = b'\0';

        match data.get(end) {
            Some(&NUL_BYTE) => data.get(start..end).ok_or(AvbIOError::RangeOutsidePartition),
            _ => Err(AvbIOError::NoSuchValue),
        }
    }
}

struct PropertyDescriptorHeader(AvbPropertyDescriptor);

impl PropertyDescriptorHeader {
    /// # Safety
    ///
    /// Behavior is undefined if any of the following conditions are violated:
    /// * The `descriptor` pointer must be non-null and point to a valid `AvbDescriptor`.
    unsafe fn from_descriptor_ptr(descriptor: *const AvbDescriptor) -> utils::Result<Self> {
        // SAFETY: It is safe as the raw pointer `descriptor` is non-null and points to
        // a valid `AvbDescriptor`.
        unsafe {
            get_valid_descriptor(
                descriptor as *const AvbPropertyDescriptor,
                avb_property_descriptor_validate_and_byteswap,
            )
            .map(Self)
        }
    }

    fn key_start(&self) -> usize {
        size_of::<AvbPropertyDescriptor>()
    }

    fn key_end(&self) -> utils::Result<usize> {
        usize_checked_add(self.key_start(), to_usize(self.0.key_num_bytes)?)
    }

    fn value_start(&self) -> utils::Result<usize> {
        // There is a NUL byte between key and value.
        usize_checked_add(self.key_end()?, 1)
    }

    fn value_end(&self) -> utils::Result<usize> {
        usize_checked_add(self.value_start()?, to_usize(self.0.value_num_bytes)?)
    }
}
