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

//! Structs and functions relating to the descriptor data.

use crate::error::AvbIOError;
use crate::partition::PartitionName;
use crate::utils::{self, is_not_null, to_usize, usize_checked_add};
use crate::Digest;
use avb_bindgen::{
    avb_descriptor_validate_and_byteswap, avb_hash_descriptor_validate_and_byteswap, AvbDescriptor,
    AvbDescriptorTag, AvbHashDescriptor,
};
use core::{
    mem::{size_of, MaybeUninit},
    ops::Range,
    slice,
};

pub(super) enum Descriptor {
    Hash(HashDescriptor),
}

impl Descriptor {
    /// # Safety
    ///
    /// Behavior is undefined if any of the following conditions are violated:
    /// * The `descriptor` pointer must be non-null and point to a valid `AvbDescriptor`.
    pub(super) unsafe fn from_descriptor_ptr(
        descriptor: *const AvbDescriptor,
    ) -> utils::Result<Self> {
        // SAFETY: It is safe as the raw pointer `descriptor` is non-null and points to
        // a valid `AvbDescriptor`.
        let avb_descriptor =
            unsafe { get_valid_descriptor(descriptor, avb_descriptor_validate_and_byteswap)? };
        let len = usize_checked_add(
            size_of::<AvbDescriptor>(),
            to_usize(avb_descriptor.num_bytes_following)?,
        )?;
        // SAFETY: It is safe because the caller ensures that `descriptor` is a non-null pointer
        // pointing to a valid struct.
        let data = unsafe { slice::from_raw_parts(descriptor as *const u8, len) };
        match avb_descriptor.tag.try_into() {
            Ok(AvbDescriptorTag::AVB_DESCRIPTOR_TAG_HASH) => {
                // SAFETY: It is safe because the caller ensures that `descriptor` is a non-null
                // pointer pointing to a valid struct.
                let h = unsafe { HashDescriptorHeader::from_descriptor_ptr(descriptor)? };
                Ok(Self::Hash(HashDescriptor::new(&h, data)?))
            }
            _ => Err(AvbIOError::NoSuchValue),
        }
    }
}

struct HashDescriptorHeader(AvbHashDescriptor);

impl HashDescriptorHeader {
    /// # Safety
    ///
    /// Behavior is undefined if any of the following conditions are violated:
    /// * The `descriptor` pointer must be non-null and point to a valid `AvbDescriptor`.
    unsafe fn from_descriptor_ptr(descriptor: *const AvbDescriptor) -> utils::Result<Self> {
        // SAFETY: It is safe as the raw pointer `descriptor` is non-null and points to
        // a valid `AvbDescriptor`.
        unsafe {
            get_valid_descriptor(
                descriptor as *const AvbHashDescriptor,
                avb_hash_descriptor_validate_and_byteswap,
            )
            .map(Self)
        }
    }

    fn partition_name_end(&self) -> utils::Result<usize> {
        usize_checked_add(size_of::<AvbHashDescriptor>(), to_usize(self.0.partition_name_len)?)
    }

    fn partition_name_range(&self) -> utils::Result<Range<usize>> {
        let start = size_of::<AvbHashDescriptor>();
        Ok(start..(self.partition_name_end()?))
    }

    fn digest_range(&self) -> utils::Result<Range<usize>> {
        let start = usize_checked_add(self.partition_name_end()?, to_usize(self.0.salt_len)?)?;
        let end = usize_checked_add(start, to_usize(self.0.digest_len)?)?;
        Ok(start..end)
    }
}

/// # Safety
///
/// Behavior is undefined if any of the following conditions are violated:
/// * The `descriptor_ptr` pointer must be non-null and point to a valid `AvbDescriptor`.
unsafe fn get_valid_descriptor<T>(
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

#[derive(Default)]
pub(crate) struct HashDescriptor {
    pub(crate) partition_name: PartitionName,
    pub(crate) digest: Digest,
}

impl HashDescriptor {
    fn new(desc: &HashDescriptorHeader, data: &[u8]) -> utils::Result<Self> {
        let partition_name = data
            .get(desc.partition_name_range()?)
            .ok_or(AvbIOError::RangeOutsidePartition)?
            .try_into()?;
        let partition_digest =
            data.get(desc.digest_range()?).ok_or(AvbIOError::RangeOutsidePartition)?;
        let mut digest = [0u8; size_of::<Digest>()];
        digest.copy_from_slice(partition_digest);
        Ok(Self { partition_name, digest })
    }
}
