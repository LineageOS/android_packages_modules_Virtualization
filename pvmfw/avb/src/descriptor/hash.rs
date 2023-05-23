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

//! Structs and functions relating to the hash descriptor.

use super::common::get_valid_descriptor;
use crate::error::AvbIOError;
use crate::partition::PartitionName;
use crate::utils::{self, to_usize, usize_checked_add};
use avb_bindgen::{
    avb_hash_descriptor_validate_and_byteswap, AvbDescriptor, AvbHashDescriptor,
    AVB_SHA256_DIGEST_SIZE,
};
use core::{mem::size_of, ops::Range};

/// Digest type for kernel and initrd.
pub type Digest = [u8; AVB_SHA256_DIGEST_SIZE as usize];

pub(crate) struct HashDescriptor<'a> {
    pub(crate) partition_name: PartitionName,
    pub(crate) digest: &'a Digest,
}

impl<'a> Default for HashDescriptor<'a> {
    fn default() -> Self {
        Self { partition_name: Default::default(), digest: &Self::EMPTY_DIGEST }
    }
}

impl<'a> HashDescriptor<'a> {
    const EMPTY_DIGEST: Digest = [0u8; AVB_SHA256_DIGEST_SIZE as usize];

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
        let h = unsafe { HashDescriptorHeader::from_descriptor_ptr(descriptor)? };
        let partition_name = data
            .get(h.partition_name_range()?)
            .ok_or(AvbIOError::RangeOutsidePartition)?
            .try_into()?;
        let digest = data
            .get(h.digest_range()?)
            .ok_or(AvbIOError::RangeOutsidePartition)?
            .try_into()
            .map_err(|_| AvbIOError::InvalidValueSize)?;
        Ok(Self { partition_name, digest })
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
