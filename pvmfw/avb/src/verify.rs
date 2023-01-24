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

//! This module handles the pvmfw payload verification.

use crate::error::{AvbIOError, AvbSlotVerifyError};
use crate::ops::{Ops, Payload};
use crate::partition::PartitionName;
use crate::utils::{is_not_null, to_usize, usize_checked_add, write};
use avb_bindgen::{
    avb_descriptor_foreach, avb_hash_descriptor_validate_and_byteswap, AvbDescriptor,
    AvbHashDescriptor, AvbVBMetaData,
};
use core::{
    ffi::{c_char, c_void},
    mem::{size_of, MaybeUninit},
    slice,
};

/// This enum corresponds to the `DebugLevel` in `VirtualMachineConfig`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DebugLevel {
    /// Not debuggable at all.
    None,
    /// Fully debuggable.
    Full,
}

extern "C" fn search_initrd_hash_descriptor(
    descriptor: *const AvbDescriptor,
    user_data: *mut c_void,
) -> bool {
    try_search_initrd_hash_descriptor(descriptor, user_data).is_ok()
}

fn try_search_initrd_hash_descriptor(
    descriptor: *const AvbDescriptor,
    user_data: *mut c_void,
) -> Result<(), AvbIOError> {
    let hash_desc = AvbHashDescriptorRef::try_from(descriptor)?;
    if matches!(
        hash_desc.partition_name()?.try_into(),
        Ok(PartitionName::InitrdDebug) | Ok(PartitionName::InitrdNormal),
    ) {
        write(user_data as *mut bool, true)?;
    }
    Ok(())
}

/// `hash_desc` only contains the metadata like fields length and flags of the descriptor.
/// The data itself is contained in `ptr`.
struct AvbHashDescriptorRef {
    hash_desc: AvbHashDescriptor,
    ptr: *const AvbDescriptor,
}

impl TryFrom<*const AvbDescriptor> for AvbHashDescriptorRef {
    type Error = AvbIOError;

    fn try_from(descriptor: *const AvbDescriptor) -> Result<Self, Self::Error> {
        is_not_null(descriptor)?;
        // SAFETY: It is safe as the raw pointer `descriptor` is a nonnull pointer and
        // we have validated that it is of hash descriptor type.
        let hash_desc = unsafe {
            let mut desc = MaybeUninit::uninit();
            if !avb_hash_descriptor_validate_and_byteswap(
                descriptor as *const AvbHashDescriptor,
                desc.as_mut_ptr(),
            ) {
                return Err(AvbIOError::Io);
            }
            desc.assume_init()
        };
        Ok(Self { hash_desc, ptr: descriptor })
    }
}

impl AvbHashDescriptorRef {
    fn check_is_in_range(&self, index: usize) -> Result<(), AvbIOError> {
        let parent_desc = self.hash_desc.parent_descriptor;
        let total_len = usize_checked_add(
            size_of::<AvbDescriptor>(),
            to_usize(parent_desc.num_bytes_following)?,
        )?;
        if index <= total_len {
            Ok(())
        } else {
            Err(AvbIOError::Io)
        }
    }

    /// Returns the non null-terminated partition name.
    fn partition_name(&self) -> Result<&[u8], AvbIOError> {
        let partition_name_offset = size_of::<AvbHashDescriptor>();
        let partition_name_len = to_usize(self.hash_desc.partition_name_len)?;
        self.check_is_in_range(usize_checked_add(partition_name_offset, partition_name_len)?)?;
        let desc = self.ptr as *const u8;
        // SAFETY: The descriptor has been validated as nonnull and the partition name is
        // contained within the image.
        unsafe { Ok(slice::from_raw_parts(desc.add(partition_name_offset), partition_name_len)) }
    }
}

fn verify_vbmeta_has_no_initrd_descriptor(
    vbmeta_image: &AvbVBMetaData,
) -> Result<(), AvbSlotVerifyError> {
    is_not_null(vbmeta_image.vbmeta_data).map_err(|_| AvbSlotVerifyError::Io)?;
    let mut has_unexpected_descriptor = false;
    // SAFETY: It is safe as the raw pointer `vbmeta_image.vbmeta_data` is a nonnull pointer.
    if !unsafe {
        avb_descriptor_foreach(
            vbmeta_image.vbmeta_data,
            vbmeta_image.vbmeta_size,
            Some(search_initrd_hash_descriptor),
            &mut has_unexpected_descriptor as *mut _ as *mut c_void,
        )
    } {
        return Err(AvbSlotVerifyError::InvalidMetadata);
    }
    if has_unexpected_descriptor {
        Err(AvbSlotVerifyError::InvalidMetadata)
    } else {
        Ok(())
    }
}

fn verify_vbmeta_is_from_kernel_partition(
    vbmeta_image: &AvbVBMetaData,
) -> Result<(), AvbSlotVerifyError> {
    match (vbmeta_image.partition_name as *const c_char).try_into() {
        Ok(PartitionName::Kernel) => Ok(()),
        _ => Err(AvbSlotVerifyError::InvalidMetadata),
    }
}

/// Verifies the payload (signed kernel + initrd) against the trusted public key.
pub fn verify_payload(
    kernel: &[u8],
    initrd: Option<&[u8]>,
    trusted_public_key: &[u8],
) -> Result<DebugLevel, AvbSlotVerifyError> {
    let mut payload = Payload::new(kernel, initrd, trusted_public_key);
    let mut ops = Ops::from(&mut payload);
    let kernel_verify_result = ops.verify_partition(PartitionName::Kernel.as_cstr())?;
    let vbmeta_images = kernel_verify_result.vbmeta_images()?;
    if vbmeta_images.len() != 1 {
        // There can only be one VBMeta.
        return Err(AvbSlotVerifyError::InvalidMetadata);
    }
    let vbmeta_image = vbmeta_images[0];
    verify_vbmeta_is_from_kernel_partition(&vbmeta_image)?;
    if initrd.is_none() {
        verify_vbmeta_has_no_initrd_descriptor(&vbmeta_image)?;
        return Ok(DebugLevel::None);
    }
    // TODO(b/256148034): Check the vbmeta doesn't have hash descriptors other than
    // boot, initrd_normal, initrd_debug.

    let debug_level = if ops.verify_partition(PartitionName::InitrdNormal.as_cstr()).is_ok() {
        DebugLevel::None
    } else if ops.verify_partition(PartitionName::InitrdDebug.as_cstr()).is_ok() {
        DebugLevel::Full
    } else {
        return Err(AvbSlotVerifyError::Verification);
    };
    Ok(debug_level)
}
