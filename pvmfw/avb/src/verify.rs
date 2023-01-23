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

use crate::error::{
    slot_verify_result_to_verify_payload_result, to_avb_io_result, AvbIOError, AvbSlotVerifyError,
};
use crate::partition::PartitionName;
use crate::utils::{as_ref, is_not_null, to_nonnull, to_usize, usize_checked_add, write};
use avb_bindgen::{
    avb_descriptor_foreach, avb_hash_descriptor_validate_and_byteswap, avb_slot_verify,
    avb_slot_verify_data_free, AvbDescriptor, AvbHashDescriptor, AvbHashtreeErrorMode, AvbIOResult,
    AvbOps, AvbSlotVerifyData, AvbSlotVerifyFlags, AvbVBMetaData,
};
use core::{
    ffi::{c_char, c_void, CStr},
    mem::{size_of, MaybeUninit},
    ptr, slice,
};

const NULL_BYTE: &[u8] = b"\0";

/// This enum corresponds to the `DebugLevel` in `VirtualMachineConfig`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DebugLevel {
    /// Not debuggable at all.
    None,
    /// Fully debuggable.
    Full,
}

extern "C" fn read_is_device_unlocked(
    _ops: *mut AvbOps,
    out_is_unlocked: *mut bool,
) -> AvbIOResult {
    to_avb_io_result(write(out_is_unlocked, false))
}

extern "C" fn get_preloaded_partition(
    ops: *mut AvbOps,
    partition: *const c_char,
    num_bytes: usize,
    out_pointer: *mut *mut u8,
    out_num_bytes_preloaded: *mut usize,
) -> AvbIOResult {
    to_avb_io_result(try_get_preloaded_partition(
        ops,
        partition,
        num_bytes,
        out_pointer,
        out_num_bytes_preloaded,
    ))
}

fn try_get_preloaded_partition(
    ops: *mut AvbOps,
    partition: *const c_char,
    num_bytes: usize,
    out_pointer: *mut *mut u8,
    out_num_bytes_preloaded: *mut usize,
) -> Result<(), AvbIOError> {
    let ops = as_ref(ops)?;
    let partition = ops.as_ref().get_partition(partition)?;
    write(out_pointer, partition.as_ptr() as *mut u8)?;
    write(out_num_bytes_preloaded, partition.len().min(num_bytes))
}

extern "C" fn read_from_partition(
    ops: *mut AvbOps,
    partition: *const c_char,
    offset: i64,
    num_bytes: usize,
    buffer: *mut c_void,
    out_num_read: *mut usize,
) -> AvbIOResult {
    to_avb_io_result(try_read_from_partition(
        ops,
        partition,
        offset,
        num_bytes,
        buffer,
        out_num_read,
    ))
}

fn try_read_from_partition(
    ops: *mut AvbOps,
    partition: *const c_char,
    offset: i64,
    num_bytes: usize,
    buffer: *mut c_void,
    out_num_read: *mut usize,
) -> Result<(), AvbIOError> {
    let ops = as_ref(ops)?;
    let partition = ops.as_ref().get_partition(partition)?;
    let buffer = to_nonnull(buffer)?;
    // SAFETY: It is safe to copy the requested number of bytes to `buffer` as `buffer`
    // is created to point to the `num_bytes` of bytes in memory.
    let buffer_slice = unsafe { slice::from_raw_parts_mut(buffer.as_ptr() as *mut u8, num_bytes) };
    copy_data_to_dst(partition, offset, buffer_slice)?;
    write(out_num_read, buffer_slice.len())
}

fn copy_data_to_dst(src: &[u8], offset: i64, dst: &mut [u8]) -> Result<(), AvbIOError> {
    let start = to_copy_start(offset, src.len()).ok_or(AvbIOError::InvalidValueSize)?;
    let end = start.checked_add(dst.len()).ok_or(AvbIOError::InvalidValueSize)?;
    dst.copy_from_slice(src.get(start..end).ok_or(AvbIOError::RangeOutsidePartition)?);
    Ok(())
}

fn to_copy_start(offset: i64, len: usize) -> Option<usize> {
    usize::try_from(offset)
        .ok()
        .or_else(|| isize::try_from(offset).ok().and_then(|v| len.checked_add_signed(v)))
}

extern "C" fn get_size_of_partition(
    ops: *mut AvbOps,
    partition: *const c_char,
    out_size_num_bytes: *mut u64,
) -> AvbIOResult {
    to_avb_io_result(try_get_size_of_partition(ops, partition, out_size_num_bytes))
}

fn try_get_size_of_partition(
    ops: *mut AvbOps,
    partition: *const c_char,
    out_size_num_bytes: *mut u64,
) -> Result<(), AvbIOError> {
    let ops = as_ref(ops)?;
    let partition = ops.as_ref().get_partition(partition)?;
    let partition_size =
        u64::try_from(partition.len()).map_err(|_| AvbIOError::InvalidValueSize)?;
    write(out_size_num_bytes, partition_size)
}

extern "C" fn read_rollback_index(
    _ops: *mut AvbOps,
    _rollback_index_location: usize,
    _out_rollback_index: *mut u64,
) -> AvbIOResult {
    // Rollback protection is not yet implemented, but
    // this method is required by `avb_slot_verify()`.
    AvbIOResult::AVB_IO_RESULT_OK
}

extern "C" fn get_unique_guid_for_partition(
    _ops: *mut AvbOps,
    _partition: *const c_char,
    _guid_buf: *mut c_char,
    _guid_buf_size: usize,
) -> AvbIOResult {
    // This method is required by `avb_slot_verify()`.
    AvbIOResult::AVB_IO_RESULT_OK
}

extern "C" fn validate_vbmeta_public_key(
    ops: *mut AvbOps,
    public_key_data: *const u8,
    public_key_length: usize,
    public_key_metadata: *const u8,
    public_key_metadata_length: usize,
    out_is_trusted: *mut bool,
) -> AvbIOResult {
    to_avb_io_result(try_validate_vbmeta_public_key(
        ops,
        public_key_data,
        public_key_length,
        public_key_metadata,
        public_key_metadata_length,
        out_is_trusted,
    ))
}

fn try_validate_vbmeta_public_key(
    ops: *mut AvbOps,
    public_key_data: *const u8,
    public_key_length: usize,
    _public_key_metadata: *const u8,
    _public_key_metadata_length: usize,
    out_is_trusted: *mut bool,
) -> Result<(), AvbIOError> {
    is_not_null(public_key_data)?;
    // SAFETY: It is safe to create a slice with the given pointer and length as
    // `public_key_data` is a valid pointer and it points to an array of length
    // `public_key_length`.
    let public_key = unsafe { slice::from_raw_parts(public_key_data, public_key_length) };
    let ops = as_ref(ops)?;
    let trusted_public_key = ops.as_ref().trusted_public_key;
    write(out_is_trusted, public_key == trusted_public_key)
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

struct AvbSlotVerifyDataWrap(*mut AvbSlotVerifyData);

impl TryFrom<*mut AvbSlotVerifyData> for AvbSlotVerifyDataWrap {
    type Error = AvbSlotVerifyError;

    fn try_from(data: *mut AvbSlotVerifyData) -> Result<Self, Self::Error> {
        is_not_null(data).map_err(|_| AvbSlotVerifyError::Io)?;
        Ok(Self(data))
    }
}

impl Drop for AvbSlotVerifyDataWrap {
    fn drop(&mut self) {
        // SAFETY: This is safe because `self.0` is checked nonnull when the
        // instance is created. We can free this pointer when the instance is
        // no longer needed.
        unsafe {
            avb_slot_verify_data_free(self.0);
        }
    }
}

impl AsRef<AvbSlotVerifyData> for AvbSlotVerifyDataWrap {
    fn as_ref(&self) -> &AvbSlotVerifyData {
        // This is safe because `self.0` is checked nonnull when the instance is created.
        as_ref(self.0).unwrap()
    }
}

impl AvbSlotVerifyDataWrap {
    fn vbmeta_images(&self) -> Result<&[AvbVBMetaData], AvbSlotVerifyError> {
        let data = self.as_ref();
        is_not_null(data.vbmeta_images).map_err(|_| AvbSlotVerifyError::Io)?;
        // SAFETY: It is safe as the raw pointer `data.vbmeta_images` is a nonnull pointer.
        let vbmeta_images =
            unsafe { slice::from_raw_parts(data.vbmeta_images, data.num_vbmeta_images) };
        Ok(vbmeta_images)
    }
}

struct Payload<'a> {
    kernel: &'a [u8],
    initrd: Option<&'a [u8]>,
    trusted_public_key: &'a [u8],
}

impl<'a> AsRef<Payload<'a>> for AvbOps {
    fn as_ref(&self) -> &Payload<'a> {
        let payload = self.user_data as *const Payload;
        // SAFETY: It is safe to cast the `AvbOps.user_data` to Payload as we have saved a
        // pointer to a valid value of Payload in user_data when creating AvbOps, and
        // assume that the Payload isn't used beyond the lifetime of the AvbOps that it
        // belongs to.
        unsafe { &*payload }
    }
}

impl<'a> Payload<'a> {
    fn get_partition(&self, partition_name: *const c_char) -> Result<&[u8], AvbIOError> {
        match partition_name.try_into()? {
            PartitionName::Kernel => Ok(self.kernel),
            PartitionName::InitrdNormal | PartitionName::InitrdDebug => {
                self.initrd.ok_or(AvbIOError::NoSuchPartition)
            }
        }
    }

    fn verify_partition(
        &mut self,
        partition_name: &CStr,
    ) -> Result<AvbSlotVerifyDataWrap, AvbSlotVerifyError> {
        let requested_partitions = [partition_name.as_ptr(), ptr::null()];
        let mut avb_ops = AvbOps {
            user_data: self as *mut _ as *mut c_void,
            ab_ops: ptr::null_mut(),
            atx_ops: ptr::null_mut(),
            read_from_partition: Some(read_from_partition),
            get_preloaded_partition: Some(get_preloaded_partition),
            write_to_partition: None,
            validate_vbmeta_public_key: Some(validate_vbmeta_public_key),
            read_rollback_index: Some(read_rollback_index),
            write_rollback_index: None,
            read_is_device_unlocked: Some(read_is_device_unlocked),
            get_unique_guid_for_partition: Some(get_unique_guid_for_partition),
            get_size_of_partition: Some(get_size_of_partition),
            read_persistent_value: None,
            write_persistent_value: None,
            validate_public_key_for_partition: None,
        };
        let ab_suffix = CStr::from_bytes_with_nul(NULL_BYTE).unwrap();
        let mut out_data = MaybeUninit::uninit();
        // SAFETY: It is safe to call `avb_slot_verify()` as the pointer arguments (`ops`,
        // `requested_partitions` and `ab_suffix`) passed to the method are all valid and
        // initialized. The last argument `out_data` is allowed to be null so that nothing
        // will be written to it.
        let result = unsafe {
            avb_slot_verify(
                &mut avb_ops,
                requested_partitions.as_ptr(),
                ab_suffix.as_ptr(),
                AvbSlotVerifyFlags::AVB_SLOT_VERIFY_FLAGS_NONE,
                AvbHashtreeErrorMode::AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                out_data.as_mut_ptr(),
            )
        };
        slot_verify_result_to_verify_payload_result(result)?;
        // SAFETY: This is safe because `out_data` has been properly initialized after
        // calling `avb_slot_verify` and it returns OK.
        let out_data = unsafe { out_data.assume_init() };
        out_data.try_into()
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
    let mut payload = Payload { kernel, initrd, trusted_public_key };
    let kernel_verify_result = payload.verify_partition(PartitionName::Kernel.as_cstr())?;
    let vbmeta_images = kernel_verify_result.vbmeta_images()?;
    if vbmeta_images.len() != 1 {
        // There can only be one VBMeta.
        return Err(AvbSlotVerifyError::InvalidMetadata);
    }
    let vbmeta_image = vbmeta_images[0];
    verify_vbmeta_is_from_kernel_partition(&vbmeta_image)?;
    if payload.initrd.is_none() {
        verify_vbmeta_has_no_initrd_descriptor(&vbmeta_image)?;
        return Ok(DebugLevel::None);
    }
    // TODO(b/256148034): Check the vbmeta doesn't have hash descriptors other than
    // boot, initrd_normal, initrd_debug.

    let debug_level = if payload.verify_partition(PartitionName::InitrdNormal.as_cstr()).is_ok() {
        DebugLevel::None
    } else if payload.verify_partition(PartitionName::InitrdDebug.as_cstr()).is_ok() {
        DebugLevel::Full
    } else {
        return Err(AvbSlotVerifyError::Verification);
    };
    Ok(debug_level)
}
