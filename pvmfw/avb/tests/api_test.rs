/*
 * Copyright (C) 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use anyhow::Result;
use avb_bindgen::{
    avb_footer_validate_and_byteswap, avb_vbmeta_image_header_to_host_byte_order, AvbFooter,
    AvbVBMetaImageHeader,
};
use pvmfw_avb::{verify_payload, AvbSlotVerifyError};
use std::{
    fs,
    mem::{size_of, transmute, MaybeUninit},
    ptr,
};

const MICRODROID_KERNEL_IMG_PATH: &str = "microdroid_kernel";
const INITRD_NORMAL_IMG_PATH: &str = "microdroid_initrd_normal.img";
const INITRD_DEBUG_IMG_PATH: &str = "microdroid_initrd_debuggable.img";
const TEST_IMG_WITH_ONE_HASHDESC_PATH: &str = "test_image_with_one_hashdesc.img";
const TEST_IMG_WITH_PROP_DESC_PATH: &str = "test_image_with_prop_desc.img";
const TEST_IMG_WITH_NON_INITRD_HASHDESC_PATH: &str = "test_image_with_non_initrd_hashdesc.img";
const UNSIGNED_TEST_IMG_PATH: &str = "unsigned_test.img";

const PUBLIC_KEY_RSA2048_PATH: &str = "data/testkey_rsa2048_pub.bin";
const PUBLIC_KEY_RSA4096_PATH: &str = "data/testkey_rsa4096_pub.bin";
const RANDOM_FOOTER_POS: usize = 30;

/// This test uses the Microdroid payload compiled on the fly to check that
/// the latest payload can be verified successfully.
#[test]
fn latest_normal_payload_passes_verification() -> Result<()> {
    assert_payload_verification_succeeds(
        &load_latest_signed_kernel()?,
        &load_latest_initrd_normal()?,
        &load_trusted_public_key()?,
    )
}

#[test]
fn latest_debug_payload_passes_verification() -> Result<()> {
    assert_payload_verification_succeeds(
        &load_latest_signed_kernel()?,
        &load_latest_initrd_debug()?,
        &load_trusted_public_key()?,
    )
}

#[test]
fn payload_expecting_no_initrd_passes_verification_with_no_initrd() -> Result<()> {
    assert_payload_verification_with_no_initrd_eq(
        &fs::read(TEST_IMG_WITH_ONE_HASHDESC_PATH)?,
        &load_trusted_public_key()?,
        Ok(()),
    )
}

#[test]
fn payload_with_non_initrd_descriptor_passes_verification_with_no_initrd() -> Result<()> {
    assert_payload_verification_with_no_initrd_eq(
        &fs::read(TEST_IMG_WITH_NON_INITRD_HASHDESC_PATH)?,
        &load_trusted_public_key()?,
        Ok(()),
    )
}

#[test]
fn payload_with_prop_descriptor_fails_verification_with_no_initrd() -> Result<()> {
    assert_payload_verification_with_no_initrd_eq(
        &fs::read(TEST_IMG_WITH_PROP_DESC_PATH)?,
        &load_trusted_public_key()?,
        Err(AvbSlotVerifyError::InvalidMetadata),
    )
}

#[test]
fn payload_expecting_initrd_fails_verification_with_no_initrd() -> Result<()> {
    assert_payload_verification_with_no_initrd_eq(
        &load_latest_signed_kernel()?,
        &load_trusted_public_key()?,
        Err(AvbSlotVerifyError::InvalidMetadata),
    )
}

#[test]
fn payload_with_empty_public_key_fails_verification() -> Result<()> {
    assert_payload_verification_fails(
        &load_latest_signed_kernel()?,
        &load_latest_initrd_normal()?,
        /*trusted_public_key=*/ &[0u8; 0],
        AvbSlotVerifyError::PublicKeyRejected,
    )
}

#[test]
fn payload_with_an_invalid_public_key_fails_verification() -> Result<()> {
    assert_payload_verification_fails(
        &load_latest_signed_kernel()?,
        &load_latest_initrd_normal()?,
        /*trusted_public_key=*/ &[0u8; 512],
        AvbSlotVerifyError::PublicKeyRejected,
    )
}

#[test]
fn payload_with_a_different_valid_public_key_fails_verification() -> Result<()> {
    assert_payload_verification_fails(
        &load_latest_signed_kernel()?,
        &load_latest_initrd_normal()?,
        &fs::read(PUBLIC_KEY_RSA2048_PATH)?,
        AvbSlotVerifyError::PublicKeyRejected,
    )
}

#[test]
fn unsigned_kernel_fails_verification() -> Result<()> {
    assert_payload_verification_fails(
        &fs::read(UNSIGNED_TEST_IMG_PATH)?,
        &load_latest_initrd_normal()?,
        &load_trusted_public_key()?,
        AvbSlotVerifyError::Io,
    )
}

#[test]
fn tampered_kernel_fails_verification() -> Result<()> {
    let mut kernel = load_latest_signed_kernel()?;
    kernel[1] = !kernel[1]; // Flip the bits

    assert_payload_verification_fails(
        &kernel,
        &load_latest_initrd_normal()?,
        &load_trusted_public_key()?,
        AvbSlotVerifyError::Verification,
    )
}

#[test]
fn tampered_kernel_footer_fails_verification() -> Result<()> {
    let mut kernel = load_latest_signed_kernel()?;
    let avb_footer_index = kernel.len() - size_of::<AvbFooter>() + RANDOM_FOOTER_POS;
    kernel[avb_footer_index] = !kernel[avb_footer_index];

    assert_payload_verification_fails(
        &kernel,
        &load_latest_initrd_normal()?,
        &load_trusted_public_key()?,
        AvbSlotVerifyError::InvalidMetadata,
    )
}

#[test]
fn tampered_vbmeta_fails_verification() -> Result<()> {
    let mut kernel = load_latest_signed_kernel()?;
    let footer = extract_avb_footer(&kernel)?;
    let vbmeta_index: usize = (footer.vbmeta_offset + 1).try_into()?;

    kernel[vbmeta_index] = !kernel[vbmeta_index]; // Flip the bits

    assert_payload_verification_fails(
        &kernel,
        &load_latest_initrd_normal()?,
        &load_trusted_public_key()?,
        AvbSlotVerifyError::InvalidMetadata,
    )
}

#[test]
fn vbmeta_with_public_key_overwritten_fails_verification() -> Result<()> {
    let mut kernel = load_latest_signed_kernel()?;
    let footer = extract_avb_footer(&kernel)?;
    let vbmeta_header = extract_vbmeta_header(&kernel, &footer)?;
    let public_key_offset = footer.vbmeta_offset as usize
        + size_of::<AvbVBMetaImageHeader>()
        + vbmeta_header.authentication_data_block_size as usize
        + vbmeta_header.public_key_offset as usize;
    let public_key_size: usize = vbmeta_header.public_key_size.try_into()?;
    let empty_public_key = vec![0u8; public_key_size];

    kernel[public_key_offset..(public_key_offset + public_key_size)]
        .copy_from_slice(&empty_public_key);

    assert_payload_verification_fails(
        &kernel,
        &load_latest_initrd_normal()?,
        &empty_public_key,
        AvbSlotVerifyError::Verification,
    )?;
    assert_payload_verification_fails(
        &kernel,
        &load_latest_initrd_normal()?,
        &load_trusted_public_key()?,
        AvbSlotVerifyError::Verification,
    )
}

#[test]
fn vbmeta_with_verification_flag_disabled_fails_verification() -> Result<()> {
    // From external/avb/libavb/avb_vbmeta_image.h
    const AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED: u32 = 2;

    // Arrange.
    let mut kernel = load_latest_signed_kernel()?;
    let footer = extract_avb_footer(&kernel)?;
    let vbmeta_header = extract_vbmeta_header(&kernel, &footer)?;
    assert_eq!(
        0, vbmeta_header.flags as u32,
        "The disable flag should not be set in the latest kernel."
    );
    let flags_addr = ptr::addr_of!(vbmeta_header.flags) as *const u8;
    // SAFETY: It is safe as both raw pointers `flags_addr` and `vbmeta_header` are not null.
    let flags_offset = unsafe { flags_addr.offset_from(ptr::addr_of!(vbmeta_header) as *const u8) };
    let flags_offset = usize::try_from(footer.vbmeta_offset)? + usize::try_from(flags_offset)?;

    // Act.
    kernel[flags_offset..(flags_offset + size_of::<u32>())]
        .copy_from_slice(&AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED.to_be_bytes());

    // Assert.
    let vbmeta_header = extract_vbmeta_header(&kernel, &footer)?;
    assert_eq!(
        AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED, vbmeta_header.flags as u32,
        "VBMeta verification flag should be disabled now."
    );
    assert_payload_verification_fails(
        &kernel,
        &load_latest_initrd_normal()?,
        &load_trusted_public_key()?,
        AvbSlotVerifyError::Verification,
    )
}

fn extract_avb_footer(kernel: &[u8]) -> Result<AvbFooter> {
    let footer_start = kernel.len() - size_of::<AvbFooter>();
    // SAFETY: The slice is the same size as the struct which only contains simple data types.
    let mut footer = unsafe {
        transmute::<[u8; size_of::<AvbFooter>()], AvbFooter>(kernel[footer_start..].try_into()?)
    };
    // SAFETY: The function updates the struct in-place.
    unsafe {
        avb_footer_validate_and_byteswap(&footer, &mut footer);
    }
    Ok(footer)
}

fn extract_vbmeta_header(kernel: &[u8], footer: &AvbFooter) -> Result<AvbVBMetaImageHeader> {
    let vbmeta_offset: usize = footer.vbmeta_offset.try_into()?;
    let vbmeta_size: usize = footer.vbmeta_size.try_into()?;
    let vbmeta_src = &kernel[vbmeta_offset..(vbmeta_offset + vbmeta_size)];
    // SAFETY: The latest kernel has a valid VBMeta header at the position specified in footer.
    let vbmeta_header = unsafe {
        let mut header = MaybeUninit::uninit();
        let src = vbmeta_src.as_ptr() as *const _ as *const AvbVBMetaImageHeader;
        avb_vbmeta_image_header_to_host_byte_order(src, header.as_mut_ptr());
        header.assume_init()
    };
    Ok(vbmeta_header)
}

fn assert_payload_verification_with_no_initrd_eq(
    kernel: &[u8],
    trusted_public_key: &[u8],
    expected_result: Result<(), AvbSlotVerifyError>,
) -> Result<()> {
    assert_eq!(expected_result, verify_payload(kernel, /*initrd=*/ None, trusted_public_key));
    Ok(())
}

fn assert_payload_verification_fails(
    kernel: &[u8],
    initrd: &[u8],
    trusted_public_key: &[u8],
    expected_error: AvbSlotVerifyError,
) -> Result<()> {
    assert_eq!(Err(expected_error), verify_payload(kernel, Some(initrd), trusted_public_key));
    Ok(())
}

fn assert_payload_verification_succeeds(
    kernel: &[u8],
    initrd: &[u8],
    trusted_public_key: &[u8],
) -> Result<()> {
    assert_eq!(Ok(()), verify_payload(kernel, Some(initrd), trusted_public_key));
    Ok(())
}

fn load_latest_signed_kernel() -> Result<Vec<u8>> {
    Ok(fs::read(MICRODROID_KERNEL_IMG_PATH)?)
}

fn load_latest_initrd_normal() -> Result<Vec<u8>> {
    Ok(fs::read(INITRD_NORMAL_IMG_PATH)?)
}

fn load_latest_initrd_debug() -> Result<Vec<u8>> {
    Ok(fs::read(INITRD_DEBUG_IMG_PATH)?)
}

fn load_trusted_public_key() -> Result<Vec<u8>> {
    Ok(fs::read(PUBLIC_KEY_RSA4096_PATH)?)
}
