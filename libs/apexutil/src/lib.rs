// Copyright 2021, The Android Open Source Project
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

//! Routines for handling APEX payload

use avb_bindgen::*;
use std::ffi::{c_void, CStr};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::mem::{size_of, zeroed};
use std::ops::Deref;
use std::ptr::null_mut;
use std::slice::{from_raw_parts, from_raw_parts_mut};
use thiserror::Error;
use zip::result::ZipError;
use zip::ZipArchive;

const APEX_PUBKEY_ENTRY: &str = "apex_pubkey";
const APEX_PAYLOAD_ENTRY: &str = "apex_payload.img";

/// Errors from parsing an APEX.
#[derive(Debug, Error)]
pub enum ApexParseError {
    /// There was an IO error.
    #[error("IO error")]
    Io(#[from] io::Error),
    /// The Zip archive was invalid.
    #[error("Cannot read zip archive")]
    InvalidZip(&'static str),
    /// The apex_pubkey file was missing from the APEX.
    #[error("APEX doesn't contain apex_pubkey")]
    PubkeyMissing,
    /// The apex_payload.img file was missing from the APEX.
    #[error("APEX doesn't contain apex_payload.img")]
    PayloadMissing,
    /// The AVB footer in the APEX payload was invalid.
    #[error("Cannot validate APEX payload AVB footer")]
    InvalidPayloadAvbFooter,
    /// There were no descriptors in the APEX payload's AVB footer.
    #[error("No descriptors found in payload AVB footer")]
    NoDescriptors,
    /// There was an invalid descriptor in the APEX payload's AVB footer.
    #[error("Invalid descriptor found in payload AVB footer")]
    InvalidDescriptor,
    /// There was no hashtree descriptor in the APEX payload's AVB footer.
    #[error("Non-hashtree descriptor found in payload AVB footer")]
    DescriptorNotHashtree,
    /// There was an invalid hashtree descriptor in the APEX payload's AVB footer.
    #[error("Invalid hashtree descriptor found in payload AVB footer")]
    InvalidHashtreeDescriptor,
}

/// Errors from verifying an APEX.
#[derive(Debug, Error)]
pub enum ApexVerificationError {
    /// There was an error parsing the APEX.
    #[error("Cannot parse APEX file")]
    ParseError(#[from] ApexParseError),
    /// The APEX payload signature did not validate.
    #[error("Cannot verify payload signature")]
    BadPayloadSignature(String),
    /// The APEX payload was signed with a different key.
    #[error("Payload is signed with the wrong key")]
    BadPayloadKey,
}

/// Verification result holds public key and root digest of apex_payload.img
pub struct ApexVerificationResult {
    /// The public key that verifies the payload signature.
    pub public_key: Vec<u8>,
    /// The root digest of the payload hashtree.
    pub root_digest: Vec<u8>,
}

/// Verify APEX payload by AVB verification and return public key and root digest
pub fn verify(path: &str) -> Result<ApexVerificationResult, ApexVerificationError> {
    let apex_file = File::open(path).map_err(ApexParseError::Io)?;
    let (public_key, image_offset, image_size) = get_public_key_and_image_info(&apex_file)?;
    let root_digest = verify_vbmeta(apex_file, image_offset, image_size, &public_key)?;
    Ok(ApexVerificationResult { public_key, root_digest })
}

fn get_public_key_and_image_info(apex_file: &File) -> Result<(Vec<u8>, u64, u64), ApexParseError> {
    let mut z = ZipArchive::new(apex_file).map_err(|err| match err {
        ZipError::Io(err) => ApexParseError::Io(err),
        ZipError::InvalidArchive(s) | ZipError::UnsupportedArchive(s) => {
            ApexParseError::InvalidZip(s)
        }
        ZipError::FileNotFound => unreachable!(),
    })?;

    let mut public_key = Vec::new();
    z.by_name(APEX_PUBKEY_ENTRY)
        .map_err(|err| match err {
            ZipError::Io(err) => ApexParseError::Io(err),
            ZipError::FileNotFound => ApexParseError::PubkeyMissing,
            ZipError::InvalidArchive(s) | ZipError::UnsupportedArchive(s) => {
                ApexParseError::InvalidZip(s)
            }
        })?
        .read_to_end(&mut public_key)?;

    let (image_offset, image_size) = z
        .by_name(APEX_PAYLOAD_ENTRY)
        .map(|f| (f.data_start(), f.size()))
        .map_err(|err| match err {
            ZipError::Io(err) => ApexParseError::Io(err),
            ZipError::FileNotFound => ApexParseError::PayloadMissing,
            ZipError::InvalidArchive(s) | ZipError::UnsupportedArchive(s) => {
                ApexParseError::InvalidZip(s)
            }
        })?;

    Ok((public_key, image_offset, image_size))
}

// Manual addition of a missing enum
#[allow(non_camel_case_types, dead_code)]
#[repr(u8)]
enum AvbDescriptorTag {
    AVB_DESCRIPTOR_TAG_PROPERTY = 0,
    AVB_DESCRIPTOR_TAG_HASHTREE,
    AVB_DESCRIPTOR_TAG_HASH,
    AVB_DESCRIPTOR_TAG_KERNEL_CMDLINE,
    AVB_DESCRIPTOR_TAG_CHAIN_PARTITION,
}

const FOOTER_SIZE: usize = size_of::<AvbFooter>();
const HASHTREE_DESCRIPTOR_SIZE: usize = size_of::<AvbHashtreeDescriptor>();

/// Verify VBmeta image and return root digest
fn verify_vbmeta<R: Read + Seek>(
    image: R,
    offset: u64,
    size: u64,
    public_key: &[u8],
) -> Result<Vec<u8>, ApexVerificationError> {
    let vbmeta = VbMeta::from(image, offset, size)?;
    vbmeta.verify(public_key)?;
    for &descriptor in vbmeta.descriptors()?.iter() {
        if let Ok(hashtree_descriptor) = HashtreeDescriptor::from(descriptor) {
            return Ok(hashtree_descriptor.root_digest());
        }
    }
    Err(ApexParseError::DescriptorNotHashtree.into())
}

struct VbMeta {
    data: Vec<u8>,
}

impl VbMeta {
    // Read a VbMeta data from a given image
    fn from<R: Read + Seek>(
        mut image: R,
        offset: u64,
        size: u64,
    ) -> Result<VbMeta, ApexParseError> {
        // Get AvbFooter first
        image.seek(SeekFrom::Start(offset + size - FOOTER_SIZE as u64))?;
        // SAFETY: AvbDescriptor is a "repr(C,packed)" struct from bindgen
        let mut footer: AvbFooter = unsafe { zeroed() };
        // SAFETY: safe to read because of seek(-FOOTER_SIZE) above
        let avb_footer_valid = unsafe {
            let footer_slice = from_raw_parts_mut(&mut footer as *mut _ as *mut u8, FOOTER_SIZE);
            image.read_exact(footer_slice)?;
            avb_footer_validate_and_byteswap(&footer, &mut footer)
        };
        if !avb_footer_valid {
            return Err(ApexParseError::InvalidPayloadAvbFooter);
        }
        // Get VbMeta block
        image.seek(SeekFrom::Start(offset + footer.vbmeta_offset))?;
        let vbmeta_size = footer.vbmeta_size as usize;
        let mut data = vec![0u8; vbmeta_size];
        image.read_exact(&mut data)?;
        Ok(VbMeta { data })
    }
    // Verify VbMeta image. Its enclosed public key should match with a given public key.
    fn verify(&self, outer_public_key: &[u8]) -> Result<(), ApexVerificationError> {
        // SAFETY: self.data points to a valid VBMeta data and avb_vbmeta_image_verify should work fine
        // with it
        let public_key = unsafe {
            let mut pk_ptr: *const u8 = null_mut();
            let mut pk_len: usize = 0;
            let res = avb_vbmeta_image_verify(
                self.data.as_ptr(),
                self.data.len(),
                &mut pk_ptr,
                &mut pk_len,
            );
            if res != AvbVBMetaVerifyResult_AVB_VBMETA_VERIFY_RESULT_OK {
                return Err(ApexVerificationError::BadPayloadSignature(
                    CStr::from_ptr(avb_vbmeta_verify_result_to_string(res))
                        .to_string_lossy()
                        .into_owned(),
                ));
            }
            from_raw_parts(pk_ptr, pk_len)
        };

        if public_key != outer_public_key {
            return Err(ApexVerificationError::BadPayloadKey);
        }
        Ok(())
    }
    // Return a slice of AvbDescriptor pointers
    fn descriptors(&self) -> Result<Descriptors, ApexParseError> {
        let mut num: usize = 0;
        // SAFETY: ptr will be freed by Descriptor.
        Ok(unsafe {
            let ptr = avb_descriptor_get_all(self.data.as_ptr(), self.data.len(), &mut num);
            if ptr.is_null() {
                return Err(ApexParseError::NoDescriptors);
            }
            let all = from_raw_parts(ptr, num);
            Descriptors { ptr, all }
        })
    }
}

struct HashtreeDescriptor {
    ptr: *const u8,
    inner: AvbHashtreeDescriptor,
}

impl HashtreeDescriptor {
    fn from(descriptor: *const AvbDescriptor) -> Result<HashtreeDescriptor, ApexParseError> {
        // SAFETY: AvbDescriptor is a "repr(C,packed)" struct from bindgen
        let mut desc: AvbDescriptor = unsafe { zeroed() };
        // SAFETY: both points to valid AvbDescriptor pointers
        if !unsafe { avb_descriptor_validate_and_byteswap(descriptor, &mut desc) } {
            return Err(ApexParseError::InvalidDescriptor);
        }
        if desc.tag != AvbDescriptorTag::AVB_DESCRIPTOR_TAG_HASHTREE as u64 {
            return Err(ApexParseError::DescriptorNotHashtree);
        }
        // SAFETY: AvbHashtreeDescriptor is a "repr(C, packed)" struct from bindgen
        let mut hashtree_descriptor: AvbHashtreeDescriptor = unsafe { zeroed() };
        // SAFETY: With tag == AVB_DESCRIPTOR_TAG_HASHTREE, descriptor should point to
        // a AvbHashtreeDescriptor.
        if !unsafe {
            avb_hashtree_descriptor_validate_and_byteswap(
                descriptor as *const AvbHashtreeDescriptor,
                &mut hashtree_descriptor,
            )
        } {
            return Err(ApexParseError::InvalidHashtreeDescriptor);
        }
        Ok(Self { ptr: descriptor as *const u8, inner: hashtree_descriptor })
    }
    fn root_digest(&self) -> Vec<u8> {
        // SAFETY: digest_ptr should point to a valid buffer of root_digest_len
        let root_digest = unsafe {
            let digest_ptr = self.ptr.offset(
                HASHTREE_DESCRIPTOR_SIZE as isize
                    + self.inner.partition_name_len as isize
                    + self.inner.salt_len as isize,
            );
            from_raw_parts(digest_ptr, self.inner.root_digest_len as usize)
        };
        root_digest.to_owned()
    }
}

// Wraps pointer to a heap-allocated array of AvbDescriptor pointers
struct Descriptors<'a> {
    ptr: *mut *const AvbDescriptor,
    all: &'a [*const AvbDescriptor],
}

// Wrapped pointer should be freed with avb_free.
impl Drop for Descriptors<'_> {
    fn drop(&mut self) {
        // SAFETY: ptr is allocated by avb_descriptor_get_all
        unsafe { avb_free(self.ptr as *mut c_void) }
    }
}

impl<'a> Deref for Descriptors<'a> {
    type Target = &'a [*const AvbDescriptor];
    fn deref(&self) -> &Self::Target {
        &self.all
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn to_hex_string(buf: &[u8]) -> String {
        buf.iter().map(|b| format!("{:02x}", b)).collect()
    }
    #[test]
    fn test_open_apex() {
        let res = verify("tests/data/test.apex").unwrap();
        assert_eq!(
            to_hex_string(&res.root_digest),
            "fe11ab17da0a3a738b54bdc3a13f6139cbdf91ec32f001f8d4bbbf8938e04e39"
        );
    }
}
