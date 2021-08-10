/*
 * Copyright (C) 2021 The Android Open Source Project
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

//! Utilities for Signature Verification

use anyhow::{anyhow, bail, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use bytes::{Buf, Bytes};
use std::io::{Read, Seek, SeekFrom};

use crate::ziputil::zip_sections;

const APK_SIG_BLOCK_MIN_SIZE: u32 = 32;
const APK_SIG_BLOCK_MAGIC: u128 = 0x3234206b636f6c4220676953204b5041;

// TODO(jooyung): introduce type
pub const SIGNATURE_RSA_PSS_WITH_SHA256: u32 = 0x0101;
pub const SIGNATURE_RSA_PSS_WITH_SHA512: u32 = 0x0102;
pub const SIGNATURE_RSA_PKCS1_V1_5_WITH_SHA256: u32 = 0x0103;
pub const SIGNATURE_RSA_PKCS1_V1_5_WITH_SHA512: u32 = 0x0104;
pub const SIGNATURE_ECDSA_WITH_SHA256: u32 = 0x0201;
pub const SIGNATURE_ECDSA_WITH_SHA512: u32 = 0x0202;
pub const SIGNATURE_DSA_WITH_SHA256: u32 = 0x0301;
pub const SIGNATURE_VERITY_RSA_PKCS1_V1_5_WITH_SHA256: u32 = 0x0421;
pub const SIGNATURE_VERITY_ECDSA_WITH_SHA256: u32 = 0x0423;
pub const SIGNATURE_VERITY_DSA_WITH_SHA256: u32 = 0x0425;

// TODO(jooyung): introduce type
const CONTENT_DIGEST_CHUNKED_SHA256: u32 = 1;
const CONTENT_DIGEST_CHUNKED_SHA512: u32 = 2;
const CONTENT_DIGEST_VERITY_CHUNKED_SHA256: u32 = 3;
#[allow(unused)]
const CONTENT_DIGEST_SHA256: u32 = 4;

pub struct SignatureInfo {
    pub signature_block: Bytes,
}

/// Returns the APK Signature Scheme block contained in the provided file for the given ID
/// and the additional information relevant for verifying the block against the file.
pub fn find_signature<F: Read + Seek>(f: F, block_id: u32) -> Result<SignatureInfo> {
    let (mut f, sections) = zip_sections(f)?;

    let (signing_block, _signing_block_offset) =
        find_signing_block(&mut f, sections.central_directory_offset)?;

    // TODO(jooyung): propagate NotFound error so that verification can fallback to V2
    let signature_scheme_block = find_signature_scheme_block(signing_block, block_id)?;
    Ok(SignatureInfo { signature_block: signature_scheme_block })
}

fn find_signing_block<T: Read + Seek>(
    reader: &mut T,
    central_directory_offset: u32,
) -> Result<(Bytes, u32)> {
    // FORMAT:
    // OFFSET       DATA TYPE  DESCRIPTION
    // * @+0  bytes uint64:    size in bytes (excluding this field)
    // * @+8  bytes payload
    // * @-24 bytes uint64:    size in bytes (same as the one above)
    // * @-16 bytes uint128:   magic
    if central_directory_offset < APK_SIG_BLOCK_MIN_SIZE {
        bail!(
            "APK too small for APK Signing Block. ZIP Central Directory offset: {}",
            central_directory_offset
        );
    }
    reader.seek(SeekFrom::Start((central_directory_offset - 24) as u64))?;
    let size_in_footer = reader.read_u64::<LittleEndian>()? as u32;
    if reader.read_u128::<LittleEndian>()? != APK_SIG_BLOCK_MAGIC {
        bail!("No APK Signing Block before ZIP Central Directory")
    }
    let total_size = size_in_footer + 8;
    let signing_block_offset = central_directory_offset
        .checked_sub(total_size)
        .ok_or_else(|| anyhow!("APK Signing Block size out of range: {}", size_in_footer))?;
    reader.seek(SeekFrom::Start(signing_block_offset as u64))?;
    let size_in_header = reader.read_u64::<LittleEndian>()? as u32;
    if size_in_header != size_in_footer {
        bail!(
            "APK Signing Block sizes in header and footer do not match: {} vs {}",
            size_in_header,
            size_in_footer
        );
    }
    reader.seek(SeekFrom::Start(signing_block_offset as u64))?;
    let mut buf = vec![0u8; total_size as usize];
    reader.read_exact(&mut buf)?;
    Ok((Bytes::from(buf), signing_block_offset))
}

fn find_signature_scheme_block(buf: Bytes, block_id: u32) -> Result<Bytes> {
    // FORMAT:
    // OFFSET       DATA TYPE  DESCRIPTION
    // * @+0  bytes uint64:    size in bytes (excluding this field)
    // * @+8  bytes pairs
    // * @-24 bytes uint64:    size in bytes (same as the one above)
    // * @-16 bytes uint128:   magic
    let mut pairs = buf.slice(8..(buf.len() - 24));
    let mut entry_count = 0;
    while pairs.has_remaining() {
        entry_count += 1;
        if pairs.remaining() < 8 {
            bail!("Insufficient data to read size of APK Signing Block entry #{}", entry_count);
        }
        let length = pairs.get_u64_le();
        let mut pair = pairs.split_to(length as usize);
        let id = pair.get_u32_le();
        if id == block_id {
            return Ok(pair);
        }
    }
    // TODO(jooyung): return NotFound error
    bail!("No APK Signature Scheme block in APK Signing Block with ID: {}", block_id)
}

pub fn is_supported_signature_algorithm(algorithm_id: u32) -> bool {
    matches!(
        algorithm_id,
        SIGNATURE_RSA_PSS_WITH_SHA256
            | SIGNATURE_RSA_PSS_WITH_SHA512
            | SIGNATURE_RSA_PKCS1_V1_5_WITH_SHA256
            | SIGNATURE_RSA_PKCS1_V1_5_WITH_SHA512
            | SIGNATURE_ECDSA_WITH_SHA256
            | SIGNATURE_ECDSA_WITH_SHA512
            | SIGNATURE_DSA_WITH_SHA256
            | SIGNATURE_VERITY_RSA_PKCS1_V1_5_WITH_SHA256
            | SIGNATURE_VERITY_ECDSA_WITH_SHA256
            | SIGNATURE_VERITY_DSA_WITH_SHA256
    )
}

fn to_content_digest_algorithm(algorithm_id: u32) -> Result<u32> {
    match algorithm_id {
        SIGNATURE_RSA_PSS_WITH_SHA256
        | SIGNATURE_RSA_PKCS1_V1_5_WITH_SHA256
        | SIGNATURE_ECDSA_WITH_SHA256
        | SIGNATURE_DSA_WITH_SHA256 => Ok(CONTENT_DIGEST_CHUNKED_SHA256),
        SIGNATURE_RSA_PSS_WITH_SHA512
        | SIGNATURE_RSA_PKCS1_V1_5_WITH_SHA512
        | SIGNATURE_ECDSA_WITH_SHA512 => Ok(CONTENT_DIGEST_CHUNKED_SHA512),
        SIGNATURE_VERITY_RSA_PKCS1_V1_5_WITH_SHA256
        | SIGNATURE_VERITY_ECDSA_WITH_SHA256
        | SIGNATURE_VERITY_DSA_WITH_SHA256 => Ok(CONTENT_DIGEST_VERITY_CHUNKED_SHA256),
        _ => bail!("Unknown signature algorithm: {}", algorithm_id),
    }
}

pub fn rank_signature_algorithm(algo: u32) -> Result<u32> {
    rank_content_digest_algorithm(to_content_digest_algorithm(algo)?)
}

fn rank_content_digest_algorithm(id: u32) -> Result<u32> {
    match id {
        CONTENT_DIGEST_CHUNKED_SHA256 => Ok(0),
        CONTENT_DIGEST_VERITY_CHUNKED_SHA256 => Ok(1),
        CONTENT_DIGEST_CHUNKED_SHA512 => Ok(2),
        _ => bail!("Unknown digest algorithm: {}", id),
    }
}
