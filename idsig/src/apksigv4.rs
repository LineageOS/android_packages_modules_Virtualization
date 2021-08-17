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

use anyhow::{anyhow, Context, Result};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use std::io::{Read, Seek};

// `apksigv4` module provides routines to decode the idsig file as defined in [APK signature
// scheme v4] (https://source.android.com/security/apksigning/v4).

/// `V4Signature` provides access to the various fields in an idsig file.
#[derive(Debug)]
pub struct V4Signature {
    /// Version of the header. Should be 2.
    pub version: Version,
    /// Provides access to the information about how the APK is hashed.
    pub hashing_info: HashingInfo,
    /// Provides access to the information that can be used to verify this file
    pub signing_info: SigningInfo,
    /// Total size of the merkle tree
    pub merkle_tree_size: u32,
    /// Offset of the merkle tree in the idsig file
    pub merkle_tree_offset: u64,
}

/// `HashingInfo` provides information about how the APK is hashed.
#[derive(Debug)]
pub struct HashingInfo {
    /// Hash algorithm used when creating the merkle tree for the APK.
    pub hash_algorithm: HashAlgorithm,
    /// The log size of a block used when creating the merkle tree. 12 if 4k block was used.
    pub log2_blocksize: u8,
    /// The salt used when creating the merkle tree. 32 bytes max.
    pub salt: Box<[u8]>,
    /// The root hash of the merkle tree created.
    pub raw_root_hash: Box<[u8]>,
}

/// `SigningInfo` provides information that can be used to verify the idsig file.
#[derive(Debug)]
pub struct SigningInfo {
    /// Digest of the APK that this idsig file is for.
    pub apk_digest: Box<[u8]>,
    /// Certificate of the signer that signed this idsig file. ASN.1 DER form.
    pub x509_certificate: Box<[u8]>,
    /// A free-form binary data
    pub additional_data: Box<[u8]>,
    /// Public key of the signer in ASN.1 DER form. This must match the `x509_certificate` field.
    pub public_key: Box<[u8]>,
    /// Signature algorithm used to sign this file.
    pub signature_algorithm_id: SignatureAlgorithmId,
    /// The signature of this file.
    pub signature: Box<[u8]>,
}

/// Version of the idsig file format
#[derive(Debug, PartialEq, FromPrimitive)]
#[repr(u32)]
pub enum Version {
    /// Version 2, the only supported version.
    V2 = 2,
}

impl Version {
    fn from(val: u32) -> Result<Version> {
        Self::from_u32(val).ok_or_else(|| anyhow!("{} is an unsupported version", val))
    }
}

/// Hash algorithm that can be used for idsig file.
#[derive(Debug, PartialEq, FromPrimitive)]
#[repr(u32)]
pub enum HashAlgorithm {
    /// SHA2-256
    SHA256 = 1,
}

impl HashAlgorithm {
    fn from(val: u32) -> Result<HashAlgorithm> {
        Self::from_u32(val).ok_or_else(|| anyhow!("{} is an unsupported hash algorithm", val))
    }
}

/// Signature algorithm that can be used for idsig file
#[derive(Debug, PartialEq, FromPrimitive)]
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum SignatureAlgorithmId {
    /// RSASSA-PSS with SHA2-256 digest, SHA2-256 MGF1, 32 bytes of salt, trailer: 0xbc
    RSASSA_PSS_SHA2_256 = 0x0101,
    /// RSASSA-PSS with SHA2-512 digest, SHA2-512 MGF1, 64 bytes of salt, trailer: 0xbc
    RSASSA_PSS_SHA2_512 = 0x0102,
    /// RSASSA-PKCS1-v1_5 with SHA2-256 digest.
    RSASSA_PKCS1_SHA2_256 = 0x0103,
    /// RSASSA-PKCS1-v1_5 with SHA2-512 digest.
    RSASSA_PKCS1_SHA2_512 = 0x0104,
    /// ECDSA with SHA2-256 digest.
    ECDSA_SHA2_256 = 0x0201,
    /// ECDSA with SHA2-512 digest.
    ECDSA_SHA2_512 = 0x0202,
    /// DSA with SHA2-256 digest
    DSA_SHA2_256 = 0x0301,
}

impl SignatureAlgorithmId {
    fn from(val: u32) -> Result<SignatureAlgorithmId> {
        Self::from_u32(val)
            .with_context(|| format!("{:#06x} is an unsupported signature algorithm", val))
    }
}

impl V4Signature {
    /// Reads a stream from `r` and then parses it into a `V4Signature` struct.
    pub fn from<T: Read + Seek>(mut r: T) -> Result<V4Signature> {
        Ok(V4Signature {
            version: Version::from(read_le_u32(&mut r)?)?,
            hashing_info: HashingInfo::from(&mut r)?,
            signing_info: SigningInfo::from(&mut r)?,
            merkle_tree_size: read_le_u32(&mut r)?,
            merkle_tree_offset: r.stream_position()?,
        })
    }
}

impl HashingInfo {
    fn from(mut r: &mut dyn Read) -> Result<HashingInfo> {
        read_le_u32(&mut r)?;
        Ok(HashingInfo {
            hash_algorithm: HashAlgorithm::from(read_le_u32(&mut r)?)?,
            log2_blocksize: read_u8(&mut r)?,
            salt: read_sized_array(&mut r)?,
            raw_root_hash: read_sized_array(&mut r)?,
        })
    }
}

impl SigningInfo {
    fn from(mut r: &mut dyn Read) -> Result<SigningInfo> {
        read_le_u32(&mut r)?;
        Ok(SigningInfo {
            apk_digest: read_sized_array(&mut r)?,
            x509_certificate: read_sized_array(&mut r)?,
            additional_data: read_sized_array(&mut r)?,
            public_key: read_sized_array(&mut r)?,
            signature_algorithm_id: SignatureAlgorithmId::from(read_le_u32(&mut r)?)?,
            signature: read_sized_array(&mut r)?,
        })
    }
}

fn read_u8(r: &mut dyn Read) -> Result<u8> {
    let mut byte = [0; 1];
    r.read_exact(&mut byte)?;
    Ok(byte[0])
}

fn read_le_u32(r: &mut dyn Read) -> Result<u32> {
    let mut bytes = [0; 4];
    r.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_sized_array(r: &mut dyn Read) -> Result<Box<[u8]>> {
    let size = read_le_u32(r)?;
    let mut data = vec![0; size as usize];
    r.read_exact(&mut data)?;
    Ok(data.into_boxed_slice())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn hexstring_from(s: &[u8]) -> String {
        s.iter().map(|byte| format!("{:02x}", byte)).reduce(|i, j| i + &j).unwrap_or_default()
    }

    #[test]
    fn parse_idsig_file() {
        let idsig = Cursor::new(include_bytes!("../testdata/test.apk.idsig"));
        let parsed = V4Signature::from(idsig).unwrap();

        assert_eq!(Version::V2, parsed.version);

        let hi = parsed.hashing_info;
        assert_eq!(HashAlgorithm::SHA256, hi.hash_algorithm);
        assert_eq!(12, hi.log2_blocksize);
        assert_eq!("", hexstring_from(hi.salt.as_ref()));
        assert_eq!(
            "ce1194fdb3cb2537daf0ac8cdf4926754adcbce5abeece7945fe25d204a0df6a",
            hexstring_from(hi.raw_root_hash.as_ref())
        );

        let si = parsed.signing_info;
        assert_eq!(
            "b5225523a813fb84ed599dd649698c080bcfed4fb19ddb00283a662a2683bc15",
            hexstring_from(si.apk_digest.as_ref())
        );
        assert_eq!("", hexstring_from(si.additional_data.as_ref()));
        assert_eq!(
            "303d021c77304d0f4732a90372bbfce095223e4ba82427ceb381f69bc6762d78021d008b99924\
                   a8585c38d7f654835eb219ae9e176b44e86dcb23153e3d9d6",
            hexstring_from(si.signature.as_ref())
        );
        assert_eq!(SignatureAlgorithmId::DSA_SHA2_256, si.signature_algorithm_id);

        assert_eq!(36864, parsed.merkle_tree_size);
        assert_eq!(2251, parsed.merkle_tree_offset);
    }
}
