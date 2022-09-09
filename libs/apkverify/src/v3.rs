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

//! Verifies APK Signature Scheme V3
//!
//! [v3 verification]: https://source.android.com/security/apksigning/v3#verification

use anyhow::{anyhow, bail, ensure, Context, Result};
use bytes::Bytes;
use openssl::hash::MessageDigest;
use openssl::pkey::{self, PKey};
use openssl::rsa::Padding;
use openssl::sign::Verifier;
use openssl::x509::X509;
use std::fs::File;
use std::io::{Read, Seek};
use std::ops::Range;
use std::path::Path;

use crate::bytes_ext::{BytesExt, LengthPrefixed, ReadFromBytes};
use crate::sigutil::*;

pub const APK_SIGNATURE_SCHEME_V3_BLOCK_ID: u32 = 0xf05368c0;

// TODO(jooyung): get "ro.build.version.sdk"
const SDK_INT: u32 = 31;

type Signers = LengthPrefixed<Vec<LengthPrefixed<Signer>>>;

struct Signer {
    signed_data: LengthPrefixed<Bytes>, // not verified yet
    min_sdk: u32,
    max_sdk: u32,
    signatures: LengthPrefixed<Vec<LengthPrefixed<Signature>>>,
    public_key: LengthPrefixed<Bytes>,
}

impl Signer {
    fn sdk_range(&self) -> Range<u32> {
        self.min_sdk..self.max_sdk
    }
}

struct SignedData {
    digests: LengthPrefixed<Vec<LengthPrefixed<Digest>>>,
    certificates: LengthPrefixed<Vec<LengthPrefixed<X509Certificate>>>,
    min_sdk: u32,
    max_sdk: u32,
    #[allow(dead_code)]
    additional_attributes: LengthPrefixed<Vec<LengthPrefixed<AdditionalAttributes>>>,
}

impl SignedData {
    fn sdk_range(&self) -> Range<u32> {
        self.min_sdk..self.max_sdk
    }
}

#[derive(Debug)]
struct Signature {
    signature_algorithm_id: u32,
    signature: LengthPrefixed<Bytes>,
}

struct Digest {
    signature_algorithm_id: u32,
    digest: LengthPrefixed<Bytes>,
}

type X509Certificate = Bytes;
type AdditionalAttributes = Bytes;

/// Verifies APK Signature Scheme v3 signatures of the provided APK and returns the public key
/// associated with the signer in DER format.
pub fn verify<P: AsRef<Path>>(path: P) -> Result<Box<[u8]>> {
    let f = File::open(path.as_ref())?;
    let mut sections = ApkSections::new(f)?;
    find_signer_and_then(&mut sections, |(signer, sections)| signer.verify(sections))
}

/// Finds the supported signer and execute a function on it.
fn find_signer_and_then<R, U, F>(sections: &mut ApkSections<R>, f: F) -> Result<U>
where
    R: Read + Seek,
    F: FnOnce((&Signer, &mut ApkSections<R>)) -> Result<U>,
{
    let mut block = sections.find_signature(APK_SIGNATURE_SCHEME_V3_BLOCK_ID)?;
    // parse v3 scheme block
    let signers = block.read::<Signers>()?;

    // find supported by platform
    let supported = signers.iter().filter(|s| s.sdk_range().contains(&SDK_INT)).collect::<Vec<_>>();

    // there should be exactly one
    if supported.len() != 1 {
        bail!(
            "APK Signature Scheme V3 only supports one signer: {} signers found.",
            supported.len()
        )
    }

    // Call the supplied function
    f((supported[0], sections))
}

/// Gets the public key (in DER format) that was used to sign the given APK/APEX file
pub fn get_public_key_der<P: AsRef<Path>>(path: P) -> Result<Box<[u8]>> {
    let f = File::open(path.as_ref())?;
    let mut sections = ApkSections::new(f)?;
    find_signer_and_then(&mut sections, |(signer, _)| {
        Ok(signer.public_key.to_vec().into_boxed_slice())
    })
}

/// Gets the v4 [apk_digest].
///
/// [apk_digest]: https://source.android.com/docs/security/apksigning/v4#apk-digest
pub fn pick_v4_apk_digest<R: Read + Seek>(apk: R) -> Result<(u32, Box<[u8]>)> {
    let mut sections = ApkSections::new(apk)?;
    let mut block = sections.find_signature(APK_SIGNATURE_SCHEME_V3_BLOCK_ID)?;
    let signers = block.read::<Signers>()?;
    ensure!(signers.len() == 1, "should only have one signer");
    signers[0].pick_v4_apk_digest()
}

impl Signer {
    /// Select the signature that uses the strongest algorithm according to the preferences of the
    /// v4 signing scheme.
    fn strongest_signature(&self) -> Result<&Signature> {
        Ok(self
            .signatures
            .iter()
            .filter(|sig| is_supported_signature_algorithm(sig.signature_algorithm_id))
            .max_by_key(|sig| get_signature_algorithm_rank(sig.signature_algorithm_id).unwrap())
            .ok_or_else(|| anyhow!("No supported signatures found"))?)
    }

    fn pick_v4_apk_digest(&self) -> Result<(u32, Box<[u8]>)> {
        let strongest = self.strongest_signature()?;
        let signed_data: SignedData = self.signed_data.slice(..).read()?;
        let digest = signed_data
            .digests
            .iter()
            .find(|&dig| dig.signature_algorithm_id == strongest.signature_algorithm_id)
            .ok_or_else(|| anyhow!("Digest not found"))?;
        Ok((digest.signature_algorithm_id, digest.digest.as_ref().to_vec().into_boxed_slice()))
    }

    /// The steps in this method implements APK Signature Scheme v3 verification step 3.
    fn verify<R: Read + Seek>(&self, sections: &mut ApkSections<R>) -> Result<Box<[u8]>> {
        // 1. Choose the strongest supported signature algorithm ID from signatures.
        let strongest = self.strongest_signature()?;

        // 2. Verify the corresponding signature from signatures against signed data using public key.
        //    (It is now safe to parse signed data.)
        let public_key = PKey::public_key_from_der(self.public_key.as_ref())?;
        verify_signed_data(&self.signed_data, strongest, &public_key)?;

        // It is now safe to parse signed data.
        let signed_data: SignedData = self.signed_data.slice(..).read()?;

        // 3. Verify the min and max SDK versions in the signed data match those specified for the
        //    signer.
        if self.sdk_range() != signed_data.sdk_range() {
            bail!("SDK versions mismatch between signed and unsigned in v3 signer block.");
        }

        // 4. Verify that the ordered list of signature algorithm IDs in digests and signatures is
        //    identical. (This is to prevent signature stripping/addition.)
        if !self
            .signatures
            .iter()
            .map(|sig| sig.signature_algorithm_id)
            .eq(signed_data.digests.iter().map(|dig| dig.signature_algorithm_id))
        {
            bail!("Signature algorithms don't match between digests and signatures records");
        }

        // 5. Compute the digest of APK contents using the same digest algorithm as the digest
        //    algorithm used by the signature algorithm.
        let digest = signed_data
            .digests
            .iter()
            .find(|&dig| dig.signature_algorithm_id == strongest.signature_algorithm_id)
            .unwrap(); // ok to unwrap since we check if two lists are the same above
        let computed = sections.compute_digest(digest.signature_algorithm_id)?;

        // 6. Verify that the computed digest is identical to the corresponding digest from digests.
        if computed != digest.digest.as_ref() {
            bail!(
                "Digest mismatch: computed={:?} vs expected={:?}",
                to_hex_string(&computed),
                to_hex_string(&digest.digest),
            );
        }

        // 7. Verify that public key of the first certificate of certificates is identical
        //    to public key.
        let cert = signed_data.certificates.first().context("No certificates listed")?;
        let cert = X509::from_der(cert.as_ref())?;
        if !cert.public_key()?.public_eq(&public_key) {
            bail!("Public key mismatch between certificate and signature record");
        }

        // TODO(jooyung) 8. If the proof-of-rotation attribute exists for the signer verify that the struct is valid and this signer is the last certificate in the list.
        Ok(self.public_key.to_vec().into_boxed_slice())
    }
}

fn verify_signed_data(data: &Bytes, signature: &Signature, key: &PKey<pkey::Public>) -> Result<()> {
    let (pkey_id, padding, digest) = match signature.signature_algorithm_id {
        SIGNATURE_RSA_PSS_WITH_SHA256 => {
            (pkey::Id::RSA, Padding::PKCS1_PSS, MessageDigest::sha256())
        }
        SIGNATURE_RSA_PSS_WITH_SHA512 => {
            (pkey::Id::RSA, Padding::PKCS1_PSS, MessageDigest::sha512())
        }
        SIGNATURE_RSA_PKCS1_V1_5_WITH_SHA256 | SIGNATURE_VERITY_RSA_PKCS1_V1_5_WITH_SHA256 => {
            (pkey::Id::RSA, Padding::PKCS1, MessageDigest::sha256())
        }
        SIGNATURE_RSA_PKCS1_V1_5_WITH_SHA512 => {
            (pkey::Id::RSA, Padding::PKCS1, MessageDigest::sha512())
        }
        SIGNATURE_ECDSA_WITH_SHA256 | SIGNATURE_VERITY_ECDSA_WITH_SHA256 => {
            (pkey::Id::EC, Padding::NONE, MessageDigest::sha256())
        }
        // TODO(b/190343842) not implemented signature algorithm
        SIGNATURE_ECDSA_WITH_SHA512
        | SIGNATURE_DSA_WITH_SHA256
        | SIGNATURE_VERITY_DSA_WITH_SHA256 => {
            bail!(
                "TODO(b/190343842) not implemented signature algorithm: {:#x}",
                signature.signature_algorithm_id
            );
        }
        _ => bail!("Unsupported signature algorithm: {:#x}", signature.signature_algorithm_id),
    };
    ensure!(key.id() == pkey_id, "Public key has the wrong ID");
    let mut verifier = Verifier::new(digest, key)?;
    if pkey_id == pkey::Id::RSA {
        verifier.set_rsa_padding(padding)?;
    }
    verifier.update(data)?;
    let verified = verifier.verify(&signature.signature)?;
    ensure!(verified, "Signature is invalid ");
    Ok(())
}

// ReadFromBytes implementations
// TODO(jooyung): add derive macro: #[derive(ReadFromBytes)]

impl ReadFromBytes for Signer {
    fn read_from_bytes(buf: &mut Bytes) -> Result<Self> {
        Ok(Self {
            signed_data: buf.read()?,
            min_sdk: buf.read()?,
            max_sdk: buf.read()?,
            signatures: buf.read()?,
            public_key: buf.read()?,
        })
    }
}

impl ReadFromBytes for SignedData {
    fn read_from_bytes(buf: &mut Bytes) -> Result<Self> {
        Ok(Self {
            digests: buf.read()?,
            certificates: buf.read()?,
            min_sdk: buf.read()?,
            max_sdk: buf.read()?,
            additional_attributes: buf.read()?,
        })
    }
}

impl ReadFromBytes for Signature {
    fn read_from_bytes(buf: &mut Bytes) -> Result<Self> {
        Ok(Signature { signature_algorithm_id: buf.read()?, signature: buf.read()? })
    }
}

impl ReadFromBytes for Digest {
    fn read_from_bytes(buf: &mut Bytes) -> Result<Self> {
        Ok(Self { signature_algorithm_id: buf.read()?, digest: buf.read()? })
    }
}

#[inline]
pub(crate) fn to_hex_string(buf: &[u8]) -> String {
    buf.iter().map(|b| format!("{:02X}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    #[test]
    fn test_pick_v4_apk_digest_only_with_v3_dsa_sha256() {
        check_v4_apk_digest(
            "tests/data/v3-only-with-dsa-sha256-1024.apk",
            SIGNATURE_DSA_WITH_SHA256,
            "0DF2426EA33AEDAF495D88E5BE0C6A1663FF0A81C5ED12D5B2929AE4B4300F2F",
        );
    }

    #[test]
    fn test_pick_v4_apk_digest_only_with_v3_pkcs1_sha512() {
        check_v4_apk_digest(
            "tests/data/v3-only-with-rsa-pkcs1-sha512-1024.apk",
            SIGNATURE_RSA_PKCS1_V1_5_WITH_SHA512,
            "9B9AE02DA60B18999BF541790F00D380006FDF0655C3C482AA0BB0AF17CF7A42\
             ECF56B973518546C9080B2FEF83027E895ED2882BFC88EA19790BBAB29AF53B3",
        );
    }

    fn check_v4_apk_digest(apk_filename: &str, expected_algorithm: u32, expected_digest: &str) {
        let apk_file = File::open(apk_filename).unwrap();
        let (signature_algorithm_id, apk_digest) = pick_v4_apk_digest(apk_file).unwrap();

        assert_eq!(expected_algorithm, signature_algorithm_id);
        assert_eq!(expected_digest, to_hex_string(apk_digest.as_ref()));
    }
}
