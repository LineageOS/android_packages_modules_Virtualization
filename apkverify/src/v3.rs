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

use anyhow::{anyhow, bail, Result};
use bytes::Bytes;
use std::fs::File;
use std::ops::Range;
use std::path::Path;

use crate::bytes_ext::{BytesExt, LengthPrefixed, ReadFromBytes};
use crate::sigutil::{find_signature, is_supported_signature_algorithm, rank_signature_algorithm};

pub const APK_SIGNATURE_SCHEME_V3_BLOCK_ID: u32 = 0xf05368c0;

// TODO(jooyung): get "ro.build.version.sdk"
const SDK_INT: u32 = 31;

/// Data model for Signature Scheme V3
/// https://source.android.com/security/apksigning/v3#verification

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
    additional_attributes: LengthPrefixed<Vec<LengthPrefixed<AdditionalAttributes>>>,
}

impl SignedData {
    fn sdk_range(&self) -> Range<u32> {
        self.min_sdk..self.max_sdk
    }
}

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

/// Verifies APK Signature Scheme v3 signatures of the provided APK and returns the certificates
/// associated with each signer.
pub fn verify<P: AsRef<Path>>(path: P) -> Result<()> {
    let mut f = File::open(path.as_ref())?;
    let signature = find_signature(&mut f, APK_SIGNATURE_SCHEME_V3_BLOCK_ID)?;
    verify_signature(&signature.signature_block)?;
    Ok(())
}

/// Verifies the contents of the provided APK file against the provided APK Signature Scheme v3
/// Block.
fn verify_signature(block: &Bytes) -> Result<()> {
    // parse v3 scheme block
    let signers = block.slice(..).read::<Signers>()?;

    // find supported by platform
    let mut supported =
        signers.iter().filter(|s| s.sdk_range().contains(&SDK_INT)).collect::<Vec<_>>();

    // there should be exactly one
    if supported.len() != 1 {
        bail!("APK Signature Scheme V3 only supports one signer: {} signers found.", signers.len())
    }

    // and it should be verified
    supported.pop().unwrap().verify()?;

    Ok(())
}

impl Signer {
    fn verify(&self) -> Result<()> {
        // 1. Choose the strongest supported signature algorithm ID from signatures. The strength
        //    ordering is up to each implementation/platform version.
        let strongest: &Signature = self
            .signatures
            .iter()
            .filter(|sig| is_supported_signature_algorithm(sig.signature_algorithm_id))
            .max_by_key(|sig| rank_signature_algorithm(sig.signature_algorithm_id).unwrap())
            .ok_or_else(|| anyhow!("No supported signatures found"))?;

        // 2. Verify the corresponding signature from signatures against signed data using public key.
        //    (It is now safe to parse signed data.)
        verify_data(&self.signed_data, strongest, &self.public_key)?;

        // It is now safe to parse signed data.
        let signed_data: SignedData = self.signed_data.slice(..).read()?;

        // 3. Verify the min and max SDK versions in the signed data match those specified for the
        //    signer.
        if self.sdk_range() != signed_data.sdk_range() {
            bail!("SDK versions mismatch between signed and unsigned in v3 signer block.");
        }
        // TODO(jooyung) 4. Verify that the ordered list of signature algorithm IDs in digests and signatures is identical. (This is to prevent signature stripping/addition.)
        // TODO(jooyung) 5. Compute the digest of APK contents using the same digest algorithm as the digest algorithm used by the signature algorithm.
        // TODO(jooyung) 6. Verify that the computed digest is identical to the corresponding digest from digests.
        // TODO(jooyung) 7. Verify that SubjectPublicKeyInfo of the first certificate of certificates is identical to public key.
        // TODO(jooyung) 8. If the proof-of-rotation attribute exists for the signer verify that the struct is valid and this signer is the last certificate in the list.
        Ok(())
    }
}

fn verify_data(_data: &Bytes, _signature: &Signature, _public_key: &Bytes) -> Result<()> {
    // TODO(jooyung): verify signed_data with signature/public key
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
