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

//! Algorithms used for APK Signature Scheme.

use anyhow::{bail, ensure, Result};
use num_derive::FromPrimitive;
use openssl::hash::MessageDigest;
use openssl::pkey::{self, PKey};
use openssl::rsa::Padding;
use openssl::sign::Verifier;
use std::cmp::Ordering;

/// [Signature Algorithm IDs]: https://source.android.com/docs/security/apksigning/v2#signature-algorithm-ids
///
/// Some of the algorithms are not implemented. See b/197052981.
#[derive(Clone, Debug, Eq, FromPrimitive)]
#[repr(u32)]
pub enum SignatureAlgorithmID {
    RsaPssWithSha256 = 0x0101,
    RsaPssWithSha512 = 0x0102,
    RsaPkcs1V15WithSha256 = 0x0103,
    RsaPkcs1V15WithSha512 = 0x0104,
    EcdsaWithSha256 = 0x0201,
    EcdsaWithSha512 = 0x0202,
    DsaWithSha256 = 0x0301,
    VerityRsaPkcs1V15WithSha256 = 0x0421,
    VerityEcdsaWithSha256 = 0x0423,
    VerityDsaWithSha256 = 0x0425,
}

impl Ord for SignatureAlgorithmID {
    /// Ranks the signature algorithm according to the corresponding content
    /// digest algorithm's rank.
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_content_digest_algorithm().cmp(&other.to_content_digest_algorithm())
    }
}

impl PartialOrd for SignatureAlgorithmID {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for SignatureAlgorithmID {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl SignatureAlgorithmID {
    pub(crate) fn to_content_digest_algorithm(&self) -> ContentDigestAlgorithm {
        match self {
            SignatureAlgorithmID::RsaPssWithSha256
            | SignatureAlgorithmID::RsaPkcs1V15WithSha256
            | SignatureAlgorithmID::EcdsaWithSha256
            | SignatureAlgorithmID::DsaWithSha256 => ContentDigestAlgorithm::ChunkedSha256,
            SignatureAlgorithmID::RsaPssWithSha512
            | SignatureAlgorithmID::RsaPkcs1V15WithSha512
            | SignatureAlgorithmID::EcdsaWithSha512 => ContentDigestAlgorithm::ChunkedSha512,
            SignatureAlgorithmID::VerityRsaPkcs1V15WithSha256
            | SignatureAlgorithmID::VerityEcdsaWithSha256
            | SignatureAlgorithmID::VerityDsaWithSha256 => {
                ContentDigestAlgorithm::VerityChunkedSha256
            }
        }
    }

    pub(crate) fn new_verifier<'a>(
        &self,
        public_key: &'a PKey<pkey::Public>,
    ) -> Result<Verifier<'a>> {
        ensure!(
            !matches!(
                self,
                SignatureAlgorithmID::DsaWithSha256 | SignatureAlgorithmID::VerityDsaWithSha256
            ),
            "TODO(b/197052981): Algorithm '{:#?}' is not implemented.",
            self
        );
        ensure!(public_key.id() == self.pkey_id(), "Public key has the wrong ID");
        let mut verifier = Verifier::new(self.new_message_digest(), public_key)?;
        if public_key.id() == pkey::Id::RSA {
            verifier.set_rsa_padding(self.rsa_padding())?;
        }
        Ok(verifier)
    }

    /// Returns the message digest corresponding to the signature algorithm
    /// according to the spec [Signature Algorithm IDs].
    fn new_message_digest(&self) -> MessageDigest {
        match self {
            SignatureAlgorithmID::RsaPssWithSha256
            | SignatureAlgorithmID::RsaPkcs1V15WithSha256
            | SignatureAlgorithmID::EcdsaWithSha256
            | SignatureAlgorithmID::DsaWithSha256
            | SignatureAlgorithmID::VerityRsaPkcs1V15WithSha256
            | SignatureAlgorithmID::VerityEcdsaWithSha256
            | SignatureAlgorithmID::VerityDsaWithSha256 => MessageDigest::sha256(),
            SignatureAlgorithmID::RsaPssWithSha512
            | SignatureAlgorithmID::RsaPkcs1V15WithSha512
            | SignatureAlgorithmID::EcdsaWithSha512 => MessageDigest::sha512(),
        }
    }

    fn pkey_id(&self) -> pkey::Id {
        match self {
            SignatureAlgorithmID::RsaPssWithSha256
            | SignatureAlgorithmID::RsaPssWithSha512
            | SignatureAlgorithmID::RsaPkcs1V15WithSha256
            | SignatureAlgorithmID::RsaPkcs1V15WithSha512
            | SignatureAlgorithmID::VerityRsaPkcs1V15WithSha256 => pkey::Id::RSA,
            SignatureAlgorithmID::EcdsaWithSha256
            | SignatureAlgorithmID::EcdsaWithSha512
            | SignatureAlgorithmID::VerityEcdsaWithSha256 => pkey::Id::EC,
            SignatureAlgorithmID::DsaWithSha256 | SignatureAlgorithmID::VerityDsaWithSha256 => {
                pkey::Id::DSA
            }
        }
    }

    fn rsa_padding(&self) -> Padding {
        match self {
            SignatureAlgorithmID::RsaPssWithSha256 | SignatureAlgorithmID::RsaPssWithSha512 => {
                Padding::PKCS1_PSS
            }
            SignatureAlgorithmID::RsaPkcs1V15WithSha256
            | SignatureAlgorithmID::VerityRsaPkcs1V15WithSha256
            | SignatureAlgorithmID::RsaPkcs1V15WithSha512 => Padding::PKCS1,
            SignatureAlgorithmID::EcdsaWithSha256
            | SignatureAlgorithmID::EcdsaWithSha512
            | SignatureAlgorithmID::VerityEcdsaWithSha256
            | SignatureAlgorithmID::DsaWithSha256
            | SignatureAlgorithmID::VerityDsaWithSha256 => Padding::NONE,
        }
    }
}

/// The rank of the content digest algorithm in this enum is used to help pick
/// v4 apk digest.
/// According to APK Signature Scheme v4, [apk digest] is the first available
/// content digest of the highest rank (rank N).
///
/// This rank was also used for step 3a of the v3 signature verification.
///
/// [apk digest]: https://source.android.com/docs/security/features/apksigning/v4#apk-digest
/// [v3 verification]: https://source.android.com/docs/security/apksigning/v3#v3-verification
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ContentDigestAlgorithm {
    ChunkedSha256 = 1,
    VerityChunkedSha256,
    ChunkedSha512,
}

impl ContentDigestAlgorithm {
    pub(crate) fn new_message_digest(&self) -> Result<MessageDigest> {
        match self {
            ContentDigestAlgorithm::ChunkedSha256 => Ok(MessageDigest::sha256()),
            ContentDigestAlgorithm::ChunkedSha512 => Ok(MessageDigest::sha512()),
            ContentDigestAlgorithm::VerityChunkedSha256 => {
                bail!("TODO(b/197052981): CONTENT_DIGEST_VERITY_CHUNKED_SHA256 is not implemented")
            }
        }
    }
}
