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

//! Generation of certificates and attestation extensions.

use alloc::vec;
use der::{
    asn1::{BitStringRef, ObjectIdentifier, UIntRef},
    oid::AssociatedOid,
    Decode, Sequence,
};
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};
use x509_cert::{
    certificate::{Certificate, TbsCertificate, Version},
    ext::Extension,
    name::Name,
    time::Validity,
};

/// OID value for ECDSA with SHA-256, see RFC 5912 s6.
const ECDSA_WITH_SHA_256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// OID value for the protected VM remote attestation extension.
///
/// This OID value was added at cl/584542390.
const AVF_ATTESTATION_EXTENSION_V1: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.1.29.1");

/// Attestation extension contents
///
/// ```asn1
/// AttestationDescription ::= SEQUENCE {
///     attestationChallenge       OCTET_STRING,
/// }
/// ```
/// TODO(b/312448064): Add VM root of trust and payload information to the extension.
#[derive(Debug, Clone, Sequence)]
pub(crate) struct AttestationExtension<'a> {
    #[asn1(type = "OCTET STRING")]
    attestation_challenge: &'a [u8],
    /// Indicates whether the VM is operating under a secure configuration.
    is_vm_secure: bool,
}

impl<'a> AssociatedOid for AttestationExtension<'a> {
    const OID: ObjectIdentifier = AVF_ATTESTATION_EXTENSION_V1;
}

impl<'a> AttestationExtension<'a> {
    pub(crate) fn new(attestation_challenge: &'a [u8], is_vm_secure: bool) -> Self {
        Self { attestation_challenge, is_vm_secure }
    }
}

/// Builds an X.509 `Certificate` as defined in RFC 5280 Section 4.1:
///
/// ```asn1
/// Certificate  ::=  SEQUENCE  {
///   tbsCertificate       TBSCertificate,
///   signatureAlgorithm   AlgorithmIdentifier,
///   signature            BIT STRING
/// }
/// ```
pub(crate) fn build_certificate<'a>(
    tbs_cert: TbsCertificate<'a>,
    signature: &'a [u8],
) -> der::Result<Certificate<'a>> {
    Ok(Certificate {
        signature_algorithm: tbs_cert.signature,
        tbs_certificate: tbs_cert,
        signature: BitStringRef::new(0, signature)?,
    })
}

/// Builds an X.509 `TbsCertificate` as defined in RFC 5280 Section 4.1:
///
/// ```asn1
/// TBSCertificate  ::=  SEQUENCE  {
///   version         [0]  EXPLICIT Version DEFAULT v1,
///   serialNumber         CertificateSerialNumber,
///   signature            AlgorithmIdentifier,
///   issuer               Name,
///   validity             Validity,
///   subject              Name,
///   subjectPublicKeyInfo SubjectPublicKeyInfo,
///   issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
///                        -- If present, version MUST be v2 or v3
///   subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
///                        -- If present, version MUST be v2 or v3
///   extensions      [3]  Extensions OPTIONAL
///                        -- If present, version MUST be v3 --
/// }
/// ```
pub(crate) fn build_tbs_certificate<'a>(
    serial_number: &'a [u8],
    issuer: Name<'a>,
    subject: Name<'a>,
    validity: Validity,
    subject_public_key_info: &'a [u8],
    attestation_ext: &'a [u8],
) -> der::Result<TbsCertificate<'a>> {
    let signature = AlgorithmIdentifier { oid: ECDSA_WITH_SHA_256, parameters: None };
    let subject_public_key_info = SubjectPublicKeyInfo::from_der(subject_public_key_info)?;
    let extensions = vec![Extension {
        extn_id: AttestationExtension::OID,
        critical: false,
        extn_value: attestation_ext,
    }];
    Ok(TbsCertificate {
        version: Version::V3,
        serial_number: UIntRef::new(serial_number)?,
        signature,
        issuer,
        validity,
        subject,
        subject_public_key_info,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
    })
}
