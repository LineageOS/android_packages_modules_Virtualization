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

//! This module contains the requests and responses definitions exchanged
//! between the host and the service VM.

use alloc::vec::Vec;
use core::fmt;
use log::error;
use serde::{Deserialize, Serialize};

type MacedPublicKey = Vec<u8>;

/// The main request type to be sent to the service VM.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ServiceVmRequest {
    /// A request to be processed by the service VM.
    ///
    /// Each request has a corresponding response item.
    Process(Request),

    /// Shuts down the service VM. No response is expected from it.
    Shutdown,
}

/// Represents a process request to be sent to the service VM.
///
/// Each request has a corresponding response item.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Request {
    /// Reverse the order of the bytes in the provided byte array.
    /// Currently this is only used for testing.
    Reverse(Vec<u8>),

    /// Generates a new ECDSA P-256 key pair that can be attested by the remote
    /// server.
    GenerateEcdsaP256KeyPair,

    /// Creates a certificate signing request to be sent to the
    /// provisioning server.
    GenerateCertificateRequest(GenerateCertificateRequestParams),
}

/// Represents a response to a request sent to the service VM.
///
/// Each response corresponds to a specific request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    /// Reverse the order of the bytes in the provided byte array.
    Reverse(Vec<u8>),

    /// Returns the new ECDSA P-256 key pair.
    GenerateEcdsaP256KeyPair(EcdsaP256KeyPair),

    /// Returns a CBOR Certificate Signing Request (Csr) serialized into a byte array.
    GenerateCertificateRequest(Vec<u8>),

    /// Encountered an error during the request processing.
    Err(RequestProcessingError),
}

/// BoringSSL API names.
#[allow(missing_docs)]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BoringSSLApiName {
    BN_new,
    BN_bn2bin_padded,
    CBB_flush,
    CBB_len,
    EC_KEY_check_key,
    EC_KEY_generate_key,
    EC_KEY_get0_group,
    EC_KEY_get0_public_key,
    EC_KEY_marshal_private_key,
    EC_KEY_new_by_curve_name,
    EC_POINT_get_affine_coordinates,
    EVP_sha256,
    HMAC,
}

/// Errors related to request processing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequestProcessingError {
    /// Failed to invoke a BoringSSL API.
    BoringSSLCallFailed(BoringSSLApiName),

    /// An error happened during the interaction with coset.
    CosetError,

    /// Any key to sign lacks a valid MAC. Maps to `STATUS_INVALID_MAC`.
    InvalidMac,

    /// No payload found in a key to sign.
    KeyToSignHasEmptyPayload,

    /// An error happened when serializing to/from a `Value`.
    CborValueError,
}

impl fmt::Display for RequestProcessingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::BoringSSLCallFailed(api_name) => {
                write!(f, "Failed to invoke a BoringSSL API: {api_name:?}")
            }
            Self::CosetError => write!(f, "Encountered an error with coset"),
            Self::InvalidMac => write!(f, "A key to sign lacks a valid MAC."),
            Self::KeyToSignHasEmptyPayload => write!(f, "No payload found in a key to sign."),
            Self::CborValueError => {
                write!(f, "An error happened when serializing to/from a CBOR Value.")
            }
        }
    }
}

impl From<coset::CoseError> for RequestProcessingError {
    fn from(e: coset::CoseError) -> Self {
        error!("Coset error: {e}");
        Self::CosetError
    }
}

impl From<ciborium::value::Error> for RequestProcessingError {
    fn from(e: ciborium::value::Error) -> Self {
        error!("CborValueError: {e}");
        Self::CborValueError
    }
}

/// Represents the params passed to GenerateCertificateRequest
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenerateCertificateRequestParams {
    /// Contains the set of keys to certify.
    pub keys_to_sign: Vec<MacedPublicKey>,

    /// challenge contains a byte strong from the provisioning server which will be
    /// included in the signed data of the CSR structure.
    /// The supported sizes is between 0 and 64 bytes, inclusive.
    pub challenge: Vec<u8>,
}

/// Represents an ECDSA P-256 key pair.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcdsaP256KeyPair {
    /// Contains a CBOR-encoded public key specified in:
    ///
    /// hardware/interfaces/security/rkp/aidl/android/hardware/security/keymint/MacedPublicKey.aidl
    pub maced_public_key: MacedPublicKey,

    /// Contains a handle to the private key.
    pub key_blob: Vec<u8>,
}
