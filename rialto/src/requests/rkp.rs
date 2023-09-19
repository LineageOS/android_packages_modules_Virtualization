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

//! This module contains functions related to the attestation of the
//! service VM via the RKP (Remote Key Provisionning) server.

use alloc::vec::Vec;
use core::result;
use service_vm_comm::{EcdsaP256KeyPair, GenerateCertificateRequestParams, RequestProcessingError};

type Result<T> = result::Result<T, RequestProcessingError>;

pub(super) fn generate_ecdsa_p256_key_pair() -> Result<EcdsaP256KeyPair> {
    // TODO(b/299055662): Generate the key pair.
    let key_pair = EcdsaP256KeyPair { maced_public_key: Vec::new(), key_blob: Vec::new() };
    Ok(key_pair)
}

pub(super) fn generate_certificate_request(
    _params: GenerateCertificateRequestParams,
) -> Result<Vec<u8>> {
    // TODO(b/299256925): Generate the certificate request
    Ok(Vec::new())
}
