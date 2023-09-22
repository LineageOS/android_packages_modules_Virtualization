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
//! service VM via the RKP (Remote Key Provisioning) server.

use super::ec_key::EcKey;
use alloc::vec::Vec;
use core::result;
use diced_open_dice::DiceArtifacts;
use service_vm_comm::{EcdsaP256KeyPair, GenerateCertificateRequestParams, RequestProcessingError};

type Result<T> = result::Result<T, RequestProcessingError>;

pub(super) fn generate_ecdsa_p256_key_pair(
    _dice_artifacts: &dyn DiceArtifacts,
) -> Result<EcdsaP256KeyPair> {
    let ec_key = EcKey::new_p256()?;

    // TODO(b/279425980): Encrypt the private key in a key blob.
    // Remove the printing of the private key.
    log::debug!("Private key: {:?}", ec_key.private_key()?.as_slice());

    // TODO(b/300068317): Build MACed public key.
    let key_pair = EcdsaP256KeyPair { maced_public_key: Vec::new(), key_blob: Vec::new() };
    Ok(key_pair)
}

pub(super) fn generate_certificate_request(
    _params: GenerateCertificateRequestParams,
    _dice_artifacts: &dyn DiceArtifacts,
) -> Result<Vec<u8>> {
    // TODO(b/299256925): Generate the certificate request
    Ok(Vec::new())
}
