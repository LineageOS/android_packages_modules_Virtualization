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
//! client VM.

use crate::keyblob::decrypt_private_key;
use alloc::vec::Vec;
use bssl_avf::{sha256, EcKey};
use core::result;
use coset::{CborSerializable, CoseSign};
use diced_open_dice::DiceArtifacts;
use log::error;
use service_vm_comm::{ClientVmAttestationParams, Csr, CsrPayload, RequestProcessingError};

type Result<T> = result::Result<T, RequestProcessingError>;

const ATTESTATION_KEY_SIGNATURE_INDEX: usize = 1;

pub(super) fn request_attestation(
    params: ClientVmAttestationParams,
    dice_artifacts: &dyn DiceArtifacts,
) -> Result<Vec<u8>> {
    let csr = Csr::from_cbor_slice(&params.csr)?;
    let cose_sign = CoseSign::from_slice(&csr.signed_csr_payload)?;
    let csr_payload = cose_sign.payload.as_ref().ok_or_else(|| {
        error!("No CsrPayload found in the CSR");
        RequestProcessingError::InternalError
    })?;
    let csr_payload = CsrPayload::from_cbor_slice(csr_payload)?;

    // AAD is empty as defined in service_vm/comm/client_vm_csr.cddl.
    let aad = &[];

    // TODO(b/310931749): Verify the first signature with CDI_Leaf_Pub of
    // the DICE chain in `cose_sign`.

    let ec_public_key = EcKey::from_cose_public_key(&csr_payload.public_key)?;
    cose_sign.verify_signature(ATTESTATION_KEY_SIGNATURE_INDEX, aad, |signature, message| {
        ecdsa_verify(&ec_public_key, signature, message)
    })?;

    // TODO(b/278717513): Compare client VM's DICE chain in the `csr` up to pvmfw
    // cert with RKP VM's DICE chain.

    let private_key =
        decrypt_private_key(&params.remotely_provisioned_key_blob, dice_artifacts.cdi_seal())
            .map_err(|e| {
                error!("Failed to decrypt the remotely provisioned key blob: {e}");
                RequestProcessingError::FailedToDecryptKeyBlob
            })?;
    let _ec_private_key = EcKey::from_ec_private_key(private_key.as_slice())?;

    // TODO(b/309441500): Build a new certificate signed with the remotely provisioned
    // `_private_key`.
    Err(RequestProcessingError::OperationUnimplemented)
}

fn ecdsa_verify(key: &EcKey, signature: &[u8], message: &[u8]) -> bssl_avf::Result<()> {
    // The message was signed with ECDSA with curve P-256 and SHA-256 at the signature generation.
    let digest = sha256(message)?;
    key.ecdsa_verify(signature, &digest)
}
