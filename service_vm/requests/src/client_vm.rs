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
use bssl_avf::EcKey;
use core::result;
use coset::{CborSerializable, CoseSign};
use diced_open_dice::DiceArtifacts;
use log::error;
use service_vm_comm::{ClientVmAttestationParams, Csr, RequestProcessingError};

type Result<T> = result::Result<T, RequestProcessingError>;

pub(super) fn request_attestation(
    params: ClientVmAttestationParams,
    dice_artifacts: &dyn DiceArtifacts,
) -> Result<Vec<u8>> {
    let csr = Csr::from_cbor_slice(&params.csr)?;
    let _cose_sign = CoseSign::from_slice(&csr.signed_csr_payload)?;
    // TODO(b/309440321): Verify the signatures in the `_cose_sign`.

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
