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

use crate::cert;
use crate::dice::{validate_client_vm_dice_chain_prefix_match, ClientVmDiceChain};
use crate::keyblob::decrypt_private_key;
use alloc::vec::Vec;
use bssl_avf::{rand_bytes, sha256, EcKey, PKey};
use core::result;
use coset::{CborSerializable, CoseSign};
use der::{Decode, Encode};
use diced_open_dice::DiceArtifacts;
use log::error;
use service_vm_comm::{ClientVmAttestationParams, Csr, CsrPayload, RequestProcessingError};
use x509_cert::{certificate::Certificate, name::Name};

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

    // Validates the prefix of the Client VM DICE chain in the CSR.
    let service_vm_dice_chain =
        dice_artifacts.bcc().ok_or(RequestProcessingError::MissingDiceChain)?;
    let client_vm_dice_chain =
        validate_client_vm_dice_chain_prefix_match(&csr.dice_cert_chain, service_vm_dice_chain)?;
    // Validates the signatures in the Client VM DICE chain and extracts the partially decoded
    // DiceChainEntryPayloads.
    let client_vm_dice_chain =
        ClientVmDiceChain::validate_signatures_and_parse_dice_chain(client_vm_dice_chain)?;

    // AAD is empty as defined in service_vm/comm/client_vm_csr.cddl.
    let aad = &[];

    // Verifies the first signature with the leaf private key in the DICE chain.
    // TODO(b/310931749): Verify the first signature with CDI_Leaf_Pub of
    // the DICE chain in `cose_sign`.

    // Verifies the second signature with the public key in the CSR payload.
    let ec_public_key = EcKey::from_cose_public_key(&csr_payload.public_key)?;
    cose_sign.verify_signature(ATTESTATION_KEY_SIGNATURE_INDEX, aad, |signature, message| {
        ecdsa_verify(&ec_public_key, signature, message)
    })?;
    let subject_public_key_info = PKey::try_from(ec_public_key)?.subject_public_key_info()?;

    // Builds the TBSCertificate.
    // The serial number can be up to 20 bytes according to RFC5280 s4.1.2.2.
    // In this case, a serial number with a length of 20 bytes is used to ensure that each
    // certificate signed by RKP VM has a unique serial number.
    let mut serial_number = [0u8; 20];
    rand_bytes(&mut serial_number)?;
    let subject = Name::encode_from_string("CN=Android Protected Virtual Machine Key")?;
    let rkp_cert = Certificate::from_der(&params.remotely_provisioned_cert)?;
    let attestation_ext = cert::AttestationExtension::new(
        &csr_payload.challenge,
        client_vm_dice_chain.all_entries_are_secure(),
    )
    .to_vec()?;
    let tbs_cert = cert::build_tbs_certificate(
        &serial_number,
        rkp_cert.tbs_certificate.subject,
        Name::from_der(&subject)?,
        rkp_cert.tbs_certificate.validity,
        &subject_public_key_info,
        &attestation_ext,
    )?;

    // Signs the TBSCertificate and builds the Certificate.
    // The two private key structs below will be zeroed out on drop.
    let private_key =
        decrypt_private_key(&params.remotely_provisioned_key_blob, dice_artifacts.cdi_seal())
            .map_err(|e| {
                error!("Failed to decrypt the remotely provisioned key blob: {e}");
                RequestProcessingError::FailedToDecryptKeyBlob
            })?;
    let ec_private_key = EcKey::from_ec_private_key(private_key.as_slice())?;
    let signature = ecdsa_sign(&ec_private_key, &tbs_cert.to_vec()?)?;
    let certificate = cert::build_certificate(tbs_cert, &signature)?;
    Ok(certificate.to_vec()?)
}

fn ecdsa_verify(key: &EcKey, signature: &[u8], message: &[u8]) -> bssl_avf::Result<()> {
    // The message was signed with ECDSA with curve P-256 and SHA-256 at the signature generation.
    let digest = sha256(message)?;
    key.ecdsa_verify(signature, &digest)
}

fn ecdsa_sign(key: &EcKey, message: &[u8]) -> bssl_avf::Result<Vec<u8>> {
    let digest = sha256(message)?;
    key.ecdsa_sign(&digest)
}
