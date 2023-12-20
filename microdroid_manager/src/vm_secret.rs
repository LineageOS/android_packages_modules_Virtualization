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

//! Class for encapsulating & managing represent VM secrets.

use anyhow::{anyhow, ensure, Result};
use android_system_virtualmachineservice::aidl::android::system::virtualmachineservice::IVirtualMachineService::IVirtualMachineService;
use android_hardware_security_secretkeeper::aidl::android::hardware::security::secretkeeper::ISecretkeeper::ISecretkeeper;
use secretkeeper_comm::data_types::request::Request;
use binder::{Strong};
use coset::CborSerializable;
use diced_open_dice::{DiceArtifacts, OwnedDiceArtifacts};
use keystore2_crypto::ZVec;
use openssl::hkdf::hkdf;
use openssl::md::Md;
use openssl::sha;
use secretkeeper_client::SkSession;
use secretkeeper_comm::data_types::{Id, ID_SIZE, Secret, SECRET_SIZE};
use secretkeeper_comm::data_types::response::Response;
use secretkeeper_comm::data_types::packet::{ResponsePacket, ResponseType};
use secretkeeper_comm::data_types::request_response_impl::{
    StoreSecretRequest, GetSecretResponse, GetSecretRequest};
use secretkeeper_comm::data_types::error::SecretkeeperError;
use zeroize::Zeroizing;

const ENCRYPTEDSTORE_KEY_IDENTIFIER: &str = "encryptedstore_key";

// Generated using hexdump -vn32 -e'14/1 "0x%02X, " 1 "\n"' /dev/urandom
const SALT_ENCRYPTED_STORE: &[u8] = &[
    0xFC, 0x1D, 0x35, 0x7B, 0x96, 0xF3, 0xEF, 0x17, 0x78, 0x7D, 0x70, 0xED, 0xEA, 0xFE, 0x1D, 0x6F,
    0xB3, 0xF9, 0x40, 0xCE, 0xDD, 0x99, 0x40, 0xAA, 0xA7, 0x0E, 0x92, 0x73, 0x90, 0x86, 0x4A, 0x75,
];
const SALT_PAYLOAD_SERVICE: &[u8] = &[
    0x8B, 0x0F, 0xF0, 0xD3, 0xB1, 0x69, 0x2B, 0x95, 0x84, 0x2C, 0x9E, 0x3C, 0x99, 0x56, 0x7A, 0x22,
    0x55, 0xF8, 0x08, 0x23, 0x81, 0x5F, 0xF5, 0x16, 0x20, 0x3E, 0xBE, 0xBA, 0xB7, 0xA8, 0x43, 0x92,
];

// TODO(b/291213394): Remove this once policy is generated from dice_chain
const HYPOTHETICAL_DICE_POLICY: [u8; 43] = [
    0x83, 0x01, 0x81, 0x83, 0x01, 0x80, 0xA1, 0x01, 0x00, 0x82, 0x83, 0x01, 0x81, 0x01, 0x73, 0x74,
    0x65, 0x73, 0x74, 0x69, 0x6E, 0x67, 0x5F, 0x64, 0x69, 0x63, 0x65, 0x5F, 0x70, 0x6F, 0x6C, 0x69,
    0x63, 0x79, 0x83, 0x02, 0x82, 0x03, 0x18, 0x64, 0x19, 0xE9, 0x75,
];
// TODO(b/291213394): Differentiate the Id of nPVM based on 'salt'
const ID_NP_VM: [u8; ID_SIZE] = [
    0xF1, 0xB2, 0xED, 0x3B, 0xD1, 0xBD, 0xF0, 0x7D, 0xE1, 0xF0, 0x01, 0xFC, 0x61, 0x71, 0xD3, 0x42,
    0xE5, 0x8A, 0xAF, 0x33, 0x6C, 0x11, 0xDC, 0xC8, 0x6F, 0xAE, 0x12, 0x5C, 0x26, 0x44, 0x6B, 0x86,
    0xCC, 0x24, 0xFD, 0xBF, 0x91, 0x4A, 0x54, 0x84, 0xF9, 0x01, 0x59, 0x25, 0x70, 0x89, 0x38, 0x8D,
    0x5E, 0xE6, 0x91, 0xDF, 0x68, 0x60, 0x69, 0x26, 0xBE, 0xFE, 0x79, 0x58, 0xF7, 0xEA, 0x81, 0x7D,
];
const SKP_SECRET_NP_VM: [u8; SECRET_SIZE] = [
    0xA9, 0x89, 0x97, 0xFE, 0xAE, 0x97, 0x55, 0x4B, 0x32, 0x35, 0xF0, 0xE8, 0x93, 0xDA, 0xEA, 0x24,
    0x06, 0xAC, 0x36, 0x8B, 0x3C, 0x95, 0x50, 0x16, 0x67, 0x71, 0x65, 0x26, 0xEB, 0xD0, 0xC3, 0x98,
];

pub enum VmSecret {
    // V2 secrets are derived from 2 independently secured secrets:
    //      1. Secretkeeper protected secrets (skp secret).
    //      2. Dice Sealing CDIs (Similar to V1).
    //
    // These are protected against rollback of boot images i.e. VM instance rebooted
    // with downgraded images will not have access to VM's secret.
    // V2 secrets require hardware support - Secretkeeper HAL, which (among other things)
    // is backed by tamper-evident storage, providing rollback protection to these secrets.
    V2 { dice: OwnedDiceArtifacts, skp_secret: ZVec },
    // V1 secrets are not protected against rollback of boot images.
    // They are reliable only if rollback of images was prevented by verified boot ie,
    // each stage (including pvmfw/Microdroid/Microdroid Manager) prevents downgrade of next
    // stage. These are now legacy secrets & used only when Secretkeeper HAL is not supported
    // by device.
    V1 { dice: OwnedDiceArtifacts },
}

fn get_id() -> [u8; ID_SIZE] {
    if super::is_strict_boot() {
        todo!("Id for protected VM is not implemented");
    } else {
        ID_NP_VM
    }
}

impl VmSecret {
    pub fn new(
        dice_artifacts: OwnedDiceArtifacts,
        vm_service: &Strong<dyn IVirtualMachineService>,
    ) -> Result<VmSecret> {
        ensure!(dice_artifacts.bcc().is_some(), "Dice chain missing");

        if let Some(sk_service) = is_sk_supported(vm_service)? {
            let id = get_id();
            let mut skp_secret = Zeroizing::new([0u8; SECRET_SIZE]);
            if super::is_strict_boot() {
                if super::is_new_instance() {
                    *skp_secret = rand::random();
                    store_secret(sk_service.clone(), id, skp_secret.clone(), &dice_artifacts)?;
                } else {
                    // Subsequent run of the pVM -> get the secret stored in Secretkeeper.
                    *skp_secret = get_secret(sk_service.clone(), id, &dice_artifacts)?;
                }
            } else {
                // TODO(b/291213394): Non protected VM don't need to use Secretkeeper, remove this
                // once we have sufficient testing on protected VM.
                store_secret(sk_service.clone(), id, SKP_SECRET_NP_VM.into(), &dice_artifacts)?;
                *skp_secret = get_secret(sk_service.clone(), id, &dice_artifacts)?;
            }
            return Ok(Self::V2 {
                dice: dice_artifacts,
                skp_secret: ZVec::try_from(skp_secret.to_vec())?,
            });
        }
        //  Use V1 secrets if Secretkeeper is not supported.
        Ok(Self::V1 { dice: dice_artifacts })
    }

    pub fn dice(&self) -> &OwnedDiceArtifacts {
        match self {
            Self::V2 { dice, .. } => dice,
            Self::V1 { dice } => dice,
        }
    }

    fn get_vm_secret(&self, salt: &[u8], identifier: &[u8], key: &mut [u8]) -> Result<()> {
        match self {
            Self::V2 { dice, skp_secret } => {
                let mut hasher = sha::Sha256::new();
                hasher.update(dice.cdi_seal());
                hasher.update(skp_secret);
                hkdf(key, Md::sha256(), &hasher.finish(), salt, identifier)?
            }
            Self::V1 { dice } => hkdf(key, Md::sha256(), dice.cdi_seal(), salt, identifier)?,
        }
        Ok(())
    }

    /// Derive sealing key for payload with following identifier.
    pub fn derive_payload_sealing_key(&self, identifier: &[u8], key: &mut [u8]) -> Result<()> {
        self.get_vm_secret(SALT_PAYLOAD_SERVICE, identifier, key)
    }

    /// Derive encryptedstore key. This uses hardcoded random salt & fixed identifier.
    pub fn derive_encryptedstore_key(&self, key: &mut [u8]) -> Result<()> {
        self.get_vm_secret(SALT_ENCRYPTED_STORE, ENCRYPTEDSTORE_KEY_IDENTIFIER.as_bytes(), key)
    }
}

fn store_secret(
    secretkeeper: binder::Strong<dyn ISecretkeeper>,
    id: [u8; ID_SIZE],
    secret: Zeroizing<[u8; SECRET_SIZE]>,
    _dice_chain: &OwnedDiceArtifacts,
) -> Result<()> {
    // Start a new secretkeeper session!
    let mut session = SkSession::new(secretkeeper).map_err(anyhow_err)?;
    let store_request = StoreSecretRequest {
        id: Id(id),
        secret: Secret(*secret),
        // TODO(b/291233371): Construct policy out of dice_chain.
        sealing_policy: HYPOTHETICAL_DICE_POLICY.to_vec(),
    };
    log::info!("Secretkeeper operation: {:?}", store_request);

    let store_request = store_request.serialize_to_packet().to_vec().map_err(anyhow_err)?;
    let store_response = session.secret_management_request(&store_request).map_err(anyhow_err)?;
    let store_response = ResponsePacket::from_slice(&store_response).map_err(anyhow_err)?;
    let response_type = store_response.response_type().map_err(anyhow_err)?;
    ensure!(
        response_type == ResponseType::Success,
        "Secretkeeper store failed with error: {:?}",
        *SecretkeeperError::deserialize_from_packet(store_response).map_err(anyhow_err)?
    );
    Ok(())
}

fn get_secret(
    secretkeeper: binder::Strong<dyn ISecretkeeper>,
    id: [u8; ID_SIZE],
    _dice_chain: &OwnedDiceArtifacts,
) -> Result<[u8; SECRET_SIZE]> {
    // Start a new secretkeeper session!
    let mut session = SkSession::new(secretkeeper).map_err(anyhow_err)?;
    let get_request = GetSecretRequest {
        id: Id(id),
        // TODO(b/291233371): Construct policy out of dice_chain.
        updated_sealing_policy: None,
    };
    log::info!("Secretkeeper operation: {:?}", get_request);

    let get_request = get_request.serialize_to_packet().to_vec().map_err(anyhow_err)?;
    let get_response = session.secret_management_request(&get_request).map_err(anyhow_err)?;
    let get_response = ResponsePacket::from_slice(&get_response).map_err(anyhow_err)?;
    let response_type = get_response.response_type().map_err(anyhow_err)?;
    ensure!(
        response_type == ResponseType::Success,
        "Secretkeeper get failed with error: {:?}",
        *SecretkeeperError::deserialize_from_packet(get_response).map_err(anyhow_err)?
    );
    let get_response =
        *GetSecretResponse::deserialize_from_packet(get_response).map_err(anyhow_err)?;
    Ok(get_response.secret.0)
}

#[inline]
fn anyhow_err<E: core::fmt::Debug>(err: E) -> anyhow::Error {
    anyhow!("{:?}", err)
}

// Get the secretkeeper connection if supported. Host can be consulted whether the device supports
// secretkeeper but that should be used with caution for protected VM.
fn is_sk_supported(
    host: &Strong<dyn IVirtualMachineService>,
) -> Result<Option<Strong<dyn ISecretkeeper>>> {
    let sk = if cfg!(llpvm_changes) {
        if super::is_strict_boot() {
            // TODO: For protected VM check for Secretkeeper authentication data in device tree.
            None
        } else {
            // For non-protected VM, believe what host claims.
            host.getSecretkeeper()
                // TODO rename this error!
                .map_err(|e| {
                    super::MicrodroidError::FailedToConnectToVirtualizationService(e.to_string())
                })?
        }
    } else {
        // LLPVM flag is disabled
        None
    };
    Ok(sk)
}
