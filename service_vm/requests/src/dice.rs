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

//! This module contains functions related to DICE.

use alloc::vec::Vec;
use ciborium::value::Value;
use core::cell::OnceCell;
use core::result;
use coset::{
    self, iana, AsCborValue, CborSerializable, CoseError, CoseKey, CoseSign1, KeyOperation,
};
use diced_open_dice::{DiceMode, HASH_SIZE};
use log::error;
use service_vm_comm::{cbor_value_type, try_as_bytes, RequestProcessingError};

type Result<T> = result::Result<T, RequestProcessingError>;

const CODE_HASH: i64 = -4670545;
const CONFIG_DESC: i64 = -4670548;
const AUTHORITY_HASH: i64 = -4670549;
const MODE: i64 = -4670551;
const SUBJECT_PUBLIC_KEY: i64 = -4670552;

/// Represents a partially decoded `DiceCertChain` from the client VM.
/// The whole chain is defined as following:
///
/// DiceCertChain = [
///     PubKeyEd25519 / PubKeyECDSA256 / PubKeyECDSA384,  ; UDS_Pub
///     + DiceChainEntry,               ; First CDI_Certificate -> Last CDI_Certificate
/// ]
#[derive(Debug, Clone)]
pub(crate) struct ClientVmDiceChain {
    pub(crate) payloads: Vec<DiceChainEntryPayload>,
}

impl ClientVmDiceChain {
    /// Validates the signatures of the entries in the `client_vm_dice_chain` as following:
    ///
    /// - The first entry of the `client_vm_dice_chain` must be signed with the root public key.
    /// - After the first entry, each entry of the `client_vm_dice_chain` must be signed with the
    ///  subject public key of the previous entry.
    ///
    /// Returns a partially decoded client VM's DICE chain if the verification succeeds.
    pub(crate) fn validate_signatures_and_parse_dice_chain(
        mut client_vm_dice_chain: Vec<Value>,
    ) -> Result<Self> {
        let root_public_key =
            CoseKey::from_cbor_value(client_vm_dice_chain.remove(0))?.try_into()?;

        let mut payloads = Vec::with_capacity(client_vm_dice_chain.len());
        let mut previous_public_key = &root_public_key;
        for (i, value) in client_vm_dice_chain.into_iter().enumerate() {
            let payload = DiceChainEntryPayload::validate_cose_signature_and_extract_payload(
                value,
                previous_public_key,
            )
            .map_err(|e| {
                error!("Failed to verify the DICE chain entry {}: {:?}", i, e);
                e
            })?;
            payloads.push(payload);
            previous_public_key = &payloads.last().unwrap().subject_public_key;
        }
        // After successfully calling `validate_client_vm_dice_chain_prefix_match`, we can be
        // certain that the client VM's DICE chain must contain at least three entries that
        // describe:
        // - pvmfw
        // - Microdroid kernel
        // - Apk/Apexes
        assert!(
            payloads.len() >= 3,
            "The client VM DICE chain must contain at least three DiceChainEntryPayloads"
        );
        Ok(Self { payloads })
    }

    /// Returns true if all payloads in the DICE chain are in normal mode.
    pub(crate) fn all_entries_are_secure(&self) -> bool {
        self.payloads.iter().all(|p| p.mode == DiceMode::kDiceModeNormal)
    }
}

/// Validates that the `client_vm_dice_chain` matches the `service_vm_dice_chain` up to the pvmfw
/// entry.
///
/// Returns a CBOR value array of the client VM's DICE chain if the verification succeeds.
pub(crate) fn validate_client_vm_dice_chain_prefix_match(
    client_vm_dice_chain: &[u8],
    service_vm_dice_chain: &[u8],
) -> Result<Vec<Value>> {
    let client_vm_dice_chain =
        try_as_value_array(Value::from_slice(client_vm_dice_chain)?, "client_vm_dice_chain")?;
    let service_vm_dice_chain =
        try_as_value_array(Value::from_slice(service_vm_dice_chain)?, "service_vm_dice_chain")?;
    if service_vm_dice_chain.len() < 3 {
        // The service VM's DICE chain must contain the root key and at least two other entries
        // that describe:
        //   - pvmfw
        //   - Service VM kernel
        error!("The service VM DICE chain must contain at least three entries");
        return Err(RequestProcessingError::InternalError);
    }
    // Ignores the last entry that describes service VM
    let entries_up_to_pvmfw = &service_vm_dice_chain[0..(service_vm_dice_chain.len() - 1)];
    if entries_up_to_pvmfw.len() + 2 != client_vm_dice_chain.len() {
        // Client VM DICE chain = entries_up_to_pvmfw
        //    + Microdroid kernel entry (added in pvmfw)
        //    + Apk/Apexes entry (added in microdroid)
        error!("The client VM's DICE chain must contain exactly two extra entries");
        return Err(RequestProcessingError::InvalidDiceChain);
    }
    if entries_up_to_pvmfw != &client_vm_dice_chain[0..entries_up_to_pvmfw.len()] {
        error!(
            "The client VM's DICE chain does not match service VM's DICE chain up to \
             the pvmfw entry"
        );
        return Err(RequestProcessingError::InvalidDiceChain);
    }
    Ok(client_vm_dice_chain)
}

#[derive(Debug, Clone)]
pub(crate) struct PublicKey(CoseKey);

impl TryFrom<CoseKey> for PublicKey {
    type Error = RequestProcessingError;

    fn try_from(key: CoseKey) -> Result<Self> {
        if !key.key_ops.contains(&KeyOperation::Assigned(iana::KeyOperation::Verify)) {
            error!("Public key does not support verification");
            return Err(RequestProcessingError::InvalidDiceChain);
        }
        Ok(Self(key))
    }
}

/// Represents a partially decoded `DiceChainEntryPayload`. The whole payload is defined in:
///
/// hardware/interfaces/security/rkp/aidl/android/hardware/security/keymint/
/// generateCertificateRequestV2.cddl
#[derive(Debug, Clone)]
pub(crate) struct DiceChainEntryPayload {
    /// TODO(b/310931749): Verify the DICE chain entry using the subject public key.
    #[allow(dead_code)]
    subject_public_key: PublicKey,
    mode: DiceMode,
    /// TODO(b/271275206): Verify Microdroid kernel authority and code hashes.
    #[allow(dead_code)]
    code_hash: [u8; HASH_SIZE],
    #[allow(dead_code)]
    authority_hash: [u8; HASH_SIZE],
    /// TODO(b/313815907): Parse the config descriptor and read Apk/Apexes info in it.
    #[allow(dead_code)]
    config_descriptor: Vec<u8>,
}

impl DiceChainEntryPayload {
    /// Validates the signature of the provided CBOR value with the provided public key and
    /// extracts payload from the value.
    fn validate_cose_signature_and_extract_payload(
        value: Value,
        _authority_public_key: &PublicKey,
    ) -> Result<Self> {
        let cose_sign1 = CoseSign1::from_cbor_value(value)?;
        // TODO(b/310931749): Verify the DICE chain entry using `authority_public_key`.

        let payload = cose_sign1.payload.ok_or_else(|| {
            error!("No payload found in the DICE chain entry");
            RequestProcessingError::InvalidDiceChain
        })?;
        let payload = Value::from_slice(&payload)?;
        let Value::Map(entries) = payload else {
            return Err(CoseError::UnexpectedItem(cbor_value_type(&payload), "map").into());
        };
        build_payload(entries)
    }
}

fn build_payload(entries: Vec<(Value, Value)>) -> Result<DiceChainEntryPayload> {
    let mut builder = PayloadBuilder::default();
    for (key, value) in entries.into_iter() {
        let Some(Ok(key)) = key.as_integer().map(i64::try_from) else {
            error!("Invalid key found in the DICE chain entry: {:?}", key);
            return Err(RequestProcessingError::InvalidDiceChain);
        };
        match key {
            SUBJECT_PUBLIC_KEY => {
                let subject_public_key = try_as_bytes(value, "subject_public_key")?;
                let subject_public_key = CoseKey::from_slice(&subject_public_key)?.try_into()?;
                builder.subject_public_key(subject_public_key)?;
            }
            MODE => builder.mode(to_mode(value)?)?,
            CODE_HASH => builder.code_hash(try_as_byte_array(value, "code_hash")?)?,
            AUTHORITY_HASH => {
                builder.authority_hash(try_as_byte_array(value, "authority_hash")?)?
            }
            CONFIG_DESC => builder.config_descriptor(try_as_bytes(value, "config_descriptor")?)?,
            _ => {}
        }
    }
    builder.build()
}

fn try_as_value_array(v: Value, context: &str) -> coset::Result<Vec<Value>> {
    if let Value::Array(data) = v {
        Ok(data)
    } else {
        let v_type = cbor_value_type(&v);
        error!("The provided value type '{v_type}' is not of type 'bytes': {context}");
        Err(CoseError::UnexpectedItem(v_type, "array"))
    }
}

fn try_as_byte_array<const N: usize>(v: Value, context: &str) -> Result<[u8; N]> {
    let data = try_as_bytes(v, context)?;
    data.try_into().map_err(|e| {
        error!("The provided value '{context}' is not an array of length {N}: {e:?}");
        RequestProcessingError::InternalError
    })
}

fn to_mode(value: Value) -> Result<DiceMode> {
    let mode = match value {
        // Mode is supposed to be encoded as a 1-byte bstr, but some implementations instead
        // encode it as an integer. Accept either. See b/273552826.
        // If Mode is omitted, it should be treated as if it was NotConfigured, according to
        // the Open Profile for DICE spec.
        Value::Bytes(bytes) => {
            if bytes.len() != 1 {
                error!("Bytes array with invalid length for mode: {:?}", bytes.len());
                return Err(RequestProcessingError::InvalidDiceChain);
            }
            bytes[0].into()
        }
        Value::Integer(i) => i,
        v => return Err(CoseError::UnexpectedItem(cbor_value_type(&v), "bstr or int").into()),
    };
    let mode = match mode {
        x if x == (DiceMode::kDiceModeNormal as i64).into() => DiceMode::kDiceModeNormal,
        x if x == (DiceMode::kDiceModeDebug as i64).into() => DiceMode::kDiceModeDebug,
        x if x == (DiceMode::kDiceModeMaintenance as i64).into() => DiceMode::kDiceModeMaintenance,
        // If Mode is invalid, it should be treated as if it was NotConfigured, according to
        // the Open Profile for DICE spec.
        _ => DiceMode::kDiceModeNotInitialized,
    };
    Ok(mode)
}

#[derive(Default, Debug, Clone)]
struct PayloadBuilder {
    subject_public_key: OnceCell<PublicKey>,
    mode: OnceCell<DiceMode>,
    code_hash: OnceCell<[u8; HASH_SIZE]>,
    authority_hash: OnceCell<[u8; HASH_SIZE]>,
    config_descriptor: OnceCell<Vec<u8>>,
}

fn set_once<T>(field: &OnceCell<T>, value: T, field_name: &str) -> Result<()> {
    field.set(value).map_err(|_| {
        error!("Field '{field_name}' is duplicated in the Payload");
        RequestProcessingError::InvalidDiceChain
    })
}

fn take_value<T>(field: &mut OnceCell<T>, field_name: &str) -> Result<T> {
    field.take().ok_or_else(|| {
        error!("Field '{field_name}' is missing in the Payload");
        RequestProcessingError::InvalidDiceChain
    })
}

impl PayloadBuilder {
    fn subject_public_key(&mut self, key: PublicKey) -> Result<()> {
        set_once(&self.subject_public_key, key, "subject_public_key")
    }

    fn mode(&mut self, mode: DiceMode) -> Result<()> {
        set_once(&self.mode, mode, "mode")
    }

    fn code_hash(&mut self, code_hash: [u8; HASH_SIZE]) -> Result<()> {
        set_once(&self.code_hash, code_hash, "code_hash")
    }

    fn authority_hash(&mut self, authority_hash: [u8; HASH_SIZE]) -> Result<()> {
        set_once(&self.authority_hash, authority_hash, "authority_hash")
    }

    fn config_descriptor(&mut self, config_descriptor: Vec<u8>) -> Result<()> {
        set_once(&self.config_descriptor, config_descriptor, "config_descriptor")
    }

    fn build(mut self) -> Result<DiceChainEntryPayload> {
        let subject_public_key = take_value(&mut self.subject_public_key, "subject_public_key")?;
        // If Mode is omitted, it should be treated as if it was NotConfigured, according to
        // the Open Profile for DICE spec.
        let mode = self.mode.take().unwrap_or(DiceMode::kDiceModeNotInitialized);
        let code_hash = take_value(&mut self.code_hash, "code_hash")?;
        let authority_hash = take_value(&mut self.authority_hash, "authority_hash")?;
        let config_descriptor = take_value(&mut self.config_descriptor, "config_descriptor")?;
        Ok(DiceChainEntryPayload {
            subject_public_key,
            mode,
            code_hash,
            authority_hash,
            config_descriptor,
        })
    }
}
