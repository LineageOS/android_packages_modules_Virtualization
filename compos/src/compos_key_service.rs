// Copyright 2021, The Android Open Source Project
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

//! Provides a binder service for key generation & verification for CompOs. We assume we have
//! access to Keystore in the VM, but not persistent storage; instead the host stores the key
//! on our behalf via this service.

use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    Algorithm::Algorithm, Digest::Digest, KeyParameter::KeyParameter,
    KeyParameterValue::KeyParameterValue, KeyPurpose::KeyPurpose, PaddingMode::PaddingMode,
    SecurityLevel::SecurityLevel, Tag::Tag,
};
use android_system_keystore2::aidl::android::system::keystore2::{
    Domain::Domain, IKeystoreSecurityLevel::IKeystoreSecurityLevel,
    IKeystoreService::IKeystoreService, KeyDescriptor::KeyDescriptor,
};
use android_system_keystore2::binder::{wait_for_interface, Strong};
use anyhow::{anyhow, Context, Result};
use compos_aidl_interface::aidl::com::android::compos::CompOsKeyData::CompOsKeyData;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature;
use scopeguard::ScopeGuard;

/// Keystore2 namespace IDs, used for access control to keys.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KeystoreNamespace {
    /// In the host we re-use the ID assigned to odsign. See system/sepolicy/private/keystore2_key_contexts.
    // TODO(alanstokes): Remove this.
    Odsign = 101,
    /// In a VM we can use the generic ID allocated for payloads. See microdroid's keystore2_key_contexts.
    VmPayload = 140,
}

const KEYSTORE_SERVICE_NAME: &str = "android.system.keystore2.IKeystoreService/default";
const PURPOSE_SIGN: KeyParameter =
    KeyParameter { tag: Tag::PURPOSE, value: KeyParameterValue::KeyPurpose(KeyPurpose::SIGN) };
const ALGORITHM: KeyParameter =
    KeyParameter { tag: Tag::ALGORITHM, value: KeyParameterValue::Algorithm(Algorithm::RSA) };
const PADDING: KeyParameter = KeyParameter {
    tag: Tag::PADDING,
    value: KeyParameterValue::PaddingMode(PaddingMode::RSA_PKCS1_1_5_SIGN),
};
const DIGEST: KeyParameter =
    KeyParameter { tag: Tag::DIGEST, value: KeyParameterValue::Digest(Digest::SHA_2_256) };
const KEY_SIZE: KeyParameter =
    KeyParameter { tag: Tag::KEY_SIZE, value: KeyParameterValue::Integer(2048) };
const EXPONENT: KeyParameter =
    KeyParameter { tag: Tag::RSA_PUBLIC_EXPONENT, value: KeyParameterValue::LongInteger(65537) };
const NO_AUTH_REQUIRED: KeyParameter =
    KeyParameter { tag: Tag::NO_AUTH_REQUIRED, value: KeyParameterValue::BoolValue(true) };

const BLOB_KEY_DESCRIPTOR: KeyDescriptor =
    KeyDescriptor { domain: Domain::BLOB, nspace: 0, alias: None, blob: None };

/// An internal service for CompOS key management.
#[derive(Clone)]
pub struct CompOsKeyService {
    namespace: KeystoreNamespace,
    random: SystemRandom,
    security_level: Strong<dyn IKeystoreSecurityLevel>,
}

impl CompOsKeyService {
    pub fn new(rpc_binder: bool) -> Result<Self> {
        let keystore_service = wait_for_interface::<dyn IKeystoreService>(KEYSTORE_SERVICE_NAME)
            .context("No Keystore service")?;

        let namespace =
            if rpc_binder { KeystoreNamespace::VmPayload } else { KeystoreNamespace::Odsign };
        Ok(CompOsKeyService {
            namespace,
            random: SystemRandom::new(),
            security_level: keystore_service
                .getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT)
                .context("Getting SecurityLevel failed")?,
        })
    }

    pub fn do_generate(&self) -> Result<CompOsKeyData> {
        let key_descriptor = KeyDescriptor { nspace: self.namespace as i64, ..BLOB_KEY_DESCRIPTOR };
        let key_parameters =
            [PURPOSE_SIGN, ALGORITHM, PADDING, DIGEST, KEY_SIZE, EXPONENT, NO_AUTH_REQUIRED];
        let attestation_key = None;
        let flags = 0;
        let entropy = [];

        let key_metadata = self
            .security_level
            .generateKey(&key_descriptor, attestation_key, &key_parameters, flags, &entropy)
            .context("Generating key failed")?;

        if let (Some(certificate), Some(blob)) = (key_metadata.certificate, key_metadata.key.blob) {
            Ok(CompOsKeyData { certificate, keyBlob: blob })
        } else {
            Err(anyhow!("Missing cert or blob"))
        }
    }

    pub fn do_verify(&self, key_blob: &[u8], public_key: &[u8]) -> Result<()> {
        let mut data = [0u8; 32];
        self.random.fill(&mut data).context("No random data")?;

        let signature = self.do_sign(key_blob, &data)?;

        let public_key =
            signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, public_key);
        public_key.verify(&data, &signature).context("Signature verification failed")?;

        Ok(())
    }

    pub fn do_sign(&self, key_blob: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let key_descriptor = KeyDescriptor {
            nspace: self.namespace as i64,
            blob: Some(key_blob.to_vec()),
            ..BLOB_KEY_DESCRIPTOR
        };
        let operation_parameters = [PURPOSE_SIGN, ALGORITHM, PADDING, DIGEST];
        let forced = false;

        let response = self
            .security_level
            .createOperation(&key_descriptor, &operation_parameters, forced)
            .context("Creating key failed")?;
        let operation = scopeguard::guard(
            response.iOperation.ok_or_else(|| anyhow!("No operation created"))?,
            |op| op.abort().unwrap_or_default(),
        );

        if response.operationChallenge.is_some() {
            return Err(anyhow!("Key requires user authorization"));
        }

        let signature = operation.finish(Some(data), None).context("Signing failed")?;
        // Operation has finished, we're no longer responsible for aborting it
        ScopeGuard::into_inner(operation);

        signature.ok_or_else(|| anyhow!("No signature returned"))
    }
}
