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

use crate::compsvc;
use crate::signer::Signer;
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    Algorithm::Algorithm, Digest::Digest, KeyParameter::KeyParameter,
    KeyParameterValue::KeyParameterValue, KeyPurpose::KeyPurpose, PaddingMode::PaddingMode,
    SecurityLevel::SecurityLevel, Tag::Tag,
};
use android_system_keystore2::aidl::android::system::keystore2::{
    Domain::Domain, IKeystoreSecurityLevel::IKeystoreSecurityLevel,
    IKeystoreService::IKeystoreService, KeyDescriptor::KeyDescriptor,
};
use anyhow::{anyhow, Context, Result};
use compos_aidl_interface::aidl::com::android::compos::{
    CompOsKeyData::CompOsKeyData,
    ICompOsKeyService::{BnCompOsKeyService, ICompOsKeyService},
    ICompService::ICompService,
};
use compos_aidl_interface::binder::{
    self, wait_for_interface, BinderFeatures, ExceptionCode, Interface, Status, Strong,
};
use log::warn;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature;
use scopeguard::ScopeGuard;
use std::ffi::CString;

/// Keystore2 namespace IDs, used for access control to keys.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KeystoreNamespace {
    /// In the host we re-use the ID assigned to odsign. See system/sepolicy/private/keystore2_key_contexts.
    // TODO(alanstokes): Remove this.
    Odsign = 101,
    /// In a VM we can use the generic ID allocated for payloads. See microdroid's keystore2_key_contexts.
    VmPayload = 140,
}

/// Constructs a binder object that implements ICompOsKeyService. namespace is the Keystore2 namespace to
/// use for the keys.
pub fn new(namespace: KeystoreNamespace) -> Result<Strong<dyn ICompOsKeyService>> {
    let keystore_service = wait_for_interface::<dyn IKeystoreService>(KEYSTORE_SERVICE_NAME)
        .context("No Keystore service")?;

    let service = CompOsKeyService {
        namespace,
        random: SystemRandom::new(),
        security_level: keystore_service
            .getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT)
            .context("Getting SecurityLevel failed")?,
    };

    Ok(BnCompOsKeyService::new_binder(service, BinderFeatures::default()))
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

#[derive(Clone)]
struct CompOsKeyService {
    namespace: KeystoreNamespace,
    random: SystemRandom,
    security_level: Strong<dyn IKeystoreSecurityLevel>,
}

impl Interface for CompOsKeyService {}

impl ICompOsKeyService for CompOsKeyService {
    fn generateSigningKey(&self) -> binder::Result<CompOsKeyData> {
        self.do_generate()
            .map_err(|e| new_binder_exception(ExceptionCode::ILLEGAL_STATE, e.to_string()))
    }

    fn verifySigningKey(&self, key_blob: &[u8], public_key: &[u8]) -> binder::Result<bool> {
        Ok(if let Err(e) = self.do_verify(key_blob, public_key) {
            warn!("Signing key verification failed: {}", e.to_string());
            false
        } else {
            true
        })
    }

    fn sign(&self, key_blob: &[u8], data: &[u8]) -> binder::Result<Vec<u8>> {
        self.do_sign(key_blob, data)
            .map_err(|e| new_binder_exception(ExceptionCode::ILLEGAL_STATE, e.to_string()))
    }

    fn getCompService(&self, key_blob: &[u8]) -> binder::Result<Strong<dyn ICompService>> {
        let signer =
            Box::new(CompOsSigner { key_blob: key_blob.to_owned(), key_service: self.clone() });
        let debuggable = true;
        Ok(compsvc::new_binder(
            "/apex/com.android.art/bin/dex2oat64".to_owned(),
            debuggable,
            Some(signer),
        ))
    }
}

/// Constructs a new Binder error `Status` with the given `ExceptionCode` and message.
fn new_binder_exception<T: AsRef<str>>(exception: ExceptionCode, message: T) -> Status {
    Status::new_exception(exception, CString::new(message.as_ref()).ok().as_deref())
}

struct CompOsSigner {
    key_blob: Vec<u8>,
    key_service: CompOsKeyService,
}

impl Signer for CompOsSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.key_service.do_sign(&self.key_blob, data)
    }
}

impl CompOsKeyService {
    fn do_generate(&self) -> Result<CompOsKeyData> {
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

    fn do_verify(&self, key_blob: &[u8], public_key: &[u8]) -> Result<()> {
        let mut data = [0u8; 32];
        self.random.fill(&mut data).context("No random data")?;

        let signature = self.do_sign(key_blob, &data)?;

        let public_key =
            signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, public_key);
        public_key.verify(&data, &signature).context("Signature verification failed")?;

        Ok(())
    }

    fn do_sign(&self, key_blob: &[u8], data: &[u8]) -> Result<Vec<u8>> {
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

        let signature = operation.finish(Some(&data), None).context("Signing failed")?;
        // Operation has finished, we're no longer responsible for aborting it
        ScopeGuard::into_inner(operation);

        signature.ok_or_else(|| anyhow!("No signature returned"))
    }
}
