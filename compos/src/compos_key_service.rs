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
use anyhow::{anyhow, Context, Result};
use compos_aidl_interface::aidl::com::android::compos::{
    CompOsKeyData::CompOsKeyData,
    ICompOsKeyService::{BnCompOsKeyService, ICompOsKeyService},
};
use compos_aidl_interface::binder::{
    self, add_service, get_interface, BinderFeatures, ExceptionCode, Interface, ProcessState,
    Status, Strong,
};
use log::{info, warn, Level};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature;
use scopeguard::ScopeGuard;
use std::ffi::CString;

const LOG_TAG: &str = "CompOsKeyService";
const OUR_SERVICE_NAME: &str = "android.system.composkeyservice";

const KEYSTORE_SERVICE_NAME: &str = "android.system.keystore2.IKeystoreService/default";
const COMPOS_NAMESPACE: i64 = 101;
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

const KEY_DESCRIPTOR: KeyDescriptor =
    KeyDescriptor { domain: Domain::BLOB, nspace: COMPOS_NAMESPACE, alias: None, blob: None };

struct CompOsKeyService {
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
}

/// Constructs a new Binder error `Status` with the given `ExceptionCode` and message.
fn new_binder_exception<T: AsRef<str>>(exception: ExceptionCode, message: T) -> Status {
    Status::new_exception(exception, CString::new(message.as_ref()).ok().as_deref())
}

impl CompOsKeyService {
    fn new(keystore_service: &Strong<dyn IKeystoreService>) -> Self {
        Self {
            random: SystemRandom::new(),
            security_level: keystore_service
                .getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT)
                .unwrap(),
        }
    }

    fn do_generate(&self) -> Result<CompOsKeyData> {
        let key_parameters =
            [PURPOSE_SIGN, ALGORITHM, PADDING, DIGEST, KEY_SIZE, EXPONENT, NO_AUTH_REQUIRED];
        let attestation_key = None;
        let flags = 0;
        let entropy = [];

        let key_metadata = self
            .security_level
            .generateKey(&KEY_DESCRIPTOR, attestation_key, &key_parameters, flags, &entropy)
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

        let signature = self.sign(key_blob, &data)?;

        let public_key =
            signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, public_key);
        public_key.verify(&data, &signature).context("Signature verification failed")?;

        Ok(())
    }

    fn sign(&self, key_blob: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let key_descriptor = KeyDescriptor { blob: Some(key_blob.to_vec()), ..KEY_DESCRIPTOR };
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

fn main() -> Result<()> {
    android_logger::init_once(
        android_logger::Config::default().with_tag(LOG_TAG).with_min_level(Level::Trace),
    );

    // We need to start the thread pool for Binder to work properly.
    ProcessState::start_thread_pool();

    let keystore_service = get_interface::<dyn IKeystoreService>(KEYSTORE_SERVICE_NAME)
        .context("No Keystore service")?;
    let service = CompOsKeyService::new(&keystore_service);
    let service = BnCompOsKeyService::new_binder(service, BinderFeatures::default());

    add_service(OUR_SERVICE_NAME, service.as_binder()).context("Adding service failed")?;
    info!("It's alive!");

    ProcessState::join_thread_pool();

    Ok(())
}
