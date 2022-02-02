/*
 * Copyright 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! RSA key pair generation, persistence (with the private key encrypted), verification and
//! signing.

#![allow(dead_code, unused_variables)]

use crate::blob_encryption;
use crate::dice::Dice;
use anyhow::{bail, Context, Result};
use compos_aidl_interface::aidl::com::android::compos::CompOsKeyData::CompOsKeyData;
use ring::{
    rand::{SecureRandom, SystemRandom},
    signature,
};

pub type DiceSigningKey = SigningKey<Dice>;
pub type DiceSigner = Signer<Dice>;

pub struct SigningKey<T: SecretStore> {
    secret_store: T,
}

pub trait SecretStore: Clone {
    fn get_secret(&self) -> Result<Vec<u8>>;
}

impl SecretStore for Dice {
    fn get_secret(&self) -> Result<Vec<u8>> {
        self.get_sealing_cdi()
    }
}

impl<T: SecretStore> SigningKey<T> {
    pub fn new(secret_store: T) -> Self {
        Self { secret_store }
    }

    pub fn generate(&self) -> Result<CompOsKeyData> {
        let key_result = compos_native::generate_key_pair();
        if key_result.public_key.is_empty() || key_result.private_key.is_empty() {
            bail!("Failed to generate key pair: {}", key_result.error);
        }

        let encrypted =
            encrypt_private_key(&self.secret_store.get_secret()?, &key_result.private_key)?;
        Ok(CompOsKeyData { publicKey: key_result.public_key, keyBlob: encrypted })
    }

    pub fn verify(&self, key_blob: &[u8], public_key: &[u8]) -> Result<()> {
        // We verify the private key by verifying the AEAD authentication tag in the signer.
        // To verify the public key matches, we sign a block of random data with the private key,
        // and then check that the signature matches the purported key.
        let mut data = [0u8; 32]; // Size is fairly arbitrary.
        SystemRandom::new().fill(&mut data).context("No random data")?;

        let signature = self.new_signer(key_blob)?.sign(&data)?;

        let public_key =
            signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, public_key);
        public_key.verify(&data, &signature).context("Signature verification failed")?;

        Ok(())
    }

    pub fn new_signer(&self, key_blob: &[u8]) -> Result<Signer<T>> {
        Ok(Signer { key_blob: key_blob.to_owned(), secret_store: self.secret_store.clone() })
    }
}

pub struct Signer<T: SecretStore> {
    key_blob: Vec<u8>,
    secret_store: T,
}

impl<T: SecretStore> Signer<T> {
    pub fn sign(self, data: &[u8]) -> Result<Vec<u8>> {
        let private_key = decrypt_private_key(&self.secret_store.get_secret()?, &self.key_blob)?;
        let sign_result = compos_native::sign(&private_key, data);
        if sign_result.signature.is_empty() {
            bail!("Failed to sign: {}", sign_result.error);
        }
        Ok(sign_result.signature)
    }
}

fn encrypt_private_key(vm_secret: &[u8], private_key: &[u8]) -> Result<Vec<u8>> {
    let aead_key = blob_encryption::derive_aead_key(vm_secret)?;
    blob_encryption::encrypt_bytes(aead_key, private_key)
}

fn decrypt_private_key(vm_secret: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
    let aead_key = blob_encryption::derive_aead_key(vm_secret)?;
    blob_encryption::decrypt_bytes(aead_key, blob)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"This is not very secret";

    #[derive(Clone)]
    struct TestSecretStore;

    impl SecretStore for TestSecretStore {
        fn get_secret(&self) -> Result<Vec<u8>> {
            Ok(SECRET.to_owned())
        }
    }

    type TestSigningKey = SigningKey<TestSecretStore>;

    fn signing_key_for_test() -> TestSigningKey {
        TestSigningKey::new(TestSecretStore)
    }

    #[test]
    fn test_generated_key_verifies() -> Result<()> {
        let signing_key = signing_key_for_test();
        let key_pair = signing_key.generate()?;

        signing_key.verify(&key_pair.keyBlob, &key_pair.publicKey)
    }

    #[test]
    fn test_bogus_key_pair_rejected() -> Result<()> {
        let signing_key = signing_key_for_test();
        let key_pair = signing_key.generate()?;

        // Swap public key & key blob - clearly invalid
        assert!(signing_key.verify(&key_pair.publicKey, &key_pair.keyBlob).is_err());

        Ok(())
    }

    #[test]
    fn test_mismatched_key_rejected() -> Result<()> {
        let signing_key = signing_key_for_test();
        let key_pair1 = signing_key.generate()?;
        let key_pair2 = signing_key.generate()?;

        // Both pairs should be valid
        signing_key.verify(&key_pair1.keyBlob, &key_pair1.publicKey)?;
        signing_key.verify(&key_pair2.keyBlob, &key_pair2.publicKey)?;

        // But using the public key from one and the private key from the other should not,
        // even though both are well-formed
        assert!(signing_key.verify(&key_pair1.publicKey, &key_pair2.keyBlob).is_err());
        Ok(())
    }
}
