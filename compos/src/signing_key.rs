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

pub struct SigningKey {
    dice: Dice,
}

impl SigningKey {
    pub fn new() -> Result<Self> {
        Ok(Self { dice: Dice::new()? })
    }

    pub fn get_boot_certificate_chain(&self) -> Result<Vec<u8>> {
        Dice::new()?.get_boot_certificate_chain()
    }

    pub fn generate(&self) -> Result<CompOsKeyData> {
        let key_result = compos_native::generate_key_pair();
        if key_result.public_key.is_empty() || key_result.private_key.is_empty() {
            bail!("Failed to generate key pair: {}", key_result.error);
        }

        let encrypted = encrypt_private_key(&self.dice, &key_result.private_key)?;
        Ok(CompOsKeyData { publicKey: key_result.public_key, keyBlob: encrypted })
    }

    pub fn verify(&self, key_blob: &[u8], public_key: &[u8]) -> Result<()> {
        // We verify the private key by verifying the AEAD authentication tag in the signer.
        // To verify the public key matches, we sign a block of random data with the private key,
        // and then check that the signature matches the purported key.
        let mut data = [0u8; 32]; // Size is fairly arbitrary.
        SystemRandom::new().fill(&mut data).context("No random data")?;

        let signature = self.new_signer(key_blob).sign(&data)?;

        let public_key =
            signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, public_key);
        public_key.verify(&data, &signature).context("Signature verification failed")?;

        Ok(())
    }

    pub fn new_signer(&self, key_blob: &[u8]) -> Signer {
        Signer { key_blob: key_blob.to_owned(), dice: self.dice.clone() }
    }
}

pub struct Signer {
    key_blob: Vec<u8>,
    dice: Dice,
}

impl Signer {
    pub fn sign(self, data: &[u8]) -> Result<Vec<u8>> {
        let private_key = decrypt_private_key(&self.dice, &self.key_blob)?;
        let sign_result = compos_native::sign(&private_key, data);
        if sign_result.signature.is_empty() {
            bail!("Failed to sign: {}", sign_result.error);
        }
        Ok(sign_result.signature)
    }
}

fn encrypt_private_key(dice: &Dice, private_key: &[u8]) -> Result<Vec<u8>> {
    let cdi = dice.get_sealing_cdi()?;
    let aead_key = blob_encryption::derive_aead_key(&cdi)?;
    blob_encryption::encrypt_bytes(aead_key, private_key)
}

fn decrypt_private_key(dice: &Dice, blob: &[u8]) -> Result<Vec<u8>> {
    let cdi = dice.get_sealing_cdi()?;
    let aead_key = blob_encryption::derive_aead_key(&cdi)?;
    blob_encryption::decrypt_bytes(aead_key, blob)
}
