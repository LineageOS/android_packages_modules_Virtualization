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

use crate::blob_encryptor::BlobEncryptor;
use crate::dice::Dice;
use anyhow::{bail, Result};
use compos_aidl_interface::aidl::com::android::compos::CompOsKeyData::CompOsKeyData;
use ring::rand::SystemRandom;

pub struct SigningKey {
    random: SystemRandom,
    dice: Dice,
    blob_encryptor: BlobEncryptor,
}

impl SigningKey {
    pub fn new() -> Result<Self> {
        Ok(Self {
            random: SystemRandom::new(),
            dice: Dice::new()?,
            blob_encryptor: BlobEncryptor::new(),
        })
    }

    pub fn generate(&self) -> Result<CompOsKeyData> {
        // TODO: generate key pair; get aead key; generate random nonce; encrypt private key;
        // generate self-signed cert
        bail!("Not implemented")
    }

    pub fn verify(&self, key_blob: &[u8], public_key: &[u8]) -> Result<()> {
        bail!("Not implemented")
    }

    pub fn new_signer(&self, key_blob: &[u8]) -> Signer {
        Signer { key_blob: key_blob.to_owned() }
    }

    fn encrypt_private_key(&self, private_key: &[u8]) -> Result<Vec<u8>> {
        let cdi = self.dice.get_sealing_cdi()?;
        let aead_key = self.blob_encryptor.derive_aead_key(&cdi)?;
        self.blob_encryptor.encrypt_bytes(aead_key, private_key)
    }

    fn decrypt_private_key(&self, blob: &[u8]) -> Result<Vec<u8>> {
        let cdi = self.dice.get_sealing_cdi()?;
        let aead_key = self.blob_encryptor.derive_aead_key(&cdi)?;
        self.blob_encryptor.decrypt_bytes(aead_key, blob)
    }
}

pub struct Signer {
    key_blob: Vec<u8>,
}

impl Signer {
    pub fn sign(self, data: &[u8]) -> Result<Vec<u8>> {
        bail!("Not implemented")
    }
}
