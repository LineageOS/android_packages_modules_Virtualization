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

use anyhow::Result;
use diced_open_dice::{DiceArtifacts, OwnedDiceArtifacts};
use keystore2_crypto::ZVec;
use openssl::hkdf::hkdf;
use openssl::md::Md;
use openssl::sha;

const ENCRYPTEDSTORE_KEY_IDENTIFIER: &str = "encryptedstore_key";

// Size of the secret stored in Secretkeeper.
const SK_SECRET_SIZE: usize = 64;

// Generated using hexdump -vn32 -e'14/1 "0x%02X, " 1 "\n"' /dev/urandom
const SALT_ENCRYPTED_STORE: &[u8] = &[
    0xFC, 0x1D, 0x35, 0x7B, 0x96, 0xF3, 0xEF, 0x17, 0x78, 0x7D, 0x70, 0xED, 0xEA, 0xFE, 0x1D, 0x6F,
    0xB3, 0xF9, 0x40, 0xCE, 0xDD, 0x99, 0x40, 0xAA, 0xA7, 0x0E, 0x92, 0x73, 0x90, 0x86, 0x4A, 0x75,
];
const SALT_PAYLOAD_SERVICE: &[u8] = &[
    0x8B, 0x0F, 0xF0, 0xD3, 0xB1, 0x69, 0x2B, 0x95, 0x84, 0x2C, 0x9E, 0x3C, 0x99, 0x56, 0x7A, 0x22,
    0x55, 0xF8, 0x08, 0x23, 0x81, 0x5F, 0xF5, 0x16, 0x20, 0x3E, 0xBE, 0xBA, 0xB7, 0xA8, 0x43, 0x92,
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

impl VmSecret {
    pub fn new(dice_artifacts: OwnedDiceArtifacts) -> Result<VmSecret> {
        if is_sk_supported() {
            // TODO(b/291213394): Change this to real Sk protected secret.
            let fake_skp_secret = ZVec::new(SK_SECRET_SIZE)?;
            return Ok(Self::V2 { dice: dice_artifacts, skp_secret: fake_skp_secret });
        }
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

// Does the hardware support Secretkeeper.
fn is_sk_supported() -> bool {
    if cfg!(llpvm_changes) {
        return false;
    };
    // TODO(b/292209416): This value should be extracted from device tree.
    // Note: this does not affect the security of pVM. pvmfw & microdroid_manager continue to block
    // upgraded images. Setting this true is equivalent to including constant salt in vm secrets.
    true
}
