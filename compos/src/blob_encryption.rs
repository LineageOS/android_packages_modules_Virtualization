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

//! Allows for data to be encrypted and authenticated (AEAD) with a key derived from some secret.
//! The encrypted blob can be passed to the untrusted host without revealing the encrypted data
//! but with the key the data can be retrieved as long as the blob has not been tampered with.

use anyhow::{bail, Context, Result};
use ring::{
    aead::{Aad, LessSafeKey, Nonce, AES_256_GCM, NONCE_LEN},
    hkdf::{Salt, HKDF_SHA256},
    rand::{SecureRandom, SystemRandom},
};

// Non-secret input to the AEAD key derivation
const KDF_INFO: &[u8] = b"CompOS blob sealing key";

pub fn derive_aead_key(input_keying_material: &[u8]) -> Result<LessSafeKey> {
    // Derive key using HKDF - see https://datatracker.ietf.org/doc/html/rfc5869#section-2
    let salt = [];
    let prk = Salt::new(HKDF_SHA256, &salt).extract(input_keying_material);
    let okm = prk.expand(&[KDF_INFO], &AES_256_GCM).context("HKDF failed")?;
    // LessSafeKey is only less safe in that it has less inherent protection against nonce
    // reuse; we are safe because we use a new random nonce for each sealing operation.
    // (See https://github.com/briansmith/ring/issues/899.)
    Ok(LessSafeKey::new(okm.into()))
}

pub fn encrypt_bytes(key: LessSafeKey, bytes: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(bytes.len() + NONCE_LEN + key.algorithm().tag_len());

    // Generate a unique nonce, since we may use the same key more than once, and put it at the
    // start of the output blob.
    let mut nonce_bytes = [0u8; NONCE_LEN];
    SystemRandom::new().fill(&mut nonce_bytes).context("Failed to generate random nonce")?;
    output.extend_from_slice(&nonce_bytes);

    // Copy input to output then encrypt & seal it in place.
    output.extend_from_slice(bytes);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let tag = key
        .seal_in_place_separate_tag(nonce, Aad::empty(), &mut output[NONCE_LEN..])
        .context("Failed to seal blob")?;
    output.extend_from_slice(tag.as_ref());

    Ok(output)
}

pub fn decrypt_bytes(key: LessSafeKey, bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() < NONCE_LEN + key.algorithm().tag_len() {
        bail!("Encrypted blob is too small");
    }

    // We expect the nonce at the start followed by the sealed data (encrypted data +
    // authentication tag).
    let nonce = Nonce::try_assume_unique_for_key(&bytes[..NONCE_LEN]).unwrap();
    let mut output = bytes[NONCE_LEN..].to_vec();

    // Verify & decrypt the data in place
    let unsealed_size =
        key.open_in_place(nonce, Aad::empty(), &mut output).context("Failed to unseal blob")?.len();

    // Remove the tag after the plaintext
    output.truncate(unsealed_size);

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip_data() -> Result<()> {
        let input_keying_material = b"Key is derived from this";
        let original_bytes = b"This is the secret data";

        let key = derive_aead_key(input_keying_material)?;
        let blob = encrypt_bytes(key, original_bytes)?;

        let key = derive_aead_key(input_keying_material)?;
        let decoded_bytes = decrypt_bytes(key, &blob)?;

        assert_eq!(decoded_bytes, original_bytes);
        Ok(())
    }

    #[test]
    fn test_modified_data_detected() -> Result<()> {
        let input_keying_material = b"Key is derived from this";
        let original_bytes = b"This is the secret data";

        let key = derive_aead_key(input_keying_material)?;
        let mut blob = encrypt_bytes(key, original_bytes)?;

        // Flip a bit.
        blob[0] ^= 1;

        let key = derive_aead_key(input_keying_material)?;
        let decoded_bytes = decrypt_bytes(key, &blob);

        assert!(decoded_bytes.is_err());
        Ok(())
    }
}
