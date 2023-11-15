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

use bssl_avf::{sha256, ApiName, EcKey, EcdsaError, Error, Result};
use coset::CborSerializable;

const MESSAGE1: &[u8] = b"test message 1";
const MESSAGE2: &[u8] = b"test message 2";

#[test]
fn ec_private_key_serialization() -> Result<()> {
    let mut ec_key = EcKey::new_p256()?;
    ec_key.generate_key()?;
    let der_encoded_ec_private_key = ec_key.ec_private_key()?;
    let deserialized_ec_key = EcKey::from_ec_private_key(der_encoded_ec_private_key.as_slice())?;

    assert_eq!(ec_key.cose_public_key()?, deserialized_ec_key.cose_public_key()?);
    Ok(())
}

#[test]
fn cose_public_key_serialization() -> Result<()> {
    let mut ec_key = EcKey::new_p256()?;
    ec_key.generate_key()?;
    let cose_key = ec_key.cose_public_key()?;
    let cose_key_data = cose_key.clone().to_vec().unwrap();
    let deserialized_ec_key = EcKey::from_cose_public_key(&cose_key_data)?;

    assert_eq!(cose_key, deserialized_ec_key.cose_public_key()?);
    Ok(())
}

#[test]
fn ecdsa_p256_signing_and_verification_succeed() -> Result<()> {
    let mut ec_key = EcKey::new_p256()?;
    ec_key.generate_key()?;
    let digest = sha256(MESSAGE1)?;

    let signature = ec_key.ecdsa_sign(&digest)?;
    ec_key.ecdsa_verify(&signature, &digest)
}

#[test]
fn verifying_ecdsa_p256_signed_with_a_different_key_fails() -> Result<()> {
    let mut ec_key1 = EcKey::new_p256()?;
    ec_key1.generate_key()?;
    let digest = sha256(MESSAGE1)?;
    let signature = ec_key1.ecdsa_sign(&digest)?;

    let mut ec_key2 = EcKey::new_p256()?;
    ec_key2.generate_key()?;
    let err = ec_key2.ecdsa_verify(&signature, &digest).unwrap_err();
    let expected_err = Error::CallFailed(ApiName::ECDSA_verify, EcdsaError::BadSignature.into());
    assert_eq!(expected_err, err);
    Ok(())
}

#[test]
fn verifying_ecdsa_p256_signed_with_a_different_message_fails() -> Result<()> {
    let mut ec_key = EcKey::new_p256()?;
    ec_key.generate_key()?;
    let digest1 = sha256(MESSAGE1)?;
    let signature = ec_key.ecdsa_sign(&digest1)?;
    let digest2 = sha256(MESSAGE2)?;

    let err = ec_key.ecdsa_verify(&signature, &digest2).unwrap_err();
    let expected_err = Error::CallFailed(ApiName::ECDSA_verify, EcdsaError::BadSignature.into());
    assert_eq!(expected_err, err);
    Ok(())
}
