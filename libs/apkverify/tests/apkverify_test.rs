/*
 * Copyright (C) 2021 The Android Open Source Project
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

use apkverify::{
    get_public_key_der, pick_v4_apk_digest, testing::assert_contains, verify, SignatureAlgorithmID,
};
use std::{fs, matches, path::Path};

const KEY_NAMES_DSA: &[&str] = &["1024", "2048", "3072"];
const KEY_NAMES_ECDSA: &[&str] = &["p256", "p384", "p521"];
const KEY_NAMES_RSA: &[&str] = &["1024", "2048", "3072", "4096", "8192", "16384"];

#[test]
fn test_verify_truncated_cd() {
    use zip::result::ZipError;
    let res = verify("tests/data/v2-only-truncated-cd.apk");
    // TODO(b/190343842): consider making a helper for err assertion
    assert!(matches!(
        res.unwrap_err().root_cause().downcast_ref::<ZipError>().unwrap(),
        ZipError::InvalidArchive(_),
    ));
}

#[test]
fn apex_signed_with_v3_rsa_pkcs1_sha512_is_valid() {
    validate_apk("tests/data/test.apex", SignatureAlgorithmID::RsaPkcs1V15WithSha512);
}

#[test]
fn test_verify_v3_dsa_sha256() {
    for key_name in KEY_NAMES_DSA.iter() {
        let res = verify(format!("tests/data/v3-only-with-dsa-sha256-{}.apk", key_name));
        assert!(res.is_err());
        assert_contains(&res.unwrap_err().to_string(), "not implemented");
    }
}

/// TODO(b/197052981): DSA algorithm is not yet supported.
#[test]
fn apks_signed_with_v3_dsa_sha256_have_valid_apk_digest() {
    for key_name in KEY_NAMES_DSA.iter() {
        validate_apk_digest(
            format!("tests/data/v3-only-with-dsa-sha256-{}.apk", key_name),
            SignatureAlgorithmID::DsaWithSha256,
        );
    }
}

#[test]
fn apks_signed_with_v3_ecdsa_sha256_are_valid() {
    for key_name in KEY_NAMES_ECDSA.iter() {
        validate_apk(
            format!("tests/data/v3-only-with-ecdsa-sha256-{}.apk", key_name),
            SignatureAlgorithmID::EcdsaWithSha256,
        );
    }
}

#[test]
fn apks_signed_with_v3_ecdsa_sha512_are_valid() {
    for key_name in KEY_NAMES_ECDSA.iter() {
        validate_apk(
            format!("tests/data/v3-only-with-ecdsa-sha512-{}.apk", key_name),
            SignatureAlgorithmID::EcdsaWithSha512,
        );
    }
}

#[test]
fn apks_signed_with_v3_rsa_pkcs1_sha256_are_valid() {
    for key_name in KEY_NAMES_RSA.iter() {
        validate_apk(
            format!("tests/data/v3-only-with-rsa-pkcs1-sha256-{}.apk", key_name),
            SignatureAlgorithmID::RsaPkcs1V15WithSha256,
        );
    }
}

#[test]
fn apks_signed_with_v3_rsa_pkcs1_sha512_are_valid() {
    for key_name in KEY_NAMES_RSA.iter() {
        validate_apk(
            format!("tests/data/v3-only-with-rsa-pkcs1-sha512-{}.apk", key_name),
            SignatureAlgorithmID::RsaPkcs1V15WithSha512,
        );
    }
}

#[test]
fn test_verify_v3_sig_does_not_verify() {
    let path_list = [
        "tests/data/v3-only-with-dsa-sha256-2048-sig-does-not-verify.apk",
        "tests/data/v3-only-with-ecdsa-sha512-p521-sig-does-not-verify.apk",
        "tests/data/v3-only-with-rsa-pkcs1-sha256-3072-sig-does-not-verify.apk",
    ];
    for path in path_list.iter() {
        let res = verify(path);
        assert!(res.is_err());
        let error_msg = &res.unwrap_err().to_string();
        assert!(
            error_msg.contains("Signature is invalid") || error_msg.contains("not implemented")
        );
    }
}

#[test]
fn test_verify_v3_digest_mismatch() {
    let path_list = [
        "tests/data/v3-only-with-dsa-sha256-3072-digest-mismatch.apk",
        "tests/data/v3-only-with-rsa-pkcs1-sha512-8192-digest-mismatch.apk",
    ];
    for path in path_list.iter() {
        let res = verify(path);
        assert!(res.is_err());
        let error_msg = &res.unwrap_err().to_string();
        assert!(error_msg.contains("Digest mismatch") || error_msg.contains("not implemented"));
    }
}

#[test]
fn test_verify_v3_wrong_apk_sig_block_magic() {
    let res = verify("tests/data/v3-only-with-ecdsa-sha512-p384-wrong-apk-sig-block-magic.apk");
    assert!(res.is_err());
    assert_contains(&res.unwrap_err().to_string(), "No APK Signing Block");
}

#[test]
fn test_verify_v3_apk_sig_block_size_mismatch() {
    let res =
        verify("tests/data/v3-only-with-rsa-pkcs1-sha512-4096-apk-sig-block-size-mismatch.apk");
    assert!(res.is_err());
    assert_contains(
        &res.unwrap_err().to_string(),
        "APK Signing Block sizes in header and footer do not match",
    );
}

#[test]
fn test_verify_v3_cert_and_public_key_mismatch() {
    let res = verify("tests/data/v3-only-cert-and-public-key-mismatch.apk");
    assert!(res.is_err());
    assert_contains(&res.unwrap_err().to_string(), "Public key mismatch");
}

#[test]
fn test_verify_v3_empty() {
    let res = verify("tests/data/v3-only-empty.apk");
    assert!(res.is_err());
    assert_contains(&res.unwrap_err().to_string(), "APK too small for APK Signing Block");
}

#[test]
fn test_verify_v3_no_certs_in_sig() {
    let res = verify("tests/data/v3-only-no-certs-in-sig.apk");
    assert!(res.is_err());
    assert_contains(&res.unwrap_err().to_string(), "No certificates listed");
}

#[test]
fn test_verify_v3_no_supported_sig_algs() {
    let res = verify("tests/data/v3-only-no-supported-sig-algs.apk");
    assert!(res.is_err());
    assert_contains(&res.unwrap_err().to_string(), "No supported signatures found");
}

#[test]
fn test_verify_v3_signatures_and_digests_block_mismatch() {
    let res = verify("tests/data/v3-only-signatures-and-digests-block-mismatch.apk");
    assert!(res.is_err());
    assert_contains(
        &res.unwrap_err().to_string(),
        "Signature algorithms don't match between digests and signatures records",
    );
}

#[test]
fn apk_signed_with_v3_unknown_additional_attr_is_valid() {
    validate_apk(
        "tests/data/v3-only-unknown-additional-attr.apk",
        SignatureAlgorithmID::RsaPkcs1V15WithSha256,
    );
}

#[test]
fn apk_signed_with_v3_unknown_pair_in_apk_sig_block_is_valid() {
    validate_apk(
        "tests/data/v3-only-unknown-pair-in-apk-sig-block.apk",
        SignatureAlgorithmID::RsaPkcs1V15WithSha256,
    );
}

#[test]
fn apk_signed_with_v3_ignorable_unsupported_sig_algs_is_valid() {
    validate_apk(
        "tests/data/v3-only-with-ignorable-unsupported-sig-algs.apk",
        SignatureAlgorithmID::RsaPkcs1V15WithSha256,
    );
}

#[test]
fn apk_signed_with_v3_stamp_is_valid() {
    validate_apk("tests/data/v3-only-with-stamp.apk", SignatureAlgorithmID::EcdsaWithSha256);
}

fn validate_apk<P: AsRef<Path>>(apk_path: P, expected_algorithm_id: SignatureAlgorithmID) {
    validate_apk_public_key(&apk_path);
    validate_apk_digest(&apk_path, expected_algorithm_id);
}

/// Validates that the following public keys are equal:
/// * public key from verification
/// * public key extracted from apk without verification
/// * expected public key from the corresponding .der file
fn validate_apk_public_key<P: AsRef<Path>>(apk_path: P) {
    let public_key_from_verification = verify(&apk_path);
    let public_key_from_verification =
        public_key_from_verification.expect("Error in verification result");

    let expected_public_key_path = format!("{}.der", apk_path.as_ref().to_str().unwrap());
    assert_bytes_eq_to_data_in_file(&public_key_from_verification, expected_public_key_path);

    let public_key_from_apk = get_public_key_der(&apk_path);
    let public_key_from_apk =
        public_key_from_apk.expect("Error when extracting public key from apk");
    assert_eq!(
        public_key_from_verification, public_key_from_apk,
        "Public key extracted directly from apk does not match the public key from verification."
    );
}

/// Validates that the following apk_digest are equal:
/// * apk_digest directly extracted from apk without computation
/// * expected apk digest from the corresponding .apk_digest file
fn validate_apk_digest<P: AsRef<Path>>(apk_path: P, expected_algorithm_id: SignatureAlgorithmID) {
    let apk = fs::File::open(&apk_path).expect("Unabled to open apk file");

    let (signature_algorithm_id, digest_from_apk) =
        pick_v4_apk_digest(apk).expect("Error when extracting apk digest.");

    assert_eq!(expected_algorithm_id, signature_algorithm_id);
    let expected_digest_path = format!("{}.apk_digest", apk_path.as_ref().to_str().unwrap());
    assert_bytes_eq_to_data_in_file(&digest_from_apk, expected_digest_path);
}

fn assert_bytes_eq_to_data_in_file<P: AsRef<Path> + std::fmt::Display>(
    bytes_data: &[u8],
    expected_data_path: P,
) {
    assert!(
        fs::metadata(&expected_data_path).is_ok(),
        "File does not exist. You can re-create it with:\n$ echo -en {} > {}\n",
        bytes_data.iter().map(|b| format!("\\\\x{:02x}", b)).collect::<String>(),
        expected_data_path
    );
    let expected_data = fs::read(&expected_data_path).unwrap();
    assert_eq!(
        expected_data, bytes_data,
        "Actual data does not match the data from: {}",
        expected_data_path
    );
}
