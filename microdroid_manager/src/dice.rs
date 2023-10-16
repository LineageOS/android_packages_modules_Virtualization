// Copyright 2023 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::dice_driver::DiceDriver;
use crate::{is_debuggable, MicrodroidData};
use anyhow::{bail, Context, Result};
use ciborium::{cbor, ser};
use diced_open_dice::OwnedDiceArtifacts;
use microdroid_metadata::PayloadMetadata;
use openssl::sha::Sha512;

/// Perform an open DICE derivation for the payload.
pub fn dice_derivation(
    dice: DiceDriver,
    verified_data: &MicrodroidData,
    payload_metadata: &PayloadMetadata,
) -> Result<OwnedDiceArtifacts> {
    // Calculate compound digests of code and authorities
    let mut code_hash_ctx = Sha512::new();
    let mut authority_hash_ctx = Sha512::new();
    code_hash_ctx.update(verified_data.apk_data.root_hash.as_ref());
    authority_hash_ctx.update(verified_data.apk_data.pubkey.as_ref());
    for extra_apk in &verified_data.extra_apks_data {
        code_hash_ctx.update(extra_apk.root_hash.as_ref());
        authority_hash_ctx.update(extra_apk.pubkey.as_ref());
    }
    for apex in &verified_data.apex_data {
        code_hash_ctx.update(apex.root_digest.as_ref());
        authority_hash_ctx.update(apex.public_key.as_ref());
    }
    let code_hash = code_hash_ctx.finish();
    let authority_hash = authority_hash_ctx.finish();

    let config_descriptor = format_payload_config_descriptor(payload_metadata)?;

    // Check debuggability, conservatively assuming it is debuggable
    let debuggable = is_debuggable()?;

    // Send the details to diced
    let hidden = verified_data.salt.clone().try_into().unwrap();
    dice.derive(code_hash, &config_descriptor, authority_hash, debuggable, hidden)
}

/// Returns a configuration descriptor of the given payload following the BCC's specification:
/// https://cs.android.com/android/platform/superproject/+/master:hardware/interfaces/security/rkp/aidl/android/hardware/security/keymint/ProtectedData.aidl
/// {
///   -70002: "Microdroid payload",
///   ? -71000: tstr ; payload_config_path
///   ? -71001: PayloadConfig
/// }
/// PayloadConfig = {
///   1: tstr ; payload_binary_name
/// }
fn format_payload_config_descriptor(payload: &PayloadMetadata) -> Result<Vec<u8>> {
    const MICRODROID_PAYLOAD_COMPONENT_NAME: &str = "Microdroid payload";

    let config_descriptor_cbor_value = match payload {
        PayloadMetadata::ConfigPath(payload_config_path) => cbor!({
            -70002 => MICRODROID_PAYLOAD_COMPONENT_NAME,
            -71000 => payload_config_path
        }),
        PayloadMetadata::Config(payload_config) => cbor!({
            -70002 => MICRODROID_PAYLOAD_COMPONENT_NAME,
            -71001 => {1 => payload_config.payload_binary_name}
        }),
        _ => bail!("Failed to match the payload against a config type: {:?}", payload),
    }
    .context("Failed to build a CBOR Value from payload metadata")?;
    let mut config_descriptor = Vec::new();

    ser::into_writer(&config_descriptor_cbor_value, &mut config_descriptor)?;
    Ok(config_descriptor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use microdroid_metadata::PayloadConfig;

    #[test]
    fn payload_metadata_with_path_formats_correctly() -> Result<()> {
        let payload_metadata = PayloadMetadata::ConfigPath("/config_path".to_string());
        let config_descriptor = format_payload_config_descriptor(&payload_metadata)?;
        static EXPECTED_CONFIG_DESCRIPTOR: &[u8] = &[
            0xa2, 0x3a, 0x00, 0x01, 0x11, 0x71, 0x72, 0x4d, 0x69, 0x63, 0x72, 0x6f, 0x64, 0x72,
            0x6f, 0x69, 0x64, 0x20, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x3a, 0x00, 0x01,
            0x15, 0x57, 0x6c, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x5f, 0x70, 0x61, 0x74,
            0x68,
        ];
        assert_eq!(EXPECTED_CONFIG_DESCRIPTOR, &config_descriptor);
        Ok(())
    }

    #[test]
    fn payload_metadata_with_config_formats_correctly() -> Result<()> {
        let payload_config = PayloadConfig {
            payload_binary_name: "payload_binary".to_string(),
            ..Default::default()
        };
        let payload_metadata = PayloadMetadata::Config(payload_config);
        let config_descriptor = format_payload_config_descriptor(&payload_metadata)?;
        static EXPECTED_CONFIG_DESCRIPTOR: &[u8] = &[
            0xa2, 0x3a, 0x00, 0x01, 0x11, 0x71, 0x72, 0x4d, 0x69, 0x63, 0x72, 0x6f, 0x64, 0x72,
            0x6f, 0x69, 0x64, 0x20, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x3a, 0x00, 0x01,
            0x15, 0x58, 0xa1, 0x01, 0x6e, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x5f, 0x62,
            0x69, 0x6e, 0x61, 0x72, 0x79,
        ];
        assert_eq!(EXPECTED_CONFIG_DESCRIPTOR, &config_descriptor);
        Ok(())
    }
}
