// Copyright 2022, The Android Open Source Project
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

//! Support for DICE derivation and BCC generation.

use core::ffi::CStr;
use core::mem::size_of;
use dice::bcc::format_config_descriptor;
use dice::bcc::Handover;
use dice::hash;
use dice::Config;
use dice::DiceMode;
use dice::InputValues;
use dice::HIDDEN_SIZE;
use pvmfw_avb::{DebugLevel, Digest, VerifiedBootData};

fn to_dice_mode(debug_level: DebugLevel) -> DiceMode {
    match debug_level {
        DebugLevel::None => DiceMode::kDiceModeNormal,
        DebugLevel::Full => DiceMode::kDiceModeDebug,
    }
}

fn to_dice_hash(verified_boot_data: &VerifiedBootData) -> dice::Result<dice::Hash> {
    let mut digests = [0u8; size_of::<Digest>() * 2];
    digests[..size_of::<Digest>()].copy_from_slice(&verified_boot_data.kernel_digest);
    if let Some(initrd_digest) = verified_boot_data.initrd_digest {
        digests[size_of::<Digest>()..].copy_from_slice(&initrd_digest);
    }
    hash(&digests)
}

/// Derive the VM-specific secrets and certificate through DICE.
pub fn derive_next_bcc(
    bcc: &Handover,
    next_bcc: &mut [u8],
    verified_boot_data: &VerifiedBootData,
    authority: &[u8],
) -> dice::Result<usize> {
    let code_hash = to_dice_hash(verified_boot_data)?;
    let auth_hash = hash(authority)?;
    let mode = to_dice_mode(verified_boot_data.debug_level);
    let component_name = CStr::from_bytes_with_nul(b"vm_entry\0").unwrap();
    let mut config_descriptor_buffer = [0; 128];
    let config_descriptor_size = format_config_descriptor(
        &mut config_descriptor_buffer,
        Some(component_name),
        None,  // component_version
        false, // resettable
    )?;
    let config = &config_descriptor_buffer[..config_descriptor_size];

    let input_values = InputValues::new(
        code_hash,
        Config::Descriptor(config),
        auth_hash,
        mode,
        [0u8; HIDDEN_SIZE], // TODO(b/249723852): Get salt from instance.img (virtio-blk) and/or TRNG.
    );

    bcc.main_flow(&input_values, next_bcc)
}
