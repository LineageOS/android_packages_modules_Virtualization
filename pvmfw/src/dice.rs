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

use crate::cstr;
use core::ffi::c_void;
use core::mem::size_of;
use core::slice;
use vmbase::memory::flushed_zeroize;

use diced_open_dice::{
    bcc_format_config_descriptor, bcc_handover_main_flow, hash, Config, DiceMode, Hash,
    InputValues, HIDDEN_SIZE,
};
use pvmfw_avb::{DebugLevel, Digest, VerifiedBootData};

fn to_dice_mode(debug_level: DebugLevel) -> DiceMode {
    match debug_level {
        DebugLevel::None => DiceMode::kDiceModeNormal,
        DebugLevel::Full => DiceMode::kDiceModeDebug,
    }
}

fn to_dice_hash(verified_boot_data: &VerifiedBootData) -> diced_open_dice::Result<Hash> {
    let mut digests = [0u8; size_of::<Digest>() * 2];
    digests[..size_of::<Digest>()].copy_from_slice(&verified_boot_data.kernel_digest);
    if let Some(initrd_digest) = verified_boot_data.initrd_digest {
        digests[size_of::<Digest>()..].copy_from_slice(&initrd_digest);
    }
    hash(&digests)
}

pub struct PartialInputs {
    pub code_hash: Hash,
    pub auth_hash: Hash,
    pub mode: DiceMode,
}

impl PartialInputs {
    pub fn new(data: &VerifiedBootData) -> diced_open_dice::Result<Self> {
        let code_hash = to_dice_hash(data)?;
        let auth_hash = hash(data.public_key)?;
        let mode = to_dice_mode(data.debug_level);

        Ok(Self { code_hash, auth_hash, mode })
    }

    pub fn write_next_bcc(
        self,
        current_bcc_handover: &[u8],
        salt: &[u8; HIDDEN_SIZE],
        next_bcc: &mut [u8],
    ) -> diced_open_dice::Result<()> {
        let mut config_descriptor_buffer = [0; 128];
        let config_descriptor_size = bcc_format_config_descriptor(
            Some(cstr!("vm_entry")),
            None,  // component_version
            false, // resettable
            &mut config_descriptor_buffer,
        )?;
        let config = &config_descriptor_buffer[..config_descriptor_size];

        let dice_inputs = InputValues::new(
            self.code_hash,
            Config::Descriptor(config),
            self.auth_hash,
            self.mode,
            *salt,
        );
        let _ = bcc_handover_main_flow(current_bcc_handover, &dice_inputs, next_bcc)?;
        Ok(())
    }
}

/// Flushes data caches over the provided address range.
///
/// # Safety
///
/// The provided address and size must be to a valid address range (typically on the stack, .bss,
/// .data, or provided BCC).
#[no_mangle]
unsafe extern "C" fn DiceClearMemory(_ctx: *mut c_void, size: usize, addr: *mut c_void) {
    // SAFETY - We must trust that the slice will be valid arrays/variables on the C code stack.
    let region = unsafe { slice::from_raw_parts_mut(addr as *mut u8, size) };
    flushed_zeroize(region)
}
