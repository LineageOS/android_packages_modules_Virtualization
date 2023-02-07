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

//! Bare metal wrapper around libopen_dice.

#![no_std]

pub use diced_open_dice::{
    bcc_format_config_descriptor, check_result, Cdi, Config, DiceError, DiceMode, Hash,
    InputValues, Result, CDI_SIZE, HASH_SIZE, HIDDEN_SIZE,
};

use open_dice_cbor_bindgen::DiceHash;

pub mod bcc;

fn ctx() -> *mut core::ffi::c_void {
    core::ptr::null_mut()
}

/// Hash the provided input using DICE's default hash function.
pub fn hash(bytes: &[u8]) -> Result<Hash> {
    let mut output: Hash = [0; HASH_SIZE];
    // SAFETY - DiceHash takes a sized input buffer and writes to a constant-sized output buffer.
    check_result(unsafe { DiceHash(ctx(), bytes.as_ptr(), bytes.len(), output.as_mut_ptr()) })?;
    Ok(output)
}
