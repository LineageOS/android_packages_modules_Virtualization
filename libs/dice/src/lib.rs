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

use core::fmt;
use core::result;

use open_dice_cbor_bindgen::DiceHash;
use open_dice_cbor_bindgen::DiceResult;
use open_dice_cbor_bindgen::DiceResult_kDiceResultBufferTooSmall as DICE_RESULT_BUFFER_TOO_SMALL;
use open_dice_cbor_bindgen::DiceResult_kDiceResultInvalidInput as DICE_RESULT_INVALID_INPUT;
use open_dice_cbor_bindgen::DiceResult_kDiceResultOk as DICE_RESULT_OK;
use open_dice_cbor_bindgen::DiceResult_kDiceResultPlatformError as DICE_RESULT_PLATFORM_ERROR;

pub mod bcc;

const CDI_SIZE: usize = open_dice_cbor_bindgen::DICE_CDI_SIZE as usize;
const HASH_SIZE: usize = open_dice_cbor_bindgen::DICE_HASH_SIZE as usize;

/// Array type of CDIs.
pub type Cdi = [u8; CDI_SIZE];
/// Array type of hashes used by DICE.
pub type Hash = [u8; HASH_SIZE];

/// Error type used by DICE.
pub enum Error {
    /// Provided input was invalid.
    InvalidInput,
    /// Provided buffer was too small.
    BufferTooSmall,
    /// Unexpected platform error.
    PlatformError,
    /// Unexpected return value.
    Unknown(DiceResult),
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidInput => write!(f, "invalid input"),
            Error::BufferTooSmall => write!(f, "buffer too small"),
            Error::PlatformError => write!(f, "platform error"),
            Error::Unknown(n) => write!(f, "unknown error: {}", n),
        }
    }
}

/// Result of DICE functions.
pub type Result<T> = result::Result<T, Error>;

fn check_call(ret: DiceResult) -> Result<()> {
    match ret {
        DICE_RESULT_OK => Ok(()),
        DICE_RESULT_INVALID_INPUT => Err(Error::InvalidInput),
        DICE_RESULT_BUFFER_TOO_SMALL => Err(Error::BufferTooSmall),
        DICE_RESULT_PLATFORM_ERROR => Err(Error::PlatformError),
        n => Err(Error::Unknown(n)),
    }
}

fn ctx() -> *mut core::ffi::c_void {
    core::ptr::null_mut()
}

/// Hash the provided input using DICE's default hash function.
pub fn hash(bytes: &[u8]) -> Result<Hash> {
    let mut output: Hash = [0; HASH_SIZE];
    // SAFETY - DiceHash takes a sized input buffer and writes to a constant-sized output buffer.
    check_call(unsafe { DiceHash(ctx(), bytes.as_ptr(), bytes.len(), output.as_mut_ptr()) })?;
    Ok(output)
}
