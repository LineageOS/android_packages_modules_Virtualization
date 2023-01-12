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
use core::mem;
use core::ptr;
use core::result;

use open_dice_cbor_bindgen::DiceConfigType_kDiceConfigTypeDescriptor as DICE_CONFIG_TYPE_DESCRIPTOR;
use open_dice_cbor_bindgen::DiceConfigType_kDiceConfigTypeInline as DICE_CONFIG_TYPE_INLINE;
use open_dice_cbor_bindgen::DiceHash;
use open_dice_cbor_bindgen::DiceInputValues;
use open_dice_cbor_bindgen::DiceMode;
use open_dice_cbor_bindgen::DiceMode_kDiceModeDebug as DICE_MODE_DEBUG;
use open_dice_cbor_bindgen::DiceMode_kDiceModeMaintenance as DICE_MODE_MAINTENANCE;
use open_dice_cbor_bindgen::DiceMode_kDiceModeNormal as DICE_MODE_NORMAL;
use open_dice_cbor_bindgen::DiceMode_kDiceModeNotInitialized as DICE_MODE_NOT_INITIALIZED;
use open_dice_cbor_bindgen::DiceResult;
use open_dice_cbor_bindgen::DiceResult_kDiceResultBufferTooSmall as DICE_RESULT_BUFFER_TOO_SMALL;
use open_dice_cbor_bindgen::DiceResult_kDiceResultInvalidInput as DICE_RESULT_INVALID_INPUT;
use open_dice_cbor_bindgen::DiceResult_kDiceResultOk as DICE_RESULT_OK;
use open_dice_cbor_bindgen::DiceResult_kDiceResultPlatformError as DICE_RESULT_PLATFORM_ERROR;

pub mod bcc;

const CDI_SIZE: usize = open_dice_cbor_bindgen::DICE_CDI_SIZE as usize;
const HASH_SIZE: usize = open_dice_cbor_bindgen::DICE_HASH_SIZE as usize;
const HIDDEN_SIZE: usize = open_dice_cbor_bindgen::DICE_HIDDEN_SIZE as usize;
const INLINE_CONFIG_SIZE: usize = open_dice_cbor_bindgen::DICE_INLINE_CONFIG_SIZE as usize;

/// Array type of CDIs.
pub type Cdi = [u8; CDI_SIZE];
/// Array type of hashes used by DICE.
pub type Hash = [u8; HASH_SIZE];
/// Array type of additional input.
pub type Hidden = [u8; HIDDEN_SIZE];
/// Array type of inline configuration values.
pub type InlineConfig = [u8; INLINE_CONFIG_SIZE];

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

/// DICE mode values.
#[derive(Clone, Copy, Debug)]
pub enum Mode {
    /// At least one security mechanism has not been configured. Also acts as a catch-all.
    /// Invalid mode values should be treated like this mode.
    NotInitialized = DICE_MODE_NOT_INITIALIZED as _,
    /// Indicates the device is operating normally under secure configuration.
    Normal = DICE_MODE_NORMAL as _,
    /// Indicates at least one criteria for Normal mode is not met.
    Debug = DICE_MODE_DEBUG as _,
    /// Indicates a recovery or maintenance mode of some kind.
    Maintenance = DICE_MODE_MAINTENANCE as _,
}

impl From<Mode> for DiceMode {
    fn from(mode: Mode) -> Self {
        mode as Self
    }
}

/// DICE configuration input type.
#[derive(Debug)]
pub enum ConfigType<'a> {
    /// Uses the formatted 64-byte configuration input value (See the Open Profile for DICE).
    Inline(InlineConfig),
    /// Uses the 64-byte hash of more configuration data.
    Descriptor(&'a [u8]),
}

/// Set of DICE inputs.
#[repr(transparent)]
#[derive(Clone, Debug)]
pub struct InputValues(DiceInputValues);

impl InputValues {
    /// Wrap the DICE inputs in a InputValues, expected by bcc::main_flow().
    pub fn new(
        code_hash: &Hash,
        code_descriptor: Option<&[u8]>,
        config: &ConfigType,
        auth_hash: Option<&Hash>,
        auth_descriptor: Option<&[u8]>,
        mode: Mode,
        hidden: Option<&Hidden>,
    ) -> Self {
        const ZEROED_INLINE_CONFIG: InlineConfig = [0; INLINE_CONFIG_SIZE];
        let (config_type, config_value, config_descriptor) = match config {
            ConfigType::Inline(value) => (DICE_CONFIG_TYPE_INLINE, *value, None),
            ConfigType::Descriptor(desc) => {
                (DICE_CONFIG_TYPE_DESCRIPTOR, ZEROED_INLINE_CONFIG, Some(*desc))
            }
        };
        let (code_descriptor, code_descriptor_size) = as_raw_parts(code_descriptor);
        let (config_descriptor, config_descriptor_size) = as_raw_parts(config_descriptor);
        let (authority_descriptor, authority_descriptor_size) = as_raw_parts(auth_descriptor);

        Self(DiceInputValues {
            code_hash: *code_hash,
            code_descriptor,
            code_descriptor_size,
            config_type,
            config_value,
            config_descriptor,
            config_descriptor_size,
            authority_hash: auth_hash.map_or([0; mem::size_of::<Hash>()], |h| *h),
            authority_descriptor,
            authority_descriptor_size,
            mode: mode.into(),
            hidden: hidden.map_or([0; mem::size_of::<Hidden>()], |h| *h),
        })
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

fn as_raw_parts<T: Sized>(s: Option<&[T]>) -> (*const T, usize) {
    match s {
        Some(s) => (s.as_ptr(), s.len()),
        None => (ptr::null(), 0),
    }
}
