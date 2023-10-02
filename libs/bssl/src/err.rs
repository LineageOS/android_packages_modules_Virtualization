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

//! Wrappers of the error handling functions in BoringSSL err.h.

use bssl_avf_error::{CipherError, GlobalError, ReasonCode};
use bssl_ffi::{self, ERR_get_error, ERR_GET_LIB_RUST, ERR_GET_REASON_RUST};

const NO_ERROR_REASON_CODE: i32 = 0;

/// Returns the reason code for the least recent error and removes that
/// error from the error queue.
pub(crate) fn get_error_reason_code() -> ReasonCode {
    let packed_error = get_packed_error();
    let reason = get_reason(packed_error);
    let lib = get_lib(packed_error);
    map_to_reason_code(reason, lib)
}

/// Returns the packed error code for the least recent error and removes that
/// error from the error queue.
///
/// Returns 0 if there are no errors in the queue.
fn get_packed_error() -> u32 {
    // SAFETY: This function only reads the error queue.
    unsafe { ERR_get_error() }
}

fn get_reason(packed_error: u32) -> i32 {
    // SAFETY: This function only reads the given error code.
    unsafe { ERR_GET_REASON_RUST(packed_error) }
}

/// Returns the library code for the error.
fn get_lib(packed_error: u32) -> i32 {
    // SAFETY: This function only reads the given error code.
    unsafe { ERR_GET_LIB_RUST(packed_error) }
}

fn map_to_reason_code(reason: i32, lib: i32) -> ReasonCode {
    if reason == NO_ERROR_REASON_CODE {
        return ReasonCode::NoError;
    }
    map_global_reason_code(reason)
        .map(ReasonCode::Global)
        .or_else(|| map_library_reason_code(reason, lib))
        .unwrap_or(ReasonCode::Unknown(reason, lib))
}

/// Global errors may occur in any library.
fn map_global_reason_code(reason: i32) -> Option<GlobalError> {
    let reason = match reason {
        bssl_ffi::ERR_R_FATAL => GlobalError::Fatal,
        bssl_ffi::ERR_R_MALLOC_FAILURE => GlobalError::MallocFailure,
        bssl_ffi::ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED => GlobalError::ShouldNotHaveBeenCalled,
        bssl_ffi::ERR_R_PASSED_NULL_PARAMETER => GlobalError::PassedNullParameter,
        bssl_ffi::ERR_R_INTERNAL_ERROR => GlobalError::InternalError,
        bssl_ffi::ERR_R_OVERFLOW => GlobalError::Overflow,
        _ => return None,
    };
    Some(reason)
}

fn map_library_reason_code(reason: i32, lib: i32) -> Option<ReasonCode> {
    u32::try_from(lib).ok().and_then(|x| match x {
        bssl_ffi::ERR_LIB_CIPHER => map_cipher_reason_code(reason).map(ReasonCode::Cipher),
        _ => None,
    })
}

fn map_cipher_reason_code(reason: i32) -> Option<CipherError> {
    let error = match reason {
        bssl_ffi::CIPHER_R_AES_KEY_SETUP_FAILED => CipherError::AesKeySetupFailed,
        bssl_ffi::CIPHER_R_BAD_DECRYPT => CipherError::BadDecrypt,
        bssl_ffi::CIPHER_R_BAD_KEY_LENGTH => CipherError::BadKeyLength,
        bssl_ffi::CIPHER_R_BUFFER_TOO_SMALL => CipherError::BufferTooSmall,
        bssl_ffi::CIPHER_R_CTRL_NOT_IMPLEMENTED => CipherError::CtrlNotImplemented,
        bssl_ffi::CIPHER_R_CTRL_OPERATION_NOT_IMPLEMENTED => {
            CipherError::CtrlOperationNotImplemented
        }
        bssl_ffi::CIPHER_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH => {
            CipherError::DataNotMultipleOfBlockLength
        }
        bssl_ffi::CIPHER_R_INITIALIZATION_ERROR => CipherError::InitializationError,
        bssl_ffi::CIPHER_R_INPUT_NOT_INITIALIZED => CipherError::InputNotInitialized,
        bssl_ffi::CIPHER_R_INVALID_AD_SIZE => CipherError::InvalidAdSize,
        bssl_ffi::CIPHER_R_INVALID_KEY_LENGTH => CipherError::InvalidKeyLength,
        bssl_ffi::CIPHER_R_INVALID_NONCE_SIZE => CipherError::InvalidNonceSize,
        bssl_ffi::CIPHER_R_INVALID_OPERATION => CipherError::InvalidOperation,
        bssl_ffi::CIPHER_R_IV_TOO_LARGE => CipherError::IvTooLarge,
        bssl_ffi::CIPHER_R_NO_CIPHER_SET => CipherError::NoCipherSet,
        bssl_ffi::CIPHER_R_OUTPUT_ALIASES_INPUT => CipherError::OutputAliasesInput,
        bssl_ffi::CIPHER_R_TAG_TOO_LARGE => CipherError::TagTooLarge,
        bssl_ffi::CIPHER_R_TOO_LARGE => CipherError::TooLarge,
        bssl_ffi::CIPHER_R_WRONG_FINAL_BLOCK_LENGTH => CipherError::WrongFinalBlockLength,
        bssl_ffi::CIPHER_R_NO_DIRECTION_SET => CipherError::NoDirectionSet,
        bssl_ffi::CIPHER_R_INVALID_NONCE => CipherError::InvalidNonce,
        _ => return None,
    };
    Some(error)
}
