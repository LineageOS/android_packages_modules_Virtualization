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

use bssl_avf_error::{CipherError, EcError, EcdsaError, GlobalError, ReasonCode};
use bssl_sys::{self, ERR_get_error, ERR_GET_LIB_RUST, ERR_GET_REASON_RUST};

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
        bssl_sys::ERR_R_FATAL => GlobalError::Fatal,
        bssl_sys::ERR_R_MALLOC_FAILURE => GlobalError::MallocFailure,
        bssl_sys::ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED => GlobalError::ShouldNotHaveBeenCalled,
        bssl_sys::ERR_R_PASSED_NULL_PARAMETER => GlobalError::PassedNullParameter,
        bssl_sys::ERR_R_INTERNAL_ERROR => GlobalError::InternalError,
        bssl_sys::ERR_R_OVERFLOW => GlobalError::Overflow,
        _ => return None,
    };
    Some(reason)
}

fn map_library_reason_code(reason: i32, lib: i32) -> Option<ReasonCode> {
    u32::try_from(lib).ok().and_then(|x| match x {
        bssl_sys::ERR_LIB_CIPHER => map_cipher_reason_code(reason).map(ReasonCode::Cipher),
        bssl_sys::ERR_LIB_EC => map_ec_reason_code(reason).map(ReasonCode::Ec),
        bssl_sys::ERR_LIB_ECDSA => map_ecdsa_reason_code(reason).map(ReasonCode::Ecdsa),
        _ => None,
    })
}

fn map_cipher_reason_code(reason: i32) -> Option<CipherError> {
    let error = match reason {
        bssl_sys::CIPHER_R_AES_KEY_SETUP_FAILED => CipherError::AesKeySetupFailed,
        bssl_sys::CIPHER_R_BAD_DECRYPT => CipherError::BadDecrypt,
        bssl_sys::CIPHER_R_BAD_KEY_LENGTH => CipherError::BadKeyLength,
        bssl_sys::CIPHER_R_BUFFER_TOO_SMALL => CipherError::BufferTooSmall,
        bssl_sys::CIPHER_R_CTRL_NOT_IMPLEMENTED => CipherError::CtrlNotImplemented,
        bssl_sys::CIPHER_R_CTRL_OPERATION_NOT_IMPLEMENTED => {
            CipherError::CtrlOperationNotImplemented
        }
        bssl_sys::CIPHER_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH => {
            CipherError::DataNotMultipleOfBlockLength
        }
        bssl_sys::CIPHER_R_INITIALIZATION_ERROR => CipherError::InitializationError,
        bssl_sys::CIPHER_R_INPUT_NOT_INITIALIZED => CipherError::InputNotInitialized,
        bssl_sys::CIPHER_R_INVALID_AD_SIZE => CipherError::InvalidAdSize,
        bssl_sys::CIPHER_R_INVALID_KEY_LENGTH => CipherError::InvalidKeyLength,
        bssl_sys::CIPHER_R_INVALID_NONCE_SIZE => CipherError::InvalidNonceSize,
        bssl_sys::CIPHER_R_INVALID_OPERATION => CipherError::InvalidOperation,
        bssl_sys::CIPHER_R_IV_TOO_LARGE => CipherError::IvTooLarge,
        bssl_sys::CIPHER_R_NO_CIPHER_SET => CipherError::NoCipherSet,
        bssl_sys::CIPHER_R_OUTPUT_ALIASES_INPUT => CipherError::OutputAliasesInput,
        bssl_sys::CIPHER_R_TAG_TOO_LARGE => CipherError::TagTooLarge,
        bssl_sys::CIPHER_R_TOO_LARGE => CipherError::TooLarge,
        bssl_sys::CIPHER_R_WRONG_FINAL_BLOCK_LENGTH => CipherError::WrongFinalBlockLength,
        bssl_sys::CIPHER_R_NO_DIRECTION_SET => CipherError::NoDirectionSet,
        bssl_sys::CIPHER_R_INVALID_NONCE => CipherError::InvalidNonce,
        _ => return None,
    };
    Some(error)
}

fn map_ec_reason_code(reason: i32) -> Option<EcError> {
    let error = match reason {
        bssl_sys::EC_R_BUFFER_TOO_SMALL => EcError::BufferTooSmall,
        bssl_sys::EC_R_COORDINATES_OUT_OF_RANGE => EcError::CoordinatesOutOfRange,
        bssl_sys::EC_R_D2I_ECPKPARAMETERS_FAILURE => EcError::D2IEcpkparametersFailure,
        bssl_sys::EC_R_EC_GROUP_NEW_BY_NAME_FAILURE => EcError::EcGroupNewByNameFailure,
        bssl_sys::EC_R_GROUP2PKPARAMETERS_FAILURE => EcError::Group2PkparametersFailure,
        bssl_sys::EC_R_I2D_ECPKPARAMETERS_FAILURE => EcError::I2DEcpkparametersFailure,
        bssl_sys::EC_R_INCOMPATIBLE_OBJECTS => EcError::IncompatibleObjects,
        bssl_sys::EC_R_INVALID_COMPRESSED_POINT => EcError::InvalidCompressedPoint,
        bssl_sys::EC_R_INVALID_COMPRESSION_BIT => EcError::InvalidCompressionBit,
        bssl_sys::EC_R_INVALID_ENCODING => EcError::InvalidEncoding,
        bssl_sys::EC_R_INVALID_FIELD => EcError::InvalidField,
        bssl_sys::EC_R_INVALID_FORM => EcError::InvalidForm,
        bssl_sys::EC_R_INVALID_GROUP_ORDER => EcError::InvalidGroupOrder,
        bssl_sys::EC_R_INVALID_PRIVATE_KEY => EcError::InvalidPrivateKey,
        bssl_sys::EC_R_MISSING_PARAMETERS => EcError::MissingParameters,
        bssl_sys::EC_R_MISSING_PRIVATE_KEY => EcError::MissingPrivateKey,
        bssl_sys::EC_R_NON_NAMED_CURVE => EcError::NonNamedCurve,
        bssl_sys::EC_R_NOT_INITIALIZED => EcError::NotInitialized,
        bssl_sys::EC_R_PKPARAMETERS2GROUP_FAILURE => EcError::Pkparameters2GroupFailure,
        bssl_sys::EC_R_POINT_AT_INFINITY => EcError::PointAtInfinity,
        bssl_sys::EC_R_POINT_IS_NOT_ON_CURVE => EcError::PointIsNotOnCurve,
        bssl_sys::EC_R_SLOT_FULL => EcError::SlotFull,
        bssl_sys::EC_R_UNDEFINED_GENERATOR => EcError::UndefinedGenerator,
        bssl_sys::EC_R_UNKNOWN_GROUP => EcError::UnknownGroup,
        bssl_sys::EC_R_UNKNOWN_ORDER => EcError::UnknownOrder,
        bssl_sys::EC_R_WRONG_ORDER => EcError::WrongOrder,
        bssl_sys::EC_R_BIGNUM_OUT_OF_RANGE => EcError::BignumOutOfRange,
        bssl_sys::EC_R_WRONG_CURVE_PARAMETERS => EcError::WrongCurveParameters,
        bssl_sys::EC_R_DECODE_ERROR => EcError::DecodeError,
        bssl_sys::EC_R_ENCODE_ERROR => EcError::EncodeError,
        bssl_sys::EC_R_GROUP_MISMATCH => EcError::GroupMismatch,
        bssl_sys::EC_R_INVALID_COFACTOR => EcError::InvalidCofactor,
        bssl_sys::EC_R_PUBLIC_KEY_VALIDATION_FAILED => EcError::PublicKeyValidationFailed,
        bssl_sys::EC_R_INVALID_SCALAR => EcError::InvalidScalar,
        _ => return None,
    };
    Some(error)
}

fn map_ecdsa_reason_code(reason: i32) -> Option<EcdsaError> {
    let error = match reason {
        bssl_sys::ECDSA_R_BAD_SIGNATURE => EcdsaError::BadSignature,
        bssl_sys::ECDSA_R_MISSING_PARAMETERS => EcdsaError::MissingParameters,
        bssl_sys::ECDSA_R_NEED_NEW_SETUP_VALUES => EcdsaError::NeedNewSetupValues,
        bssl_sys::ECDSA_R_NOT_IMPLEMENTED => EcdsaError::NotImplemented,
        bssl_sys::ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED => {
            EcdsaError::RandomNumberGenerationFailed
        }
        bssl_sys::ECDSA_R_ENCODE_ERROR => EcdsaError::EncodeError,
        bssl_sys::ECDSA_R_TOO_MANY_ITERATIONS => EcdsaError::TooManyIterations,
        _ => return None,
    };
    Some(error)
}
