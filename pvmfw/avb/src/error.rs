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

//! This module contains the error thrown by the payload verification API.

use avb_bindgen::AvbSlotVerifyResult;

use core::fmt;

/// This error is the error part of `AvbSlotVerifyResult`.
/// It is the error thrown by the payload verification API `verify_payload()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AvbSlotVerifyError {
    /// AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_ARGUMENT
    InvalidArgument,
    /// AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_METADATA
    InvalidMetadata,
    /// AVB_SLOT_VERIFY_RESULT_ERROR_IO
    Io,
    /// AVB_SLOT_VERIFY_RESULT_ERROR_OOM
    Oom,
    /// AVB_SLOT_VERIFY_RESULT_ERROR_PUBLIC_KEY_REJECTED
    PublicKeyRejected,
    /// AVB_SLOT_VERIFY_RESULT_ERROR_ROLLBACK_INDEX
    RollbackIndex,
    /// AVB_SLOT_VERIFY_RESULT_ERROR_UNSUPPORTED_VERSION
    UnsupportedVersion,
    /// AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION
    Verification,
}

impl fmt::Display for AvbSlotVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InvalidArgument => write!(f, "Invalid parameters."),
            Self::InvalidMetadata => write!(f, "Invalid metadata."),
            Self::Io => write!(f, "I/O error while trying to load data or get a rollback index."),
            Self::Oom => write!(f, "Unable to allocate memory."),
            Self::PublicKeyRejected => write!(f, "Public key rejected or data not signed."),
            Self::RollbackIndex => write!(f, "Rollback index is less than its stored value."),
            Self::UnsupportedVersion => write!(
                f,
                "Some of the metadata requires a newer version of libavb than what is in use."
            ),
            Self::Verification => write!(f, "Data does not verify."),
        }
    }
}

pub(crate) fn slot_verify_result_to_verify_payload_result(
    result: AvbSlotVerifyResult,
) -> Result<(), AvbSlotVerifyError> {
    match result {
        AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_OK => Ok(()),
        AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_ARGUMENT => {
            Err(AvbSlotVerifyError::InvalidArgument)
        }
        AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_METADATA => {
            Err(AvbSlotVerifyError::InvalidMetadata)
        }
        AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_ERROR_IO => Err(AvbSlotVerifyError::Io),
        AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_ERROR_OOM => Err(AvbSlotVerifyError::Oom),
        AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_ERROR_PUBLIC_KEY_REJECTED => {
            Err(AvbSlotVerifyError::PublicKeyRejected)
        }
        AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_ERROR_ROLLBACK_INDEX => {
            Err(AvbSlotVerifyError::RollbackIndex)
        }
        AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_ERROR_UNSUPPORTED_VERSION => {
            Err(AvbSlotVerifyError::UnsupportedVersion)
        }
        AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION => {
            Err(AvbSlotVerifyError::Verification)
        }
    }
}
