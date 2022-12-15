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

//! This module regroups methods related to AvbOps.

#![warn(unsafe_op_in_unsafe_fn)]
// TODO(b/256148034): Remove this when the feature is code complete.
#![allow(dead_code)]
#![allow(unused_imports)]

use alloc::ffi::CString;
use avb_bindgen::{avb_slot_verify, AvbHashtreeErrorMode, AvbSlotVerifyFlags, AvbSlotVerifyResult};
use core::fmt;
use log::debug;

/// Error code from AVB image verification.
#[derive(Clone, Copy, Debug)]
pub enum AvbImageVerifyError {
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

fn to_avb_verify_result(result: AvbSlotVerifyResult) -> Result<(), AvbImageVerifyError> {
    match result {
        AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_OK => Ok(()),
        AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_ARGUMENT => {
            Err(AvbImageVerifyError::InvalidArgument)
        }
        AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_METADATA => {
            Err(AvbImageVerifyError::InvalidMetadata)
        }
        AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_ERROR_IO => Err(AvbImageVerifyError::Io),
        AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_ERROR_OOM => Err(AvbImageVerifyError::Oom),
        AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_ERROR_PUBLIC_KEY_REJECTED => {
            Err(AvbImageVerifyError::PublicKeyRejected)
        }
        AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_ERROR_ROLLBACK_INDEX => {
            Err(AvbImageVerifyError::RollbackIndex)
        }
        AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_ERROR_UNSUPPORTED_VERSION => {
            Err(AvbImageVerifyError::UnsupportedVersion)
        }
        AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION => {
            Err(AvbImageVerifyError::Verification)
        }
    }
}

impl fmt::Display for AvbImageVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InvalidArgument => write!(f, "Invalid parameters."),
            Self::InvalidMetadata => write!(f, "Invalid metadata."),
            Self::Io => write!(f, "I/O error while trying to load data or get a rollback index."),
            Self::Oom => write!(f, "Unable to allocate memory."),
            Self::PublicKeyRejected => write!(
                f,
                "Everything is verified correctly out but the public key is not accepted. \
                This includes the case where integrity data is not signed."
            ),
            Self::RollbackIndex => write!(f, "Rollback index is less than its stored value."),
            Self::UnsupportedVersion => write!(
                f,
                "Some of the metadata requires a newer version of libavb than what is in use."
            ),
            Self::Verification => write!(f, "Data does not verify."),
        }
    }
}

/// Verifies that for the given image:
///  - The given public key is acceptable.
///  - The VBMeta struct is valid.
///  - The partitions of the image match the descriptors of the verified VBMeta struct.
/// Returns Ok if everything is verified correctly and the public key is accepted.
pub fn verify_image(_image: &[u8], _public_key: &[u8]) -> Result<(), AvbImageVerifyError> {
    // TODO(b/256148034): Call verify_slot() from pvmfw.
    AvbOps::new().verify_slot()
}

/// TODO(b/256148034): Make AvbOps a rust wrapper of avb_bindgen::AvbOps using foreign_types.
struct AvbOps {}

impl AvbOps {
    fn new() -> Self {
        AvbOps {}
    }

    fn verify_slot(&mut self) -> Result<(), AvbImageVerifyError> {
        let flags = AvbSlotVerifyFlags::AVB_SLOT_VERIFY_FLAGS_NO_VBMETA_PARTITION;
        let hashtree_error_mode = AvbHashtreeErrorMode::AVB_HASHTREE_ERROR_MODE_EIO;
        debug!("flags: {:?}", flags);
        debug!("hashtree_error_mode: {:?}", hashtree_error_mode);
        // TODO(b/256148034): Verify the kernel image with avb_slot_verify()
        // let result = unsafe {
        //     avb_slot_verify(
        //         self.as_ptr(),
        //         requested_partitions.as_ptr(),
        //         ab_suffix.as_ptr(),
        //         flags,
        //         hashtree_error_mode,
        //         &image.as_ptr(),
        //     )
        // };
        let result = AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_OK;
        to_avb_verify_result(result)
    }
}
