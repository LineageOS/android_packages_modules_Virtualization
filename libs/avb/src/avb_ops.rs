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

extern crate alloc;

use alloc::ffi::CString;
use avb_bindgen::{
    avb_slot_verify, AvbHashtreeErrorMode_AVB_HASHTREE_ERROR_MODE_EIO,
    AvbSlotVerifyFlags_AVB_SLOT_VERIFY_FLAGS_NO_VBMETA_PARTITION,
    AvbSlotVerifyResult_AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_ARGUMENT,
    AvbSlotVerifyResult_AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_METADATA,
    AvbSlotVerifyResult_AVB_SLOT_VERIFY_RESULT_ERROR_IO,
    AvbSlotVerifyResult_AVB_SLOT_VERIFY_RESULT_ERROR_OOM,
    AvbSlotVerifyResult_AVB_SLOT_VERIFY_RESULT_ERROR_PUBLIC_KEY_REJECTED,
    AvbSlotVerifyResult_AVB_SLOT_VERIFY_RESULT_ERROR_ROLLBACK_INDEX,
    AvbSlotVerifyResult_AVB_SLOT_VERIFY_RESULT_ERROR_UNSUPPORTED_VERSION,
    AvbSlotVerifyResult_AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION,
    AvbSlotVerifyResult_AVB_SLOT_VERIFY_RESULT_OK,
};
use core::fmt;
use log::debug;

/// Error code from AVB image verification.
#[derive(Clone, Copy, Debug)]
pub enum AvbImageVerifyError {
    /// AvbSlotVerifyResult_AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_ARGUMENT
    InvalidArgument,
    /// AvbSlotVerifyResult_AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_METADATA
    InvalidMetadata,
    /// AvbSlotVerifyResult_AVB_SLOT_VERIFY_RESULT_ERROR_IO
    Io,
    /// AvbSlotVerifyResult_AVB_SLOT_VERIFY_RESULT_ERROR_OOM
    Oom,
    /// AvbSlotVerifyResult_AVB_SLOT_VERIFY_RESULT_ERROR_PUBLIC_KEY_REJECTED
    PublicKeyRejected,
    /// AvbSlotVerifyResult_AVB_SLOT_VERIFY_RESULT_ERROR_ROLLBACK_INDEX
    RollbackIndex,
    /// AvbSlotVerifyResult_AVB_SLOT_VERIFY_RESULT_ERROR_UNSUPPORTED_VERSION
    UnsupportedVersion,
    /// AvbSlotVerifyResult_AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION
    Verification,
    /// Unknown error.
    Unknown(u32),
}

fn to_avb_verify_result(result: u32) -> Result<(), AvbImageVerifyError> {
    #[allow(non_upper_case_globals)]
    match result {
        AvbSlotVerifyResult_AVB_SLOT_VERIFY_RESULT_OK => Ok(()),
        AvbSlotVerifyResult_AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_ARGUMENT => {
            Err(AvbImageVerifyError::InvalidArgument)
        }
        AvbSlotVerifyResult_AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_METADATA => {
            Err(AvbImageVerifyError::InvalidMetadata)
        }
        AvbSlotVerifyResult_AVB_SLOT_VERIFY_RESULT_ERROR_IO => Err(AvbImageVerifyError::Io),
        AvbSlotVerifyResult_AVB_SLOT_VERIFY_RESULT_ERROR_OOM => Err(AvbImageVerifyError::Oom),
        AvbSlotVerifyResult_AVB_SLOT_VERIFY_RESULT_ERROR_PUBLIC_KEY_REJECTED => {
            Err(AvbImageVerifyError::PublicKeyRejected)
        }
        AvbSlotVerifyResult_AVB_SLOT_VERIFY_RESULT_ERROR_ROLLBACK_INDEX => {
            Err(AvbImageVerifyError::RollbackIndex)
        }
        AvbSlotVerifyResult_AVB_SLOT_VERIFY_RESULT_ERROR_UNSUPPORTED_VERSION => {
            Err(AvbImageVerifyError::UnsupportedVersion)
        }
        AvbSlotVerifyResult_AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION => {
            Err(AvbImageVerifyError::Verification)
        }
        _ => Err(AvbImageVerifyError::Unknown(result)),
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
            Self::Unknown(e) => write!(f, "Unknown avb_slot_verify error '{e}'"),
        }
    }
}

/// Verifies that for the given image:
///  - The given public key is acceptable.
///  - The VBMeta struct is valid.
///  - The partitions of the image match the descriptors of the verified VBMeta struct.
/// Returns Ok if everything is verified correctly and the public key is accepted.
pub fn verify_image(image: &[u8], public_key: &[u8]) -> Result<(), AvbImageVerifyError> {
    AvbOps::new().verify_image(image, public_key)
}

/// TODO(b/256148034): Make AvbOps a rust wrapper of avb_bindgen::AvbOps using foreign_types.
struct AvbOps {}

impl AvbOps {
    fn new() -> Self {
        AvbOps {}
    }

    fn verify_image(&self, image: &[u8], public_key: &[u8]) -> Result<(), AvbImageVerifyError> {
        debug!("AVB image: addr={:?}, size={:#x} ({1})", image.as_ptr(), image.len());
        debug!(
            "AVB public key: addr={:?}, size={:#x} ({1})",
            public_key.as_ptr(),
            public_key.len()
        );
        // TODO(b/256148034): Verify the kernel image with avb_slot_verify()
        // let result = unsafe {
        //     avb_slot_verify(
        //         self.as_ptr(),
        //         requested_partitions.as_ptr(),
        //         ab_suffix.as_ptr(),
        //         AvbSlotVerifyFlags_AVB_SLOT_VERIFY_FLAGS_NO_VBMETA_PARTITION,
        //         AvbHashtreeErrorMode_AVB_HASHTREE_ERROR_MODE_EIO,
        //         &image.as_ptr(),
        //     )
        // };
        let result = AvbSlotVerifyResult_AVB_SLOT_VERIFY_RESULT_OK;
        to_avb_verify_result(result)
    }
}
