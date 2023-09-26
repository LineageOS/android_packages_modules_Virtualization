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

//! Errors and relating structs thrown by the BoringSSL wrapper library.

#![cfg_attr(not(feature = "std"), no_std)]

use core::{fmt, result};
use serde::{Deserialize, Serialize};

/// libbssl_avf result type.
pub type Result<T> = result::Result<T, Error>;

/// Error type used by libbssl_avf.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Error {
    /// Failed to invoke a BoringSSL API.
    CallFailed(ApiName),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::CallFailed(api_name) => {
                write!(f, "Failed to invoke the BoringSSL API: {api_name:?}")
            }
        }
    }
}

/// BoringSSL API names.
#[allow(missing_docs)]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApiName {
    BN_new,
    BN_bn2bin_padded,
    CBB_flush,
    CBB_len,
    EC_KEY_check_key,
    EC_KEY_generate_key,
    EC_KEY_get0_group,
    EC_KEY_get0_public_key,
    EC_KEY_marshal_private_key,
    EC_KEY_new_by_curve_name,
    EC_POINT_get_affine_coordinates,
    EVP_sha256,
    HMAC,
}
