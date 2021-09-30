// Copyright 2021, The Android Open Source Project
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

//! Bindings native helpers for composd.

pub use ffi::*;

#[cxx::bridge]
mod ffi {
    /// Contains either a key or a reason why the key could not be extracted.
    struct KeyResult {
        /// The extracted key. If empty, the attempt to extract the key failed.
        key: Vec<u8>,
        /// A description of what went wrong if the attempt failed.
        error: String,
    }

    unsafe extern "C++" {
        include!("composd_native.h");

        // SAFETY: The C++ implementation manages its own memory, and does not retain or abuse
        // the der_certificate reference. cxx handles the mapping of the return value.

        /// Parse the supplied DER X.509 certificate and extract the subject's RsaPublicKey.
        fn extract_rsa_public_key(der_certificate: &[u8]) -> KeyResult;
    }
}
