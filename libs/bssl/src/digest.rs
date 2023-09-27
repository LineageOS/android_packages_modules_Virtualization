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

//! Wrappers of the digest functions in BoringSSL digest.h.

use bssl_ffi::{EVP_MD_size, EVP_sha256, EVP_sha512, EVP_MD};

/// Message digester wrapping `EVP_MD`.
#[derive(Clone, Debug)]
pub struct Digester(pub(crate) &'static EVP_MD);

impl Digester {
    /// Returns a `Digester` implementing `SHA-256` algorithm.
    pub fn sha256() -> Self {
        // SAFETY: This function does not access any Rust variables and simply returns
        // a pointer to the static variable in BoringSSL.
        let p = unsafe { EVP_sha256() };
        // SAFETY: The returned pointer should always be valid and points to a static
        // `EVP_MD`.
        Self(unsafe { &*p })
    }

    /// Returns a `Digester` implementing `SHA-512` algorithm.
    #[allow(dead_code)]
    pub fn sha512() -> Self {
        // SAFETY: This function does not access any Rust variables and simply returns
        // a pointer to the static variable in BoringSSL.
        let p = unsafe { EVP_sha512() };
        // SAFETY: The returned pointer should always be valid and points to a static
        // `EVP_MD`.
        Self(unsafe { &*p })
    }

    /// Returns the digest size in bytes.
    pub fn size(&self) -> usize {
        // SAFETY: The inner pointer is fetched from EVP_* hash functions in BoringSSL digest.h
        unsafe { EVP_MD_size(self.0) }
    }
}
