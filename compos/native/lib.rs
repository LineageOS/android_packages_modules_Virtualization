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

//! Native helpers for CompOS.

pub use crypto::*;

#[cxx::bridge]
mod crypto {
    /// Contains either a key pair or a reason why the key could not be extracted.
    struct KeyResult {
        /// The DER-encoded RSAPublicKey
        /// (https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.1.1).
        public_key: Vec<u8>,
        /// The DER-encoded RSAPrivateKey
        /// (https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.1.2).
        /// Note that this is unencrypted.
        private_key: Vec<u8>,
        /// A description of what went wrong if the attempt failed.
        error: String,
    }

    /// Contains either a signature or a reason why signing failed.
    struct SignResult {
        /// The RSAES-PKCS1-v1_5 signature
        /// (https://datatracker.ietf.org/doc/html/rfc3447#section-7.2).
        signature: Vec<u8>,
        /// A description of what went wrong if the attempt failed.
        error: String,
    }

    unsafe extern "C++" {
        include!("compos_native.h");

        // SAFETY: The C++ implementation manages its own memory. cxx handles the mapping of the
        // return value.

        /// Generate a public/private key pair.
        fn generate_key_pair() -> KeyResult;

        // SAFETY: The C++ implementation manages its own memory, and does not retain or abuse
        // the references passed to it. cxx handles the mapping of the return value.

        /// Sign data using a SHA256 digest and RSAES-PKCS1-v1_5 using the given
        /// DER-encoded RSAPrivateKey.
        fn sign(private_key: &[u8], data: &[u8]) -> SignResult;
    }
}
