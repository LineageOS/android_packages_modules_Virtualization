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

//! Wrappers of the EVP functions in BoringSSL evp.h.

use crate::cbb::CbbFixed;
use crate::ec_key::EcKey;
use crate::util::{check_int_result, to_call_failed_error};
use alloc::vec::Vec;
use bssl_avf_error::{ApiName, Result};
use bssl_ffi::{
    CBB_flush, CBB_len, EVP_PKEY_free, EVP_PKEY_new, EVP_PKEY_set1_EC_KEY, EVP_marshal_public_key,
    EVP_PKEY,
};
use core::ptr::NonNull;

/// Wrapper of an `EVP_PKEY` object, representing a public or private key.
pub struct EvpPKey {
    pkey: NonNull<EVP_PKEY>,
    /// Since this struct owns the inner key, the inner key remains valid as
    /// long as the pointer to `EVP_PKEY` is valid.
    _inner_key: EcKey,
}

impl Drop for EvpPKey {
    fn drop(&mut self) {
        // SAFETY: It is safe because `EVP_PKEY` has been allocated by BoringSSL and isn't
        // used after this.
        unsafe { EVP_PKEY_free(self.pkey.as_ptr()) }
    }
}

/// Creates a new empty `EVP_PKEY`.
fn new_pkey() -> Result<NonNull<EVP_PKEY>> {
    // SAFETY: The returned pointer is checked below.
    let key = unsafe { EVP_PKEY_new() };
    NonNull::new(key).ok_or(to_call_failed_error(ApiName::EVP_PKEY_new))
}

impl TryFrom<EcKey> for EvpPKey {
    type Error = bssl_avf_error::Error;

    fn try_from(key: EcKey) -> Result<Self> {
        let pkey = new_pkey()?;
        // SAFETY: The function only sets the inner key of the initialized and
        // non-null `EVP_PKEY` to point to the given `EC_KEY`. It only reads from
        // and writes to the initialized `EVP_PKEY`.
        // Since this struct owns the inner key, the inner key remains valid as
        // long as `EVP_PKEY` is valid.
        let ret = unsafe { EVP_PKEY_set1_EC_KEY(pkey.as_ptr(), key.0.as_ptr()) };
        check_int_result(ret, ApiName::EVP_PKEY_set1_EC_KEY)?;
        Ok(Self { pkey, _inner_key: key })
    }
}

impl EvpPKey {
    /// Returns a DER-encoded SubjectPublicKeyInfo structure as specified
    /// in RFC 5280 s4.1.2.7:
    ///
    /// https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.7
    pub fn subject_public_key_info(&self) -> Result<Vec<u8>> {
        const CAPACITY: usize = 256;
        let mut buf = [0u8; CAPACITY];
        let mut cbb = CbbFixed::new(buf.as_mut());
        // SAFETY: The function only write bytes to the buffer managed by the valid `CBB`.
        // The inner key in `EVP_PKEY` was set to a valid key when the object was created.
        // As this struct owns the inner key, the inner key is guaranteed to be valid
        // throughout the execution of the function.
        let ret = unsafe { EVP_marshal_public_key(cbb.as_mut(), self.pkey.as_ptr()) };
        check_int_result(ret, ApiName::EVP_marshal_public_key)?;
        // SAFETY: This is safe because the CBB pointer is a valid pointer initialized with
        // `CBB_init_fixed()`.
        check_int_result(unsafe { CBB_flush(cbb.as_mut()) }, ApiName::CBB_flush)?;
        // SAFETY: This is safe because the CBB pointer is initialized with `CBB_init_fixed()`,
        // and it has been flushed, thus it has no active children.
        let len = unsafe { CBB_len(cbb.as_ref()) };
        Ok(buf.get(0..len).ok_or(to_call_failed_error(ApiName::CBB_len))?.to_vec())
    }
}
