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

//! Native helpers for composd.

pub use art::*;
pub use crypto::*;

#[cxx::bridge]
mod crypto {
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

mod art {
    use anyhow::{anyhow, Result};
    use libc::c_char;
    use std::ffi::{CStr, OsStr};
    use std::io::Error;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr::null;

    // From libartpalette(-system)
    extern "C" {
        fn PaletteCreateOdrefreshStagingDirectory(out_staging_dir: *mut *const c_char) -> i32;
    }
    const PALETTE_STATUS_OK: i32 = 0;
    const PALETTE_STATUS_CHECK_ERRNO: i32 = 1;

    /// Creates and returns the staging directory for odrefresh.
    pub fn palette_create_odrefresh_staging_directory() -> Result<&'static Path> {
        let mut staging_dir: *const c_char = null();
        // SAFETY: The C function always returns a non-null C string (after created the directory).
        let status = unsafe { PaletteCreateOdrefreshStagingDirectory(&mut staging_dir) };
        match status {
            PALETTE_STATUS_OK => {
                // SAFETY: The previously returned `*const c_char` should point to a legitimate C
                // string.
                let cstr = unsafe { CStr::from_ptr(staging_dir) };
                let path = OsStr::from_bytes(cstr.to_bytes()).as_ref();
                Ok(path)
            }
            PALETTE_STATUS_CHECK_ERRNO => Err(anyhow!(Error::last_os_error().to_string())),
            _ => Err(anyhow!("Failed with palette status {}", status)),
        }
    }
}
