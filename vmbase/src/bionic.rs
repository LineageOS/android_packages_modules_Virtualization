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

//! Low-level compatibility layer between baremetal Rust and Bionic C functions.

use core::ffi::c_char;
use core::ffi::c_int;
use core::ffi::CStr;

use crate::eprintln;
use crate::linker;

/// Reference to __stack_chk_guard.
pub static STACK_CHK_GUARD: &u64 = unsafe { &linker::__stack_chk_guard };

#[no_mangle]
extern "C" fn __stack_chk_fail() -> ! {
    panic!("stack guard check failed");
}

/// Called from C to cause abnormal program termination.
#[no_mangle]
extern "C" fn abort() -> ! {
    panic!("C code called abort()")
}

/// Error number set and read by C functions.
pub static mut ERRNO: c_int = 0;

#[no_mangle]
unsafe extern "C" fn __errno() -> *mut c_int {
    &mut ERRNO as *mut _
}

/// Reports a fatal error detected by Bionic.
///
/// # Safety
///
/// Input strings `prefix` and `format` must be properly NULL-terminated.
///
/// # Note
///
/// This Rust functions is missing the last argument of its C/C++ counterpart, a va_list.
#[no_mangle]
unsafe extern "C" fn async_safe_fatal_va_list(prefix: *const c_char, format: *const c_char) {
    let prefix = CStr::from_ptr(prefix);
    let format = CStr::from_ptr(format);

    if let (Ok(prefix), Ok(format)) = (prefix.to_str(), format.to_str()) {
        // We don't bother with printf formatting.
        eprintln!("FATAL BIONIC ERROR: {prefix}: \"{format}\" (unformatted)");
    }
}
