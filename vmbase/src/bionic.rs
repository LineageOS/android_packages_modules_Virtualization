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
use core::ffi::c_void;
use core::ffi::CStr;
use core::slice;
use core::str;

use crate::console;
use crate::eprintln;
use crate::linker;

const EOF: c_int = -1;

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

fn set_errno(value: c_int) {
    // SAFETY - vmbase is currently single-threaded.
    unsafe { ERRNO = value };
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

#[repr(usize)]
/// Arbitrary token FILE pseudo-pointers used by C to refer to the default streams.
enum File {
    Stdout = 0x7670cf00,
    Stderr = 0x9d118200,
}

impl TryFrom<usize> for File {
    type Error = &'static str;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            x if x == File::Stdout as _ => Ok(File::Stdout),
            x if x == File::Stderr as _ => Ok(File::Stderr),
            _ => Err("Received Invalid FILE* from C"),
        }
    }
}

#[no_mangle]
static stdout: File = File::Stdout;
#[no_mangle]
static stderr: File = File::Stderr;

#[no_mangle]
extern "C" fn fputs(c_str: *const c_char, stream: usize) -> c_int {
    // SAFETY - Just like libc, we need to assume that `s` is a valid NULL-terminated string.
    let c_str = unsafe { CStr::from_ptr(c_str) };

    if let (Ok(s), Ok(_)) = (c_str.to_str(), File::try_from(stream)) {
        console::write_str(s);
        0
    } else {
        set_errno(EOF);
        EOF
    }
}

#[no_mangle]
extern "C" fn fwrite(ptr: *const c_void, size: usize, nmemb: usize, stream: usize) -> usize {
    let length = size.saturating_mul(nmemb);

    // SAFETY - Just like libc, we need to assume that `ptr` is valid.
    let bytes = unsafe { slice::from_raw_parts(ptr as *const u8, length) };

    if let (Ok(s), Ok(_)) = (str::from_utf8(bytes), File::try_from(stream)) {
        console::write_str(s);
        length
    } else {
        0
    }
}
