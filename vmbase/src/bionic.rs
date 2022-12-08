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

use crate::linker;

/// Reference to __stack_chk_guard.
pub static STACK_CHK_GUARD: &u64 = unsafe { &linker::__stack_chk_guard };

#[no_mangle]
extern "C" fn __stack_chk_fail() -> ! {
    panic!("stack guard check failed");
}
