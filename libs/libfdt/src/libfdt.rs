// Copyright 2024, The Android Open Source Project
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

//! Low-level libfdt_bindgen wrapper, easy to integrate safely in higher-level APIs.

use crate::{fdt_err_expect_zero, Result};

// Function names are the C function names without the `fdt_` prefix.

/// Safe wrapper around `fdt_create_empty_tree()` (C function).
pub(crate) fn create_empty_tree(fdt: &mut [u8]) -> Result<()> {
    let len = fdt.len().try_into().unwrap();
    let fdt = fdt.as_mut_ptr().cast();
    // SAFETY: fdt_create_empty_tree() only write within the specified length,
    //          and returns error if buffer was insufficient.
    //          There will be no memory write outside of the given fdt.
    let ret = unsafe { libfdt_bindgen::fdt_create_empty_tree(fdt, len) };

    fdt_err_expect_zero(ret)
}

/// Safe wrapper around `fdt_check_full()` (C function).
pub(crate) fn check_full(fdt: &[u8]) -> Result<()> {
    let len = fdt.len();
    let fdt = fdt.as_ptr().cast();
    // SAFETY: Only performs read accesses within the limits of the slice. If successful, this
    // call guarantees to other unsafe calls that the header contains a valid totalsize (w.r.t.
    // 'len' i.e. the self.fdt slice) that those C functions can use to perform bounds
    // checking. The library doesn't maintain an internal state (such as pointers) between
    // calls as it expects the client code to keep track of the objects (DT, nodes, ...).
    let ret = unsafe { libfdt_bindgen::fdt_check_full(fdt, len) };

    fdt_err_expect_zero(ret)
}
