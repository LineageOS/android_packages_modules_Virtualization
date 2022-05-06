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

//! Rust entry point.

use crate::{console, power::shutdown};

/// This is the entry point to the Rust code, called from the binary entry point in `entry.S`.
#[no_mangle]
extern "C" fn rust_entry() -> ! {
    console::init();
    unsafe {
        main();
    }
    shutdown();
}

extern "Rust" {
    /// Main function provided by the application using the `main!` macro.
    fn main();
}

/// Marks the main function of the binary.
///
/// Example:
///
/// ```rust
/// use vmbase::main;
///
/// main!(my_main);
///
/// fn my_main() {
///     println!("Hello world");
/// }
/// ```
#[macro_export]
macro_rules! main {
    ($name:path) => {
        // Export a symbol with a name matching the extern declaration above.
        #[export_name = "main"]
        fn __main() {
            // Ensure that the main function provided by the application has the correct type.
            $name()
        }
    };
}
