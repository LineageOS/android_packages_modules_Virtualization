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

//! pVM firmware.

#![no_main]
#![no_std]

mod exceptions;

use vmbase::{main, println};

main!(main);

/// Entry point for pVM firmware.
pub fn main(fdt_address: u64, payload_start: u64, payload_size: u64, arg3: u64) {
    println!("pVM firmware");
    println!(
        "fdt_address={:#018x}, payload_start={:#018x}, payload_size={:#018x}, x3={:#018x}",
        fdt_address, payload_start, payload_size, arg3,
    );

    println!("Starting payload...");
    // Safe because this is a function we have implemented in assembly that matches its signature
    // here.
    unsafe {
        start_payload(fdt_address, payload_start);
    }
}

extern "C" {
    fn start_payload(fdt_address: u64, payload_start: u64) -> !;
}
