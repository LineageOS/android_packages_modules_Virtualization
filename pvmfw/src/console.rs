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

//! Console driver for 8250 UART.

use crate::uart::Uart;
use core::fmt::{write, Arguments, Write};
use spin::mutex::SpinMutex;

const BASE_ADDRESS: usize = 0x3f8;

static CONSOLE: SpinMutex<Option<Uart>> = SpinMutex::new(None);

/// Initialises a new instance of the UART driver and returns it.
fn create() -> Uart {
    // Safe because BASE_ADDRESS is the base of the MMIO region for a UART and is mapped as device
    // memory.
    unsafe { Uart::new(BASE_ADDRESS) }
}

/// Initialises the global instance of the UART driver. This must be called before using
/// the `print!` and `println!` macros.
pub fn init() {
    let uart = create();
    CONSOLE.lock().replace(uart);
}

/// Writes a string to the console.
///
/// Panics if [`init`] was not called first.
pub fn write_str(s: &str) {
    CONSOLE.lock().as_mut().unwrap().write_str(s).unwrap();
}

/// Writes a formatted string to the console.
///
/// Panics if [`init`] was not called first.
#[allow(unused)]
pub fn write_args(format_args: Arguments) {
    write(CONSOLE.lock().as_mut().unwrap(), format_args).unwrap();
}

/// Reinitialises the UART driver and writes a string to it.
///
/// This is intended for use in situations where the UART may be in an unknown state or the global
/// instance may be locked, such as in an exception handler or panic handler.
pub fn emergency_write_str(s: &str) {
    let mut uart = create();
    let _ = uart.write_str(s);
}
