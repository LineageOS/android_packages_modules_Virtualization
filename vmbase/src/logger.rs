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

//! Logger for vmbase.
//!
//! Internally uses the println! vmbase macro, which prints to crosvm's UART.
//! Note: may not work if the VM is in an inconsistent state. Exception handlers
//! should avoid using this logger and instead print with eprintln!.

extern crate log;

use super::println;
use log::{LevelFilter, Log, Metadata, Record, SetLoggerError};

struct Logger;
static LOGGER: Logger = Logger;

impl Log for Logger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        println!("[{}] {}", record.level(), record.args());
    }

    fn flush(&self) {}
}

/// Initialize vmbase logger with a given max logging level.
pub fn init(max_level: LevelFilter) -> Result<(), SetLoggerError> {
    log::set_logger(&LOGGER)?;
    log::set_max_level(max_level);
    Ok(())
}
