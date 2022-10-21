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

//! Low-level entry and exit points of pvmfw.

use crate::helpers::FDT_MAX_SIZE;
use crate::jump_to_payload;
use core::slice;
use log::{error, LevelFilter};
use vmbase::{logger, main, power::reboot};

#[derive(Debug, Clone)]
enum RebootReason {
    /// An unexpected internal error happened.
    InternalError,
}

main!(start);

/// Entry point for pVM firmware.
pub fn start(fdt_address: u64, payload_start: u64, payload_size: u64, _arg3: u64) {
    // Limitations in this function:
    // - can't access non-pvmfw memory (only statically-mapped memory)
    // - can't access MMIO (therefore, no logging)

    match main_wrapper(fdt_address as usize, payload_start as usize, payload_size as usize) {
        Ok(_) => jump_to_payload(fdt_address, payload_start),
        Err(_) => reboot(),
    }

    // if we reach this point and return, vmbase::entry::rust_entry() will call power::shutdown().
}

/// Sets up the environment for main() and wraps its result for start().
///
/// Provide the abstractions necessary for start() to abort the pVM boot and for main() to run with
/// the assumption that its environment has been properly configured.
fn main_wrapper(fdt: usize, payload: usize, payload_size: usize) -> Result<(), RebootReason> {
    // Limitations in this function:
    // - only access MMIO once (and while) it has been mapped and configured
    // - only perform logging once the logger has been initialized
    // - only access non-pvmfw memory once (and while) it has been mapped
    logger::init(LevelFilter::Debug).map_err(|_| RebootReason::InternalError)?;

    // TODO: Check that the FDT is fully contained in RAM.
    // SAFETY - We trust the VMM, for now.
    let fdt = unsafe { slice::from_raw_parts_mut(fdt as *mut u8, FDT_MAX_SIZE) };
    // TODO: Check that the payload is fully contained in RAM and doesn't overlap with the FDT.
    // SAFETY - We trust the VMM, for now.
    let payload = unsafe { slice::from_raw_parts(payload as *const u8, payload_size) };

    // This wrapper allows main() to be blissfully ignorant of platform details.
    crate::main(fdt, payload).map_err(|e| {
        error!("{e}");
        RebootReason::InternalError
    })?;

    Ok(())
}
