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

use crate::heap;
use crate::helpers;
use crate::mmio_guard;
use core::arch::asm;
use core::slice;
use log::debug;
use log::error;
use log::LevelFilter;
use vmbase::{console, layout, logger, main, power::reboot};

#[derive(Debug, Clone)]
enum RebootReason {
    /// A malformed BCC was received.
    InvalidBcc,
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

    // SAFETY - This function should and will only be called once, here.
    unsafe { heap::init() };

    logger::init(LevelFilter::Info).map_err(|_| RebootReason::InternalError)?;

    const FDT_MAX_SIZE: usize = helpers::SIZE_2MB;
    // TODO: Check that the FDT is fully contained in RAM.
    // SAFETY - We trust the VMM, for now.
    let fdt = unsafe { slice::from_raw_parts_mut(fdt as *mut u8, FDT_MAX_SIZE) };
    // TODO: Check that the payload is fully contained in RAM and doesn't overlap with the FDT.
    // SAFETY - We trust the VMM, for now.
    let payload = unsafe { slice::from_raw_parts(payload as *const u8, payload_size) };

    // Use debug!() to avoid printing to the UART if we failed to configure it as only local
    // builds that have tweaked the logger::init() call will actually attempt to log the message.

    mmio_guard::init().map_err(|e| {
        debug!("{e}");
        RebootReason::InternalError
    })?;

    mmio_guard::map(console::BASE_ADDRESS).map_err(|e| {
        debug!("Failed to configure the UART: {e}");
        RebootReason::InternalError
    })?;

    // SAFETY - We only get the appended payload from here, once. It is mapped and the linker
    // script prevents it from overlapping with other objects.
    let bcc = as_bcc(unsafe { get_appended_data_slice() }).ok_or_else(|| {
        error!("Invalid BCC");
        RebootReason::InvalidBcc
    })?;

    // This wrapper allows main() to be blissfully ignorant of platform details.
    crate::main(fdt, payload, bcc);

    // TODO: Overwrite BCC before jumping to payload to avoid leaking our sealing key.

    mmio_guard::unmap(console::BASE_ADDRESS).map_err(|e| {
        error!("Failed to unshare the UART: {e}");
        RebootReason::InternalError
    })?;

    Ok(())
}

fn jump_to_payload(fdt_address: u64, payload_start: u64) -> ! {
    const SCTLR_EL1_RES1: usize = (0b11 << 28) | (0b101 << 20) | (0b1 << 11);
    // Stage 1 instruction access cacheability is unaffected.
    const SCTLR_EL1_I: usize = 0b1 << 12;
    // SETEND instruction disabled at EL0 in aarch32 mode.
    const SCTLR_EL1_SED: usize = 0b1 << 8;
    // Various IT instructions are disabled at EL0 in aarch32 mode.
    const SCTLR_EL1_ITD: usize = 0b1 << 7;

    const SCTLR_EL1_VAL: usize = SCTLR_EL1_RES1 | SCTLR_EL1_ITD | SCTLR_EL1_SED | SCTLR_EL1_I;

    // SAFETY - We're exiting pvmfw by passing the register values we need to a noreturn asm!().
    unsafe {
        asm!(
            "msr sctlr_el1, {sctlr_el1_val}",
            "isb",
            "mov x1, xzr",
            "mov x2, xzr",
            "mov x3, xzr",
            "mov x4, xzr",
            "mov x5, xzr",
            "mov x6, xzr",
            "mov x7, xzr",
            "mov x8, xzr",
            "mov x9, xzr",
            "mov x10, xzr",
            "mov x11, xzr",
            "mov x12, xzr",
            "mov x13, xzr",
            "mov x14, xzr",
            "mov x15, xzr",
            "mov x16, xzr",
            "mov x17, xzr",
            "mov x18, xzr",
            "mov x19, xzr",
            "mov x20, xzr",
            "mov x21, xzr",
            "mov x22, xzr",
            "mov x23, xzr",
            "mov x24, xzr",
            "mov x25, xzr",
            "mov x26, xzr",
            "mov x27, xzr",
            "mov x28, xzr",
            "mov x29, xzr",
            "msr ttbr0_el1, xzr",
            "isb",
            "dsb nsh",
            "br x30",
            sctlr_el1_val = in(reg) SCTLR_EL1_VAL,
            in("x0") fdt_address,
            in("x30") payload_start,
            options(nomem, noreturn, nostack),
        );
    };
}

unsafe fn get_appended_data_slice() -> &'static mut [u8] {
    let base = helpers::align_up(layout::binary_end(), helpers::SIZE_4KB).unwrap();
    // pvmfw is contained in a 2MiB region so the payload can't be larger than the 2MiB alignment.
    let size = helpers::align_up(base, helpers::SIZE_2MB).unwrap() - base;

    slice::from_raw_parts_mut(base as *mut u8, size)
}

fn as_bcc(data: &mut [u8]) -> Option<&mut [u8]> {
    const BCC_SIZE: usize = helpers::SIZE_4KB;

    if cfg!(feature = "legacy") {
        // TODO(b/256148034): return None if BccHandoverParse(bcc) != kDiceResultOk.
        Some(&mut data[..BCC_SIZE])
    } else {
        None
    }
}
