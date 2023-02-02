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
#![feature(default_alloc_error_handler)]

extern crate alloc;

mod config;
mod debug_policy;
mod dice;
mod entry;
mod exceptions;
mod fdt;
mod gpt;
mod heap;
mod helpers;
mod hvc;
mod instance;
mod memory;
mod mmio_guard;
mod mmu;
mod smccc;
mod virtio;

use alloc::boxed::Box;

use crate::dice::PartialInputs;
use crate::entry::RebootReason;
use crate::fdt::modify_for_next_stage;
use crate::helpers::flush;
use crate::helpers::GUEST_PAGE_SIZE;
use crate::instance::get_or_generate_instance_salt;
use crate::memory::MemoryTracker;
use crate::virtio::pci;
use diced_open_dice::bcc_handover_main_flow;
use diced_open_dice::bcc_handover_parse;
use fdtpci::{PciError, PciInfo};
use libfdt::Fdt;
use log::{debug, error, info, trace};
use pvmfw_avb::verify_payload;
use pvmfw_embedded_key::PUBLIC_KEY;

const NEXT_BCC_SIZE: usize = GUEST_PAGE_SIZE;

fn main(
    fdt: &mut Fdt,
    signed_kernel: &[u8],
    ramdisk: Option<&[u8]>,
    current_bcc_handover: &[u8],
    memory: &mut MemoryTracker,
) -> Result<(), RebootReason> {
    info!("pVM firmware");
    debug!("FDT: {:?}", fdt.as_ptr());
    debug!("Signed kernel: {:?} ({:#x} bytes)", signed_kernel.as_ptr(), signed_kernel.len());
    debug!("AVB public key: addr={:?}, size={:#x} ({1})", PUBLIC_KEY.as_ptr(), PUBLIC_KEY.len());
    if let Some(rd) = ramdisk {
        debug!("Ramdisk: {:?} ({:#x} bytes)", rd.as_ptr(), rd.len());
    } else {
        debug!("Ramdisk: None");
    }
    let bcc_handover = bcc_handover_parse(current_bcc_handover).map_err(|e| {
        error!("Invalid BCC Handover: {e:?}");
        RebootReason::InvalidBcc
    })?;
    trace!("BCC: {bcc_handover:x?}");

    // Set up PCI bus for VirtIO devices.
    let pci_info = PciInfo::from_fdt(fdt).map_err(handle_pci_error)?;
    debug!("PCI: {:#x?}", pci_info);
    let mut pci_root = pci::initialise(pci_info, memory)?;

    let verified_boot_data = verify_payload(signed_kernel, ramdisk, PUBLIC_KEY).map_err(|e| {
        error!("Failed to verify the payload: {e}");
        RebootReason::PayloadVerificationError
    })?;

    let next_bcc = heap::aligned_boxed_slice(NEXT_BCC_SIZE, GUEST_PAGE_SIZE).ok_or_else(|| {
        error!("Failed to allocate the next-stage BCC");
        RebootReason::InternalError
    })?;
    // By leaking the slice, its content will be left behind for the next stage.
    let next_bcc = Box::leak(next_bcc);

    let dice_inputs = PartialInputs::new(&verified_boot_data).map_err(|e| {
        error!("Failed to compute partial DICE inputs: {e:?}");
        RebootReason::InternalError
    })?;
    let (new_instance, salt) =
        get_or_generate_instance_salt(&mut pci_root, &dice_inputs).map_err(|e| {
            error!("Failed to get instance.img salt: {e}");
            RebootReason::InternalError
        })?;
    trace!("Got salt from instance.img: {salt:x?}");

    let dice_inputs = dice_inputs.into_input_values(&salt).map_err(|e| {
        error!("Failed to generate DICE inputs: {e:?}");
        RebootReason::InternalError
    })?;
    let _ = bcc_handover_main_flow(current_bcc_handover, &dice_inputs, next_bcc).map_err(|e| {
        error!("Failed to derive next-stage DICE secrets: {e:?}");
        RebootReason::SecretDerivationError
    })?;
    flush(next_bcc);

    let strict_boot = false; // TODO(b/268307476): Flip in its own commit to isolate testing.
    modify_for_next_stage(fdt, next_bcc, new_instance, strict_boot).map_err(|e| {
        error!("Failed to configure device tree: {e}");
        RebootReason::InternalError
    })?;

    info!("Starting payload...");
    Ok(())
}

/// Logs the given PCI error and returns the appropriate `RebootReason`.
fn handle_pci_error(e: PciError) -> RebootReason {
    error!("{}", e);
    match e {
        PciError::FdtErrorPci(_)
        | PciError::FdtNoPci
        | PciError::FdtErrorReg(_)
        | PciError::FdtMissingReg
        | PciError::FdtRegEmpty
        | PciError::FdtRegMissingSize
        | PciError::CamWrongSize(_)
        | PciError::FdtErrorRanges(_)
        | PciError::FdtMissingRanges
        | PciError::RangeAddressMismatch { .. }
        | PciError::NoSuitableRange => RebootReason::InvalidFdt,
    }
}
