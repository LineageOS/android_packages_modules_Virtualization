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
mod heap;
mod helpers;
mod hvc;
mod memory;
mod mmio_guard;
mod mmu;
mod smccc;
mod virtio;

use alloc::boxed::Box;

use crate::{
    dice::derive_next_bcc,
    entry::RebootReason,
    fdt::add_dice_node,
    helpers::flush,
    helpers::GUEST_PAGE_SIZE,
    memory::MemoryTracker,
    virtio::pci::{self, find_virtio_devices},
};
use ::dice::bcc;
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
    bcc: &bcc::Handover,
    memory: &mut MemoryTracker,
) -> Result<(), RebootReason> {
    info!("pVM firmware");
    debug!("FDT: {:?}", fdt as *const libfdt::Fdt);
    debug!("Signed kernel: {:?} ({:#x} bytes)", signed_kernel.as_ptr(), signed_kernel.len());
    debug!("AVB public key: addr={:?}, size={:#x} ({1})", PUBLIC_KEY.as_ptr(), PUBLIC_KEY.len());
    if let Some(rd) = ramdisk {
        debug!("Ramdisk: {:?} ({:#x} bytes)", rd.as_ptr(), rd.len());
    } else {
        debug!("Ramdisk: None");
    }
    trace!("BCC: {bcc:x?}");

    // Set up PCI bus for VirtIO devices.
    let pci_info = PciInfo::from_fdt(fdt).map_err(handle_pci_error)?;
    debug!("PCI: {:#x?}", pci_info);
    let mut pci_root = pci::initialise(pci_info, memory)?;
    find_virtio_devices(&mut pci_root).map_err(handle_pci_error)?;

    verify_payload(signed_kernel, ramdisk, PUBLIC_KEY).map_err(|e| {
        error!("Failed to verify the payload: {e}");
        RebootReason::PayloadVerificationError
    })?;

    let debug_mode = false; // TODO(b/256148034): Derive the DICE mode from the received initrd.
    const HASH_SIZE: usize = 64;
    let mut hashes = [0; HASH_SIZE * 2]; // TODO(b/256148034): Extract AvbHashDescriptor digests.
    hashes[..HASH_SIZE].copy_from_slice(&::dice::hash(signed_kernel).map_err(|_| {
        error!("Failed to hash the kernel");
        RebootReason::InternalError
    })?);
    // Note: Using signed_kernel currently makes the DICE code input depend on its VBMeta fields.
    let code_hash = if let Some(rd) = ramdisk {
        hashes[HASH_SIZE..].copy_from_slice(&::dice::hash(rd).map_err(|_| {
            error!("Failed to hash the ramdisk");
            RebootReason::InternalError
        })?);
        &hashes[..]
    } else {
        &hashes[..HASH_SIZE]
    };
    let next_bcc = heap::aligned_boxed_slice(NEXT_BCC_SIZE, GUEST_PAGE_SIZE).ok_or_else(|| {
        error!("Failed to allocate the next-stage BCC");
        RebootReason::InternalError
    })?;
    // By leaking the slice, its content will be left behind for the next stage.
    let next_bcc = Box::leak(next_bcc);
    let next_bcc_size =
        derive_next_bcc(bcc, next_bcc, code_hash, debug_mode, PUBLIC_KEY).map_err(|e| {
            error!("Failed to derive next-stage DICE secrets: {e:?}");
            RebootReason::SecretDerivationError
        })?;
    trace!("Next BCC: {:x?}", bcc::Handover::new(&next_bcc[..next_bcc_size]));

    flush(next_bcc);

    add_dice_node(fdt, next_bcc.as_ptr() as usize, NEXT_BCC_SIZE).map_err(|e| {
        error!("Failed to add DICE node to device tree: {e}");
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
