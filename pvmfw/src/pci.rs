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

//! Functions to scan the PCI bus for VirtIO device and allocate BARs.

use crate::{entry::RebootReason, memory::MemoryTracker};
use core::ffi::CStr;
use libfdt::{Fdt, FdtNode};
use log::{debug, error};

/// PCI MMIO configuration region size.
const PCI_CFG_SIZE: usize = 0x100_0000;

/// Finds an FDT node with compatible=pci-host-cam-generic.
pub fn pci_node(fdt: &Fdt) -> Result<FdtNode, RebootReason> {
    fdt.compatible_nodes(CStr::from_bytes_with_nul(b"pci-host-cam-generic\0").unwrap())
        .map_err(|e| {
            error!("Failed to find PCI bus in FDT: {}", e);
            RebootReason::InvalidFdt
        })?
        .next()
        .ok_or(RebootReason::InvalidFdt)
}

pub fn map_cam(pci_node: &FdtNode, memory: &mut MemoryTracker) -> Result<(), RebootReason> {
    // Parse reg property to find CAM.
    let pci_reg = pci_node
        .reg()
        .map_err(|e| {
            error!("Error getting reg property from PCI node: {}", e);
            RebootReason::InvalidFdt
        })?
        .ok_or_else(|| {
            error!("PCI node missing reg property.");
            RebootReason::InvalidFdt
        })?
        .next()
        .ok_or_else(|| {
            error!("Empty reg property on PCI node.");
            RebootReason::InvalidFdt
        })?;
    let cam_addr = pci_reg.addr as usize;
    let cam_size = pci_reg.size.ok_or_else(|| {
        error!("PCI reg property missing size.");
        RebootReason::InvalidFdt
    })? as usize;
    debug!("Found PCI CAM at {:#x}-{:#x}", cam_addr, cam_addr + cam_size);
    // Check that the CAM is the size we expect, so we don't later try accessing it beyond its
    // bounds. If it is a different size then something is very wrong and we shouldn't continue to
    // access it; maybe there is some new version of PCI we don't know about.
    if cam_size != PCI_CFG_SIZE {
        error!("FDT says PCI CAM is {} bytes but we expected {}.", cam_size, PCI_CFG_SIZE);
        return Err(RebootReason::InvalidFdt);
    }

    // Map the CAM as MMIO.
    memory.map_mmio_range(cam_addr..cam_addr + cam_size).map_err(|e| {
        error!("Failed to map PCI CAM: {}", e);
        RebootReason::InternalError
    })?;

    Ok(())
}
