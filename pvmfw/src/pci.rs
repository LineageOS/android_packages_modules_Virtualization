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

use crate::{
    entry::RebootReason,
    memory::{MemoryRange, MemoryTracker},
};
use core::{ffi::CStr, ops::Range};
use libfdt::{AddressRange, Fdt, FdtNode};
use log::{debug, error};

/// PCI MMIO configuration region size.
const PCI_CFG_SIZE: usize = 0x100_0000;

/// Information about the PCI bus parsed from the device tree.
#[derive(Debug)]
pub struct PciInfo {
    /// The MMIO range used by the memory-mapped PCI CAM.
    cam_range: MemoryRange,
    /// The MMIO range from which 32-bit PCI BARs should be allocated.
    bar_range: Range<u32>,
}

impl PciInfo {
    /// Finds the PCI node in the FDT, parses its properties and validates it.
    pub fn from_fdt(fdt: &Fdt) -> Result<Self, RebootReason> {
        let pci_node = pci_node(fdt)?;

        let cam_range = parse_cam_range(&pci_node)?;
        let bar_range = parse_ranges(&pci_node)?;

        Ok(Self { cam_range, bar_range })
    }

    /// Maps the CAM and BAR range in the page table and MMIO guard.
    pub fn map(&self, memory: &mut MemoryTracker) -> Result<(), RebootReason> {
        memory.map_mmio_range(self.cam_range.clone()).map_err(|e| {
            error!("Failed to map PCI CAM: {}", e);
            RebootReason::InternalError
        })?;

        memory.map_mmio_range(self.bar_range.start as usize..self.bar_range.end as usize).map_err(
            |e| {
                error!("Failed to map PCI MMIO range: {}", e);
                RebootReason::InternalError
            },
        )?;

        Ok(())
    }
}

/// Finds an FDT node with compatible=pci-host-cam-generic.
fn pci_node(fdt: &Fdt) -> Result<FdtNode, RebootReason> {
    fdt.compatible_nodes(CStr::from_bytes_with_nul(b"pci-host-cam-generic\0").unwrap())
        .map_err(|e| {
            error!("Failed to find PCI bus in FDT: {}", e);
            RebootReason::InvalidFdt
        })?
        .next()
        .ok_or(RebootReason::InvalidFdt)
}

/// Parses the "reg" property of the given PCI FDT node to find the MMIO CAM range.
fn parse_cam_range(pci_node: &FdtNode) -> Result<MemoryRange, RebootReason> {
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

    Ok(cam_addr..cam_addr + cam_size)
}

/// Parses the "ranges" property of the given PCI FDT node, and returns the largest suitable range
/// to use for non-prefetchable 32-bit memory BARs.
fn parse_ranges(pci_node: &FdtNode) -> Result<Range<u32>, RebootReason> {
    let mut memory_address = 0;
    let mut memory_size = 0;

    for AddressRange { addr: (flags, bus_address), parent_addr: cpu_physical, size } in pci_node
        .ranges::<(u32, u64), u64, u64>()
        .map_err(|e| {
            error!("Error getting ranges property from PCI node: {}", e);
            RebootReason::InvalidFdt
        })?
        .ok_or_else(|| {
            error!("PCI node missing ranges property.");
            RebootReason::InvalidFdt
        })?
    {
        let flags = PciMemoryFlags(flags);
        let prefetchable = flags.prefetchable();
        let range_type = flags.range_type();
        debug!(
            "range: {:?} {}prefetchable bus address: {:#018x} CPU physical address: {:#018x} size: {:#018x}",
            range_type,
            if prefetchable { "" } else { "non-" },
            bus_address,
            cpu_physical,
            size,
        );

        // Use a 64-bit range for 32-bit memory, if it is low enough, because crosvm doesn't
        // currently provide any 32-bit ranges.
        if !prefetchable
            && matches!(range_type, PciRangeType::Memory32 | PciRangeType::Memory64)
            && size > memory_size.into()
            && bus_address + size < u32::MAX.into()
        {
            if bus_address != cpu_physical {
                error!(
                    "bus address {:#018x} != CPU physical address {:#018x}",
                    bus_address, cpu_physical
                );
                return Err(RebootReason::InvalidFdt);
            }
            memory_address = u32::try_from(cpu_physical).unwrap();
            memory_size = u32::try_from(size).unwrap();
        }
    }

    if memory_size == 0 {
        error!("No suitable PCI memory range found.");
        return Err(RebootReason::InvalidFdt);
    }

    Ok(memory_address..memory_address + memory_size)
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct PciMemoryFlags(u32);

impl PciMemoryFlags {
    pub fn prefetchable(self) -> bool {
        self.0 & 0x80000000 != 0
    }

    pub fn range_type(self) -> PciRangeType {
        PciRangeType::from((self.0 & 0x3000000) >> 24)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum PciRangeType {
    ConfigurationSpace,
    IoSpace,
    Memory32,
    Memory64,
}

impl From<u32> for PciRangeType {
    fn from(value: u32) -> Self {
        match value {
            0 => Self::ConfigurationSpace,
            1 => Self::IoSpace,
            2 => Self::Memory32,
            3 => Self::Memory64,
            _ => panic!("Tried to convert invalid range type {}", value),
        }
    }
}
