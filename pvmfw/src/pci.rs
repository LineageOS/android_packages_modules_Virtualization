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
use core::{
    ffi::CStr,
    fmt::{self, Display, Formatter},
    ops::Range,
};
use libfdt::{AddressRange, Fdt, FdtError, FdtNode};
use log::{debug, error};
use virtio_drivers::pci::{
    bus::{self, BarInfo, Cam, Command, DeviceFunction, MemoryBarType, PciRoot},
    virtio_device_type,
};

/// PCI MMIO configuration region size.
const PCI_CFG_SIZE: usize = 0x100_0000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PciError {
    FdtErrorPci(FdtError),
    FdtNoPci,
    FdtErrorReg(FdtError),
    FdtMissingReg,
    FdtRegEmpty,
    FdtRegMissingSize,
    CamWrongSize(usize),
    FdtErrorRanges(FdtError),
    FdtMissingRanges,
    RangeAddressMismatch { bus_address: u64, cpu_physical: u64 },
    NoSuitableRange,
    BarInfoFailed(bus::PciError),
    BarAllocationFailed { size: u32, device_function: DeviceFunction },
    UnsupportedBarType(MemoryBarType),
}

impl Display for PciError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::FdtErrorPci(e) => write!(f, "Error getting PCI node from FDT: {}", e),
            Self::FdtNoPci => write!(f, "Failed to find PCI bus in FDT."),
            Self::FdtErrorReg(e) => write!(f, "Error getting reg property from PCI node: {}", e),
            Self::FdtMissingReg => write!(f, "PCI node missing reg property."),
            Self::FdtRegEmpty => write!(f, "Empty reg property on PCI node."),
            Self::FdtRegMissingSize => write!(f, "PCI reg property missing size."),
            Self::CamWrongSize(cam_size) => write!(
                f,
                "FDT says PCI CAM is {} bytes but we expected {}.",
                cam_size, PCI_CFG_SIZE
            ),
            Self::FdtErrorRanges(e) => {
                write!(f, "Error getting ranges property from PCI node: {}", e)
            }
            Self::FdtMissingRanges => write!(f, "PCI node missing ranges property."),
            Self::RangeAddressMismatch { bus_address, cpu_physical } => {
                write!(
                    f,
                    "bus address {:#018x} != CPU physical address {:#018x}",
                    bus_address, cpu_physical
                )
            }
            Self::NoSuitableRange => write!(f, "No suitable PCI memory range found."),
            Self::BarInfoFailed(e) => write!(f, "Error getting PCI BAR information: {}", e),
            Self::BarAllocationFailed { size, device_function } => write!(
                f,
                "Failed to allocate memory BAR of size {} for PCI device {}.",
                size, device_function
            ),
            Self::UnsupportedBarType(address_type) => {
                write!(f, "Memory BAR address type {:?} not supported.", address_type)
            }
        }
    }
}

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
    pub fn from_fdt(fdt: &Fdt) -> Result<Self, PciError> {
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

    /// Returns the `PciRoot` for the memory-mapped CAM found in the FDT. The CAM should be mapped
    /// before this is called, by calling [`PciInfo::map`].
    ///
    /// # Safety
    ///
    /// To prevent concurrent access, only one `PciRoot` should exist in the program. Thus this
    /// method must only be called once, and there must be no other `PciRoot` constructed using the
    /// same CAM.
    pub unsafe fn make_pci_root(&self) -> PciRoot {
        PciRoot::new(self.cam_range.start as *mut u8, Cam::MmioCam)
    }
}

/// Finds an FDT node with compatible=pci-host-cam-generic.
fn pci_node(fdt: &Fdt) -> Result<FdtNode, PciError> {
    fdt.compatible_nodes(CStr::from_bytes_with_nul(b"pci-host-cam-generic\0").unwrap())
        .map_err(PciError::FdtErrorPci)?
        .next()
        .ok_or(PciError::FdtNoPci)
}

/// Parses the "reg" property of the given PCI FDT node to find the MMIO CAM range.
fn parse_cam_range(pci_node: &FdtNode) -> Result<MemoryRange, PciError> {
    let pci_reg = pci_node
        .reg()
        .map_err(PciError::FdtErrorReg)?
        .ok_or(PciError::FdtMissingReg)?
        .next()
        .ok_or(PciError::FdtRegEmpty)?;
    let cam_addr = pci_reg.addr as usize;
    let cam_size = pci_reg.size.ok_or(PciError::FdtRegMissingSize)? as usize;
    debug!("Found PCI CAM at {:#x}-{:#x}", cam_addr, cam_addr + cam_size);
    // Check that the CAM is the size we expect, so we don't later try accessing it beyond its
    // bounds. If it is a different size then something is very wrong and we shouldn't continue to
    // access it; maybe there is some new version of PCI we don't know about.
    if cam_size != PCI_CFG_SIZE {
        return Err(PciError::CamWrongSize(cam_size));
    }

    Ok(cam_addr..cam_addr + cam_size)
}

/// Parses the "ranges" property of the given PCI FDT node, and returns the largest suitable range
/// to use for non-prefetchable 32-bit memory BARs.
fn parse_ranges(pci_node: &FdtNode) -> Result<Range<u32>, PciError> {
    let mut memory_address = 0;
    let mut memory_size = 0;

    for AddressRange { addr: (flags, bus_address), parent_addr: cpu_physical, size } in pci_node
        .ranges::<(u32, u64), u64, u64>()
        .map_err(PciError::FdtErrorRanges)?
        .ok_or(PciError::FdtMissingRanges)?
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
                return Err(PciError::RangeAddressMismatch { bus_address, cpu_physical });
            }
            memory_address = u32::try_from(cpu_physical).unwrap();
            memory_size = u32::try_from(size).unwrap();
        }
    }

    if memory_size == 0 {
        return Err(PciError::NoSuitableRange);
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

/// Allocates BARs for all VirtIO PCI devices.
pub fn allocate_all_virtio_bars(
    pci_root: &mut PciRoot,
    allocator: &mut PciMemory32Allocator,
) -> Result<(), PciError> {
    for (device_function, info) in pci_root.enumerate_bus(0) {
        let (status, command) = pci_root.get_status_command(device_function);
        debug!(
            "Found PCI device {} at {}, status {:?} command {:?}",
            info, device_function, status, command
        );
        if let Some(virtio_type) = virtio_device_type(&info) {
            debug!("  VirtIO {:?}", virtio_type);
            allocate_bars(pci_root, device_function, allocator)?;
        }
    }

    Ok(())
}

/// Allocates 32-bit memory addresses for PCI BARs.
#[derive(Debug)]
pub struct PciMemory32Allocator {
    /// The start of the available (not yet allocated) address space for PCI BARs.
    start: u32,
    /// The end of the available address space.
    end: u32,
}

impl PciMemory32Allocator {
    pub fn new(pci_info: &PciInfo) -> Self {
        Self { start: pci_info.bar_range.start, end: pci_info.bar_range.end }
    }

    /// Allocates a 32-bit memory address region for a PCI BAR of the given power-of-2 size.
    ///
    /// It will have alignment matching the size. The size must be a power of 2.
    pub fn allocate_memory_32(&mut self, size: u32) -> Option<u32> {
        assert!(size.is_power_of_two());
        let allocated_address = align_up(self.start, size);
        if allocated_address + size <= self.end {
            self.start = allocated_address + size;
            Some(allocated_address)
        } else {
            None
        }
    }
}

/// Allocates appropriately-sized memory regions and assigns them to the device's BARs.
fn allocate_bars(
    root: &mut PciRoot,
    device_function: DeviceFunction,
    allocator: &mut PciMemory32Allocator,
) -> Result<(), PciError> {
    let mut bar_index = 0;
    while bar_index < 6 {
        let info = root.bar_info(device_function, bar_index).map_err(PciError::BarInfoFailed)?;
        debug!("BAR {}: {}", bar_index, info);
        // Ignore I/O bars, as they aren't required for the VirtIO driver.
        if let BarInfo::Memory { address_type, size, .. } = info {
            match address_type {
                _ if size == 0 => {}
                MemoryBarType::Width32 => {
                    let address = allocator
                        .allocate_memory_32(size)
                        .ok_or(PciError::BarAllocationFailed { size, device_function })?;
                    debug!("Allocated address {:#010x}", address);
                    root.set_bar_32(device_function, bar_index, address);
                }
                _ => {
                    return Err(PciError::UnsupportedBarType(address_type));
                }
            }
        }

        bar_index += 1;
        if info.takes_two_entries() {
            bar_index += 1;
        }
    }

    // Enable the device to use its BARs.
    root.set_command(
        device_function,
        Command::IO_SPACE | Command::MEMORY_SPACE | Command::BUS_MASTER,
    );
    let (status, command) = root.get_status_command(device_function);
    debug!("Allocated BARs and enabled device, status {:?} command {:?}", status, command);

    Ok(())
}

// TODO: Make the alignment functions in the helpers module generic once const_trait_impl is stable.
const fn align_up(value: u32, alignment: u32) -> u32 {
    ((value - 1) | (alignment - 1)) + 1
}
