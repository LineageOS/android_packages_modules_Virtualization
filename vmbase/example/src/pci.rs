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

use aarch64_paging::paging::MemoryRegion;
use alloc::alloc::{alloc, dealloc, Layout};
use core::{ffi::CStr, mem::size_of};
use libfdt::{Fdt, FdtNode, Reg};
use log::{debug, info};
use virtio_drivers::{
    pci::{
        bus::{BarInfo, Cam, Command, DeviceFunction, MemoryBarType, PciRoot},
        virtio_device_type, PciTransport,
    },
    DeviceType, Hal, PhysAddr, Transport, VirtAddr, VirtIOBlk, PAGE_SIZE,
};

/// The standard sector size of a VirtIO block device, in bytes.
const SECTOR_SIZE_BYTES: usize = 512;

/// The size in sectors of the test block device we expect.
const EXPECTED_SECTOR_COUNT: usize = 4;

/// Finds an FDT node with compatible=pci-host-cam-generic.
pub fn pci_node(fdt: &Fdt) -> FdtNode {
    fdt.compatible_nodes(CStr::from_bytes_with_nul(b"pci-host-cam-generic\0").unwrap())
        .unwrap()
        .next()
        .unwrap()
}

pub fn check_pci(reg: Reg<u64>, allocator: &mut PciMemory32Allocator) {
    let mut pci_root = unsafe { PciRoot::new(reg.addr as *mut u8, Cam::MmioCam) };
    let mut checked_virtio_device_count = 0;
    for (device_function, info) in pci_root.enumerate_bus(0) {
        let (status, command) = pci_root.get_status_command(device_function);
        info!("Found {} at {}, status {:?} command {:?}", info, device_function, status, command);
        if let Some(virtio_type) = virtio_device_type(&info) {
            info!("  VirtIO {:?}", virtio_type);
            allocate_bars(&mut pci_root, device_function, allocator);
            let mut transport =
                PciTransport::new::<HalImpl>(&mut pci_root, device_function).unwrap();
            info!(
                "Detected virtio PCI device with device type {:?}, features {:#018x}",
                transport.device_type(),
                transport.read_device_features(),
            );
            if check_virtio_device(transport, virtio_type) {
                checked_virtio_device_count += 1;
            }
        }
    }

    assert_eq!(checked_virtio_device_count, 1);
}

/// Checks the given VirtIO device, if we know how to.
///
/// Returns true if the device was checked, or false if it was ignored.
fn check_virtio_device(transport: impl Transport, device_type: DeviceType) -> bool {
    if device_type == DeviceType::Block {
        let mut blk = VirtIOBlk::<HalImpl, _>::new(transport).expect("failed to create blk driver");
        info!("Found {} KiB block device.", blk.capacity() * SECTOR_SIZE_BYTES as u64 / 1024);
        assert_eq!(blk.capacity(), EXPECTED_SECTOR_COUNT as u64);
        let mut data = [0; SECTOR_SIZE_BYTES * EXPECTED_SECTOR_COUNT];
        for i in 0..EXPECTED_SECTOR_COUNT {
            blk.read_block(i, &mut data[i * SECTOR_SIZE_BYTES..(i + 1) * SECTOR_SIZE_BYTES])
                .expect("Failed to read block device.");
        }
        for (i, chunk) in data.chunks(size_of::<u32>()).enumerate() {
            assert_eq!(chunk, &(i as u32).to_le_bytes());
        }
        info!("Read expected data from block device.");
        true
    } else {
        false
    }
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

/// Allocates 32-bit memory addresses for PCI BARs.
pub struct PciMemory32Allocator {
    start: u32,
    end: u32,
}

impl PciMemory32Allocator {
    /// Creates a new allocator based on the ranges property of the given PCI node.
    pub fn for_pci_ranges(pci_node: &FdtNode) -> Self {
        let mut memory_32_address = 0;
        let mut memory_32_size = 0;
        for range in pci_node
            .ranges::<u128, u64, u64>()
            .expect("Error getting ranges property from PCI node")
            .expect("PCI node missing ranges property.")
        {
            let flags = PciMemoryFlags((range.addr >> 64) as u32);
            let prefetchable = flags.prefetchable();
            let range_type = flags.range_type();
            let bus_address = range.addr as u64;
            let cpu_physical = range.parent_addr;
            let size = range.size;
            info!(
                "range: {:?} {}prefetchable bus address: {:#018x} host physical address: {:#018x} size: {:#018x}",
                range_type,
                if prefetchable { "" } else { "non-" },
                bus_address,
                cpu_physical,
                size,
            );
            if !prefetchable
                && ((range_type == PciRangeType::Memory32 && size > memory_32_size.into())
                    || (range_type == PciRangeType::Memory64
                        && size > memory_32_size.into()
                        && bus_address + size < u32::MAX.into()))
            {
                // Use the 64-bit range for 32-bit memory, if it is low enough.
                assert_eq!(bus_address, cpu_physical);
                memory_32_address = u32::try_from(cpu_physical).unwrap();
                memory_32_size = u32::try_from(size).unwrap();
            }
        }
        if memory_32_size == 0 {
            panic!("No PCI memory regions found.");
        }

        Self { start: memory_32_address, end: memory_32_address + memory_32_size }
    }

    /// Gets a memory region covering the address space from which this allocator will allocate.
    pub fn get_region(&self) -> MemoryRegion {
        MemoryRegion::new(self.start as usize, self.end as usize)
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

/// Allocates appropriately-sized memory regions and assigns them to the device's BARs.
fn allocate_bars(
    root: &mut PciRoot,
    device_function: DeviceFunction,
    allocator: &mut PciMemory32Allocator,
) {
    let mut bar_index = 0;
    while bar_index < 6 {
        let info = root.bar_info(device_function, bar_index).unwrap();
        debug!("BAR {}: {}", bar_index, info);
        // Ignore I/O bars, as they aren't required for the VirtIO driver.
        if let BarInfo::Memory { address_type, size, .. } = info {
            match address_type {
                _ if size == 0 => {}
                MemoryBarType::Width32 => {
                    let address = allocator.allocate_memory_32(size).unwrap();
                    debug!("Allocated address {:#010x}", address);
                    root.set_bar_32(device_function, bar_index, address);
                }
                MemoryBarType::Width64 => {
                    let address = allocator.allocate_memory_32(size).unwrap();
                    debug!("Allocated address {:#010x}", address);
                    root.set_bar_64(device_function, bar_index, address.into());
                }
                _ => panic!("Memory BAR address type {:?} not supported.", address_type),
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
}

const fn align_up(value: u32, alignment: u32) -> u32 {
    ((value - 1) | (alignment - 1)) + 1
}

struct HalImpl;

impl Hal for HalImpl {
    fn dma_alloc(pages: usize) -> PhysAddr {
        debug!("dma_alloc: pages={}", pages);
        let layout = Layout::from_size_align(pages * PAGE_SIZE, PAGE_SIZE).unwrap();
        // Safe because the layout has a non-zero size.
        let vaddr = unsafe { alloc(layout) } as VirtAddr;
        Self::virt_to_phys(vaddr)
    }

    fn dma_dealloc(paddr: PhysAddr, pages: usize) -> i32 {
        debug!("dma_dealloc: paddr={:#x}, pages={}", paddr, pages);
        let vaddr = Self::phys_to_virt(paddr);
        let layout = Layout::from_size_align(pages * PAGE_SIZE, PAGE_SIZE).unwrap();
        // Safe because the memory was allocated by `dma_alloc` above using the same allocator, and
        // the layout is the same as was used then.
        unsafe {
            dealloc(vaddr as *mut u8, layout);
        }
        0
    }

    fn phys_to_virt(paddr: PhysAddr) -> VirtAddr {
        paddr
    }

    fn virt_to_phys(vaddr: VirtAddr) -> PhysAddr {
        vaddr
    }
}
