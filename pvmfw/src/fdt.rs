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

//! High-level FDT functions.

use crate::cstr;
use crate::helpers::GUEST_PAGE_SIZE;
use crate::RebootReason;
use core::ffi::CStr;
use core::num::NonZeroUsize;
use core::ops::Range;
use fdtpci::PciMemoryFlags;
use fdtpci::PciRangeType;
use libfdt::AddressRange;
use libfdt::CellIterator;
use libfdt::Fdt;
use libfdt::FdtError;
use log::error;
use tinyvec::ArrayVec;

/// Extract from /config the address range containing the pre-loaded kernel.
pub fn kernel_range(fdt: &libfdt::Fdt) -> libfdt::Result<Option<Range<usize>>> {
    let addr = cstr!("kernel-address");
    let size = cstr!("kernel-size");

    if let Some(config) = fdt.node(cstr!("/config"))? {
        if let (Some(addr), Some(size)) = (config.getprop_u32(addr)?, config.getprop_u32(size)?) {
            let addr = addr as usize;
            let size = size as usize;

            return Ok(Some(addr..(addr + size)));
        }
    }

    Ok(None)
}

/// Extract from /chosen the address range containing the pre-loaded ramdisk.
pub fn initrd_range(fdt: &libfdt::Fdt) -> libfdt::Result<Option<Range<usize>>> {
    let start = cstr!("linux,initrd-start");
    let end = cstr!("linux,initrd-end");

    if let Some(chosen) = fdt.chosen()? {
        if let (Some(start), Some(end)) = (chosen.getprop_u32(start)?, chosen.getprop_u32(end)?) {
            return Ok(Some((start as usize)..(end as usize)));
        }
    }

    Ok(None)
}

/// Read and validate the size and base address of memory, and returns the size
fn parse_memory_node(fdt: &libfdt::Fdt) -> Result<NonZeroUsize, RebootReason> {
    let memory_range = fdt
        .memory()
        // Actually, these checks are unnecessary because we read /memory node in entry.rs
        // where the exactly same checks are done. We are repeating the same check just for
        // extra safety (in case when the code structure changes in the future).
        .map_err(|e| {
            error!("Failed to get /memory from the DT: {e}");
            RebootReason::InvalidFdt
        })?
        .ok_or_else(|| {
            error!("Node /memory was found empty");
            RebootReason::InvalidFdt
        })?
        .next()
        .ok_or_else(|| {
            error!("Failed to read memory range from the DT");
            RebootReason::InvalidFdt
        })?;

    let base = memory_range.start;
    if base as u64 != DeviceTreeInfo::RAM_BASE_ADDR {
        error!("Memory base address {:#x} is not {:#x}", base, DeviceTreeInfo::RAM_BASE_ADDR);
        return Err(RebootReason::InvalidFdt);
    }

    let size = memory_range.len(); // end is exclusive
    if size % GUEST_PAGE_SIZE != 0 {
        error!("Memory size {:#x} is not a multiple of page size {:#x}", size, GUEST_PAGE_SIZE);
        return Err(RebootReason::InvalidFdt);
    }
    // In the u-boot implementation, we checked if base + size > u64::MAX, but we don't need that
    // because memory() function uses checked_add when constructing the Range object. If an
    // overflow happened, we should have gotten None from the next() call above and would have
    // bailed already.

    NonZeroUsize::new(size).ok_or_else(|| {
        error!("Memory size can't be 0");
        RebootReason::InvalidFdt
    })
}

/// Read the number of CPUs
fn parse_cpu_nodes(fdt: &libfdt::Fdt) -> Result<NonZeroUsize, RebootReason> {
    let num = fdt
        .compatible_nodes(cstr!("arm,arm-v8"))
        .map_err(|e| {
            error!("Failed to read compatible nodes \"arm,arm-v8\" from DT: {e}");
            RebootReason::InvalidFdt
        })?
        .count();
    NonZeroUsize::new(num).ok_or_else(|| {
        error!("Number of CPU can't be 0");
        RebootReason::InvalidFdt
    })
}

#[derive(Debug)]
#[allow(dead_code)] // TODO: remove this
struct PciInfo {
    ranges: [Range<u64>; 2],
    num_irq: usize,
}

/// Read and validate PCI node
fn parse_pci_nodes(fdt: &libfdt::Fdt) -> Result<PciInfo, RebootReason> {
    let node = fdt
        .compatible_nodes(cstr!("pci-host-cam-generic"))
        .map_err(|e| {
            error!("Failed to read compatible node \"pci-host-cam-generic\" from DT: {e}");
            RebootReason::InvalidFdt
        })?
        .next()
        .ok_or_else(|| {
            // pvmfw requires at least one pci device (virtio-blk) for the instance disk. So,
            // let's fail early.
            error!("Compatible node \"pci-host-cam-generic\" doesn't exist");
            RebootReason::InvalidFdt
        })?;

    let mut iter = node
        .ranges::<(u32, u64), u64, u64>()
        .map_err(|e| {
            error!("Failed to read ranges from PCI node: {e}");
            RebootReason::InvalidFdt
        })?
        .ok_or_else(|| {
            error!("PCI node missing ranges property");
            RebootReason::InvalidFdt
        })?;

    let range0 = iter.next().ok_or_else(|| {
        error!("First range missing in PCI node");
        RebootReason::InvalidFdt
    })?;
    let range0 = get_and_validate_pci_range(&range0)?;

    let range1 = iter.next().ok_or_else(|| {
        error!("Second range missing in PCI node");
        RebootReason::InvalidFdt
    })?;
    let range1 = get_and_validate_pci_range(&range1)?;

    let num_irq = count_and_validate_pci_irq_masks(&node)?;

    validate_pci_irq_maps(&node)?;

    Ok(PciInfo { ranges: [range0, range1], num_irq })
}

fn get_and_validate_pci_range(
    range: &AddressRange<(u32, u64), u64, u64>,
) -> Result<Range<u64>, RebootReason> {
    let mem_flags = PciMemoryFlags(range.addr.0);
    let range_type = mem_flags.range_type();
    let prefetchable = mem_flags.prefetchable();
    let bus_addr = range.addr.1;
    let cpu_addr = range.parent_addr;
    let size = range.size;
    if range_type != PciRangeType::Memory64 {
        error!("Invalid range type {:?} for bus address {:#x} in PCI node", range_type, bus_addr);
        return Err(RebootReason::InvalidFdt);
    }
    if prefetchable {
        error!("PCI bus address {:#x} in PCI node is prefetchable", bus_addr);
        return Err(RebootReason::InvalidFdt);
    }
    // Enforce ID bus-to-cpu mappings, as used by crosvm.
    if bus_addr != cpu_addr {
        error!("PCI bus address: {:#x} is different from CPU address: {:#x}", bus_addr, cpu_addr);
        return Err(RebootReason::InvalidFdt);
    }
    let bus_end = bus_addr.checked_add(size).ok_or_else(|| {
        error!("PCI address range size {:#x} too big", size);
        RebootReason::InvalidFdt
    })?;
    Ok(bus_addr..bus_end)
}

/// Iterator that takes N cells as a chunk
struct CellChunkIterator<'a, const N: usize> {
    cells: CellIterator<'a>,
}

impl<'a, const N: usize> CellChunkIterator<'a, N> {
    fn new(cells: CellIterator<'a>) -> Self {
        Self { cells }
    }
}

impl<'a, const N: usize> Iterator for CellChunkIterator<'a, N> {
    type Item = [u32; N];
    fn next(&mut self) -> Option<Self::Item> {
        let mut ret: Self::Item = [0; N];
        for i in ret.iter_mut() {
            *i = self.cells.next()?;
        }
        Some(ret)
    }
}

fn count_and_validate_pci_irq_masks(pci_node: &libfdt::FdtNode) -> Result<usize, RebootReason> {
    const IRQ_MASK_CELLS: usize = 4;
    const IRQ_MASK_ADDR_HI: u32 = 0xf800;
    const IRQ_MASK_ADDR_ME: u32 = 0x0;
    const IRQ_MASK_ADDR_LO: u32 = 0x0;
    const IRQ_MASK_ANY_IRQ: u32 = 0x7;
    const EXPECTED: [u32; IRQ_MASK_CELLS] =
        [IRQ_MASK_ADDR_HI, IRQ_MASK_ADDR_ME, IRQ_MASK_ADDR_LO, IRQ_MASK_ANY_IRQ];

    let mut irq_count: usize = 0;
    for irq_mask in CellChunkIterator::<IRQ_MASK_CELLS>::new(
        pci_node
            .getprop_cells(cstr!("interrupt-map-mask"))
            .map_err(|e| {
                error!("Failed to read interrupt-map-mask property: {e}");
                RebootReason::InvalidFdt
            })?
            .ok_or_else(|| {
                error!("PCI node missing interrupt-map-mask property");
                RebootReason::InvalidFdt
            })?,
    ) {
        if irq_mask != EXPECTED {
            error!("invalid irq mask {:?}", irq_mask);
            return Err(RebootReason::InvalidFdt);
        }
        irq_count += 1;
    }
    Ok(irq_count)
}

fn validate_pci_irq_maps(pci_node: &libfdt::FdtNode) -> Result<(), RebootReason> {
    const IRQ_MAP_CELLS: usize = 10;
    const PCI_DEVICE_IDX: usize = 11;
    const PCI_IRQ_ADDR_ME: u32 = 0;
    const PCI_IRQ_ADDR_LO: u32 = 0;
    const PCI_IRQ_INTC: u32 = 1;
    const AARCH64_IRQ_BASE: u32 = 4; // from external/crosvm/aarch64/src/lib.rs
    const GIC_SPI: u32 = 0;
    const IRQ_TYPE_LEVEL_HIGH: u32 = 4;

    let mut phys_hi: u32 = 0;
    let mut irq_nr = AARCH64_IRQ_BASE;

    for irq_map in CellChunkIterator::<IRQ_MAP_CELLS>::new(
        pci_node
            .getprop_cells(cstr!("interrupt-map"))
            .map_err(|e| {
                error!("Failed to read interrupt-map property: {e}");
                RebootReason::InvalidFdt
            })?
            .ok_or_else(|| {
                error!("PCI node missing interrupt-map property");
                RebootReason::InvalidFdt
            })?,
    ) {
        phys_hi += 0x1 << PCI_DEVICE_IDX;

        let pci_addr = (irq_map[0], irq_map[1], irq_map[2]);
        let pci_irq_number = irq_map[3];
        let _controller_phandle = irq_map[4]; // skipped.
        let gic_addr = (irq_map[5], irq_map[6]); // address-cells is <2> for GIC
                                                 // interrupt-cells is <3> for GIC
        let gic_peripheral_interrupt_type = irq_map[7];
        let gic_irq_number = irq_map[8];
        let gic_irq_type = irq_map[9];

        let expected_pci_addr = (phys_hi, PCI_IRQ_ADDR_ME, PCI_IRQ_ADDR_LO);

        if pci_addr != expected_pci_addr {
            error!("PCI device address {:#x} {:#x} {:#x} in interrupt-map is different from expected address \
                   {:#x} {:#x} {:#x}",
                   pci_addr.0, pci_addr.1, pci_addr.2, expected_pci_addr.0, expected_pci_addr.1, expected_pci_addr.2);
            return Err(RebootReason::InvalidFdt);
        }
        if pci_irq_number != PCI_IRQ_INTC {
            error!(
                "PCI INT# {:#x} in interrupt-map is different from expected value {:#x}",
                pci_irq_number, PCI_IRQ_INTC
            );
            return Err(RebootReason::InvalidFdt);
        }
        if gic_addr != (0, 0) {
            error!(
                "GIC address {:#x} {:#x} in interrupt-map is different from expected address \
                   {:#x} {:#x}",
                gic_addr.0, gic_addr.1, 0, 0
            );
            return Err(RebootReason::InvalidFdt);
        }
        if gic_peripheral_interrupt_type != GIC_SPI {
            error!("GIC peripheral interrupt type {:#x} in interrupt-map is different from expected value \
                   {:#x}", gic_peripheral_interrupt_type, GIC_SPI);
            return Err(RebootReason::InvalidFdt);
        }
        if gic_irq_number != irq_nr {
            error!(
                "GIC irq number {:#x} in interrupt-map is unexpected. Expected {:#x}",
                gic_irq_number, irq_nr
            );
            return Err(RebootReason::InvalidFdt);
        }
        irq_nr += 1; // move to next irq
        if gic_irq_type != IRQ_TYPE_LEVEL_HIGH {
            error!(
                "IRQ type in {:#x} is invalid. Must be LEVEL_HIGH {:#x}",
                gic_irq_type, IRQ_TYPE_LEVEL_HIGH
            );
            return Err(RebootReason::InvalidFdt);
        }
    }
    Ok(())
}

#[derive(Default, Debug)]
#[allow(dead_code)] // TODO: remove this
pub struct SerialInfo {
    addrs: ArrayVec<[u64; Self::SERIAL_MAX_COUNT]>,
}

impl SerialInfo {
    const SERIAL_MAX_COUNT: usize = 4;
}

fn parse_serial_nodes(fdt: &libfdt::Fdt) -> Result<SerialInfo, RebootReason> {
    let mut ret: SerialInfo = Default::default();
    for (i, node) in fdt
        .compatible_nodes(cstr!("ns16550a"))
        .map_err(|e| {
            error!("Failed to read compatible nodes \"ns16550a\" from DT: {e}");
            RebootReason::InvalidFdt
        })?
        .enumerate()
    {
        if i >= ret.addrs.capacity() {
            error!("Too many serials: {i}");
            return Err(RebootReason::InvalidFdt);
        }
        let reg = node
            .reg()
            .map_err(|e| {
                error!("Failed to read reg property from \"ns16550a\" node: {e}");
                RebootReason::InvalidFdt
            })?
            .ok_or_else(|| {
                error!("No reg property in \"ns16550a\" node");
                RebootReason::InvalidFdt
            })?
            .next()
            .ok_or_else(|| {
                error!("No value in reg property of \"ns16550a\" node");
                RebootReason::InvalidFdt
            })?;
        ret.addrs.push(reg.addr);
    }
    Ok(ret)
}

#[derive(Debug)]
#[allow(dead_code)] // TODO: remove this
pub struct SwiotlbInfo {
    size: u64,
    align: u64,
}

fn parse_swiotlb_nodes(fdt: &libfdt::Fdt) -> Result<SwiotlbInfo, RebootReason> {
    let node = fdt
        .compatible_nodes(cstr!("restricted-dma-pool"))
        .map_err(|e| {
            error!("Failed to read compatible nodes \"restricted-dma-pool\" from DT: {e}");
            RebootReason::InvalidFdt
        })?
        .next()
        .ok_or_else(|| {
            error!("No compatible node \"restricted-dma-pool\" in DT");
            RebootReason::InvalidFdt
        })?;
    let size = node
        .getprop_u64(cstr!("size"))
        .map_err(|e| {
            error!("Failed to read \"size\" property of \"restricted-dma-pool\": {e}");
            RebootReason::InvalidFdt
        })?
        .ok_or_else(|| {
            error!("No \"size\" property in \"restricted-dma-pool\"");
            RebootReason::InvalidFdt
        })?;

    let align = node
        .getprop_u64(cstr!("alignment"))
        .map_err(|e| {
            error!("Failed to read \"alignment\" property of \"restricted-dma-pool\": {e}");
            RebootReason::InvalidFdt
        })?
        .ok_or_else(|| {
            error!("No \"alignment\" property in \"restricted-dma-pool\"");
            RebootReason::InvalidFdt
        })?;

    if size == 0 || (size % GUEST_PAGE_SIZE as u64) != 0 {
        error!("Invalid swiotlb size {:#x}", size);
        return Err(RebootReason::InvalidFdt);
    }

    if (align % GUEST_PAGE_SIZE as u64) != 0 {
        error!("Invalid swiotlb alignment {:#x}", align);
        return Err(RebootReason::InvalidFdt);
    }

    Ok(SwiotlbInfo { size, align })
}

#[derive(Debug)]
#[allow(dead_code)] // TODO: remove this
pub struct DeviceTreeInfo {
    memory_size: NonZeroUsize,
    num_cpu: NonZeroUsize,
    pci_info: PciInfo,
    serial_info: SerialInfo,
    swiotlb_info: SwiotlbInfo,
}

impl DeviceTreeInfo {
    const RAM_BASE_ADDR: u64 = 0x8000_0000;
}

pub fn parse_device_tree(fdt: &libfdt::Fdt) -> Result<DeviceTreeInfo, RebootReason> {
    Ok(DeviceTreeInfo {
        memory_size: parse_memory_node(fdt)?,
        num_cpu: parse_cpu_nodes(fdt)?,
        pci_info: parse_pci_nodes(fdt)?,
        serial_info: parse_serial_nodes(fdt)?,
        swiotlb_info: parse_swiotlb_nodes(fdt)?,
    })
}

/// Modifies the input DT according to the fields of the configuration.
pub fn modify_for_next_stage(
    fdt: &mut Fdt,
    bcc: &[u8],
    new_instance: bool,
    strict_boot: bool,
) -> libfdt::Result<()> {
    fdt.unpack()?;

    add_dice_node(fdt, bcc.as_ptr() as usize, bcc.len())?;

    set_or_clear_chosen_flag(fdt, cstr!("avf,strict-boot"), strict_boot)?;
    set_or_clear_chosen_flag(fdt, cstr!("avf,new-instance"), new_instance)?;

    fdt.pack()?;

    Ok(())
}

/// Add a "google,open-dice"-compatible reserved-memory node to the tree.
fn add_dice_node(fdt: &mut Fdt, addr: usize, size: usize) -> libfdt::Result<()> {
    // We reject DTs with missing reserved-memory node as validation should have checked that the
    // "swiotlb" subnode (compatible = "restricted-dma-pool") was present.
    let mut reserved_memory =
        fdt.node_mut(cstr!("/reserved-memory"))?.ok_or(libfdt::FdtError::NotFound)?;

    let mut dice = reserved_memory.add_subnode(cstr!("dice"))?;

    dice.appendprop(cstr!("compatible"), b"google,open-dice\0")?;

    dice.appendprop(cstr!("no-map"), &[])?;

    let addr = addr.try_into().unwrap();
    let size = size.try_into().unwrap();
    dice.appendprop_addrrange(cstr!("reg"), addr, size)?;

    Ok(())
}

fn set_or_clear_chosen_flag(fdt: &mut Fdt, flag: &CStr, value: bool) -> libfdt::Result<()> {
    // TODO(b/249054080): Refactor to not panic if the DT doesn't contain a /chosen node.
    let mut chosen = fdt.chosen_mut()?.unwrap();
    if value {
        chosen.setprop_empty(flag)?;
    } else {
        match chosen.delprop(flag) {
            Ok(()) | Err(FdtError::NotFound) => (),
            Err(e) => return Err(e),
        }
    }

    Ok(())
}
