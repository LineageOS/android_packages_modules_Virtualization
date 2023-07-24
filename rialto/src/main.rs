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

//! Project Rialto main source file.

#![no_main]
#![no_std]

mod communication;
mod error;
mod exceptions;

extern crate alloc;

use crate::communication::DataChannel;
use crate::error::{Error, Result};
use core::num::NonZeroUsize;
use core::slice;
use fdtpci::PciInfo;
use hyp::{get_mem_sharer, get_mmio_guard};
use libfdt::FdtError;
use log::{debug, error, info};
use virtio_drivers::{
    device::socket::VsockAddr,
    transport::{pci::bus::PciRoot, DeviceType, Transport},
    Hal,
};
use vmbase::{
    configure_heap,
    fdt::SwiotlbInfo,
    layout::{self, crosvm},
    main,
    memory::{MemoryTracker, PageTable, MEMORY, PAGE_SIZE, SIZE_128KB},
    power::reboot,
    virtio::{
        pci::{self, PciTransportIterator, VirtIOSocket},
        HalImpl,
    },
};

fn host_addr() -> VsockAddr {
    const PROTECTED_VM_PORT: u32 = 5679;
    const NON_PROTECTED_VM_PORT: u32 = 5680;
    const VMADDR_CID_HOST: u64 = 2;

    let port = if is_protected_vm() { PROTECTED_VM_PORT } else { NON_PROTECTED_VM_PORT };
    VsockAddr { cid: VMADDR_CID_HOST, port }
}

fn is_protected_vm() -> bool {
    // Use MMIO support to determine whether the VM is protected.
    get_mmio_guard().is_some()
}

fn new_page_table() -> Result<PageTable> {
    let mut page_table = PageTable::default();

    page_table.map_data(&layout::scratch_range().into())?;
    page_table.map_data(&layout::stack_range(40 * PAGE_SIZE).into())?;
    page_table.map_code(&layout::text_range().into())?;
    page_table.map_rodata(&layout::rodata_range().into())?;
    page_table.map_device(&layout::console_uart_range().into())?;

    Ok(page_table)
}

/// # Safety
///
/// Behavior is undefined if any of the following conditions are violated:
/// * The `fdt_addr` must be a valid pointer and points to a valid `Fdt`.
unsafe fn try_main(fdt_addr: usize) -> Result<()> {
    info!("Welcome to Rialto!");
    let page_table = new_page_table()?;

    MEMORY.lock().replace(MemoryTracker::new(
        page_table,
        crosvm::MEM_START..layout::MAX_VIRT_ADDR,
        crosvm::MMIO_RANGE,
        None, // Rialto doesn't have any payload for now.
    ));

    let fdt_range = MEMORY
        .lock()
        .as_mut()
        .unwrap()
        .alloc(fdt_addr, NonZeroUsize::new(crosvm::FDT_MAX_SIZE).unwrap())?;
    // SAFETY: The tracker validated the range to be in main memory, mapped, and not overlap.
    let fdt = unsafe { slice::from_raw_parts(fdt_range.start as *mut u8, fdt_range.len()) };
    // We do not need to validate the DT since it is already validated in pvmfw.
    let fdt = libfdt::Fdt::from_slice(fdt)?;

    let memory_range = fdt.first_memory_range()?;
    MEMORY.lock().as_mut().unwrap().shrink(&memory_range).map_err(|e| {
        error!("Failed to use memory range value from DT: {memory_range:#x?}");
        e
    })?;

    if let Some(mem_sharer) = get_mem_sharer() {
        let granule = mem_sharer.granule()?;
        MEMORY.lock().as_mut().unwrap().init_dynamic_shared_pool(granule).map_err(|e| {
            error!("Failed to initialize dynamically shared pool.");
            e
        })?;
    } else if let Ok(swiotlb_info) = SwiotlbInfo::new_from_fdt(fdt) {
        let range = swiotlb_info.fixed_range().ok_or_else(|| {
            error!("Pre-shared pool range not specified in swiotlb node");
            Error::from(FdtError::BadValue)
        })?;
        MEMORY.lock().as_mut().unwrap().init_static_shared_pool(range).map_err(|e| {
            error!("Failed to initialize pre-shared pool.");
            e
        })?;
    } else {
        info!("No MEM_SHARE capability detected or swiotlb found: allocating buffers from heap.");
        MEMORY.lock().as_mut().unwrap().init_heap_shared_pool().map_err(|e| {
            error!("Failed to initialize heap-based pseudo-shared pool.");
            e
        })?;
    }

    let pci_info = PciInfo::from_fdt(fdt)?;
    debug!("PCI: {pci_info:#x?}");
    let mut pci_root = pci::initialize(pci_info, MEMORY.lock().as_mut().unwrap())
        .map_err(Error::PciInitializationFailed)?;
    debug!("PCI root: {pci_root:#x?}");
    let socket_device = find_socket_device::<HalImpl>(&mut pci_root)?;
    debug!("Found socket device: guest cid = {:?}", socket_device.guest_cid());

    let mut data_channel = DataChannel::from(socket_device);
    data_channel.connect(host_addr())?;
    data_channel.handle_incoming_request()?;
    data_channel.force_close()?;

    Ok(())
}

fn find_socket_device<T: Hal>(pci_root: &mut PciRoot) -> Result<VirtIOSocket<T>> {
    PciTransportIterator::<T>::new(pci_root)
        .find(|t| DeviceType::Socket == t.device_type())
        .map(VirtIOSocket::<T>::new)
        .transpose()
        .map_err(Error::VirtIOSocketCreationFailed)?
        .ok_or(Error::MissingVirtIOSocketDevice)
}

fn try_unshare_all_memory() -> Result<()> {
    info!("Starting unsharing memory...");

    // No logging after unmapping UART.
    if let Some(mmio_guard) = get_mmio_guard() {
        mmio_guard.unmap(vmbase::console::BASE_ADDRESS)?;
    }
    // Unshares all memory and deactivates page table.
    drop(MEMORY.lock().take());
    Ok(())
}

fn unshare_all_memory() {
    if let Err(e) = try_unshare_all_memory() {
        error!("Failed to unshare the memory: {e}");
    }
}

/// Entry point for Rialto.
pub fn main(fdt_addr: u64, _a1: u64, _a2: u64, _a3: u64) {
    log::set_max_level(log::LevelFilter::Debug);
    // SAFETY: `fdt_addr` is supposed to be a valid pointer and points to
    // a valid `Fdt`.
    match unsafe { try_main(fdt_addr as usize) } {
        Ok(()) => unshare_all_memory(),
        Err(e) => {
            error!("Rialto failed with {e}");
            unshare_all_memory();
            reboot()
        }
    }
}

main!(main);
configure_heap!(SIZE_128KB);
