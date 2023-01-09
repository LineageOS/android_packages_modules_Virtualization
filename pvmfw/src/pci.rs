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

//! Functions to scan the PCI bus for VirtIO devices.

use crate::{entry::RebootReason, memory::MemoryTracker};
use fdtpci::{PciError, PciInfo};
use log::{debug, error};
use virtio_drivers::transport::pci::{bus::PciRoot, virtio_device_type};

/// Maps the CAM and BAR range in the page table and MMIO guard.
pub fn map_mmio(pci_info: &PciInfo, memory: &mut MemoryTracker) -> Result<(), RebootReason> {
    memory.map_mmio_range(pci_info.cam_range.clone()).map_err(|e| {
        error!("Failed to map PCI CAM: {}", e);
        RebootReason::InternalError
    })?;

    memory
        .map_mmio_range(pci_info.bar_range.start as usize..pci_info.bar_range.end as usize)
        .map_err(|e| {
            error!("Failed to map PCI MMIO range: {}", e);
            RebootReason::InternalError
        })?;

    Ok(())
}

/// Finds VirtIO PCI devices.
pub fn find_virtio_devices(pci_root: &mut PciRoot) -> Result<(), PciError> {
    for (device_function, info) in pci_root.enumerate_bus(0) {
        let (status, command) = pci_root.get_status_command(device_function);
        debug!(
            "Found PCI device {} at {}, status {:?} command {:?}",
            info, device_function, status, command
        );
        if let Some(virtio_type) = virtio_device_type(&info) {
            debug!("  VirtIO {:?}", virtio_type);
        }
    }

    Ok(())
}
