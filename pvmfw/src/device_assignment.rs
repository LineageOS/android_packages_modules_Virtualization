// Copyright 2023, The Android Open Source Project
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

//! Validate device assignment written in crosvm DT with VM DTBO, and apply it
//! to platform DT.
//! Declared in separated libs for adding unit tests, which requires libstd.

#[cfg(test)]
extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::ffi::CString;
use alloc::fmt;
use alloc::vec;
use alloc::vec::Vec;
use core::ffi::CStr;
use core::iter::Iterator;
use core::mem;
use hyp::DeviceAssigningHypervisor;
use libfdt::{Fdt, FdtError, FdtNode, Phandle, Reg};
use log::error;

// TODO(b/308694211): Use cstr! from vmbase instead.
macro_rules! cstr {
    ($str:literal) => {{
        const S: &str = concat!($str, "\0");
        const C: &::core::ffi::CStr = match ::core::ffi::CStr::from_bytes_with_nul(S.as_bytes()) {
            Ok(v) => v,
            Err(_) => panic!("string contains interior NUL"),
        };
        C
    }};
}

// TODO(b/277993056): Keep constants derived from platform.dts in one place.
const CELLS_PER_INTERRUPT: usize = 3; // from /intc node in platform.dts

/// Errors in device assignment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceAssignmentError {
    /// Invalid VM DTBO
    InvalidDtbo,
    /// Invalid __symbols__
    InvalidSymbols,
    /// Invalid <reg>
    InvalidReg,
    /// Invalid <interrupts>
    InvalidInterrupts,
    /// Invalid <iommus>
    InvalidIommus,
    /// Invalid pvIOMMU node
    InvalidPvIommu,
    /// Too many pvIOMMU
    TooManyPvIommu,
    /// Duplicated pvIOMMU IDs exist
    DuplicatedPvIommuIds,
    /// Unsupported overlay target syntax. Only supports <target-path> with full path.
    UnsupportedOverlayTarget,
    /// Internal error
    Internal,
    /// Unexpected error from libfdt
    UnexpectedFdtError(FdtError),
}

impl From<FdtError> for DeviceAssignmentError {
    fn from(e: FdtError) -> Self {
        DeviceAssignmentError::UnexpectedFdtError(e)
    }
}

impl fmt::Display for DeviceAssignmentError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InvalidDtbo => write!(f, "Invalid DTBO"),
            Self::InvalidSymbols => write!(
                f,
                "Invalid property in /__symbols__. Must point to valid assignable device node."
            ),
            Self::InvalidReg => write!(f, "Invalid <reg>"),
            Self::InvalidInterrupts => write!(f, "Invalid <interrupts>"),
            Self::InvalidIommus => write!(f, "Invalid <iommus>"),
            Self::InvalidPvIommu => write!(f, "Invalid pvIOMMU node"),
            Self::TooManyPvIommu => write!(
                f,
                "Too many pvIOMMU node. Insufficient pre-populated pvIOMMUs in platform DT"
            ),
            Self::DuplicatedPvIommuIds => {
                write!(f, "Duplicated pvIOMMU IDs exist. IDs must unique")
            }
            Self::UnsupportedOverlayTarget => {
                write!(f, "Unsupported overlay target. Only supports 'target-path = \"/\"'")
            }
            Self::Internal => write!(f, "Internal error"),
            Self::UnexpectedFdtError(e) => write!(f, "Unexpected Error from libfdt: {e}"),
        }
    }
}

pub type Result<T> = core::result::Result<T, DeviceAssignmentError>;

/// Represents VM DTBO
#[repr(transparent)]
pub struct VmDtbo(Fdt);

impl VmDtbo {
    /// Wraps a mutable slice containing a VM DTBO.
    ///
    /// Fails if the VM DTBO does not pass validation.
    pub fn from_mut_slice(dtbo: &mut [u8]) -> Result<&mut Self> {
        // This validates DTBO
        let fdt = Fdt::from_mut_slice(dtbo)?;
        // SAFETY: VmDtbo is a transparent wrapper around Fdt, so representation is the same.
        Ok(unsafe { mem::transmute::<&mut Fdt, &mut Self>(fdt) })
    }

    // Locates device node path as if the given dtbo node path is assigned and VM DTBO is overlaid.
    // For given dtbo node path, this concatenates <target-path> of the enclosing fragment and
    // relative path from __overlay__ node.
    //
    // Here's an example with sample VM DTBO:
    //    / {
    //       fragment@rng {
    //         target-path = "/";  // Always 'target-path = "/"'. Disallows <target> or other path.
    //         __overlay__ {
    //           rng { ... };      // Actual device node is here. If overlaid, path would be "/rng"
    //         };
    //       };
    //       __symbols__ {         // List of assignable devices
    //         // Each property describes an assigned device device information.
    //         // property name is the device label, and property value is the path in the VM DTBO.
    //         rng = "/fragment@rng/__overlay__/rng";
    //       };
    //    };
    //
    // Then locate_overlay_target_path(cstr!("/fragment@rng/__overlay__/rng")) is Ok("/rng")
    //
    // Contrary to fdt_overlay_target_offset(), this API enforces overlay target property
    // 'target-path = "/"', so the overlay doesn't modify and/or append platform DT's existing
    // node and/or properties. The enforcement is for compatibility reason.
    fn locate_overlay_target_path(&self, dtbo_node_path: &CStr) -> Result<CString> {
        let dtbo_node_path_bytes = dtbo_node_path.to_bytes();
        if dtbo_node_path_bytes.first() != Some(&b'/') {
            return Err(DeviceAssignmentError::UnsupportedOverlayTarget);
        }

        let node = self.0.node(dtbo_node_path)?.ok_or(DeviceAssignmentError::InvalidSymbols)?;

        let fragment_node = node.supernode_at_depth(1)?;
        let target_path = fragment_node
            .getprop_str(cstr!("target-path"))?
            .ok_or(DeviceAssignmentError::InvalidDtbo)?;
        if target_path != cstr!("/") {
            return Err(DeviceAssignmentError::UnsupportedOverlayTarget);
        }

        let mut components = dtbo_node_path_bytes
            .split(|char| *char == b'/')
            .filter(|&component| !component.is_empty())
            .skip(1);
        let overlay_node_name = components.next();
        if overlay_node_name != Some(b"__overlay__") {
            return Err(DeviceAssignmentError::InvalidDtbo);
        }
        let mut overlaid_path = Vec::with_capacity(dtbo_node_path_bytes.len());
        for component in components {
            overlaid_path.push(b'/');
            overlaid_path.extend_from_slice(component);
        }
        overlaid_path.push(b'\0');

        Ok(CString::from_vec_with_nul(overlaid_path).unwrap())
    }
}

fn is_overlayable_node(dtbo_path: &CStr) -> bool {
    dtbo_path
        .to_bytes()
        .split(|char| *char == b'/')
        .filter(|&component| !component.is_empty())
        .nth(1)
        .map_or(false, |name| name == b"__overlay__")
}

impl AsRef<Fdt> for VmDtbo {
    fn as_ref(&self) -> &Fdt {
        &self.0
    }
}

impl AsMut<Fdt> for VmDtbo {
    fn as_mut(&mut self) -> &mut Fdt {
        &mut self.0
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct PvIommu {
    // ID from pvIOMMU node
    id: u32,
}

impl PvIommu {
    fn parse(node: &FdtNode) -> Result<Self> {
        let iommu_cells = node
            .getprop_u32(cstr!("#iommu-cells"))?
            .ok_or(DeviceAssignmentError::InvalidPvIommu)?;
        // Ensures <#iommu-cells> = 1. It means that `<iommus>` entry contains pair of
        // (pvIOMMU ID, vSID)
        if iommu_cells != 1 {
            return Err(DeviceAssignmentError::InvalidPvIommu);
        }
        let id = node.getprop_u32(cstr!("id"))?.ok_or(DeviceAssignmentError::InvalidPvIommu)?;
        Ok(Self { id })
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct Vsid(u32);

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct DeviceReg {
    addr: u64,
    size: u64,
}

impl TryFrom<Reg<u64>> for DeviceReg {
    type Error = DeviceAssignmentError;

    fn try_from(reg: Reg<u64>) -> Result<Self> {
        Ok(Self { addr: reg.addr, size: reg.size.ok_or(DeviceAssignmentError::InvalidReg)? })
    }
}

fn parse_node_reg(node: &FdtNode) -> Result<Vec<DeviceReg>> {
    node.reg()?
        .ok_or(DeviceAssignmentError::InvalidReg)?
        .map(DeviceReg::try_from)
        .collect::<Result<Vec<_>>>()
}

fn to_be_bytes(reg: &[DeviceReg]) -> Vec<u8> {
    let mut reg_cells = vec![];
    for x in reg {
        reg_cells.extend_from_slice(&x.addr.to_be_bytes());
        reg_cells.extend_from_slice(&x.size.to_be_bytes());
    }
    reg_cells
}

/// Assigned device information parsed from crosvm DT.
/// Keeps everything in the owned data because underlying FDT will be reused for platform DT.
#[derive(Debug, Eq, PartialEq)]
struct AssignedDeviceInfo {
    // Node path of assigned device (e.g. "/rng")
    node_path: CString,
    // DTBO node path of the assigned device (e.g. "/fragment@rng/__overlay__/rng")
    dtbo_node_path: CString,
    // <reg> property from the crosvm DT
    reg: Vec<DeviceReg>,
    // <interrupts> property from the crosvm DT
    interrupts: Vec<u8>,
    // Parsed <iommus> property from the crosvm DT. Tuple of PvIommu and vSID.
    iommus: Vec<(PvIommu, Vsid)>,
}

impl AssignedDeviceInfo {
    fn parse_reg(
        node: &FdtNode,
        hypervisor: &dyn DeviceAssigningHypervisor,
    ) -> Result<Vec<DeviceReg>> {
        let device_reg = parse_node_reg(node)?;
        // TODO(b/277993056): Valid the result back with physical reg
        for reg in &device_reg {
            hypervisor.get_phys_mmio_token(reg.addr, reg.size).map_err(|e| {
                let name = node.name();
                error!("Failed to validate device <reg>, error={e:?}, name={name:?}, reg={reg:?}");
                DeviceAssignmentError::InvalidReg
            })?;
        }
        Ok(device_reg)
    }

    fn parse_interrupts(node: &FdtNode) -> Result<Vec<u8>> {
        // Validation: Validate if interrupts cell numbers are multiple of #interrupt-cells.
        // We can't know how many interrupts would exist.
        let interrupts_cells = node
            .getprop_cells(cstr!("interrupts"))?
            .ok_or(DeviceAssignmentError::InvalidInterrupts)?
            .count();
        if interrupts_cells % CELLS_PER_INTERRUPT != 0 {
            return Err(DeviceAssignmentError::InvalidInterrupts);
        }

        // Once validated, keep the raw bytes so patch can be done with setprop()
        Ok(node.getprop(cstr!("interrupts")).unwrap().unwrap().into())
    }

    // TODO(b/277993056): Also validate /__local_fixups__ to ensure that <iommus> has phandle.
    fn parse_iommus(
        node: &FdtNode,
        pviommus: &BTreeMap<Phandle, PvIommu>,
        hypervisor: &dyn DeviceAssigningHypervisor,
    ) -> Result<Vec<(PvIommu, Vsid)>> {
        let mut iommus = vec![];
        let Some(mut cells) = node.getprop_cells(cstr!("iommus"))? else {
            return Ok(iommus);
        };
        while let Some(cell) = cells.next() {
            // Parse pvIOMMU ID
            let phandle = Phandle::try_from(cell).or(Err(DeviceAssignmentError::InvalidIommus))?;
            let pviommu = pviommus.get(&phandle).ok_or(DeviceAssignmentError::InvalidIommus)?;

            // Parse vSID
            let Some(cell) = cells.next() else {
                return Err(DeviceAssignmentError::InvalidIommus);
            };
            let vsid = Vsid(cell);

            // TODO(b/277993056): Valid the result back with phys iommu id and sid..
            hypervisor
                .get_phys_iommu_token(pviommu.id.into(), vsid.0.into())
                .map_err(|e| {
                    let name = node.name().unwrap_or_default();
                    error!("Failed to validate device <iommus>, error={e:?}, name={name:?}, pviommu={pviommu:?}, vsid={:?}", vsid.0);
                    DeviceAssignmentError::InvalidIommus
                })?;

            iommus.push((*pviommu, vsid));
        }
        Ok(iommus)
    }

    fn parse(
        fdt: &Fdt,
        vm_dtbo: &VmDtbo,
        dtbo_node_path: &CStr,
        pviommus: &BTreeMap<Phandle, PvIommu>,
        hypervisor: &dyn DeviceAssigningHypervisor,
    ) -> Result<Option<Self>> {
        let node_path = vm_dtbo.locate_overlay_target_path(dtbo_node_path)?;

        let Some(node) = fdt.node(&node_path)? else { return Ok(None) };

        let reg = Self::parse_reg(&node, hypervisor)?;
        let interrupts = Self::parse_interrupts(&node)?;
        let iommus = Self::parse_iommus(&node, pviommus, hypervisor)?;
        Ok(Some(Self { node_path, dtbo_node_path: dtbo_node_path.into(), reg, interrupts, iommus }))
    }

    fn patch(&self, fdt: &mut Fdt, pviommu_phandles: &BTreeMap<PvIommu, Phandle>) -> Result<()> {
        let mut dst = fdt.node_mut(&self.node_path)?.unwrap();
        dst.setprop(cstr!("reg"), &to_be_bytes(&self.reg))?;
        dst.setprop(cstr!("interrupts"), &self.interrupts)?;
        let mut iommus = Vec::with_capacity(8 * self.iommus.len());
        for (pviommu, vsid) in &self.iommus {
            let phandle = pviommu_phandles.get(pviommu).unwrap();
            iommus.extend_from_slice(&u32::from(*phandle).to_be_bytes());
            iommus.extend_from_slice(&vsid.0.to_be_bytes());
        }
        dst.setprop(cstr!("iommus"), &iommus)?;

        Ok(())
    }
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct DeviceAssignmentInfo {
    pviommus: BTreeSet<PvIommu>,
    assigned_devices: Vec<AssignedDeviceInfo>,
    filtered_dtbo_paths: Vec<CString>,
}

impl DeviceAssignmentInfo {
    const PVIOMMU_COMPATIBLE: &CStr = cstr!("pkvm,pviommu");

    /// Parses pvIOMMUs in fdt
    // Note: This will validate pvIOMMU ids' uniqueness, even when unassigned.
    fn parse_pviommus(fdt: &Fdt) -> Result<BTreeMap<Phandle, PvIommu>> {
        let mut pviommus = BTreeMap::new();
        for compatible in fdt.compatible_nodes(Self::PVIOMMU_COMPATIBLE)? {
            let Some(phandle) = compatible.get_phandle()? else {
                continue; // Skips unreachable pvIOMMU node
            };
            let pviommu = PvIommu::parse(&compatible)?;
            if pviommus.insert(phandle, pviommu).is_some() {
                return Err(FdtError::BadPhandle.into());
            }
        }
        Ok(pviommus)
    }

    /// Parses fdt and vm_dtbo, and creates new DeviceAssignmentInfo
    // TODO(b/277993056): Parse __local_fixups__
    // TODO(b/277993056): Parse __fixups__
    pub fn parse(
        fdt: &Fdt,
        vm_dtbo: &VmDtbo,
        hypervisor: &dyn DeviceAssigningHypervisor,
    ) -> Result<Option<Self>> {
        let Some(symbols_node) = vm_dtbo.as_ref().symbols()? else {
            // /__symbols__ should contain all assignable devices.
            // If empty, then nothing can be assigned.
            return Ok(None);
        };

        let pviommus = Self::parse_pviommus(fdt)?;
        let unique_pviommus: BTreeSet<_> = pviommus.values().cloned().collect();
        if pviommus.len() != unique_pviommus.len() {
            return Err(DeviceAssignmentError::DuplicatedPvIommuIds);
        }

        let mut assigned_devices = vec![];
        let mut filtered_dtbo_paths = vec![];
        for symbol_prop in symbols_node.properties()? {
            let symbol_prop_value = symbol_prop.value()?;
            let dtbo_node_path = CStr::from_bytes_with_nul(symbol_prop_value)
                .or(Err(DeviceAssignmentError::InvalidSymbols))?;
            if !is_overlayable_node(dtbo_node_path) {
                continue;
            }
            let assigned_device =
                AssignedDeviceInfo::parse(fdt, vm_dtbo, dtbo_node_path, &pviommus, hypervisor)?;
            if let Some(assigned_device) = assigned_device {
                assigned_devices.push(assigned_device);
            } else {
                filtered_dtbo_paths.push(dtbo_node_path.into());
            }
        }
        if assigned_devices.is_empty() {
            return Ok(None);
        }

        // Clean up any nodes that wouldn't be overlaid but may contain reference to filtered nodes.
        // Otherwise, `fdt_apply_overlay()` would fail because of missing phandle reference.
        filtered_dtbo_paths.push(CString::new("/__symbols__").unwrap());
        // TODO(b/277993056): Also filter other unused nodes/props in __local_fixups__
        filtered_dtbo_paths.push(CString::new("/__local_fixups__/host").unwrap());

        // Note: Any node without __overlay__ will be ignored by fdt_apply_overlay,
        // so doesn't need to be filtered.

        Ok(Some(Self { pviommus: unique_pviommus, assigned_devices, filtered_dtbo_paths }))
    }

    /// Filters VM DTBO to only contain necessary information for booting pVM
    /// In detail, this will remove followings by setting nop node / nop property.
    ///   - Removes unassigned devices
    ///   - Removes /__symbols__ node
    // TODO(b/277993056): remove unused dependencies in VM DTBO.
    // TODO(b/277993056): remove supernodes' properties.
    // TODO(b/277993056): remove unused alises.
    pub fn filter(&self, vm_dtbo: &mut VmDtbo) -> Result<()> {
        let vm_dtbo = vm_dtbo.as_mut();

        // Filters unused node in assigned devices
        for filtered_dtbo_path in &self.filtered_dtbo_paths {
            let node = vm_dtbo.node_mut(filtered_dtbo_path).unwrap().unwrap();
            node.nop()?;
        }

        Ok(())
    }

    fn patch_pviommus(&self, fdt: &mut Fdt) -> Result<BTreeMap<PvIommu, Phandle>> {
        let mut compatible = fdt.root_mut()?.next_compatible(Self::PVIOMMU_COMPATIBLE)?;
        let mut pviommu_phandles = BTreeMap::new();

        for pviommu in &self.pviommus {
            let mut node = compatible.ok_or(DeviceAssignmentError::TooManyPvIommu)?;
            let phandle = node.as_node().get_phandle()?.ok_or(DeviceAssignmentError::Internal)?;
            node.setprop_inplace(cstr!("id"), &pviommu.id.to_be_bytes())?;
            if pviommu_phandles.insert(*pviommu, phandle).is_some() {
                return Err(DeviceAssignmentError::Internal);
            }
            compatible = node.next_compatible(Self::PVIOMMU_COMPATIBLE)?;
        }

        // Filters pre-populated but unassigned pvIOMMUs.
        while let Some(filtered_pviommu) = compatible {
            compatible = filtered_pviommu.delete_and_next_compatible(Self::PVIOMMU_COMPATIBLE)?;
        }

        Ok(pviommu_phandles)
    }

    pub fn patch(&self, fdt: &mut Fdt) -> Result<()> {
        let pviommu_phandles = self.patch_pviommus(fdt)?;

        // Patches assigned devices
        for device in &self.assigned_devices {
            device.patch(fdt, &pviommu_phandles)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::{BTreeMap, BTreeSet};
    use std::fs;

    const VM_DTBO_FILE_PATH: &str = "test_pvmfw_devices_vm_dtbo.dtbo";
    const VM_DTBO_WITHOUT_SYMBOLS_FILE_PATH: &str =
        "test_pvmfw_devices_vm_dtbo_without_symbols.dtbo";
    const FDT_WITHOUT_IOMMUS_FILE_PATH: &str = "test_pvmfw_devices_without_iommus.dtb";
    const FDT_WITHOUT_DEVICE_FILE_PATH: &str = "test_pvmfw_devices_without_device.dtb";
    const FDT_FILE_PATH: &str = "test_pvmfw_devices_with_rng.dtb";
    const FDT_WITH_MULTIPLE_DEVICES_IOMMUS_FILE_PATH: &str =
        "test_pvmfw_devices_with_multiple_devices_iommus.dtb";
    const FDT_WITH_IOMMU_SHARING: &str = "test_pvmfw_devices_with_iommu_sharing.dtb";
    const FDT_WITH_IOMMU_ID_CONFLICT: &str = "test_pvmfw_devices_with_iommu_id_conflict.dtb";

    #[derive(Debug, Default)]
    struct MockHypervisor {
        mmio_tokens: BTreeMap<(u64, u64), u64>,
        iommu_tokens: BTreeMap<(u64, u64), (u64, u64)>,
    }

    impl DeviceAssigningHypervisor for MockHypervisor {
        fn get_phys_mmio_token(&self, base_ipa: u64, size: u64) -> hyp::Result<u64> {
            Ok(*self.mmio_tokens.get(&(base_ipa, size)).ok_or(hyp::Error::KvmError(
                hyp::KvmError::InvalidParameter,
                0xc6000012, /* VENDOR_HYP_KVM_DEV_REQ_MMIO_FUNC_ID */
            ))?)
        }

        fn get_phys_iommu_token(&self, pviommu_id: u64, vsid: u64) -> hyp::Result<(u64, u64)> {
            Ok(*self.iommu_tokens.get(&(pviommu_id, vsid)).ok_or(hyp::Error::KvmError(
                hyp::KvmError::InvalidParameter,
                0xc6000013, /* VENDOR_HYP_KVM_DEV_REQ_DMA_FUNC_ID */
            ))?)
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    struct AssignedDeviceNode {
        path: CString,
        reg: Vec<u8>,
        interrupts: Vec<u8>,
        iommus: Vec<u32>, // pvIOMMU id and vSID
    }

    impl AssignedDeviceNode {
        fn parse(fdt: &Fdt, path: &CStr) -> Result<Self> {
            let Some(node) = fdt.node(path)? else {
                return Err(FdtError::NotFound.into());
            };

            let reg = node.getprop(cstr!("reg"))?.ok_or(DeviceAssignmentError::InvalidReg)?;
            let interrupts = node
                .getprop(cstr!("interrupts"))?
                .ok_or(DeviceAssignmentError::InvalidInterrupts)?;
            let mut iommus = vec![];
            if let Some(mut cells) = node.getprop_cells(cstr!("iommus"))? {
                while let Some(pviommu_id) = cells.next() {
                    // pvIOMMU id
                    let phandle = Phandle::try_from(pviommu_id)?;
                    let pviommu = fdt
                        .node_with_phandle(phandle)?
                        .ok_or(DeviceAssignmentError::InvalidIommus)?;
                    let compatible = pviommu.getprop_str(cstr!("compatible"));
                    if compatible != Ok(Some(cstr!("pkvm,pviommu"))) {
                        return Err(DeviceAssignmentError::InvalidIommus);
                    }
                    let id = pviommu
                        .getprop_u32(cstr!("id"))?
                        .ok_or(DeviceAssignmentError::InvalidIommus)?;
                    iommus.push(id);

                    // vSID
                    let Some(vsid) = cells.next() else {
                        return Err(DeviceAssignmentError::InvalidIommus);
                    };
                    iommus.push(vsid);
                }
            }
            Ok(Self { path: path.into(), reg: reg.into(), interrupts: interrupts.into(), iommus })
        }
    }

    fn collect_pviommus(fdt: &Fdt) -> Result<Vec<u32>> {
        let mut pviommus = BTreeSet::new();
        for pviommu in fdt.compatible_nodes(cstr!("pkvm,pviommu"))? {
            if let Ok(Some(id)) = pviommu.getprop_u32(cstr!("id")) {
                pviommus.insert(id);
            }
        }
        Ok(pviommus.iter().cloned().collect())
    }

    fn into_fdt_prop(native_bytes: Vec<u32>) -> Vec<u8> {
        let mut v = Vec::with_capacity(native_bytes.len() * 4);
        for byte in native_bytes {
            v.extend_from_slice(&byte.to_be_bytes());
        }
        v
    }

    impl From<[u64; 2]> for DeviceReg {
        fn from(fdt_cells: [u64; 2]) -> Self {
            DeviceReg { addr: fdt_cells[0], size: fdt_cells[1] }
        }
    }

    #[test]
    fn device_info_new_without_symbols() {
        let mut fdt_data = fs::read(FDT_FILE_PATH).unwrap();
        let mut vm_dtbo_data = fs::read(VM_DTBO_WITHOUT_SYMBOLS_FILE_PATH).unwrap();
        let fdt = Fdt::from_mut_slice(&mut fdt_data).unwrap();
        let vm_dtbo = VmDtbo::from_mut_slice(&mut vm_dtbo_data).unwrap();

        let hypervisor: MockHypervisor = Default::default();
        let device_info = DeviceAssignmentInfo::parse(fdt, vm_dtbo, &hypervisor).unwrap();
        assert_eq!(device_info, None);
    }

    #[test]
    fn device_info_new_without_device() {
        let mut fdt_data = fs::read(FDT_WITHOUT_DEVICE_FILE_PATH).unwrap();
        let mut vm_dtbo_data = fs::read(VM_DTBO_FILE_PATH).unwrap();
        let fdt = Fdt::from_mut_slice(&mut fdt_data).unwrap();
        let vm_dtbo = VmDtbo::from_mut_slice(&mut vm_dtbo_data).unwrap();

        let hypervisor: MockHypervisor = Default::default();
        let device_info = DeviceAssignmentInfo::parse(fdt, vm_dtbo, &hypervisor).unwrap();
        assert_eq!(device_info, None);
    }

    #[test]
    fn device_info_assigned_info_without_iommus() {
        let mut fdt_data = fs::read(FDT_WITHOUT_IOMMUS_FILE_PATH).unwrap();
        let mut vm_dtbo_data = fs::read(VM_DTBO_FILE_PATH).unwrap();
        let fdt = Fdt::from_mut_slice(&mut fdt_data).unwrap();
        let vm_dtbo = VmDtbo::from_mut_slice(&mut vm_dtbo_data).unwrap();

        let hypervisor = MockHypervisor {
            mmio_tokens: [((0x9, 0xFF), 0x300)].into(),
            iommu_tokens: BTreeMap::new(),
        };
        let device_info = DeviceAssignmentInfo::parse(fdt, vm_dtbo, &hypervisor).unwrap().unwrap();

        let expected = [AssignedDeviceInfo {
            node_path: CString::new("/bus0/backlight").unwrap(),
            dtbo_node_path: cstr!("/fragment@backlight/__overlay__/bus0/backlight").into(),
            reg: vec![[0x9, 0xFF].into()],
            interrupts: into_fdt_prop(vec![0x0, 0xF, 0x4]),
            iommus: vec![],
        }];

        assert_eq!(device_info.assigned_devices, expected);
    }

    #[test]
    fn device_info_assigned_info() {
        let mut fdt_data = fs::read(FDT_FILE_PATH).unwrap();
        let mut vm_dtbo_data = fs::read(VM_DTBO_FILE_PATH).unwrap();
        let fdt = Fdt::from_mut_slice(&mut fdt_data).unwrap();
        let vm_dtbo = VmDtbo::from_mut_slice(&mut vm_dtbo_data).unwrap();

        let hypervisor = MockHypervisor {
            mmio_tokens: [((0x9, 0xFF), 0x12F00000)].into(),
            iommu_tokens: [((0x4, 0xFF0), (0x12E40000, 0x3))].into(),
        };
        let device_info = DeviceAssignmentInfo::parse(fdt, vm_dtbo, &hypervisor).unwrap().unwrap();

        let expected = [AssignedDeviceInfo {
            node_path: CString::new("/rng").unwrap(),
            dtbo_node_path: cstr!("/fragment@rng/__overlay__/rng").into(),
            reg: vec![[0x9, 0xFF].into()],
            interrupts: into_fdt_prop(vec![0x0, 0xF, 0x4]),
            iommus: vec![(PvIommu { id: 0x4 }, Vsid(0xFF0))],
        }];

        assert_eq!(device_info.assigned_devices, expected);
    }

    // TODO(b/311655051): Test with real once instead of empty FDT.
    #[test]
    fn device_info_new_with_empty_device_tree() {
        let mut fdt_data = vec![0; pvmfw_fdt_template::RAW.len()];
        let mut vm_dtbo_data = fs::read(VM_DTBO_FILE_PATH).unwrap();
        let fdt = Fdt::create_empty_tree(&mut fdt_data).unwrap();
        let vm_dtbo = VmDtbo::from_mut_slice(&mut vm_dtbo_data).unwrap();

        let hypervisor: MockHypervisor = Default::default();
        let device_info = DeviceAssignmentInfo::parse(fdt, vm_dtbo, &hypervisor).unwrap();
        assert_eq!(device_info, None);
    }

    #[test]
    fn device_info_filter() {
        let mut fdt_data = fs::read(FDT_FILE_PATH).unwrap();
        let mut vm_dtbo_data = fs::read(VM_DTBO_FILE_PATH).unwrap();
        let fdt = Fdt::from_mut_slice(&mut fdt_data).unwrap();
        let vm_dtbo = VmDtbo::from_mut_slice(&mut vm_dtbo_data).unwrap();

        let hypervisor = MockHypervisor {
            mmio_tokens: [((0x9, 0xFF), 0x12F00000)].into(),
            iommu_tokens: [((0x4, 0xFF0), (0x12E40000, 0x3))].into(),
        };
        let device_info = DeviceAssignmentInfo::parse(fdt, vm_dtbo, &hypervisor).unwrap().unwrap();
        device_info.filter(vm_dtbo).unwrap();

        let vm_dtbo = vm_dtbo.as_mut();

        let rng = vm_dtbo.node(cstr!("/fragment@rng/__overlay__/rng")).unwrap();
        assert_ne!(rng, None);

        let light = vm_dtbo.node(cstr!("/fragment@rng/__overlay__/light")).unwrap();
        assert_eq!(light, None);

        let led = vm_dtbo.node(cstr!("/fragment@led/__overlay__/led")).unwrap();
        assert_eq!(led, None);

        let backlight =
            vm_dtbo.node(cstr!("/fragment@backlight/__overlay__/bus0/backlight")).unwrap();
        assert_eq!(backlight, None);

        let symbols_node = vm_dtbo.symbols().unwrap();
        assert_eq!(symbols_node, None);
    }

    #[test]
    fn device_info_patch() {
        let mut fdt_data = fs::read(FDT_WITHOUT_IOMMUS_FILE_PATH).unwrap();
        let mut vm_dtbo_data = fs::read(VM_DTBO_FILE_PATH).unwrap();
        let mut data = vec![0_u8; fdt_data.len() + vm_dtbo_data.len()];
        let fdt = Fdt::from_mut_slice(&mut fdt_data).unwrap();
        let vm_dtbo = VmDtbo::from_mut_slice(&mut vm_dtbo_data).unwrap();
        let platform_dt = Fdt::create_empty_tree(data.as_mut_slice()).unwrap();

        let hypervisor = MockHypervisor {
            mmio_tokens: [((0x9, 0xFF), 0x300)].into(),
            iommu_tokens: BTreeMap::new(),
        };
        let device_info = DeviceAssignmentInfo::parse(fdt, vm_dtbo, &hypervisor).unwrap().unwrap();
        device_info.filter(vm_dtbo).unwrap();

        // SAFETY: Damaged VM DTBO wouldn't be used after this unsafe block.
        unsafe {
            platform_dt.apply_overlay(vm_dtbo.as_mut()).unwrap();
        }
        device_info.patch(platform_dt).unwrap();

        let rng_node = platform_dt.node(cstr!("/bus0/backlight")).unwrap().unwrap();
        let phandle = rng_node.getprop_u32(cstr!("phandle")).unwrap();
        assert_ne!(None, phandle);

        // Note: Intentionally not using AssignedDeviceNode for matching all props.
        type FdtResult<T> = libfdt::Result<T>;
        let expected: Vec<(FdtResult<&CStr>, FdtResult<Vec<u8>>)> = vec![
            (Ok(cstr!("android,backlight,ignore-gctrl-reset")), Ok(Vec::new())),
            (Ok(cstr!("compatible")), Ok(Vec::from(*b"android,backlight\0"))),
            (Ok(cstr!("interrupts")), Ok(into_fdt_prop(vec![0x0, 0xF, 0x4]))),
            (Ok(cstr!("iommus")), Ok(Vec::new())),
            (Ok(cstr!("phandle")), Ok(into_fdt_prop(vec![phandle.unwrap()]))),
            (Ok(cstr!("reg")), Ok(into_fdt_prop(vec![0x0, 0x9, 0x0, 0xFF]))),
        ];

        let mut properties: Vec<_> = rng_node
            .properties()
            .unwrap()
            .map(|prop| (prop.name(), prop.value().map(|x| x.into())))
            .collect();
        properties.sort_by(|a, b| {
            let lhs = a.0.unwrap_or_default();
            let rhs = b.0.unwrap_or_default();
            lhs.partial_cmp(rhs).unwrap()
        });

        assert_eq!(properties, expected);
    }

    #[test]
    fn device_info_overlay_iommu() {
        let mut fdt_data = fs::read(FDT_FILE_PATH).unwrap();
        let mut vm_dtbo_data = fs::read(VM_DTBO_FILE_PATH).unwrap();
        let fdt = Fdt::from_mut_slice(&mut fdt_data).unwrap();
        let vm_dtbo = VmDtbo::from_mut_slice(&mut vm_dtbo_data).unwrap();
        let mut platform_dt_data = pvmfw_fdt_template::RAW.to_vec();
        platform_dt_data.resize(pvmfw_fdt_template::RAW.len() * 2, 0);
        let platform_dt = Fdt::from_mut_slice(&mut platform_dt_data).unwrap();
        platform_dt.unpack().unwrap();

        let hypervisor = MockHypervisor {
            mmio_tokens: [((0x9, 0xFF), 0x12F00000)].into(),
            iommu_tokens: [((0x4, 0xFF0), (0x12E40000, 0x3))].into(),
        };
        let device_info = DeviceAssignmentInfo::parse(fdt, vm_dtbo, &hypervisor).unwrap().unwrap();
        device_info.filter(vm_dtbo).unwrap();

        // SAFETY: Damaged VM DTBO wouldn't be used after this unsafe block.
        unsafe {
            platform_dt.apply_overlay(vm_dtbo.as_mut()).unwrap();
        }
        device_info.patch(platform_dt).unwrap();

        let expected = AssignedDeviceNode {
            path: CString::new("/rng").unwrap(),
            reg: into_fdt_prop(vec![0x0, 0x9, 0x0, 0xFF]),
            interrupts: into_fdt_prop(vec![0x0, 0xF, 0x4]),
            iommus: vec![0x4, 0xFF0],
        };

        let node = AssignedDeviceNode::parse(platform_dt, &expected.path);
        assert_eq!(node, Ok(expected));

        let pviommus = collect_pviommus(platform_dt);
        assert_eq!(pviommus, Ok(vec![0x4]));
    }

    #[test]
    fn device_info_multiple_devices_iommus() {
        let mut fdt_data = fs::read(FDT_WITH_MULTIPLE_DEVICES_IOMMUS_FILE_PATH).unwrap();
        let mut vm_dtbo_data = fs::read(VM_DTBO_FILE_PATH).unwrap();
        let fdt = Fdt::from_mut_slice(&mut fdt_data).unwrap();
        let vm_dtbo = VmDtbo::from_mut_slice(&mut vm_dtbo_data).unwrap();
        let mut platform_dt_data = pvmfw_fdt_template::RAW.to_vec();
        platform_dt_data.resize(pvmfw_fdt_template::RAW.len() * 2, 0);
        let platform_dt = Fdt::from_mut_slice(&mut platform_dt_data).unwrap();
        platform_dt.unpack().unwrap();

        let hypervisor = MockHypervisor {
            mmio_tokens: [
                ((0x9, 0xFF), 0x12F00000),
                ((0x100, 0x1000), 0xF00000),
                ((0x200, 0x1000), 0xF10000),
            ]
            .into(),
            iommu_tokens: [
                ((0x4, 0xFF0), (0x12E40000, 3)),
                ((0x40, 0xFFA), (0x40000, 0x4)),
                ((0x50, 0xFFB), (0x50000, 0x5)),
            ]
            .into(),
        };
        let device_info = DeviceAssignmentInfo::parse(fdt, vm_dtbo, &hypervisor).unwrap().unwrap();
        device_info.filter(vm_dtbo).unwrap();

        // SAFETY: Damaged VM DTBO wouldn't be used after this unsafe block.
        unsafe {
            platform_dt.apply_overlay(vm_dtbo.as_mut()).unwrap();
        }
        device_info.patch(platform_dt).unwrap();

        let expected_devices = [
            AssignedDeviceNode {
                path: CString::new("/rng").unwrap(),
                reg: into_fdt_prop(vec![0x0, 0x9, 0x0, 0xFF]),
                interrupts: into_fdt_prop(vec![0x0, 0xF, 0x4]),
                iommus: vec![0x4, 0xFF0],
            },
            AssignedDeviceNode {
                path: CString::new("/light").unwrap(),
                reg: into_fdt_prop(vec![0x0, 0x100, 0x0, 0x1000, 0x0, 0x200, 0x0, 0x1000]),
                interrupts: into_fdt_prop(vec![0x0, 0xF, 0x5]),
                iommus: vec![0x40, 0xFFA, 0x50, 0xFFB],
            },
        ];

        for expected in expected_devices {
            let node = AssignedDeviceNode::parse(platform_dt, &expected.path);
            assert_eq!(node, Ok(expected));
        }
        let pviommus = collect_pviommus(platform_dt);
        assert_eq!(pviommus, Ok(vec![0x4, 0x40, 0x50]));
    }

    #[test]
    fn device_info_iommu_sharing() {
        let mut fdt_data = fs::read(FDT_WITH_IOMMU_SHARING).unwrap();
        let mut vm_dtbo_data = fs::read(VM_DTBO_FILE_PATH).unwrap();
        let fdt = Fdt::from_mut_slice(&mut fdt_data).unwrap();
        let vm_dtbo = VmDtbo::from_mut_slice(&mut vm_dtbo_data).unwrap();
        let mut platform_dt_data = pvmfw_fdt_template::RAW.to_vec();
        platform_dt_data.resize(pvmfw_fdt_template::RAW.len() * 2, 0);
        let platform_dt = Fdt::from_mut_slice(&mut platform_dt_data).unwrap();
        platform_dt.unpack().unwrap();

        let hypervisor = MockHypervisor {
            mmio_tokens: [((0x9, 0xFF), 0x12F00000), ((0x100, 0x9), 0x12000000)].into(),
            iommu_tokens: [((0x4, 0xFF0), (0x12E40000, 3))].into(),
        };
        let device_info = DeviceAssignmentInfo::parse(fdt, vm_dtbo, &hypervisor).unwrap().unwrap();
        device_info.filter(vm_dtbo).unwrap();

        // SAFETY: Damaged VM DTBO wouldn't be used after this unsafe block.
        unsafe {
            platform_dt.apply_overlay(vm_dtbo.as_mut()).unwrap();
        }
        device_info.patch(platform_dt).unwrap();

        let expected_devices = [
            AssignedDeviceNode {
                path: CString::new("/rng").unwrap(),
                reg: into_fdt_prop(vec![0x0, 0x9, 0x0, 0xFF]),
                interrupts: into_fdt_prop(vec![0x0, 0xF, 0x4]),
                iommus: vec![0x4, 0xFF0],
            },
            AssignedDeviceNode {
                path: CString::new("/led").unwrap(),
                reg: into_fdt_prop(vec![0x0, 0x100, 0x0, 0x9]),
                interrupts: into_fdt_prop(vec![0x0, 0xF, 0x5]),
                iommus: vec![0x4, 0xFF0],
            },
        ];

        for expected in expected_devices {
            let node = AssignedDeviceNode::parse(platform_dt, &expected.path);
            assert_eq!(node, Ok(expected));
        }

        let pviommus = collect_pviommus(platform_dt);
        assert_eq!(pviommus, Ok(vec![0x4]));
    }

    #[test]
    fn device_info_iommu_id_conflict() {
        let mut fdt_data = fs::read(FDT_WITH_IOMMU_ID_CONFLICT).unwrap();
        let mut vm_dtbo_data = fs::read(VM_DTBO_FILE_PATH).unwrap();
        let fdt = Fdt::from_mut_slice(&mut fdt_data).unwrap();
        let vm_dtbo = VmDtbo::from_mut_slice(&mut vm_dtbo_data).unwrap();

        let hypervisor = MockHypervisor {
            mmio_tokens: [((0x9, 0xFF), 0x12F00000)].into(),
            iommu_tokens: [((0x4, 0xFF0), (0x12E40000, 0x3))].into(),
        };
        let device_info = DeviceAssignmentInfo::parse(fdt, vm_dtbo, &hypervisor);

        assert_eq!(device_info, Err(DeviceAssignmentError::DuplicatedPvIommuIds));
    }

    #[test]
    fn device_info_invalid_reg() {
        let mut fdt_data = fs::read(FDT_FILE_PATH).unwrap();
        let mut vm_dtbo_data = fs::read(VM_DTBO_FILE_PATH).unwrap();
        let fdt = Fdt::from_mut_slice(&mut fdt_data).unwrap();
        let vm_dtbo = VmDtbo::from_mut_slice(&mut vm_dtbo_data).unwrap();

        let hypervisor = MockHypervisor {
            mmio_tokens: BTreeMap::new(),
            iommu_tokens: [((0x4, 0xFF0), (0x12E40000, 0x3))].into(),
        };
        let device_info = DeviceAssignmentInfo::parse(fdt, vm_dtbo, &hypervisor);

        assert_eq!(device_info, Err(DeviceAssignmentError::InvalidReg));
    }

    #[test]
    fn device_info_invalid_iommus() {
        let mut fdt_data = fs::read(FDT_FILE_PATH).unwrap();
        let mut vm_dtbo_data = fs::read(VM_DTBO_FILE_PATH).unwrap();
        let fdt = Fdt::from_mut_slice(&mut fdt_data).unwrap();
        let vm_dtbo = VmDtbo::from_mut_slice(&mut vm_dtbo_data).unwrap();

        let hypervisor = MockHypervisor {
            mmio_tokens: [((0x9, 0xFF), 0x12F00000)].into(),
            iommu_tokens: BTreeMap::new(),
        };
        let device_info = DeviceAssignmentInfo::parse(fdt, vm_dtbo, &hypervisor);

        assert_eq!(device_info, Err(DeviceAssignmentError::InvalidIommus));
    }
}
