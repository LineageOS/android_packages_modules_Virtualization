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

//! Page table management.

use aarch64_paging::idmap::IdMap;
use aarch64_paging::paging::{Attributes, MemoryRegion, PteUpdater};
use aarch64_paging::MapError;
use core::{ops::Range, result};

/// Software bit used to indicate a device that should be lazily mapped.
pub const MMIO_LAZY_MAP_FLAG: Attributes = Attributes::SWFLAG_0;

// We assume that:
// - MAIR_EL1.Attr0 = "Device-nGnRE memory" (0b0000_0100)
// - MAIR_EL1.Attr1 = "Normal memory, Outer & Inner WB Non-transient, R/W-Allocate" (0b1111_1111)
const MEMORY: Attributes =
    Attributes::VALID.union(Attributes::NORMAL).union(Attributes::NON_GLOBAL);
const DEVICE_LAZY: Attributes =
    MMIO_LAZY_MAP_FLAG.union(Attributes::DEVICE_NGNRE).union(Attributes::EXECUTE_NEVER);
const DEVICE: Attributes = DEVICE_LAZY.union(Attributes::VALID);
const CODE: Attributes = MEMORY.union(Attributes::READ_ONLY);
const DATA: Attributes = MEMORY.union(Attributes::EXECUTE_NEVER);
const RODATA: Attributes = DATA.union(Attributes::READ_ONLY);
const DATA_DBM: Attributes = RODATA.union(Attributes::DBM);

type Result<T> = result::Result<T, MapError>;

/// High-level API for managing MMU mappings.
pub struct PageTable {
    idmap: IdMap,
}

impl From<IdMap> for PageTable {
    fn from(idmap: IdMap) -> Self {
        Self { idmap }
    }
}

impl PageTable {
    /// Activates the page table.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the PageTable instance has valid and identical mappings for the
    /// code being currently executed. Otherwise, the Rust execution model (on which the borrow
    /// checker relies) would be violated.
    pub unsafe fn activate(&mut self) {
        self.idmap.activate()
    }

    /// Maps the given range of virtual addresses to the physical addresses as lazily mapped
    /// nGnRE device memory.
    pub fn map_device_lazy(&mut self, range: &Range<usize>) -> Result<()> {
        self.map_range(range, DEVICE_LAZY)
    }

    /// Maps the given range of virtual addresses to the physical addresses as valid device
    /// nGnRE device memory.
    pub fn map_device(&mut self, range: &Range<usize>) -> Result<()> {
        self.map_range(range, DEVICE)
    }

    /// Maps the given range of virtual addresses to the physical addresses as non-executable
    /// and writable normal memory.
    pub fn map_data(&mut self, range: &Range<usize>) -> Result<()> {
        self.map_range(range, DATA)
    }

    /// Maps the given range of virtual addresses to the physical addresses as non-executable,
    /// read-only and writable-clean normal memory.
    pub fn map_data_dbm(&mut self, range: &Range<usize>) -> Result<()> {
        self.map_range(range, DATA_DBM)
    }

    /// Maps the given range of virtual addresses to the physical addresses as read-only
    /// normal memory.
    pub fn map_code(&mut self, range: &Range<usize>) -> Result<()> {
        self.map_range(range, CODE)
    }

    /// Maps the given range of virtual addresses to the physical addresses as non-executable
    /// and read-only normal memory.
    pub fn map_rodata(&mut self, range: &Range<usize>) -> Result<()> {
        self.map_range(range, RODATA)
    }

    /// Maps the given range of virtual addresses to the physical addresses with the given
    /// attributes.
    fn map_range(&mut self, range: &Range<usize>, attr: Attributes) -> Result<()> {
        self.idmap.map_range(&MemoryRegion::new(range.start, range.end), attr)
    }

    /// Applies the provided updater function to a number of PTEs corresponding to a given memory
    /// range.
    pub fn modify_range(&mut self, range: &Range<usize>, f: &PteUpdater) -> Result<()> {
        self.idmap.modify_range(&MemoryRegion::new(range.start, range.end), f)
    }
}
