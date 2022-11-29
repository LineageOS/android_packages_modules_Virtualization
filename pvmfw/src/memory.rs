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

//! Low-level allocation and tracking of main memory.

use crate::helpers;
use crate::mmu;
use core::cmp::max;
use core::cmp::min;
use core::fmt;
use core::mem;
use core::mem::MaybeUninit;
use core::num::NonZeroUsize;
use core::ops::Range;
use core::result;
use log::error;

type MemoryRange = Range<usize>;

#[derive(Clone, Copy, Debug)]
enum MemoryType {
    ReadOnly,
    ReadWrite,
}

#[derive(Clone, Debug)]
struct MemoryRegion {
    range: MemoryRange,
    mem_type: MemoryType,
}

impl MemoryRegion {
    /// True if the instance overlaps with the passed range.
    pub fn overlaps(&self, range: &MemoryRange) -> bool {
        let our: &MemoryRange = self.as_ref();
        max(our.start, range.start) < min(our.end, range.end)
    }

    /// True if the instance is fully contained within the passed range.
    pub fn is_within(&self, range: &MemoryRange) -> bool {
        let our: &MemoryRange = self.as_ref();
        self.as_ref() == &(max(our.start, range.start)..min(our.end, range.end))
    }
}

impl AsRef<MemoryRange> for MemoryRegion {
    fn as_ref(&self) -> &MemoryRange {
        &self.range
    }
}

/// Tracks non-overlapping slices of main memory.
pub struct MemoryTracker {
    // TODO: Use tinyvec::ArrayVec
    count: usize,
    regions: [MaybeUninit<MemoryRegion>; MemoryTracker::CAPACITY],
    total: MemoryRange,
    page_table: mmu::PageTable,
}

/// Errors for MemoryTracker operations.
#[derive(Debug, Clone)]
pub enum MemoryTrackerError {
    /// Tried to modify the memory base address.
    DifferentBaseAddress,
    /// Tried to shrink to a larger memory size.
    SizeTooLarge,
    /// Tracked regions would not fit in memory size.
    SizeTooSmall,
    /// Reached limit number of tracked regions.
    Full,
    /// Region is out of the tracked memory address space.
    OutOfRange,
    /// New region overlaps with tracked regions.
    Overlaps,
    /// Region couldn't be mapped.
    FailedToMap,
}

impl fmt::Display for MemoryTrackerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::DifferentBaseAddress => write!(f, "Received different base address"),
            Self::SizeTooLarge => write!(f, "Tried to shrink to a larger memory size"),
            Self::SizeTooSmall => write!(f, "Tracked regions would not fit in memory size"),
            Self::Full => write!(f, "Reached limit number of tracked regions"),
            Self::OutOfRange => write!(f, "Region is out of the tracked memory address space"),
            Self::Overlaps => write!(f, "New region overlaps with tracked regions"),
            Self::FailedToMap => write!(f, "Failed to map the new region"),
        }
    }
}

type Result<T> = result::Result<T, MemoryTrackerError>;

impl MemoryTracker {
    const CAPACITY: usize = 5;
    /// Base of the system's contiguous "main" memory.
    const BASE: usize = 0x8000_0000;
    /// First address that can't be translated by a level 1 TTBR0_EL1.
    const MAX_ADDR: usize = 1 << 39;

    /// Create a new instance from an active page table, covering the maximum RAM size.
    pub fn new(page_table: mmu::PageTable) -> Self {
        Self {
            total: Self::BASE..Self::MAX_ADDR,
            count: 0,
            page_table,
            // SAFETY - MaybeUninit items (of regions) do not require initialization.
            regions: unsafe { MaybeUninit::uninit().assume_init() },
        }
    }

    /// Resize the total RAM size.
    ///
    /// This function fails if it contains regions that are not included within the new size.
    pub fn shrink(&mut self, range: &MemoryRange) -> Result<()> {
        if range.start != self.total.start {
            return Err(MemoryTrackerError::DifferentBaseAddress);
        }
        if self.total.end < range.end {
            return Err(MemoryTrackerError::SizeTooLarge);
        }
        if !self.regions().iter().all(|r| r.is_within(range)) {
            return Err(MemoryTrackerError::SizeTooSmall);
        }

        self.total = range.clone();
        Ok(())
    }

    /// Allocate the address range for a const slice; returns None if failed.
    pub fn alloc_range(&mut self, range: &MemoryRange) -> Result<MemoryRange> {
        self.page_table.map_rodata(range).map_err(|e| {
            error!("Error during range allocation: {e}");
            MemoryTrackerError::FailedToMap
        })?;
        self.add(MemoryRegion { range: range.clone(), mem_type: MemoryType::ReadOnly })
    }

    /// Allocate the address range for a mutable slice; returns None if failed.
    pub fn alloc_range_mut(&mut self, range: &MemoryRange) -> Result<MemoryRange> {
        self.page_table.map_data(range).map_err(|e| {
            error!("Error during mutable range allocation: {e}");
            MemoryTrackerError::FailedToMap
        })?;
        self.add(MemoryRegion { range: range.clone(), mem_type: MemoryType::ReadWrite })
    }

    /// Allocate the address range for a const slice; returns None if failed.
    pub fn alloc(&mut self, base: usize, size: NonZeroUsize) -> Result<MemoryRange> {
        self.alloc_range(&(base..(base + size.get())))
    }

    /// Allocate the address range for a mutable slice; returns None if failed.
    pub fn alloc_mut(&mut self, base: usize, size: NonZeroUsize) -> Result<MemoryRange> {
        self.alloc_range_mut(&(base..(base + size.get())))
    }

    fn regions(&self) -> &[MemoryRegion] {
        // SAFETY - The first self.count regions have been properly initialized.
        unsafe { mem::transmute::<_, &[MemoryRegion]>(&self.regions[..self.count]) }
    }

    fn add(&mut self, region: MemoryRegion) -> Result<MemoryRange> {
        if !region.is_within(&self.total) {
            return Err(MemoryTrackerError::OutOfRange);
        }
        if self.regions().iter().any(|r| r.overlaps(region.as_ref())) {
            return Err(MemoryTrackerError::Overlaps);
        }
        if self.regions.len() == self.count {
            return Err(MemoryTrackerError::Full);
        }

        let region = self.regions[self.count].write(region);
        self.count += 1;
        Ok(region.as_ref().clone())
    }
}

impl Drop for MemoryTracker {
    fn drop(&mut self) {
        for region in self.regions().iter() {
            match region.mem_type {
                MemoryType::ReadWrite => {
                    // TODO: Use page table's dirty bit to only flush pages that were touched.
                    helpers::flush_region(region.range.start, region.range.len())
                }
                MemoryType::ReadOnly => {}
            }
        }
    }
}
