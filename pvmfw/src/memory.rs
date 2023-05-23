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

#![deny(unsafe_op_in_unsafe_fn)]

use crate::helpers::{self, page_4kb_of, RangeExt, PVMFW_PAGE_SIZE, SIZE_4MB};
use crate::mmu;
use aarch64_paging::paging::{Attributes, Descriptor, MemoryRegion as VaRange};
use alloc::alloc::alloc_zeroed;
use alloc::alloc::dealloc;
use alloc::alloc::handle_alloc_error;
use alloc::boxed::Box;
use alloc::vec::Vec;
use buddy_system_allocator::{FrameAllocator, LockedFrameAllocator};
use core::alloc::Layout;
use core::cmp::max;
use core::cmp::min;
use core::fmt;
use core::num::NonZeroUsize;
use core::ops::Range;
use core::ptr::NonNull;
use core::result;
use hyp::get_hypervisor;
use log::error;
use log::trace;
use once_cell::race::OnceBox;
use spin::mutex::SpinMutex;
use tinyvec::ArrayVec;

/// Base of the system's contiguous "main" memory.
pub const BASE_ADDR: usize = 0x8000_0000;
/// First address that can't be translated by a level 1 TTBR0_EL1.
pub const MAX_ADDR: usize = 1 << 40;

pub type MemoryRange = Range<usize>;

pub static MEMORY: SpinMutex<Option<MemoryTracker>> = SpinMutex::new(None);
unsafe impl Send for MemoryTracker {}

#[derive(Clone, Copy, Debug, Default)]
enum MemoryType {
    #[default]
    ReadOnly,
    ReadWrite,
}

#[derive(Clone, Debug, Default)]
struct MemoryRegion {
    range: MemoryRange,
    mem_type: MemoryType,
}

impl MemoryRegion {
    /// True if the instance overlaps with the passed range.
    pub fn overlaps(&self, range: &MemoryRange) -> bool {
        overlaps(&self.range, range)
    }

    /// True if the instance is fully contained within the passed range.
    pub fn is_within(&self, range: &MemoryRange) -> bool {
        self.as_ref().is_within(range)
    }
}

impl AsRef<MemoryRange> for MemoryRegion {
    fn as_ref(&self) -> &MemoryRange {
        &self.range
    }
}

/// Returns true if one range overlaps with the other at all.
fn overlaps<T: Copy + Ord>(a: &Range<T>, b: &Range<T>) -> bool {
    max(a.start, b.start) < min(a.end, b.end)
}

/// Tracks non-overlapping slices of main memory.
pub struct MemoryTracker {
    total: MemoryRange,
    page_table: mmu::PageTable,
    regions: ArrayVec<[MemoryRegion; MemoryTracker::CAPACITY]>,
    mmio_regions: ArrayVec<[MemoryRange; MemoryTracker::MMIO_CAPACITY]>,
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
    /// Region couldn't be unmapped.
    FailedToUnmap,
    /// Error from the interaction with the hypervisor.
    Hypervisor(hyp::Error),
    /// Failure to set `SHARED_MEMORY`.
    SharedMemorySetFailure,
    /// Failure to set `SHARED_POOL`.
    SharedPoolSetFailure,
    /// Invalid page table entry.
    InvalidPte,
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
            Self::FailedToUnmap => write!(f, "Failed to unmap the new region"),
            Self::Hypervisor(e) => e.fmt(f),
            Self::SharedMemorySetFailure => write!(f, "Failed to set SHARED_MEMORY"),
            Self::SharedPoolSetFailure => write!(f, "Failed to set SHARED_POOL"),
            Self::InvalidPte => write!(f, "Page table entry is not valid"),
        }
    }
}

impl From<hyp::Error> for MemoryTrackerError {
    fn from(e: hyp::Error) -> Self {
        Self::Hypervisor(e)
    }
}

type Result<T> = result::Result<T, MemoryTrackerError>;

static SHARED_POOL: OnceBox<LockedFrameAllocator<32>> = OnceBox::new();
static SHARED_MEMORY: SpinMutex<Option<MemorySharer>> = SpinMutex::new(None);

/// Allocates memory on the heap and shares it with the host.
///
/// Unshares all pages when dropped.
pub struct MemorySharer {
    granule: usize,
    shared_regions: Vec<(usize, Layout)>,
}

impl MemorySharer {
    const INIT_CAP: usize = 10;

    pub fn new(granule: usize) -> Self {
        assert!(granule.is_power_of_two());
        Self { granule, shared_regions: Vec::with_capacity(Self::INIT_CAP) }
    }

    /// Get from the global allocator a granule-aligned region that suits `hint` and share it.
    pub fn refill(&mut self, pool: &mut FrameAllocator<32>, hint: Layout) {
        let layout = hint.align_to(self.granule).unwrap().pad_to_align();
        assert_ne!(layout.size(), 0);
        // SAFETY - layout has non-zero size.
        let Some(shared) = NonNull::new(unsafe { alloc_zeroed(layout) }) else {
            handle_alloc_error(layout);
        };

        let base = shared.as_ptr() as usize;
        let end = base.checked_add(layout.size()).unwrap();
        trace!("Sharing memory region {:#x?}", base..end);
        for vaddr in (base..end).step_by(self.granule) {
            let vaddr = NonNull::new(vaddr as *mut _).unwrap();
            get_hypervisor().mem_share(virt_to_phys(vaddr).try_into().unwrap()).unwrap();
        }
        self.shared_regions.push((base, layout));

        pool.add_frame(base, end);
    }
}

impl Drop for MemorySharer {
    fn drop(&mut self) {
        while let Some((base, layout)) = self.shared_regions.pop() {
            let end = base.checked_add(layout.size()).unwrap();
            trace!("Unsharing memory region {:#x?}", base..end);
            for vaddr in (base..end).step_by(self.granule) {
                let vaddr = NonNull::new(vaddr as *mut _).unwrap();
                get_hypervisor().mem_unshare(virt_to_phys(vaddr).try_into().unwrap()).unwrap();
            }

            // SAFETY - The region was obtained from alloc_zeroed() with the recorded layout.
            unsafe { dealloc(base as *mut _, layout) };
        }
    }
}

impl MemoryTracker {
    const CAPACITY: usize = 5;
    const MMIO_CAPACITY: usize = 5;
    const PVMFW_RANGE: MemoryRange = (BASE_ADDR - SIZE_4MB)..BASE_ADDR;

    /// Create a new instance from an active page table, covering the maximum RAM size.
    pub fn new(page_table: mmu::PageTable) -> Self {
        Self {
            total: BASE_ADDR..MAX_ADDR,
            page_table,
            regions: ArrayVec::new(),
            mmio_regions: ArrayVec::new(),
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
        if !self.regions.iter().all(|r| r.is_within(range)) {
            return Err(MemoryTrackerError::SizeTooSmall);
        }

        self.total = range.clone();
        Ok(())
    }

    /// Allocate the address range for a const slice; returns None if failed.
    pub fn alloc_range(&mut self, range: &MemoryRange) -> Result<MemoryRange> {
        let region = MemoryRegion { range: range.clone(), mem_type: MemoryType::ReadOnly };
        self.check(&region)?;
        self.page_table.map_rodata(range).map_err(|e| {
            error!("Error during range allocation: {e}");
            MemoryTrackerError::FailedToMap
        })?;
        self.add(region)
    }

    /// Allocate the address range for a mutable slice; returns None if failed.
    pub fn alloc_range_mut(&mut self, range: &MemoryRange) -> Result<MemoryRange> {
        let region = MemoryRegion { range: range.clone(), mem_type: MemoryType::ReadWrite };
        self.check(&region)?;
        self.page_table.map_data(range).map_err(|e| {
            error!("Error during mutable range allocation: {e}");
            MemoryTrackerError::FailedToMap
        })?;
        self.add(region)
    }

    /// Allocate the address range for a const slice; returns None if failed.
    pub fn alloc(&mut self, base: usize, size: NonZeroUsize) -> Result<MemoryRange> {
        self.alloc_range(&(base..(base + size.get())))
    }

    /// Allocate the address range for a mutable slice; returns None if failed.
    pub fn alloc_mut(&mut self, base: usize, size: NonZeroUsize) -> Result<MemoryRange> {
        self.alloc_range_mut(&(base..(base + size.get())))
    }

    /// Checks that the given range of addresses is within the MMIO region, and then maps it
    /// appropriately.
    pub fn map_mmio_range(&mut self, range: MemoryRange) -> Result<()> {
        // MMIO space is below the main memory region.
        if range.end > self.total.start || overlaps(&Self::PVMFW_RANGE, &range) {
            return Err(MemoryTrackerError::OutOfRange);
        }
        if self.mmio_regions.iter().any(|r| overlaps(r, &range)) {
            return Err(MemoryTrackerError::Overlaps);
        }
        if self.mmio_regions.len() == self.mmio_regions.capacity() {
            return Err(MemoryTrackerError::Full);
        }

        self.page_table.map_device_lazy(&range).map_err(|e| {
            error!("Error during MMIO device mapping: {e}");
            MemoryTrackerError::FailedToMap
        })?;

        if self.mmio_regions.try_push(range).is_some() {
            return Err(MemoryTrackerError::Full);
        }

        Ok(())
    }

    /// Checks that the given region is within the range of the `MemoryTracker` and doesn't overlap
    /// with any other previously allocated regions, and that the regions ArrayVec has capacity to
    /// add it.
    fn check(&self, region: &MemoryRegion) -> Result<()> {
        if !region.is_within(&self.total) {
            return Err(MemoryTrackerError::OutOfRange);
        }
        if self.regions.iter().any(|r| r.overlaps(&region.range)) {
            return Err(MemoryTrackerError::Overlaps);
        }
        if self.regions.len() == self.regions.capacity() {
            return Err(MemoryTrackerError::Full);
        }
        Ok(())
    }

    fn add(&mut self, region: MemoryRegion) -> Result<MemoryRange> {
        if self.regions.try_push(region).is_some() {
            return Err(MemoryTrackerError::Full);
        }

        Ok(self.regions.last().unwrap().as_ref().clone())
    }

    /// Unmaps all tracked MMIO regions from the MMIO guard.
    ///
    /// Note that they are not unmapped from the page table.
    pub fn mmio_unmap_all(&mut self) -> Result<()> {
        for range in &self.mmio_regions {
            self.page_table
                .modify_range(range, &mmio_guard_unmap_page)
                .map_err(|_| MemoryTrackerError::FailedToUnmap)?;
        }
        Ok(())
    }

    /// Initialize the shared heap to dynamically share memory from the global allocator.
    pub fn init_dynamic_shared_pool(&mut self) -> Result<()> {
        let granule = get_hypervisor().memory_protection_granule()?;
        let previous = SHARED_MEMORY.lock().replace(MemorySharer::new(granule));
        if previous.is_some() {
            return Err(MemoryTrackerError::SharedMemorySetFailure);
        }

        SHARED_POOL
            .set(Box::new(LockedFrameAllocator::new()))
            .map_err(|_| MemoryTrackerError::SharedPoolSetFailure)?;

        Ok(())
    }

    /// Initialize the shared heap from a static region of memory.
    ///
    /// Some hypervisors such as Gunyah do not support a MemShare API for guest
    /// to share its memory with host. Instead they allow host to designate part
    /// of guest memory as "shared" ahead of guest starting its execution. The
    /// shared memory region is indicated in swiotlb node. On such platforms use
    /// a separate heap to allocate buffers that can be shared with host.
    pub fn init_static_shared_pool(&mut self, range: Range<usize>) -> Result<()> {
        let size = NonZeroUsize::new(range.len()).unwrap();
        let range = self.alloc_mut(range.start, size)?;
        let shared_pool = LockedFrameAllocator::<32>::new();

        shared_pool.lock().insert(range);

        SHARED_POOL
            .set(Box::new(shared_pool))
            .map_err(|_| MemoryTrackerError::SharedPoolSetFailure)?;

        Ok(())
    }

    /// Unshares any memory that may have been shared.
    pub fn unshare_all_memory(&mut self) {
        drop(SHARED_MEMORY.lock().take());
    }

    /// Handles translation fault for blocks flagged for lazy MMIO mapping by enabling the page
    /// table entry and MMIO guard mapping the block. Breaks apart a block entry if required.
    pub fn handle_mmio_fault(&mut self, addr: usize) -> Result<()> {
        let page_range = page_4kb_of(addr)..page_4kb_of(addr) + PVMFW_PAGE_SIZE;
        self.page_table
            .modify_range(&page_range, &verify_lazy_mapped_block)
            .map_err(|_| MemoryTrackerError::InvalidPte)?;
        get_hypervisor().mmio_guard_map(page_range.start)?;
        // Maps a single device page, breaking up block mappings if necessary.
        self.page_table.map_device(&page_range).map_err(|_| MemoryTrackerError::FailedToMap)
    }
}

impl Drop for MemoryTracker {
    fn drop(&mut self) {
        for region in &self.regions {
            match region.mem_type {
                MemoryType::ReadWrite => {
                    // TODO(b/269738062): Use PT's dirty bit to only flush pages that were touched.
                    helpers::flush_region(region.range.start, region.range.len())
                }
                MemoryType::ReadOnly => {}
            }
        }
        self.unshare_all_memory()
    }
}

/// Allocates a memory range of at least the given size and alignment that is shared with the host.
/// Returns a pointer to the buffer.
pub fn alloc_shared(layout: Layout) -> hyp::Result<NonNull<u8>> {
    assert_ne!(layout.size(), 0);
    let Some(buffer) = try_shared_alloc(layout) else {
        handle_alloc_error(layout);
    };

    trace!("Allocated shared buffer at {buffer:?} with {layout:?}");
    Ok(buffer)
}

fn try_shared_alloc(layout: Layout) -> Option<NonNull<u8>> {
    let mut shared_pool = SHARED_POOL.get().unwrap().lock();

    if let Some(buffer) = shared_pool.alloc_aligned(layout) {
        Some(NonNull::new(buffer as _).unwrap())
    } else if let Some(shared_memory) = SHARED_MEMORY.lock().as_mut() {
        shared_memory.refill(&mut shared_pool, layout);
        shared_pool.alloc_aligned(layout).map(|buffer| NonNull::new(buffer as _).unwrap())
    } else {
        None
    }
}

/// Unshares and deallocates a memory range which was previously allocated by `alloc_shared`.
///
/// The layout passed in must be the same layout passed to the original `alloc_shared` call.
///
/// # Safety
///
/// The memory must have been allocated by `alloc_shared` with the same layout, and not yet
/// deallocated.
pub unsafe fn dealloc_shared(vaddr: NonNull<u8>, layout: Layout) -> hyp::Result<()> {
    SHARED_POOL.get().unwrap().lock().dealloc_aligned(vaddr.as_ptr() as usize, layout);

    trace!("Deallocated shared buffer at {vaddr:?} with {layout:?}");
    Ok(())
}

/// Returns the intermediate physical address corresponding to the given virtual address.
///
/// As we use identity mapping for everything, this is just a cast, but it's useful to use it to be
/// explicit about where we are converting from virtual to physical address.
pub fn virt_to_phys(vaddr: NonNull<u8>) -> usize {
    vaddr.as_ptr() as _
}

/// Returns a pointer for the virtual address corresponding to the given non-zero intermediate
/// physical address.
///
/// Panics if `paddr` is 0.
pub fn phys_to_virt(paddr: usize) -> NonNull<u8> {
    NonNull::new(paddr as _).unwrap()
}

/// Checks whether a PTE at given level is a page or block descriptor.
#[inline]
fn is_leaf_pte(flags: &Attributes, level: usize) -> bool {
    const LEAF_PTE_LEVEL: usize = 3;
    if flags.contains(Attributes::TABLE_OR_PAGE) {
        level == LEAF_PTE_LEVEL
    } else {
        level < LEAF_PTE_LEVEL
    }
}

/// Checks whether block flags indicate it should be MMIO guard mapped.
fn verify_lazy_mapped_block(
    _range: &VaRange,
    desc: &mut Descriptor,
    level: usize,
) -> result::Result<(), ()> {
    let flags = desc.flags().expect("Unsupported PTE flags set");
    if !is_leaf_pte(&flags, level) {
        return Ok(()); // Skip table PTEs as they aren't tagged with MMIO_LAZY_MAP_FLAG.
    }
    if flags.contains(mmu::MMIO_LAZY_MAP_FLAG) && !flags.contains(Attributes::VALID) {
        Ok(())
    } else {
        Err(())
    }
}

/// MMIO guard unmaps page
fn mmio_guard_unmap_page(
    va_range: &VaRange,
    desc: &mut Descriptor,
    level: usize,
) -> result::Result<(), ()> {
    let flags = desc.flags().expect("Unsupported PTE flags set");
    // This function will be called on an address range that corresponds to a device. Only if a
    // page has been accessed (written to or read from), will it contain the VALID flag and be MMIO
    // guard mapped. Therefore, we can skip unmapping invalid pages, they were never MMIO guard
    // mapped anyway.
    if is_leaf_pte(&flags, level) && flags.contains(Attributes::VALID) {
        assert!(
            flags.contains(mmu::MMIO_LAZY_MAP_FLAG),
            "Attempting MMIO guard unmap for non-device pages"
        );
        assert_eq!(
            va_range.len(),
            PVMFW_PAGE_SIZE,
            "Failed to break down block mapping before MMIO guard mapping"
        );
        let page_base = va_range.start().0;
        assert_eq!(page_base % PVMFW_PAGE_SIZE, 0);
        // Since mmio_guard_map takes IPAs, if pvmfw moves non-ID address mapping, page_base
        // should be converted to IPA. However, since 0x0 is a valid MMIO address, we don't use
        // virt_to_phys here, and just pass page_base instead.
        get_hypervisor().mmio_guard_unmap(page_base).map_err(|e| {
            error!("Error MMIO guard unmapping: {e}");
        })?;
    }
    Ok(())
}
