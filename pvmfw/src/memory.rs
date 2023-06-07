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

use crate::helpers::PVMFW_PAGE_SIZE;
use aarch64_paging::idmap::IdMap;
use aarch64_paging::paging::{Attributes, Descriptor, MemoryRegion as VaRange};
use aarch64_paging::MapError;
use alloc::alloc::handle_alloc_error;
use alloc::boxed::Box;
use buddy_system_allocator::LockedFrameAllocator;
use core::alloc::Layout;
use core::fmt;
use core::iter::once;
use core::num::NonZeroUsize;
use core::ops::Range;
use core::ptr::NonNull;
use core::result;
use hyp::get_hypervisor;
use log::trace;
use log::{debug, error};
use once_cell::race::OnceBox;
use spin::mutex::SpinMutex;
use tinyvec::ArrayVec;
use vmbase::{
    dsb, isb, layout,
    memory::{
        flush_dirty_range, is_leaf_pte, page_4kb_of, set_dbm_enabled, MemorySharer, PageTable,
        MMIO_LAZY_MAP_FLAG, SIZE_2MB, SIZE_4KB,
    },
    tlbi,
    util::{align_up, RangeExt as _},
};

/// First address that can't be translated by a level 1 TTBR0_EL1.
pub const MAX_ADDR: usize = 1 << 40;

const PT_ROOT_LEVEL: usize = 1;
const PT_ASID: usize = 1;

pub type MemoryRange = Range<usize>;

pub static MEMORY: SpinMutex<Option<MemoryTracker>> = SpinMutex::new(None);
unsafe impl Send for MemoryTracker {}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
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

/// Tracks non-overlapping slices of main memory.
pub struct MemoryTracker {
    total: MemoryRange,
    page_table: PageTable,
    regions: ArrayVec<[MemoryRegion; MemoryTracker::CAPACITY]>,
    mmio_regions: ArrayVec<[MemoryRange; MemoryTracker::MMIO_CAPACITY]>,
    mmio_range: MemoryRange,
    payload_range: MemoryRange,
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
    /// Failed to flush memory region.
    FlushRegionFailed,
    /// Failed to set PTE dirty state.
    SetPteDirtyFailed,
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
            Self::FlushRegionFailed => write!(f, "Failed to flush memory region"),
            Self::SetPteDirtyFailed => write!(f, "Failed to set PTE dirty state"),
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

impl MemoryTracker {
    const CAPACITY: usize = 5;
    const MMIO_CAPACITY: usize = 5;

    /// Create a new instance from an active page table, covering the maximum RAM size.
    pub fn new(
        mut page_table: PageTable,
        total: MemoryRange,
        mmio_range: MemoryRange,
        payload_range: MemoryRange,
    ) -> Self {
        assert!(
            !total.overlaps(&mmio_range),
            "MMIO space should not overlap with the main memory region."
        );

        // Activate dirty state management first, otherwise we may get permission faults immediately
        // after activating the new page table. This has no effect before the new page table is
        // activated because none of the entries in the initial idmap have the DBM flag.
        set_dbm_enabled(true);

        debug!("Activating dynamic page table...");
        // SAFETY - page_table duplicates the static mappings for everything that the Rust code is
        // aware of so activating it shouldn't have any visible effect.
        unsafe { page_table.activate() }
        debug!("... Success!");

        Self {
            total,
            page_table,
            regions: ArrayVec::new(),
            mmio_regions: ArrayVec::new(),
            mmio_range,
            payload_range,
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
        if !self.regions.iter().all(|r| r.range.is_within(range)) {
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
        self.page_table.map_data_dbm(range).map_err(|e| {
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
        if !range.is_within(&self.mmio_range) {
            return Err(MemoryTrackerError::OutOfRange);
        }
        if self.mmio_regions.iter().any(|r| range.overlaps(r)) {
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
        if !region.range.is_within(&self.total) {
            return Err(MemoryTrackerError::OutOfRange);
        }
        if self.regions.iter().any(|r| region.range.overlaps(&r.range)) {
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

        Ok(self.regions.last().unwrap().range.clone())
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
        const INIT_CAP: usize = 10;

        let granule = get_hypervisor().memory_protection_granule()?;
        let previous = SHARED_MEMORY.lock().replace(MemorySharer::new(granule, INIT_CAP));
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

    /// Flush all memory regions marked as writable-dirty.
    fn flush_dirty_pages(&mut self) -> Result<()> {
        // Collect memory ranges for which dirty state is tracked.
        let writable_regions =
            self.regions.iter().filter(|r| r.mem_type == MemoryType::ReadWrite).map(|r| &r.range);
        // Execute a barrier instruction to ensure all hardware updates to the page table have been
        // observed before reading PTE flags to determine dirty state.
        dsb!("ish");
        // Now flush writable-dirty pages in those regions.
        for range in writable_regions.chain(once(&self.payload_range)) {
            self.page_table
                .modify_range(range, &flush_dirty_range)
                .map_err(|_| MemoryTrackerError::FlushRegionFailed)?;
        }
        Ok(())
    }

    /// Handles permission fault for read-only blocks by setting writable-dirty state.
    /// In general, this should be called from the exception handler when hardware dirty
    /// state management is disabled or unavailable.
    pub fn handle_permission_fault(&mut self, addr: usize) -> Result<()> {
        self.page_table
            .modify_range(&(addr..addr + 1), &mark_dirty_block)
            .map_err(|_| MemoryTrackerError::SetPteDirtyFailed)
    }
}

impl Drop for MemoryTracker {
    fn drop(&mut self) {
        set_dbm_enabled(false);
        self.flush_dirty_pages().unwrap();
        self.unshare_all_memory();
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
    if flags.contains(MMIO_LAZY_MAP_FLAG) && !flags.contains(Attributes::VALID) {
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
    if !is_leaf_pte(&flags, level) {
        return Ok(());
    }
    // This function will be called on an address range that corresponds to a device. Only if a
    // page has been accessed (written to or read from), will it contain the VALID flag and be MMIO
    // guard mapped. Therefore, we can skip unmapping invalid pages, they were never MMIO guard
    // mapped anyway.
    if flags.contains(Attributes::VALID) {
        assert!(
            flags.contains(MMIO_LAZY_MAP_FLAG),
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

/// Clears read-only flag on a PTE, making it writable-dirty. Used when dirty state is managed
/// in software to handle permission faults on read-only descriptors.
fn mark_dirty_block(
    va_range: &VaRange,
    desc: &mut Descriptor,
    level: usize,
) -> result::Result<(), ()> {
    let flags = desc.flags().ok_or(())?;
    if !is_leaf_pte(&flags, level) {
        return Ok(());
    }
    if flags.contains(Attributes::DBM) {
        assert!(flags.contains(Attributes::READ_ONLY), "unexpected PTE writable state");
        desc.modify_flags(Attributes::empty(), Attributes::READ_ONLY);
        // Updating the read-only bit of a PTE requires TLB invalidation.
        // A TLB maintenance instruction is only guaranteed to be complete after a DSB instruction.
        // An ISB instruction is required to ensure the effects of completed TLB maintenance
        // instructions are visible to instructions fetched afterwards.
        // See ARM ARM E2.3.10, and G5.9.
        tlbi!("vale1", PT_ASID, va_range.start().0);
        dsb!("ish");
        isb!();
        Ok(())
    } else {
        Err(())
    }
}

/// Returns memory range reserved for the appended payload.
pub fn appended_payload_range() -> MemoryRange {
    let start = align_up(layout::binary_end(), SIZE_4KB).unwrap();
    // pvmfw is contained in a 2MiB region so the payload can't be larger than the 2MiB alignment.
    let end = align_up(start, SIZE_2MB).unwrap();
    start..end
}

/// Region allocated for the stack.
pub fn stack_range() -> MemoryRange {
    const STACK_PAGES: usize = 8;

    layout::stack_range(STACK_PAGES * PVMFW_PAGE_SIZE)
}

pub fn init_page_table() -> result::Result<PageTable, MapError> {
    let mut page_table: PageTable = IdMap::new(PT_ASID, PT_ROOT_LEVEL).into();

    // Stack and scratch ranges are explicitly zeroed and flushed before jumping to payload,
    // so dirty state management can be omitted.
    page_table.map_data(&layout::scratch_range())?;
    page_table.map_data(&stack_range())?;
    page_table.map_code(&layout::text_range())?;
    page_table.map_rodata(&layout::rodata_range())?;
    page_table.map_data_dbm(&appended_payload_range())?;
    if let Err(e) = page_table.map_device(&layout::console_uart_range()) {
        error!("Failed to remap the UART as a dynamic page table entry: {e}");
        return Err(e);
    }
    Ok(page_table)
}
