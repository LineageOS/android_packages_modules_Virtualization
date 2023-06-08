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

//! Shared memory management.

use super::page_table::{is_leaf_pte, MMIO_LAZY_MAP_FLAG};
use super::util::{virt_to_phys, PAGE_SIZE};
use aarch64_paging::paging::{Attributes, Descriptor, MemoryRegion as VaRange};
use alloc::alloc::{alloc_zeroed, dealloc, handle_alloc_error};
use alloc::vec::Vec;
use buddy_system_allocator::FrameAllocator;
use core::alloc::Layout;
use core::ptr::NonNull;
use core::result;
use hyp::get_hypervisor;
use log::{error, trace};

/// Allocates memory on the heap and shares it with the host.
///
/// Unshares all pages when dropped.
pub struct MemorySharer {
    granule: usize,
    shared_regions: Vec<(usize, Layout)>,
}

impl MemorySharer {
    /// Constructs a new `MemorySharer` instance with the specified granule size and capacity.
    /// `granule` must be a power of 2.
    pub fn new(granule: usize, capacity: usize) -> Self {
        assert!(granule.is_power_of_two());
        Self { granule, shared_regions: Vec::with_capacity(capacity) }
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

/// Checks whether block flags indicate it should be MMIO guard mapped.
/// As the return type is required by the crate `aarch64_paging`, we cannot address the lint
/// issue `clippy::result_unit_err`.
#[allow(clippy::result_unit_err)]
pub fn verify_lazy_mapped_block(
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
/// As the return type is required by the crate `aarch64_paging`, we cannot address the lint
/// issue `clippy::result_unit_err`.
#[allow(clippy::result_unit_err)]
pub fn mmio_guard_unmap_page(
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
            PAGE_SIZE,
            "Failed to break down block mapping before MMIO guard mapping"
        );
        let page_base = va_range.start().0;
        assert_eq!(page_base % PAGE_SIZE, 0);
        // Since mmio_guard_map takes IPAs, if pvmfw moves non-ID address mapping, page_base
        // should be converted to IPA. However, since 0x0 is a valid MMIO address, we don't use
        // virt_to_phys here, and just pass page_base instead.
        get_hypervisor().mmio_guard_unmap(page_base).map_err(|e| {
            error!("Error MMIO guard unmapping: {e}");
        })?;
    }
    Ok(())
}
