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

use super::util::virt_to_phys;
use alloc::alloc::{alloc_zeroed, dealloc, handle_alloc_error};
use alloc::vec::Vec;
use buddy_system_allocator::FrameAllocator;
use core::alloc::Layout;
use core::ptr::NonNull;
use hyp::get_hypervisor;
use log::trace;

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
