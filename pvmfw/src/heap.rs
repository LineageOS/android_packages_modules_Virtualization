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

//! Heap implementation.

use alloc::alloc::alloc;
use alloc::alloc::Layout;
use alloc::boxed::Box;

use core::alloc::GlobalAlloc as _;
use core::ffi::c_void;
use core::mem;
use core::num::NonZeroUsize;
use core::ptr;
use core::ptr::NonNull;

use buddy_system_allocator::LockedHeap;

#[global_allocator]
static HEAP_ALLOCATOR: LockedHeap<32> = LockedHeap::<32>::new();

static mut HEAP: [u8; 65536] = [0; 65536];

pub unsafe fn init() {
    HEAP_ALLOCATOR.lock().init(HEAP.as_mut_ptr() as usize, HEAP.len());
}

/// Allocate an aligned but uninitialized slice of heap.
pub fn aligned_boxed_slice(size: usize, align: usize) -> Option<Box<[u8]>> {
    let size = NonZeroUsize::new(size)?.get();
    let layout = Layout::from_size_align(size, align).ok()?;
    // SAFETY - We verify that `size` and the returned `ptr` are non-null.
    let ptr = unsafe { alloc(layout) };
    let ptr = NonNull::new(ptr)?.as_ptr();
    let slice_ptr = ptr::slice_from_raw_parts_mut(ptr, size);

    // SAFETY - The memory was allocated using the proper layout by our global_allocator.
    Some(unsafe { Box::from_raw(slice_ptr) })
}

#[no_mangle]
unsafe extern "C" fn malloc(size: usize) -> *mut c_void {
    malloc_(size).map_or(ptr::null_mut(), |p| p.cast::<c_void>().as_ptr())
}

#[no_mangle]
unsafe extern "C" fn free(ptr: *mut c_void) {
    if let Some(ptr) = NonNull::new(ptr).map(|p| p.cast::<usize>().as_ptr().offset(-1)) {
        if let Some(size) = NonZeroUsize::new(*ptr) {
            if let Some(layout) = malloc_layout(size) {
                HEAP_ALLOCATOR.dealloc(ptr as *mut u8, layout);
            }
        }
    }
}

unsafe fn malloc_(size: usize) -> Option<NonNull<usize>> {
    let size = NonZeroUsize::new(size)?.checked_add(mem::size_of::<usize>())?;
    let ptr = HEAP_ALLOCATOR.alloc(malloc_layout(size)?);
    let ptr = NonNull::new(ptr)?.cast::<usize>().as_ptr();
    *ptr = size.get();
    NonNull::new(ptr.offset(1))
}

fn malloc_layout(size: NonZeroUsize) -> Option<Layout> {
    const ALIGN: usize = mem::size_of::<u64>();
    Layout::from_size_align(size.get(), ALIGN).ok()
}
