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

use core::alloc::GlobalAlloc as _;
use core::alloc::Layout;
use core::ffi::c_void;
use core::mem;
use core::num::NonZeroUsize;
use core::ptr;
use core::ptr::NonNull;

use buddy_system_allocator::LockedHeap;

#[global_allocator]
static HEAP_ALLOCATOR: LockedHeap<32> = LockedHeap::<32>::new();

static mut HEAP: [u8; 131072] = [0; 131072];

pub unsafe fn init() {
    HEAP_ALLOCATOR.lock().init(HEAP.as_mut_ptr() as usize, HEAP.len());
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
