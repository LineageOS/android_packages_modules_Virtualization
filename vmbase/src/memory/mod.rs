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

//! Memory management.

mod dbm;
mod page_table;
mod shared;
mod util;

pub use dbm::{flush_dirty_range, mark_dirty_block, set_dbm_enabled};
pub use page_table::PageTable;
pub use shared::{mmio_guard_unmap_page, verify_lazy_mapped_block, MemorySharer};
pub use util::{
    flush, flushed_zeroize, min_dcache_line_size, page_4kb_of, phys_to_virt, virt_to_phys,
    PAGE_SIZE, SIZE_2MB, SIZE_4KB, SIZE_4MB,
};
