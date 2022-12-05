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

//! Iterators over cells, and various layers on top of them.

use crate::{AddrCells, SizeCells};
use core::{mem::size_of, ops::Range, slice::ChunksExact};

/// Iterator over cells of a DT property.
#[derive(Debug)]
pub struct CellIterator<'a> {
    chunks: ChunksExact<'a, u8>,
}

impl<'a> CellIterator<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        const CHUNK_SIZE: usize = size_of::<<CellIterator as Iterator>::Item>();

        Self { chunks: bytes.chunks_exact(CHUNK_SIZE) }
    }
}

impl<'a> Iterator for CellIterator<'a> {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        Some(Self::Item::from_be_bytes(self.chunks.next()?.try_into().ok()?))
    }
}

/// Iterator over a 'reg' property of a DT node.
#[derive(Debug)]
pub struct RegIterator<'a> {
    cells: CellIterator<'a>,
    addr_cells: AddrCells,
    size_cells: SizeCells,
}

/// Represents a contiguous region within the address space defined by the parent bus.
/// Commonly means the offsets and lengths of MMIO blocks, but may have a different meaning on some
/// bus types. Addresses in the address space defined by the root node are CPU real addresses.
#[derive(Copy, Clone, Debug)]
pub struct Reg<T> {
    /// Base address of the region.
    pub addr: T,
    /// Size of the region (optional).
    pub size: Option<T>,
}

impl<'a> RegIterator<'a> {
    pub(crate) fn new(
        cells: CellIterator<'a>,
        addr_cells: AddrCells,
        size_cells: SizeCells,
    ) -> Self {
        Self { cells, addr_cells, size_cells }
    }
}

impl<'a> Iterator for RegIterator<'a> {
    type Item = Reg<u64>;

    fn next(&mut self) -> Option<Self::Item> {
        let make_double = |a, b| (u64::from(a) << 32) | u64::from(b);

        let addr = match self.addr_cells {
            AddrCells::Single => self.cells.next()?.into(),
            AddrCells::Double => make_double(self.cells.next()?, self.cells.next()?),
        };
        // If the parent node specifies a value of 0 for #size-cells, 'size' shall be omitted.
        let size = match self.size_cells {
            SizeCells::None => None,
            SizeCells::Single => Some(self.cells.next()?.into()),
            SizeCells::Double => Some(make_double(self.cells.next()?, self.cells.next()?)),
        };

        Some(Self::Item { addr, size })
    }
}

/// Iterator over the address ranges defined by the /memory/ node.
#[derive(Debug)]
pub struct MemRegIterator<'a> {
    reg: RegIterator<'a>,
}

impl<'a> MemRegIterator<'a> {
    pub(crate) fn new(reg: RegIterator<'a>) -> Self {
        Self { reg }
    }
}

impl<'a> Iterator for MemRegIterator<'a> {
    type Item = Range<usize>;

    fn next(&mut self) -> Option<Self::Item> {
        let next = self.reg.next()?;
        let addr = usize::try_from(next.addr).ok()?;
        let size = usize::try_from(next.size?).ok()?;

        Some(addr..addr.checked_add(size)?)
    }
}
