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

//! Support for the pvmfw configuration data format.

use crate::helpers;
use core::fmt;
use core::mem;
use core::num::NonZeroUsize;
use core::ops::Range;
use core::result;

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
struct Header {
    magic: u32,
    version: u32,
    total_size: u32,
    flags: u32,
    entries: [HeaderEntry; Entry::COUNT],
}

#[derive(Debug)]
pub enum Error {
    /// Reserved region can't fit configuration header.
    BufferTooSmall,
    /// Header doesn't contain the expect magic value.
    InvalidMagic,
    /// Version of the header isn't supported.
    UnsupportedVersion(u16, u16),
    /// Header sets flags incorrectly or uses reserved flags.
    InvalidFlags(u32),
    /// Header describes configuration data that doesn't fit in the expected buffer.
    InvalidSize(usize),
    /// Header entry is invalid.
    InvalidEntry(Entry),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::BufferTooSmall => write!(f, "Reserved region is smaller than config header"),
            Self::InvalidMagic => write!(f, "Wrong magic number"),
            Self::UnsupportedVersion(x, y) => write!(f, "Version {x}.{y} not supported"),
            Self::InvalidFlags(v) => write!(f, "Flags value {v:#x} is incorrect or reserved"),
            Self::InvalidSize(sz) => write!(f, "Total size ({sz:#x}) overflows reserved region"),
            Self::InvalidEntry(e) => write!(f, "Entry {e:?} is invalid"),
        }
    }
}

pub type Result<T> = result::Result<T, Error>;

impl Header {
    const MAGIC: u32 = u32::from_ne_bytes(*b"pvmf");
    const PADDED_SIZE: usize =
        helpers::unchecked_align_up(mem::size_of::<Self>(), mem::size_of::<u64>());

    pub const fn version(major: u16, minor: u16) -> u32 {
        ((major as u32) << 16) | (minor as u32)
    }

    pub const fn version_tuple(&self) -> (u16, u16) {
        ((self.version >> 16) as u16, self.version as u16)
    }

    pub fn total_size(&self) -> usize {
        self.total_size as usize
    }

    pub fn body_size(&self) -> usize {
        self.total_size() - Self::PADDED_SIZE
    }

    fn get_body_range(&self, entry: Entry) -> Result<Option<Range<usize>>> {
        let e = self.entries[entry as usize];

        if e.is_empty() {
            Ok(None)
        } else if e.fits_in(self.total_size()) {
            Ok(Some(e.as_body_range()))
        } else {
            Err(Error::InvalidEntry(entry))
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Entry {
    Bcc = 0,
    DebugPolicy = 1,
}

impl Entry {
    const COUNT: usize = 2;
}

#[repr(packed)]
#[derive(Clone, Copy, Debug)]
struct HeaderEntry {
    offset: u32,
    size: u32,
}

impl HeaderEntry {
    pub fn is_empty(&self) -> bool {
        self.offset() == 0 && self.size() == 0
    }

    pub fn fits_in(&self, max_size: usize) -> bool {
        (Header::PADDED_SIZE..max_size).contains(&self.offset())
            && NonZeroUsize::new(self.size())
                .and_then(|s| s.checked_add(self.offset()))
                .filter(|&x| x.get() <= max_size)
                .is_some()
    }

    pub fn as_body_range(&self) -> Range<usize> {
        let start = self.offset() - Header::PADDED_SIZE;

        start..(start + self.size())
    }

    pub fn offset(&self) -> usize {
        self.offset as usize
    }

    pub fn size(&self) -> usize {
        self.size as usize
    }
}

#[derive(Debug)]
pub struct Config<'a> {
    body: &'a mut [u8],
    bcc_range: Range<usize>,
    dp_range: Option<Range<usize>>,
}

impl<'a> Config<'a> {
    /// Take ownership of a pvmfw configuration consisting of its header and following entries.
    ///
    /// SAFETY - 'data' should respect the alignment of Header.
    pub unsafe fn new(data: &'a mut [u8]) -> Result<Self> {
        let header = data.get(..Header::PADDED_SIZE).ok_or(Error::BufferTooSmall)?;

        let header = &*(header.as_ptr() as *const Header);

        if header.magic != Header::MAGIC {
            return Err(Error::InvalidMagic);
        }

        if header.version != Header::version(1, 0) {
            let (major, minor) = header.version_tuple();
            return Err(Error::UnsupportedVersion(major, minor));
        }

        if header.flags != 0 {
            return Err(Error::InvalidFlags(header.flags));
        }

        let bcc_range =
            header.get_body_range(Entry::Bcc)?.ok_or(Error::InvalidEntry(Entry::Bcc))?;
        let dp_range = header.get_body_range(Entry::DebugPolicy)?;

        let body = data
            .get_mut(Header::PADDED_SIZE..)
            .ok_or(Error::BufferTooSmall)?
            .get_mut(..header.body_size())
            .ok_or_else(|| Error::InvalidSize(header.total_size()))?;

        Ok(Self { body, bcc_range, dp_range })
    }

    /// Get slice containing the platform BCC.
    pub fn get_bcc_mut(&mut self) -> &mut [u8] {
        &mut self.body[self.bcc_range.clone()]
    }

    /// Get slice containing the platform debug policy.
    pub fn get_debug_policy(&mut self) -> Option<&mut [u8]> {
        self.dp_range.as_ref().map(|r| &mut self.body[r.clone()])
    }
}
