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

use core::fmt;
use core::mem;
use core::num::NonZeroUsize;
use core::ops::Range;
use core::result;
use core::slice;
use log::{info, warn};
use static_assertions::const_assert_eq;
use vmbase::util::RangeExt;
use zerocopy::{FromBytes, FromZeroes, LayoutVerified};

/// Configuration data header.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, FromZeroes, FromBytes)]
struct Header {
    /// Magic number; must be `Header::MAGIC`.
    magic: u32,
    /// Version of the header format.
    version: Version,
    /// Total size of the configuration data.
    total_size: u32,
    /// Feature flags; currently reserved and must be zero.
    flags: u32,
}

#[derive(Debug)]
pub enum Error {
    /// Reserved region can't fit configuration header.
    BufferTooSmall,
    /// Header has the wrong alignment
    HeaderMisaligned,
    /// Header doesn't contain the expect magic value.
    InvalidMagic,
    /// Version of the header isn't supported.
    UnsupportedVersion(Version),
    /// Header describes configuration data that doesn't fit in the expected buffer.
    InvalidSize(usize),
    /// Header entry is missing.
    MissingEntry(Entry),
    /// Range described by entry does not fit within config data.
    EntryOutOfBounds(Entry, Range<usize>, Range<usize>),
    /// Entries are in out of order
    EntryOutOfOrder,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::BufferTooSmall => write!(f, "Reserved region is smaller than config header"),
            Self::HeaderMisaligned => write!(f, "Reserved region is misaligned"),
            Self::InvalidMagic => write!(f, "Wrong magic number"),
            Self::UnsupportedVersion(v) => write!(f, "Version {v} not supported"),
            Self::InvalidSize(sz) => write!(f, "Total size ({sz:#x}) overflows reserved region"),
            Self::MissingEntry(entry) => write!(f, "Mandatory {entry:?} entry is missing"),
            Self::EntryOutOfBounds(entry, range, limits) => {
                write!(
                    f,
                    "Entry {entry:?} out of bounds: {range:#x?} must be within range {limits:#x?}"
                )
            }
            Self::EntryOutOfOrder => write!(f, "Entries are out of order"),
        }
    }
}

pub type Result<T> = result::Result<T, Error>;

impl Header {
    const MAGIC: u32 = u32::from_ne_bytes(*b"pvmf");
    const VERSION_1_0: Version = Version { major: 1, minor: 0 };
    const VERSION_1_1: Version = Version { major: 1, minor: 1 };

    pub fn total_size(&self) -> usize {
        self.total_size as usize
    }

    pub fn body_lowest_bound(&self) -> Result<usize> {
        let entries_offset = mem::size_of::<Self>();

        // Ensure that the entries are properly aligned and do not require padding.
        const_assert_eq!(mem::align_of::<Header>() % mem::align_of::<HeaderEntry>(), 0);
        const_assert_eq!(mem::size_of::<Header>() % mem::align_of::<HeaderEntry>(), 0);

        let entries_size = self.entry_count()?.checked_mul(mem::size_of::<HeaderEntry>()).unwrap();

        Ok(entries_offset.checked_add(entries_size).unwrap())
    }

    pub fn entry_count(&self) -> Result<usize> {
        let last_entry = match self.version {
            Self::VERSION_1_0 => Entry::DebugPolicy,
            Self::VERSION_1_1 => Entry::VmDtbo,
            v @ Version { major: 1, .. } => {
                const LATEST: Version = Header::VERSION_1_1;
                warn!("Parsing unknown config data version {v} as version {LATEST}");
                return Ok(Entry::COUNT);
            }
            v => return Err(Error::UnsupportedVersion(v)),
        };

        Ok(last_entry as usize + 1)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Entry {
    Bcc,
    DebugPolicy,
    VmDtbo,
    #[allow(non_camel_case_types)] // TODO: Use mem::variant_count once stable.
    _VARIANT_COUNT,
}

impl Entry {
    const COUNT: usize = Self::_VARIANT_COUNT as usize;
}

#[repr(packed)]
#[derive(Clone, Copy, Debug, FromZeroes, FromBytes)]
struct HeaderEntry {
    offset: u32,
    size: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Eq, FromZeroes, FromBytes, PartialEq)]
pub struct Version {
    minor: u16,
    major: u16,
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Copy the fields to local variables to prevent unaligned access.
        let (major, minor) = (self.major, self.minor);
        write!(f, "{}.{}", major, minor)
    }
}

/// Range with non-empty length.
#[derive(Debug, Copy, Clone)]
struct NonEmptyRange {
    start: usize,
    size: NonZeroUsize,
}

impl NonEmptyRange {
    pub fn new(start: usize, size: usize) -> Option<Self> {
        // Ensure end() is safe.
        start.checked_add(size).unwrap();

        Some(Self { start, size: NonZeroUsize::new(size)? })
    }

    fn end(&self) -> usize {
        self.start + self.len()
    }

    fn len(&self) -> usize {
        self.size.into()
    }

    fn as_range(&self) -> Range<usize> {
        self.start..self.end()
    }
}

#[derive(Debug)]
pub struct Config<'a> {
    body: &'a mut [u8],
    ranges: [Option<NonEmptyRange>; Entry::COUNT],
}

impl<'a> Config<'a> {
    /// Take ownership of a pvmfw configuration consisting of its header and following entries.
    pub fn new(bytes: &'a mut [u8]) -> Result<Self> {
        const HEADER_SIZE: usize = mem::size_of::<Header>();
        if bytes.len() < HEADER_SIZE {
            return Err(Error::BufferTooSmall);
        }

        let (header, rest) =
            LayoutVerified::<_, Header>::new_from_prefix(bytes).ok_or(Error::HeaderMisaligned)?;
        let header = header.into_ref();

        if header.magic != Header::MAGIC {
            return Err(Error::InvalidMagic);
        }

        let header_flags = header.flags;
        if header_flags != 0 {
            warn!("Ignoring unknown config flags: {header_flags:#x}");
        }

        info!("pvmfw config version: {}", header.version);

        // Validate that we won't get an invalid alignment in the following due to padding to u64.
        const_assert_eq!(HEADER_SIZE % mem::size_of::<u64>(), 0);

        // Ensure that Header::total_size isn't larger than anticipated by the caller and resize
        // the &[u8] to catch OOB accesses to entries/blobs.
        let total_size = header.total_size();
        let rest = if let Some(rest_size) = total_size.checked_sub(HEADER_SIZE) {
            rest.get_mut(..rest_size).ok_or(Error::InvalidSize(total_size))?
        } else {
            return Err(Error::InvalidSize(total_size));
        };

        let (header_entries, body) =
            LayoutVerified::<_, [HeaderEntry]>::new_slice_from_prefix(rest, header.entry_count()?)
                .ok_or(Error::BufferTooSmall)?;

        // Validate that we won't get an invalid alignment in the following due to padding to u64.
        const_assert_eq!(mem::size_of::<HeaderEntry>() % mem::size_of::<u64>(), 0);

        // Ensure entries are in the body.
        let limits = header.body_lowest_bound()?..total_size;
        let mut ranges: [Option<NonEmptyRange>; Entry::COUNT] = [None; Entry::COUNT];
        let mut last_end = 0;
        for entry in [Entry::Bcc, Entry::DebugPolicy, Entry::VmDtbo] {
            let Some(header_entry) = header_entries.get(entry as usize) else { continue };
            let entry_offset = header_entry.offset.try_into().unwrap();
            let entry_size = header_entry.size.try_into().unwrap();
            let Some(range) = NonEmptyRange::new(entry_offset, entry_size) else { continue };
            let range = range.as_range();
            if !range.is_within(&limits) {
                return Err(Error::EntryOutOfBounds(entry, range, limits));
            }

            if last_end > range.start {
                return Err(Error::EntryOutOfOrder);
            }
            last_end = range.end;

            ranges[entry as usize] = NonEmptyRange::new(
                entry_offset - limits.start, // is_within() validates safety of this.
                entry_size,
            );
        }
        // Ensures that BCC exists.
        ranges[Entry::Bcc as usize].ok_or(Error::MissingEntry(Entry::Bcc))?;

        Ok(Self { body, ranges })
    }

    /// Get slice containing the platform BCC.
    pub fn get_entries(&mut self) -> (&mut [u8], Option<&mut [u8]>) {
        // This assumes that the blobs are in-order w.r.t. the entries.
        let bcc_range = self.get_entry_range(Entry::Bcc);
        let dp_range = self.get_entry_range(Entry::DebugPolicy);
        let vm_dtbo_range = self.get_entry_range(Entry::VmDtbo);
        // TODO(b/291191157): Provision device assignment with this.
        if let Some(vm_dtbo_range) = vm_dtbo_range {
            info!("Found VM DTBO at {:?}", vm_dtbo_range);
        }

        // SAFETY: When instantiate, ranges are validated to be in the body range without
        // overlapping.
        unsafe {
            let ptr = self.body.as_mut_ptr() as usize;
            (
                Self::from_raw_range_mut(ptr, bcc_range.unwrap()),
                dp_range.map(|dp_range| Self::from_raw_range_mut(ptr, dp_range)),
            )
        }
    }

    fn get_entry_range(&self, entry: Entry) -> Option<NonEmptyRange> {
        self.ranges[entry as usize]
    }

    unsafe fn from_raw_range_mut(ptr: usize, range: NonEmptyRange) -> &'a mut [u8] {
        // SAFETY: The caller must ensure that the range is valid from ptr.
        unsafe { slice::from_raw_parts_mut((ptr + range.start) as *mut u8, range.end()) }
    }
}
