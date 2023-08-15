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
use core::ops::Range;
use core::result;
use log::info;
use static_assertions::const_assert_eq;
use vmbase::util::RangeExt;
use zerocopy::{FromBytes, LayoutVerified};

/// Configuration data header.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, FromBytes)]
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
    /// Header sets flags incorrectly or uses reserved flags.
    InvalidFlags(u32),
    /// Header describes configuration data that doesn't fit in the expected buffer.
    InvalidSize(usize),
    /// Header entry is missing.
    MissingEntry(Entry),
    /// Range described by entry does not fit within config data.
    EntryOutOfBounds(Entry, Range<usize>, Range<usize>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::BufferTooSmall => write!(f, "Reserved region is smaller than config header"),
            Self::HeaderMisaligned => write!(f, "Reserved region is misaligned"),
            Self::InvalidMagic => write!(f, "Wrong magic number"),
            Self::UnsupportedVersion(v) => write!(f, "Version {v} not supported"),
            Self::InvalidFlags(v) => write!(f, "Flags value {v:#x} is incorrect or reserved"),
            Self::InvalidSize(sz) => write!(f, "Total size ({sz:#x}) overflows reserved region"),
            Self::MissingEntry(entry) => write!(f, "Mandatory {entry:?} entry is missing"),
            Self::EntryOutOfBounds(entry, range, limits) => {
                write!(
                    f,
                    "Entry {entry:?} out of bounds: {range:#x?} must be within range {limits:#x?}"
                )
            }
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

    pub fn body_offset(&self) -> Result<usize> {
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
#[derive(Clone, Copy, Debug, FromBytes)]
struct HeaderEntry {
    offset: u32,
    size: u32,
}

impl HeaderEntry {
    pub fn as_range(&self) -> Option<Range<usize>> {
        let size = usize::try_from(self.size).unwrap();
        if size != 0 {
            let offset = self.offset.try_into().unwrap();
            // Allow overflows here for the Range to properly describe the entry (validated later).
            Some(offset..(offset + size))
        } else {
            None
        }
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Eq, FromBytes, PartialEq)]
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

#[derive(Debug)]
pub struct Config<'a> {
    body: &'a mut [u8],
    ranges: [Option<Range<usize>>; Entry::COUNT],
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

        if header.flags != 0 {
            return Err(Error::InvalidFlags(header.flags));
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

        let limits = header.body_offset()?..total_size;
        let ranges = [
            // TODO: Find a way to do this programmatically even if the trait
            // `core::marker::Copy` is not implemented for `core::ops::Range<usize>`.
            Self::validated_body_range(Entry::Bcc, &header_entries, &limits)?,
            Self::validated_body_range(Entry::DebugPolicy, &header_entries, &limits)?,
            Self::validated_body_range(Entry::VmDtbo, &header_entries, &limits)?,
        ];

        Ok(Self { body, ranges })
    }

    /// Get slice containing the platform BCC.
    pub fn get_entries(&mut self) -> Result<(&mut [u8], Option<&mut [u8]>)> {
        // This assumes that the blobs are in-order w.r.t. the entries.
        let bcc_range = self.get_entry_range(Entry::Bcc).ok_or(Error::MissingEntry(Entry::Bcc))?;
        let dp_range = self.get_entry_range(Entry::DebugPolicy);
        let vm_dtbo_range = self.get_entry_range(Entry::VmDtbo);
        // TODO(b/291191157): Provision device assignment with this.
        if let Some(vm_dtbo_range) = vm_dtbo_range {
            info!("Found VM DTBO at {:?}", vm_dtbo_range);
        }
        let bcc_start = bcc_range.start;
        let bcc_end = bcc_range.len();
        let (_, rest) = self.body.split_at_mut(bcc_start);
        let (bcc, rest) = rest.split_at_mut(bcc_end);

        let dp = if let Some(dp_range) = dp_range {
            let dp_start = dp_range.start.checked_sub(bcc_range.end).unwrap();
            let dp_end = dp_range.len();
            let (_, rest) = rest.split_at_mut(dp_start);
            let (dp, _) = rest.split_at_mut(dp_end);
            Some(dp)
        } else {
            None
        };

        Ok((bcc, dp))
    }

    pub fn get_entry_range(&self, entry: Entry) -> Option<Range<usize>> {
        self.ranges[entry as usize].clone()
    }

    fn validated_body_range(
        entry: Entry,
        header_entries: &[HeaderEntry],
        limits: &Range<usize>,
    ) -> Result<Option<Range<usize>>> {
        if let Some(header_entry) = header_entries.get(entry as usize) {
            if let Some(r) = header_entry.as_range() {
                return if r.start <= r.end && r.is_within(limits) {
                    let start = r.start - limits.start;
                    let end = r.end - limits.start;

                    Ok(Some(start..end))
                } else {
                    Err(Error::EntryOutOfBounds(entry, r, limits.clone()))
                };
            }
        }

        Ok(None)
    }
}
