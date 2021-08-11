/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Utilities for zip handling

use anyhow::{bail, Result};
use bytes::{Buf, BufMut};
use std::io::{Read, Seek, SeekFrom};
use zip::ZipArchive;

const EOCD_MIN_SIZE: usize = 22;
const EOCD_CENTRAL_DIRECTORY_OFFSET_FIELD_OFFSET: usize = 16;
const EOCD_MAGIC: u32 = 0x06054b50;

#[derive(Debug, PartialEq)]
pub struct ZipSections {
    pub central_directory_offset: u32,
    pub central_directory_size: u32,
    pub eocd_offset: u32,
    pub eocd_size: u32,
}

/// Discover the layout of a zip file.
pub fn zip_sections<R: Read + Seek>(mut reader: R) -> Result<(R, ZipSections)> {
    // open a zip to parse EOCD
    let archive = ZipArchive::new(reader)?;
    let eocd_size = archive.comment().len() + EOCD_MIN_SIZE;
    if archive.offset() != 0 {
        bail!("Invalid ZIP: offset should be 0, but {}.", archive.offset());
    }
    // retrieve reader back
    reader = archive.into_inner();
    // the current position should point EOCD offset
    let eocd_offset = reader.seek(SeekFrom::Current(0))?;
    let mut eocd = vec![0u8; eocd_size as usize];
    reader.read_exact(&mut eocd)?;
    if (&eocd[0..]).get_u32_le() != EOCD_MAGIC {
        bail!("Invalid ZIP: ZipArchive::new() should point EOCD after reading.");
    }
    let central_directory_offset = get_central_directory_offset(&eocd)?;
    let central_directory_size = eocd_offset as u32 - central_directory_offset;
    Ok((
        reader,
        ZipSections {
            central_directory_offset,
            central_directory_size,
            eocd_offset: eocd_offset as u32,
            eocd_size: eocd_size as u32,
        },
    ))
}

fn get_central_directory_offset(buf: &[u8]) -> Result<u32> {
    if buf.len() < EOCD_MIN_SIZE {
        bail!("Invalid EOCD size: {}", buf.len());
    }
    Ok((&buf[EOCD_CENTRAL_DIRECTORY_OFFSET_FIELD_OFFSET..]).get_u32_le())
}

/// Update EOCD's central_directory_offset field.
pub fn set_central_directory_offset(buf: &mut [u8], value: u32) -> Result<()> {
    if buf.len() < EOCD_MIN_SIZE {
        bail!("Invalid EOCD size: {}", buf.len());
    }
    (&mut buf[EOCD_CENTRAL_DIRECTORY_OFFSET_FIELD_OFFSET..]).put_u32_le(value);
    Ok(())
}
