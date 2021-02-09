/*
 * Copyright (C) 2020 The Android Open Source Project
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

//! A module for reading data by chunks.

use std::fs::File;
use std::io::Result;
use std::os::unix::fs::FileExt;

use crate::common::COMMON_PAGE_SIZE;

/// A trait for reading data by chunks. The data is assumed readonly and has fixed length. Chunks
/// can be read by specifying the chunk index. Only the last chunk may have incomplete chunk size.
pub trait ReadOnlyDataByChunk {
    /// Default chunk size.
    const CHUNK_SIZE: u64 = COMMON_PAGE_SIZE;

    /// Read the `chunk_index`-th chunk to `buf`. Each slice/chunk has size `CHUNK_SIZE` except for
    /// the last one, which can be an incomplete chunk. `buf` is currently required to be large
    /// enough to hold a full chunk of data. Reading beyond the file size (including empty file)
    /// will crash.
    fn read_chunk(&self, chunk_index: u64, buf: &mut [u8]) -> Result<usize>;
}

fn chunk_index_to_range(size: u64, chunk_size: u64, chunk_index: u64) -> Result<(u64, u64)> {
    let start = chunk_index * chunk_size;
    assert!(start < size);
    let end = std::cmp::min(size, start + chunk_size);
    Ok((start, end))
}

/// A read-only file that can be read by chunks.
pub struct ChunkedFileReader {
    file: File,
    size: u64,
}

impl ChunkedFileReader {
    /// Creates a `ChunkedFileReader` to read from for the specified `path`.
    pub fn new(file: File) -> Result<ChunkedFileReader> {
        let size = file.metadata()?.len();
        Ok(ChunkedFileReader { file, size })
    }

    pub fn len(&self) -> u64 {
        self.size
    }
}

impl ReadOnlyDataByChunk for ChunkedFileReader {
    fn read_chunk(&self, chunk_index: u64, buf: &mut [u8]) -> Result<usize> {
        debug_assert!(buf.len() as u64 >= Self::CHUNK_SIZE);
        let (start, end) = chunk_index_to_range(self.size, Self::CHUNK_SIZE, chunk_index)?;
        let size = (end - start) as usize;
        self.file.read_at(&mut buf[..size], start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::temp_dir;

    #[test]
    fn test_read_4k_file() -> Result<()> {
        let file_reader = ChunkedFileReader::new(File::open("testdata/input.4k")?)?;
        let mut buf = [0u8; 4096];
        let size = file_reader.read_chunk(0, &mut buf)?;
        assert_eq!(size, buf.len());
        Ok(())
    }

    #[test]
    fn test_read_4k1_file() -> Result<()> {
        let file_reader = ChunkedFileReader::new(File::open("testdata/input.4k1")?)?;
        let mut buf = [0u8; 4096];
        let size = file_reader.read_chunk(0, &mut buf)?;
        assert_eq!(size, buf.len());
        let size = file_reader.read_chunk(1, &mut buf)?;
        assert_eq!(size, 1);
        Ok(())
    }

    #[test]
    fn test_read_4m_file() -> Result<()> {
        let file_reader = ChunkedFileReader::new(File::open("testdata/input.4m")?)?;
        for index in 0..file_reader.len() / 4096 {
            let mut buf = [0u8; 4096];
            let size = file_reader.read_chunk(index, &mut buf)?;
            assert_eq!(size, buf.len());
        }
        Ok(())
    }

    #[test]
    #[should_panic]
    fn test_read_beyond_file_size() {
        let file_reader = ChunkedFileReader::new(File::open("testdata/input.4k").unwrap()).unwrap();
        let mut buf = [0u8; 4096];
        let _ = file_reader.read_chunk(1u64, &mut buf); // should panic
    }

    #[test]
    #[should_panic]
    fn test_read_empty_file() {
        let mut temp_file = temp_dir();
        temp_file.push("authfs_test_empty_file");
        let file_reader = ChunkedFileReader::new(File::create(temp_file).unwrap()).unwrap();
        let mut buf = [0u8; 4096];
        let _ = file_reader.read_chunk(0, &mut buf); // should panic
    }
}
