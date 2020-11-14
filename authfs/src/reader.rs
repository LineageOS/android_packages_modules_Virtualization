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
use std::path::Path;

/// A trait for reading data by chunks. The data is assumed readonly and has fixed length. Chunks
/// can be read by specifying the chunk index. Only the last chunk may have incomplete chunk size.
pub trait ReadOnlyDataByChunk {
    /// Default chunk size.
    const CHUNK_SIZE: u64 = 4096;

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
    #[allow(dead_code)]
    pub fn new<P: AsRef<Path>>(path: P) -> Result<ChunkedFileReader> {
        let file = File::open(path)?;
        let size = file.metadata()?.len();
        Ok(ChunkedFileReader { file, size })
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

impl ReadOnlyDataByChunk for &[u8] {
    fn read_chunk(&self, chunk_index: u64, buf: &mut [u8]) -> Result<usize> {
        debug_assert!(buf.len() as u64 >= Self::CHUNK_SIZE);
        let chunk = &self.chunks(Self::CHUNK_SIZE as usize).nth(chunk_index as usize).unwrap();
        buf[..chunk.len()].copy_from_slice(&chunk);
        Ok(chunk.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_reading_more_than_4kb_data<T: ReadOnlyDataByChunk>(
        reader: T,
        data_size: u64,
    ) -> Result<()> {
        let mut buf = [0u8; 4096];
        assert_eq!(reader.read_chunk(0, &mut buf)?, 4096);
        let last_index = (data_size + 4095) / 4096 - 1;
        assert_eq!(reader.read_chunk(last_index, &mut buf)?, (data_size % 4096) as usize);
        Ok(())
    }

    // TODO(victorhsieh): test ChunkedFileReader once there is a way to access testdata in the test
    // environement.

    #[test]
    fn test_read_in_memory_data() -> Result<()> {
        let data = &[1u8; 5000][..];
        test_reading_more_than_4kb_data(data, data.len() as u64)
    }

    #[test]
    #[should_panic]
    #[allow(unused_must_use)]
    fn test_read_in_memory_empty_data() {
        let data = &[][..]; // zero length slice
        let mut buf = [0u8; 4096];
        data.read_chunk(0, &mut buf); // should panic
    }

    #[test]
    #[should_panic]
    #[allow(unused_must_use)]
    fn test_read_beyond_file_size() {
        let data = &[1u8; 5000][..];
        let mut buf = [0u8; 4096];
        let last_index_plus_1 = (data.len() + 4095) / 4096;
        data.read_chunk(last_index_plus_1 as u64, &mut buf); // should panic
    }
}
