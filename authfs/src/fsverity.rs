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

use std::io;
use thiserror::Error;

use crate::crypto::{CryptoError, Sha256Hasher};
use crate::reader::ReadOnlyDataByChunk;

const ZEROS: [u8; 4096] = [0u8; 4096];

#[derive(Error, Debug)]
pub enum FsverityError {
    #[error("Cannot verify a block")]
    CannotVerify,
    #[error("I/O error")]
    Io(#[from] io::Error),
    #[error("Crypto")]
    UnexpectedCryptoError(#[from] CryptoError),
}

type HashBuffer = [u8; Sha256Hasher::HASH_SIZE];

fn divide_roundup(dividend: u64, divisor: u64) -> u64 {
    (dividend + divisor - 1) / divisor
}

fn hash_with_padding(chunk: &[u8], pad_to: usize) -> Result<HashBuffer, CryptoError> {
    let padding_size = pad_to - chunk.len();
    Sha256Hasher::new()?.update(&chunk)?.update(&ZEROS[..padding_size])?.finalize()
}

#[allow(dead_code)]
fn verity_check<T: ReadOnlyDataByChunk>(
    chunk: &[u8],
    chunk_index: u64,
    file_size: u64,
    merkle_tree: &T,
) -> Result<HashBuffer, FsverityError> {
    // The caller should not be able to produce a chunk at the first place if `file_size` is 0. The
    // current implementation expects to crash when a `ReadOnlyDataByChunk` implementation reads
    // beyone the file size, including empty file.
    assert_ne!(file_size, 0);

    let chunk_hash = hash_with_padding(&chunk, T::CHUNK_SIZE as usize)?;

    fsverity_walk(chunk_index, file_size, merkle_tree)?.try_fold(
        chunk_hash,
        |actual_hash, result| {
            let (merkle_chunk, hash_offset_in_chunk) = result?;
            let expected_hash =
                &merkle_chunk[hash_offset_in_chunk..hash_offset_in_chunk + Sha256Hasher::HASH_SIZE];
            if actual_hash != expected_hash {
                return Err(FsverityError::CannotVerify);
            }
            Ok(hash_with_padding(&merkle_chunk, T::CHUNK_SIZE as usize)?)
        },
    )
}

fn log128_ceil(num: u64) -> Option<u64> {
    match num {
        0 => None,
        n => Some(divide_roundup(64 - (n - 1).leading_zeros() as u64, 7)),
    }
}

/// Given a chunk index and the size of the file, returns an iterator that walks the Merkle tree
/// from the leaf to the root. The iterator carries the slice of the chunk/node as well as the
/// offset of the child node's hash. It is up to the iterator user to use the node and hash,
/// e.g. for the actual verification.
#[allow(clippy::needless_collect)]
fn fsverity_walk<'a, T: ReadOnlyDataByChunk>(
    chunk_index: u64,
    file_size: u64,
    merkle_tree: &'a T,
) -> Result<impl Iterator<Item = Result<([u8; 4096], usize), FsverityError>> + 'a, FsverityError> {
    let hashes_per_node = T::CHUNK_SIZE / Sha256Hasher::HASH_SIZE as u64;
    let hash_pages = divide_roundup(file_size, hashes_per_node * T::CHUNK_SIZE);
    debug_assert_eq!(hashes_per_node, 128u64);
    let max_level = log128_ceil(hash_pages).expect("file should not be empty") as u32;
    let root_to_leaf_steps = (0..=max_level)
        .rev()
        .map(|x| {
            let leaves_per_hash = hashes_per_node.pow(x);
            let leaves_size_per_hash = T::CHUNK_SIZE * leaves_per_hash;
            let leaves_size_per_node = leaves_size_per_hash * hashes_per_node;
            let nodes_at_level = divide_roundup(file_size, leaves_size_per_node);
            let level_size = nodes_at_level * T::CHUNK_SIZE;
            let offset_in_level = (chunk_index / leaves_per_hash) * Sha256Hasher::HASH_SIZE as u64;
            (level_size, offset_in_level)
        })
        .scan(0, |level_offset, (level_size, offset_in_level)| {
            let this_level_offset = *level_offset;
            *level_offset += level_size;
            let global_hash_offset = this_level_offset + offset_in_level;
            Some(global_hash_offset)
        })
        .map(|global_hash_offset| {
            let chunk_index = global_hash_offset / T::CHUNK_SIZE;
            let hash_offset_in_chunk = (global_hash_offset % T::CHUNK_SIZE) as usize;
            (chunk_index, hash_offset_in_chunk)
        })
        .collect::<Vec<_>>();

    Ok(root_to_leaf_steps.into_iter().rev().map(move |(chunk_index, hash_offset_in_chunk)| {
        let mut merkle_chunk = [0u8; 4096];
        let _ = merkle_tree.read_chunk(chunk_index, &mut merkle_chunk)?;
        Ok((merkle_chunk, hash_offset_in_chunk))
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reader::ReadOnlyDataByChunk;
    use anyhow::Result;

    fn total_chunk_number(file_size: u64) -> u64 {
        (file_size + 4095) / 4096
    }

    #[test]
    fn fsverity_verify_full_read_4k() -> Result<()> {
        let file = &include_bytes!("../testdata/input.4k")[..];
        let merkle_tree = &include_bytes!("../testdata/input.4k.merkle_dump")[..];

        let mut buf = [0u8; 4096];

        for i in 0..total_chunk_number(file.len() as u64) {
            let size = file.read_chunk(i, &mut buf[..])?;
            assert!(verity_check(&buf[..size], i, file.len() as u64, &merkle_tree).is_ok());
        }
        Ok(())
    }

    #[test]
    fn fsverity_verify_full_read_4k1() -> Result<()> {
        let file = &include_bytes!("../testdata/input.4k1")[..];
        let merkle_tree = &include_bytes!("../testdata/input.4k1.merkle_dump")[..];

        let mut buf = [0u8; 4096];
        for i in 0..total_chunk_number(file.len() as u64) {
            let size = file.read_chunk(i, &mut buf[..])?;
            assert!(verity_check(&buf[..size], i, file.len() as u64, &merkle_tree).is_ok());
        }
        Ok(())
    }

    #[test]
    fn fsverity_verify_full_read_4m() -> Result<()> {
        let file = &include_bytes!("../testdata/input.4m")[..];
        let merkle_tree = &include_bytes!("../testdata/input.4m.merkle_dump")[..];

        let mut buf = [0u8; 4096];
        for i in 0..total_chunk_number(file.len() as u64) {
            let size = file.read_chunk(i, &mut buf[..])?;
            assert!(verity_check(&buf[..size], i, file.len() as u64, &merkle_tree).is_ok());
        }
        Ok(())
    }

    #[test]
    fn fsverity_verify_bad_merkle_tree() -> Result<()> {
        let file = &include_bytes!("../testdata/input.4m")[..];
        // First leaf node is corrupted.
        let merkle_tree = &include_bytes!("../testdata/input.4m.merkle_dump.bad")[..];

        // A lowest broken node (a 4K chunk that contains 128 sha256 hashes) will fail the read
        // failure of the underlying chunks, but not before or after.
        let mut buf = [0u8; 4096];
        let num_hashes = 4096 / 32;
        let last_index = num_hashes;
        for i in 0..last_index {
            let size = file.read_chunk(i, &mut buf[..])?;
            assert!(verity_check(&buf[..size], i, file.len() as u64, &merkle_tree).is_err());
        }
        let size = file.read_chunk(last_index, &mut buf[..])?;
        assert!(verity_check(&buf[..size], last_index, file.len() as u64, &merkle_tree).is_ok());
        Ok(())
    }
}
