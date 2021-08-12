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

//! `idsig` provides routines for creating the idsig file that is defined for the APK signature
//! scheme v4 and for parsing the file.

use ring::digest::{self, Algorithm};
use std::io::{Cursor, Read, Result, Seek, SeekFrom, Write};

/// `HashTree` is a merkle tree (and its root hash) that is compatible with fs-verity.
pub struct HashTree {
    /// Binary presentation of the merkle tree
    pub tree: Vec<u8>,
    /// Root hash
    pub root_hash: Vec<u8>,
}

impl HashTree {
    /// Creates merkle tree from `input`, using the given `salt` and hashing `algorithm`. `input`
    /// is divided into `block_size` chunks.
    pub fn from<R: Read>(
        input: &mut R,
        input_size: usize,
        salt: &[u8],
        block_size: usize,
        algorithm: &'static Algorithm,
    ) -> Result<Self> {
        let salt = zero_pad_salt(salt, algorithm);
        let tree = generate_hash_tree(input, input_size, &salt, block_size, algorithm)?;

        // Root hash is from the first block of the hash or the input data if there is no hash tree
        // generate which can happen when input data is smaller than block size
        let root_hash = if tree.is_empty() {
            hash_one_level(input, input_size, &salt, block_size, algorithm)?
        } else {
            let mut ctx = digest::Context::new(algorithm);
            ctx.update(&salt);
            ctx.update(&tree[0..block_size]);
            ctx.finish().as_ref().to_vec()
        };
        Ok(HashTree { tree, root_hash })
    }
}

/// Calculate hash tree for the blocks in `input`.
///
/// This function implements: https://www.kernel.org/doc/html/latest/filesystems/fsverity.html#merkle-tree
///
/// The file contents is divided into blocks, where the block size is configurable but is usually
/// 4096 bytes. The end of the last block is zero-padded if needed. Each block is then hashed,
/// producing the first level of hashes. Then, the hashes in this first level are grouped into
/// blocksize-byte blocks (zero-padding the ends as needed) and these blocks are hashed,
/// producing the second level of hashes. This proceeds up the tree until only a single block
/// remains.
fn generate_hash_tree<R: Read>(
    input: &mut R,
    input_size: usize,
    salt: &[u8],
    block_size: usize,
    algorithm: &'static Algorithm,
) -> Result<Vec<u8>> {
    let digest_size = algorithm.output_len;
    let (hash_level_offsets, tree_size) =
        calc_hash_level_offsets(input_size, block_size, digest_size);

    let mut hash_tree = Cursor::new(vec![0; tree_size]);
    let mut input_size = input_size;
    for (level, offset) in hash_level_offsets.iter().enumerate() {
        let hashes = if level == 0 {
            hash_one_level(input, input_size, salt, block_size, algorithm)?
        } else {
            // For the intermediate levels, input is the output from the previous level
            hash_tree.seek(SeekFrom::Start(hash_level_offsets[level - 1] as u64)).unwrap();
            hash_one_level(&mut hash_tree, input_size, salt, block_size, algorithm)?
        };
        hash_tree.seek(SeekFrom::Start(*offset as u64)).unwrap();
        hash_tree.write_all(hashes.as_ref()).unwrap();
        // Output from this level becomes input for the next level
        input_size = hashes.len();
    }
    Ok(hash_tree.into_inner())
}

/// Calculate hashes for the blocks in `input`. The end of the last block is zero-padded if needed.
/// Each block is then hashed, producing a stream of hashes for a level.
fn hash_one_level<R: Read>(
    input: &mut R,
    input_size: usize,
    salt: &[u8],
    block_size: usize,
    algorithm: &'static Algorithm,
) -> Result<Vec<u8>> {
    // Input is zero padded when it's not multiple of blocks. Note that `take()` is also needed to
    // not read more than `input_size` from the `input` reader. This is required because `input`
    // can be from the in-memory hashtree. We need to read only the part of hashtree that is for
    // the current level.
    let pad_size = round_to_multiple(input_size, block_size) - input_size;
    let mut input = input.take(input_size as u64).chain(Cursor::new(vec![0; pad_size]));

    // Read one block from input, write the hash of it to the output. Repeat that for all input
    // blocks.
    let mut hashes = Cursor::new(Vec::new());
    let mut buf = vec![0; block_size];
    let mut num_blocks = (input_size + block_size - 1) / block_size;
    while num_blocks > 0 {
        input.read_exact(&mut buf)?;
        let mut ctx = digest::Context::new(algorithm);
        ctx.update(salt);
        ctx.update(&buf);
        let hash = ctx.finish();
        hashes.write_all(hash.as_ref())?;
        num_blocks -= 1;
    }
    Ok(hashes.into_inner())
}

/// Calculate the size of hashes for each level, and also returns the total size of the hash tree.
/// This function is needed because hash tree is stored upside down; hashes for level N is stored
/// "after" hashes for level N + 1.
fn calc_hash_level_offsets(
    input_size: usize,
    block_size: usize,
    digest_size: usize,
) -> (Vec<usize>, usize) {
    // The input is split into multiple blocks and each block is hashed, which becomes the input
    // for the next level. Size of a single hash is `digest_size`.
    let mut level_sizes = Vec::new();
    loop {
        // Input for this level is from either the last level (if exists), or the input parameter.
        let input_size = *level_sizes.last().unwrap_or(&input_size);
        if input_size <= block_size {
            break;
        }
        let num_blocks = (input_size + block_size - 1) / block_size;
        let hashes_size = round_to_multiple(num_blocks * digest_size, block_size);
        level_sizes.push(hashes_size);
    }
    if level_sizes.is_empty() {
        return ([].to_vec(), 0);
    }

    // The hash tree is stored upside down. The top level is at offset 0. The second level comes
    // next, and so on. Level 0 is located at the end.
    //
    // Given level_sizes [10, 3, 1], the offsets for each label are ...
    //
    // Level 2 is at offset 0
    // Level 1 is at offset 1 (because Level 2 is of size 1)
    // Level 0 is at offset 4 (because Level 1 is of size 3)
    //
    // This is done by accumulating the sizes in reverse order (i.e. from the highest level to the
    // level 1 (not level 0)
    let mut offsets = level_sizes.iter().rev().take(level_sizes.len() - 1).fold(
        vec![0; 1], // offset for the top level
        |mut offsets, size| {
            offsets.push(offsets.last().unwrap() + size);
            offsets
        },
    );
    offsets.reverse(); // reverse the offsets again so that index N is for level N
    let tree_size = level_sizes.iter().sum();
    (offsets, tree_size)
}

/// Round `n` up to the nearest multiple of `unit`
fn round_to_multiple(n: usize, unit: usize) -> usize {
    (n + unit - 1) & !(unit - 1)
}

/// Pad zero to salt if necessary.
///
/// According to https://www.kernel.org/doc/html/latest/filesystems/fsverity.html:
///
/// If a salt was specified, then it’s zero-padded to the closest multiple of the input size of the
/// hash algorithm’s compression function, e.g. 64 bytes for SHA-256 or 128 bytes for SHA-512. The
/// padded salt is prepended to every data or Merkle tree block that is hashed.
fn zero_pad_salt(salt: &[u8], algorithm: &Algorithm) -> Vec<u8> {
    if salt.is_empty() {
        salt.to_vec()
    } else {
        let padded_len = round_to_multiple(salt.len(), algorithm.block_len);
        let mut salt = salt.to_vec();
        salt.resize(padded_len, 0);
        salt
    }
}

#[cfg(test)]
mod tests {
    use crate::*;
    use ring::digest;
    use std::fs::{self, File};

    #[test]
    fn compare_with_golden_output() -> Result<()> {
        // The golden outputs are generated by using the `fsverity` utility.
        let sizes = ["512", "4K", "1M", "10000000"];
        for size in sizes.iter() {
            let input_name = format!("testdata/input.{}", size);
            let mut input = File::open(&input_name)?;
            let golden_hash_tree = fs::read(format!("testdata/input.{}.hash", size))?;
            let golden_descriptor = fs::read(format!("testdata/input.{}.descriptor", size))?;
            let golden_root_hash = &golden_descriptor[16..16 + 32];

            let size = std::fs::metadata(&input_name)?.len() as usize;
            let salt = vec![1, 2, 3, 4, 5, 6];
            let ht = HashTree::from(&mut input, size, &salt, 4096, &digest::SHA256)?;

            assert_eq!(golden_hash_tree.as_slice(), ht.tree.as_slice());
            assert_eq!(golden_root_hash, ht.root_hash.as_slice());
        }
        Ok(())
    }
}
