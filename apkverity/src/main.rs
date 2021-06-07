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

//! `apkdmverity` is a program that protects a signed APK file using dm-verity. The APK is assumed
//! to be signed using APK signature scheme V4. The idsig file generated by the signing scheme is
//! also used as an input to provide the merkle tree. This program is currently intended to be used
//! to securely mount the APK inside Microdroid. Since the APK is physically stored in the file
//! system managed by the host Android which is assumed to be compromisable, it is important to
//! keep the integrity of the file "inside" Microdroid.

mod apksigv4;
mod dm;
mod loopdevice;
mod util;

use crate::apksigv4::*;

use anyhow::{bail, Context, Result};
use clap::{App, Arg};
use std::fmt::Debug;
use std::fs;
use std::fs::File;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

fn main() -> Result<()> {
    let matches = App::new("apkverity")
        .about("Creates a dm-verity block device out of APK signed with APK signature scheme V4.")
        .arg(
            Arg::with_name("apk")
                .help("Input APK file. Must be signed using the APK signature scheme V4.")
                .required(true),
        )
        .arg(
            Arg::with_name("idsig")
                .help("The idsig file having the merkle tree and the signing info.")
                .required(true),
        )
        .arg(
            Arg::with_name("name")
                .help(
                    "Name of the dm-verity block device. The block device is created at \
                      \"/dev/mapper/<name>\".",
                )
                .required(true),
        )
        .get_matches();

    let apk = matches.value_of("apk").unwrap();
    let idsig = matches.value_of("idsig").unwrap();
    let name = matches.value_of("name").unwrap();
    enable_verity(apk, idsig, name)?;
    Ok(())
}

struct VerityResult {
    data_device: PathBuf,
    hash_device: PathBuf,
    mapper_device: PathBuf,
}

const BLOCK_SIZE: u64 = 4096;

// Makes a dm-verity block device out of `apk` and its accompanying `idsig` files.
fn enable_verity<P: AsRef<Path> + Debug>(apk: P, idsig: P, name: &str) -> Result<VerityResult> {
    // Attach the apk file to a loop device if the apk file is a regular file. If not (i.e. block
    // device), we only need to get the size and use the block device as it is.
    let (data_device, apk_size) = if fs::metadata(&apk)?.file_type().is_block_device() {
        (apk.as_ref().to_path_buf(), util::blkgetsize64(apk.as_ref())?)
    } else {
        let apk_size = fs::metadata(&apk)?.len();
        if apk_size % BLOCK_SIZE != 0 {
            bail!("The size of {:?} is not multiple of {}.", &apk, BLOCK_SIZE)
        }
        (loopdevice::attach(&apk, 0, apk_size)?, apk_size)
    };

    // Parse the idsig file to locate the merkle tree in it, then attach the file to a loop device
    // with the offset so that the start of the merkle tree becomes the beginning of the loop
    // device.
    let sig = V4Signature::from(File::open(&idsig)?)?;
    let offset = sig.merkle_tree_offset;
    let size = sig.merkle_tree_size as u64;
    let hash_device = loopdevice::attach(&idsig, offset, size)?;

    // Build a dm-verity target spec from the information from the idsig file. The apk and the
    // idsig files are used as the data device and the hash device, respectively.
    let target = dm::DmVerityTargetBuilder::default()
        .data_device(&data_device, apk_size)
        .hash_device(&hash_device)
        .root_digest(&sig.hashing_info.raw_root_hash)
        .hash_algorithm(match sig.hashing_info.hash_algorithm {
            apksigv4::HashAlgorithm::SHA256 => dm::DmVerityHashAlgorithm::SHA256,
        })
        .salt(&sig.hashing_info.salt)
        .build()
        .context(format!("Merkle tree in {:?} is not compatible with dm-verity", &idsig))?;

    // Actually create a dm-verity block device using the spec.
    let dm = dm::DeviceMapper::new()?;
    let mapper_device =
        dm.create_device(&name, &target).context("Failed to create dm-verity device")?;

    Ok(VerityResult { data_device, hash_device, mapper_device })
}

#[cfg(test)]
mod tests {
    use crate::*;
    use std::fs::OpenOptions;
    use std::io::{Cursor, Write};
    use std::os::unix::fs::FileExt;

    struct TestContext<'a> {
        data_backing_file: &'a Path,
        hash_backing_file: &'a Path,
        result: &'a VerityResult,
    }

    fn create_block_aligned_file(path: &Path, data: &[u8]) {
        let mut f = File::create(&path).unwrap();
        f.write_all(data).unwrap();

        // Add padding so that the size of the file is multiple of 4096.
        let aligned_size = (data.len() as u64 + BLOCK_SIZE - 1) & !(BLOCK_SIZE - 1);
        let padding = aligned_size - data.len() as u64;
        f.write_all(vec![0; padding as usize].as_slice()).unwrap();
    }

    fn prepare_inputs(test_dir: &Path, apk: &[u8], idsig: &[u8]) -> (PathBuf, PathBuf) {
        let apk_path = test_dir.join("test.apk");
        let idsig_path = test_dir.join("test.apk.idsig");
        create_block_aligned_file(&apk_path, apk);
        create_block_aligned_file(&idsig_path, idsig);
        (apk_path, idsig_path)
    }

    fn run_test(apk: &[u8], idsig: &[u8], name: &str, check: fn(TestContext)) {
        let test_dir = tempfile::TempDir::new().unwrap();
        let (apk_path, idsig_path) = prepare_inputs(&test_dir.path(), apk, idsig);

        // Run the program and register clean-ups.
        let ret = enable_verity(&apk_path, &idsig_path, name).unwrap();
        let ret = scopeguard::guard(ret, |ret| {
            loopdevice::detach(ret.data_device).unwrap();
            loopdevice::detach(ret.hash_device).unwrap();
            let dm = dm::DeviceMapper::new().unwrap();
            dm.delete_device_deferred(name).unwrap();
        });

        check(TestContext {
            data_backing_file: &apk_path,
            hash_backing_file: &idsig_path,
            result: &ret,
        });
    }

    #[test]
    fn correct_inputs() {
        let apk = include_bytes!("../testdata/test.apk");
        let idsig = include_bytes!("../testdata/test.apk.idsig");
        run_test(apk.as_ref(), idsig.as_ref(), "correct", |ctx| {
            let verity = fs::read(&ctx.result.mapper_device).unwrap();
            let original = fs::read(&ctx.result.data_device).unwrap();
            assert_eq!(verity.len(), original.len()); // fail fast
            assert_eq!(verity.as_slice(), original.as_slice());
        });
    }

    // A single byte change in the APK file causes an IO error
    #[test]
    fn incorrect_apk() {
        let apk = include_bytes!("../testdata/test.apk");
        let idsig = include_bytes!("../testdata/test.apk.idsig");

        let mut modified_apk = Vec::new();
        modified_apk.extend_from_slice(apk);
        if let Some(byte) = modified_apk.get_mut(100) {
            *byte = 1;
        }

        run_test(modified_apk.as_slice(), idsig.as_ref(), "incorrect_apk", |ctx| {
            let ret = fs::read(&ctx.result.mapper_device).map_err(|e| e.kind());
            assert_eq!(ret, Err(std::io::ErrorKind::Other));
        });
    }

    // A single byte change in the merkle tree also causes an IO error
    #[test]
    fn incorrect_merkle_tree() {
        let apk = include_bytes!("../testdata/test.apk");
        let idsig = include_bytes!("../testdata/test.apk.idsig");

        // Make a single-byte change to the merkle tree
        let offset = V4Signature::from(Cursor::new(&idsig)).unwrap().merkle_tree_offset as usize;

        let mut modified_idsig = Vec::new();
        modified_idsig.extend_from_slice(idsig);
        if let Some(byte) = modified_idsig.get_mut(offset + 10) {
            *byte = 1;
        }

        run_test(apk.as_ref(), modified_idsig.as_slice(), "incorrect_merkle_tree", |ctx| {
            let ret = fs::read(&ctx.result.mapper_device).map_err(|e| e.kind());
            assert_eq!(ret, Err(std::io::ErrorKind::Other));
        });
    }

    // APK is not altered when the verity device is created, but later modified. IO error should
    // occur when trying to read the data around the modified location. This is the main scenario
    // that we'd like to protect.
    #[test]
    fn tampered_apk() {
        let apk = include_bytes!("../testdata/test.apk");
        let idsig = include_bytes!("../testdata/test.apk.idsig");

        run_test(apk.as_ref(), idsig.as_ref(), "tampered_apk", |ctx| {
            // At this moment, the verity device is created. Then let's change 10 bytes in the
            // backing data file.
            const MODIFIED_OFFSET: u64 = 10000;
            let f = OpenOptions::new().read(true).write(true).open(ctx.data_backing_file).unwrap();
            f.write_at(&[0, 1], MODIFIED_OFFSET).unwrap();

            // Read around the modified location causes an error
            let f = File::open(&ctx.result.mapper_device).unwrap();
            let mut buf = vec![0; 10]; // just read 10 bytes
            let ret = f.read_at(&mut buf, MODIFIED_OFFSET).map_err(|e| e.kind());
            assert!(ret.is_err());
            assert_eq!(ret, Err(std::io::ErrorKind::Other));
        });
    }

    // idsig file is not alread when the verity device is created, but later modified. Unlike to
    // the APK case, this doesn't occur IO error because the merkle tree is already cached.
    #[test]
    fn tampered_idsig() {
        let apk = include_bytes!("../testdata/test.apk");
        let idsig = include_bytes!("../testdata/test.apk.idsig");
        run_test(apk.as_ref(), idsig.as_ref(), "tampered_idsig", |ctx| {
            // Change 10 bytes in the merkle tree.
            let f = OpenOptions::new().read(true).write(true).open(ctx.hash_backing_file).unwrap();
            f.write_at(&[0, 10], 100).unwrap();

            let verity = fs::read(&ctx.result.mapper_device).unwrap();
            let original = fs::read(&ctx.result.data_device).unwrap();
            assert_eq!(verity.len(), original.len());
            assert_eq!(verity.as_slice(), original.as_slice());
        });
    }

    // test if both files are already block devices
    #[test]
    fn inputs_are_block_devices() {
        use std::ops::Deref;
        let apk = include_bytes!("../testdata/test.apk");
        let idsig = include_bytes!("../testdata/test.apk.idsig");

        let test_dir = tempfile::TempDir::new().unwrap();
        let (apk_path, idsig_path) = prepare_inputs(&test_dir.path(), apk, idsig);

        // attach the files to loop devices to make them block devices
        let apk_size = fs::metadata(&apk_path).unwrap().len();
        let idsig_size = fs::metadata(&idsig_path).unwrap().len();

        // Note that apk_loop_device is not detatched. This is because, when the apk file is
        // already a block device, `enable_verity` uses the block device as it is. The detatching
        // of the data device is done in the scopeguard for the return value of `enable_verity`
        // below. Only the idsig_loop_device needs detatching.
        let apk_loop_device = loopdevice::attach(&apk_path, 0, apk_size).unwrap();
        let idsig_loop_device =
            scopeguard::guard(loopdevice::attach(&idsig_path, 0, idsig_size).unwrap(), |dev| {
                loopdevice::detach(dev).unwrap()
            });

        let name = "loop_as_input";
        // Run the program WITH the loop devices, not the regular files.
        let ret = enable_verity(apk_loop_device.deref(), idsig_loop_device.deref(), &name).unwrap();
        let ret = scopeguard::guard(ret, |ret| {
            loopdevice::detach(ret.data_device).unwrap();
            loopdevice::detach(ret.hash_device).unwrap();
            let dm = dm::DeviceMapper::new().unwrap();
            dm.delete_device_deferred(name).unwrap();
        });

        let verity = fs::read(&ret.mapper_device).unwrap();
        let original = fs::read(&apk_path).unwrap();
        assert_eq!(verity.len(), original.len()); // fail fast
        assert_eq!(verity.as_slice(), original.as_slice());
    }
}
