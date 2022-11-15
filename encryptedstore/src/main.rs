/*
 * Copyright (C) 2022 The Android Open Source Project
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

//! `encryptedstore` is a program that (as the name indicates) provides encrypted storage
//! solution in a VM. This is based on dm-crypt & requires the (64 bytes') key & the backing device.
//! It uses dm_rust lib.

use anyhow::{ensure, Context, Result};
use clap::{arg, App};
use dm::{crypt::CipherType, util};
use log::info;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;

fn main() -> Result<()> {
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("encryptedstore")
            .with_min_level(log::Level::Info),
    );
    info!("Starting encryptedstore binary");

    let matches = App::new("encryptedstore")
        .args(&[
            arg!(--blkdevice <FILE> "the block device backing the encrypted storage")
                .required(true),
            arg!(--key <KEY> "key (in hex) equivalent to 64 bytes)").required(true),
        ])
        .get_matches();

    let blkdevice = Path::new(matches.value_of("blkdevice").unwrap());
    let key = matches.value_of("key").unwrap();
    ensure!(
        std::fs::metadata(&blkdevice)
            .context(format!("Failed to get metadata of {:?}", blkdevice))?
            .file_type()
            .is_block_device(),
        "The path:{:?} is not of a block device",
        blkdevice
    );

    enable_crypt(blkdevice, key, "cryptdev")?;
    Ok(())
}

fn enable_crypt(data_device: &Path, key: &str, name: &str) -> Result<()> {
    let dev_size = util::blkgetsize64(data_device)?;
    let key = hex::decode(key).context("Unable to decode hex key")?;
    ensure!(key.len() == 64, "We need 64 bytes' key for aes-xts cipher for block encryption");

    // Create the dm-crypt spec
    let target = dm::crypt::DmCryptTargetBuilder::default()
        .data_device(data_device, dev_size)
        .cipher(CipherType::AES256XTS) // TODO(b/259253336) Move to HCTR2 based encryption.
        .key(&key)
        .build()
        .context("Couldn't build the DMCrypt target")?;
    let dm = dm::DeviceMapper::new()?;
    dm.create_crypt_device(name, &target).context("Failed to create dm-crypt device")?;

    Ok(())
}
