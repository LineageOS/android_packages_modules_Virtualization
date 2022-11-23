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

/// `crypt` module implements the "crypt" target in the device mapper framework. Specifically,
/// it provides `DmCryptTargetBuilder` struct which is used to construct a `DmCryptTarget` struct
/// which is then given to `DeviceMapper` to create a mapper device.
use crate::util::*;
use crate::DmTargetSpec;

use anyhow::{bail, Context, Result};
use data_model::DataInit;
use std::io::Write;
use std::mem::size_of;
use std::path::Path;

const SECTOR_SIZE: u64 = 512;

// The UAPI for the crypt target is at:
// Documentation/admin-guide/device-mapper/dm-crypt.rst

/// Supported ciphers
pub enum CipherType {
    // AES-256-HCTR2 takes a 32-byte key
    AES256HCTR2,
    // XTS requires key of twice the length of the underlying block cipher i.e., 64B for AES256
    AES256XTS,
}
impl CipherType {
    fn get_kernel_crypto_name(&self) -> &str {
        match *self {
            // We use "plain64" as the IV/nonce generation algorithm -
            // which basically is the sector number.
            CipherType::AES256HCTR2 => "aes-hctr2-plain64",
            CipherType::AES256XTS => "aes-xts-plain64",
        }
    }
}

pub struct DmCryptTarget(Box<[u8]>);

impl DmCryptTarget {
    /// Flatten into slice
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }
}

pub struct DmCryptTargetBuilder<'a> {
    cipher: CipherType,
    key: Option<&'a [u8]>,
    iv_offset: u64,
    device_path: Option<&'a Path>,
    offset: u64,
    device_size: u64,
    // TODO(b/238179332) Extend this to include opt_params, in particular 'integrity'
}

impl<'a> Default for DmCryptTargetBuilder<'a> {
    fn default() -> Self {
        DmCryptTargetBuilder {
            cipher: CipherType::AES256HCTR2,
            key: None,
            iv_offset: 0,
            device_path: None,
            offset: 0,
            device_size: 0,
        }
    }
}

impl<'a> DmCryptTargetBuilder<'a> {
    /// Sets the device that will be used as the data device (i.e. providing actual data).
    pub fn data_device(&mut self, p: &'a Path, size: u64) -> &mut Self {
        self.device_path = Some(p);
        self.device_size = size;
        self
    }

    /// Sets the encryption cipher.
    pub fn cipher(&mut self, cipher: CipherType) -> &mut Self {
        self.cipher = cipher;
        self
    }

    /// Sets the key used for encryption. Input is byte array.
    pub fn key(&mut self, key: &'a [u8]) -> &mut Self {
        self.key = Some(key);
        self
    }

    /// The IV offset is a sector count that is added to the sector number before creating the IV.
    pub fn iv_offset(&mut self, iv_offset: u64) -> &mut Self {
        self.iv_offset = iv_offset;
        self
    }

    /// Starting sector within the device where the encrypted data begins
    pub fn offset(&mut self, offset: u64) -> &mut Self {
        self.offset = offset;
        self
    }

    /// Constructs a `DmCryptTarget`.
    pub fn build(&self) -> Result<DmCryptTarget> {
        // The `DmCryptTarget` struct actually is a flattened data consisting of a header and
        // body. The format of the header is `dm_target_spec` as defined in
        // include/uapi/linux/dm-ioctl.h.
        let device_path = self
            .device_path
            .context("data device is not set")?
            .to_str()
            .context("data device path is not encoded in utf8")?;

        let key =
            if let Some(key) = self.key { hexstring_from(key) } else { bail!("key is not set") };

        // Step2: serialize the information according to the spec, which is ...
        // DmTargetSpec{...}
        // <cipher> <key> <iv_offset> <device path> \
        // <offset> [<#opt_params> <opt_params>]
        let mut body = String::new();
        use std::fmt::Write;
        write!(&mut body, "{} ", self.cipher.get_kernel_crypto_name())?;
        write!(&mut body, "{} ", key)?;
        write!(&mut body, "{} ", self.iv_offset)?;
        write!(&mut body, "{} ", device_path)?;
        write!(&mut body, "{} ", self.offset)?;
        write!(&mut body, "\0")?; // null terminator

        let size = size_of::<DmTargetSpec>() + body.len();
        let aligned_size = (size + 7) & !7; // align to 8 byte boundaries
        let padding = aligned_size - size;

        let mut header = DmTargetSpec::new("crypt")?;
        header.sector_start = 0;
        header.length = self.device_size / SECTOR_SIZE; // number of 512-byte sectors
        header.next = aligned_size as u32;

        let mut buf = Vec::with_capacity(aligned_size);
        buf.write_all(header.as_slice())?;
        buf.write_all(body.as_bytes())?;
        buf.write_all(vec![0; padding].as_slice())?;

        Ok(DmCryptTarget(buf.into_boxed_slice()))
    }
}
