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

//! Logic for handling the DICE values and boot operations.

use anyhow::{bail, Context, Error, Result};
use byteorder::{NativeEndian, ReadBytesExt};
use diced_open_dice_cbor::{
    Config, ContextImpl, InputValuesOwned, Mode, OpenDiceCborContext, CDI_SIZE, HASH_SIZE,
    HIDDEN_SIZE,
};
use keystore2_crypto::ZVec;
use libc::{c_void, mmap, munmap, MAP_FAILED, MAP_PRIVATE, PROT_READ};
use openssl::hkdf::hkdf;
use openssl::md::Md;
use std::fs;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use std::slice;

/// Artifacts that are kept in the process address space after the artifacts from the driver have
/// been consumed.
pub struct DiceContext {
    pub cdi_attest: [u8; CDI_SIZE],
    pub cdi_seal: [u8; CDI_SIZE],
    pub bcc: Vec<u8>,
}

/// Artifacts that are mapped into the process address space from the driver.
pub enum DiceDriver<'a> {
    Real {
        driver_path: PathBuf,
        mmap_addr: *mut c_void,
        mmap_size: usize,
        cdi_attest: &'a [u8; CDI_SIZE],
        cdi_seal: &'a [u8; CDI_SIZE],
        bcc: &'a [u8],
    },
    Fake(DiceContext),
}

impl DiceDriver<'_> {
    pub fn new(driver_path: &Path) -> Result<Self> {
        if driver_path.exists() {
            log::info!("Using DICE values from driver");
        } else if super::is_strict_boot() {
            bail!("Strict boot requires DICE value from driver but none were found");
        } else {
            log::warn!("Using sample DICE values");
            let (cdi_attest, cdi_seal, bcc) = diced_sample_inputs::make_sample_bcc_and_cdis()
                .expect("Failed to create sample dice artifacts.");
            return Ok(Self::Fake(DiceContext {
                cdi_attest: cdi_attest[..].try_into().unwrap(),
                cdi_seal: cdi_seal[..].try_into().unwrap(),
                bcc,
            }));
        };

        let mut file = fs::File::open(driver_path)
            .map_err(|error| Error::new(error).context("Opening driver"))?;
        let mmap_size =
            file.read_u64::<NativeEndian>()
                .map_err(|error| Error::new(error).context("Reading driver"))? as usize;
        // It's safe to map the driver as the service will only create a single
        // mapping per process.
        let mmap_addr = unsafe {
            let fd = file.as_raw_fd();
            mmap(null_mut(), mmap_size, PROT_READ, MAP_PRIVATE, fd, 0)
        };
        if mmap_addr == MAP_FAILED {
            bail!("Failed to mmap {:?}", driver_path);
        }
        // The slice is created for the region of memory that was just
        // successfully mapped into the process address space so it will be
        // accessible and not referenced from anywhere else.
        let mmap_buf =
            unsafe { slice::from_raw_parts((mmap_addr as *const u8).as_ref().unwrap(), mmap_size) };
        // Very inflexible parsing / validation of the BccHandover data. Assumes deterministically
        // encoded CBOR.
        //
        // BccHandover = {
        //   1 : bstr .size 32,     ; CDI_Attest
        //   2 : bstr .size 32,     ; CDI_Seal
        //   3 : Bcc,               ; Certificate chain
        // }
        if mmap_buf[0..4] != [0xa3, 0x01, 0x58, 0x20]
            || mmap_buf[36..39] != [0x02, 0x58, 0x20]
            || mmap_buf[71] != 0x03
        {
            bail!("BccHandover format mismatch");
        }
        Ok(Self::Real {
            driver_path: driver_path.to_path_buf(),
            mmap_addr,
            mmap_size,
            cdi_attest: mmap_buf[4..36].try_into().unwrap(),
            cdi_seal: mmap_buf[39..71].try_into().unwrap(),
            bcc: &mmap_buf[72..],
        })
    }

    pub fn get_sealing_key(&self, identifier: &[u8]) -> Result<ZVec> {
        // Deterministically derive a key to use for sealing data, rather than using the CDI
        // directly, so we have the chance to rotate the key if needed. A salt isn't needed as the
        // input key material is already cryptographically strong.
        let cdi_seal = match self {
            Self::Real { cdi_seal, .. } => cdi_seal,
            Self::Fake(fake) => &fake.cdi_seal,
        };
        let salt = &[];
        let mut key = ZVec::new(32)?;
        hkdf(&mut key, Md::sha256(), cdi_seal, salt, identifier)?;
        Ok(key)
    }

    pub fn derive(
        self,
        code_hash: [u8; HASH_SIZE],
        config_desc: &[u8],
        authority_hash: [u8; HASH_SIZE],
        debug: bool,
        hidden: [u8; HIDDEN_SIZE],
    ) -> Result<DiceContext> {
        let input_values = InputValuesOwned::new(
            code_hash,
            Config::Descriptor(config_desc),
            authority_hash,
            None,
            if debug { Mode::Debug } else { Mode::Normal },
            hidden,
        );
        let (cdi_attest, cdi_seal, bcc) = match &self {
            Self::Real { cdi_attest, cdi_seal, bcc, .. } => (*cdi_attest, *cdi_seal, *bcc),
            Self::Fake(fake) => (&fake.cdi_attest, &fake.cdi_seal, fake.bcc.as_slice()),
        };
        let (cdi_attest, cdi_seal, bcc) = OpenDiceCborContext::new()
            .bcc_main_flow(cdi_attest, cdi_seal, bcc, &input_values)
            .context("DICE derive from driver")?;
        if let Self::Real { driver_path, .. } = &self {
            // Writing to the device wipes the artifacts. The string is ignored by the driver but
            // included for documentation.
            fs::write(driver_path, "wipe")
                .map_err(|err| Error::new(err).context("Wiping driver"))?;
        }
        Ok(DiceContext {
            cdi_attest: cdi_attest[..].try_into().unwrap(),
            cdi_seal: cdi_seal[..].try_into().unwrap(),
            bcc,
        })
    }
}

impl Drop for DiceDriver<'_> {
    fn drop(&mut self) {
        if let &mut Self::Real { mmap_addr, mmap_size, .. } = self {
            // All references to the mapped region have the same lifetime as self. Since self is
            // being dropped, so are all the references to the mapped region meaning its safe to
            // unmap.
            let ret = unsafe { munmap(mmap_addr, mmap_size) };
            if ret != 0 {
                log::warn!("Failed to munmap ({})", ret);
            }
        }
    }
}
