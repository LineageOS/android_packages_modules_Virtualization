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

use anyhow::{anyhow, bail, Context, Error, Result};
use byteorder::{NativeEndian, ReadBytesExt};
use diced_open_dice::{
    bcc_handover_parse, retry_bcc_main_flow, BccHandover, Cdi, Config, DiceMode, Hash, Hidden,
    InputValues, OwnedDiceArtifacts,
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

/// Derives a sealing key from the DICE sealing CDI.
pub fn derive_sealing_key(
    cdi_seal: &Cdi,
    salt: &[u8],
    info: &[u8],
    keysize: usize,
) -> Result<ZVec> {
    let mut key = ZVec::new(keysize)?;
    hkdf(&mut key, Md::sha256(), cdi_seal, salt, info)?;
    Ok(key)
}

/// Artifacts that are mapped into the process address space from the driver.
pub enum DiceDriver<'a> {
    Real {
        driver_path: PathBuf,
        mmap_addr: *mut c_void,
        mmap_size: usize,
        bcc_handover: BccHandover<'a>,
    },
    Fake(OwnedDiceArtifacts),
}

impl DiceDriver<'_> {
    pub fn new(driver_path: &Path) -> Result<Self> {
        if driver_path.exists() {
            log::info!("Using DICE values from driver");
        } else if super::is_strict_boot() {
            bail!("Strict boot requires DICE value from driver but none were found");
        } else {
            log::warn!("Using sample DICE values");
            let dice_artifacts = diced_sample_inputs::make_sample_bcc_and_cdis()
                .expect("Failed to create sample dice artifacts.");
            return Ok(Self::Fake(dice_artifacts));
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
        let bcc_handover =
            bcc_handover_parse(mmap_buf).map_err(|_| anyhow!("Failed to parse Bcc Handover"))?;
        Ok(Self::Real {
            driver_path: driver_path.to_path_buf(),
            mmap_addr,
            mmap_size,
            bcc_handover,
        })
    }

    pub fn get_sealing_key(&self, identifier: &[u8]) -> Result<ZVec> {
        // Deterministically derive a key to use for sealing data, rather than using the CDI
        // directly, so we have the chance to rotate the key if needed. A salt isn't needed as the
        // input key material is already cryptographically strong.
        let cdi_seal = match self {
            Self::Real { bcc_handover, .. } => bcc_handover.cdi_seal,
            Self::Fake(fake) => &fake.cdi_values.cdi_seal,
        };
        let salt = &[];
        derive_sealing_key(cdi_seal, salt, identifier, 32)
    }

    pub fn derive(
        self,
        code_hash: Hash,
        config_desc: &[u8],
        authority_hash: Hash,
        debug: bool,
        hidden: Hidden,
    ) -> Result<OwnedDiceArtifacts> {
        let input_values = InputValues::new(
            code_hash,
            Config::Descriptor(config_desc),
            authority_hash,
            if debug { DiceMode::kDiceModeDebug } else { DiceMode::kDiceModeNormal },
            hidden,
        );
        let (cdi_attest, cdi_seal, bcc) = match &self {
            Self::Real { bcc_handover, .. } => (
                bcc_handover.cdi_attest,
                bcc_handover.cdi_seal,
                bcc_handover.bcc.ok_or_else(|| anyhow!("bcc is none"))?,
            ),
            Self::Fake(fake) => {
                (&fake.cdi_values.cdi_attest, &fake.cdi_values.cdi_seal, fake.bcc.as_slice())
            }
        };
        let dice_artifacts = retry_bcc_main_flow(cdi_attest, cdi_seal, bcc, &input_values)
            .context("DICE derive from driver")?;
        if let Self::Real { driver_path, .. } = &self {
            // Writing to the device wipes the artifacts. The string is ignored by the driver but
            // included for documentation.
            fs::write(driver_path, "wipe")
                .map_err(|err| Error::new(err).context("Wiping driver"))?;
        }
        Ok(dice_artifacts)
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
