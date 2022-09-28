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

//! Main entry point for the microdroid DICE service implementation.

use android_hardware_security_dice::aidl::android::hardware::security::dice::{
    Bcc::Bcc, BccHandover::BccHandover, InputValues::InputValues as BinderInputValues,
    Signature::Signature,
};
use anyhow::{bail, ensure, Context, Error, Result};
use byteorder::{NativeEndian, ReadBytesExt};
use dice::{ContextImpl, OpenDiceCborContext};
use diced::{dice, DiceMaintenance, DiceNode, DiceNodeImpl};
use diced_utils::make_bcc_handover;
use libc::{c_void, mmap, munmap, MAP_FAILED, MAP_PRIVATE, PROT_READ};
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::io::AsRawFd;
use std::panic;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use std::slice;
use std::sync::{Arc, RwLock};

const AVF_STRICT_BOOT: &str = "/sys/firmware/devicetree/base/chosen/avf,strict-boot";
const DICE_NODE_SERVICE_NAME: &str = "android.security.dice.IDiceNode";
const DICE_MAINTENANCE_SERVICE_NAME: &str = "android.security.dice.IDiceMaintenance";

/// Artifacts that are mapped into the process address space from the driver.
struct MappedDriverArtifacts<'a> {
    mmap_addr: *mut c_void,
    mmap_size: usize,
    cdi_attest: &'a [u8; dice::CDI_SIZE],
    cdi_seal: &'a [u8; dice::CDI_SIZE],
    bcc: &'a [u8],
}

impl MappedDriverArtifacts<'_> {
    fn new(driver_path: &Path) -> Result<Self> {
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
        Ok(Self {
            mmap_addr,
            mmap_size,
            cdi_attest: mmap_buf[4..36].try_into().unwrap(),
            cdi_seal: mmap_buf[39..71].try_into().unwrap(),
            bcc: &mmap_buf[72..],
        })
    }
}

impl Drop for MappedDriverArtifacts<'_> {
    fn drop(&mut self) {
        // All references to the mapped region have the same lifetime as self.
        // Since self is being dropped, so are all the references to the mapped
        // region meaning its safe to unmap.
        let ret = unsafe { munmap(self.mmap_addr, self.mmap_size) };
        if ret != 0 {
            log::warn!("Failed to munmap ({})", ret);
        }
    }
}

/// Artifacts that are kept in the process address space after the artifacts
/// from the driver have been consumed.
#[derive(Clone, Serialize, Deserialize)]
struct RawArtifacts {
    cdi_attest: [u8; dice::CDI_SIZE],
    cdi_seal: [u8; dice::CDI_SIZE],
    bcc: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
enum UpdatableArtifacts {
    Invalid,
    Driver(PathBuf),
    Updated(RawArtifacts),
}

impl UpdatableArtifacts {
    fn get(
        &self,
        input_values: &BinderInputValues,
    ) -> Result<(dice::CdiAttest, dice::CdiSeal, Vec<u8>)> {
        let input_values: diced_utils::InputValues = input_values.into();
        match self {
            Self::Invalid => bail!("No DICE artifacts available."),
            Self::Driver(driver_path) => {
                let artifacts = MappedDriverArtifacts::new(driver_path.as_path())?;
                dice::OpenDiceCborContext::new().bcc_main_flow(
                    artifacts.cdi_attest,
                    artifacts.cdi_seal,
                    artifacts.bcc,
                    &input_values,
                )
            }
            Self::Updated(artifacts) => dice::OpenDiceCborContext::new().bcc_main_flow(
                &artifacts.cdi_attest,
                &artifacts.cdi_seal,
                &artifacts.bcc,
                &input_values,
            ),
        }
        .context("Deriving artifacts")
    }

    fn update(self, inputs: &BinderInputValues) -> Result<Self> {
        if let Self::Invalid = self {
            bail!("Cannot update invalid DICE artifacts.");
        }
        let (cdi_attest, cdi_seal, bcc) =
            self.get(inputs).context("Failed to get update artifacts.")?;
        if let Self::Driver(ref driver_path) = self {
            // Writing to the device wipes the artifacts. The string is ignored
            // by the driver but included for documentation.
            fs::write(driver_path, "wipe")
                .map_err(|error| Error::new(error).context("Wiping driver"))?;
        }
        Ok(Self::Updated(RawArtifacts {
            cdi_attest: cdi_attest[..].try_into().unwrap(),
            cdi_seal: cdi_seal[..].try_into().unwrap(),
            bcc,
        }))
    }
}

struct ArtifactManager {
    artifacts: RwLock<UpdatableArtifacts>,
}

impl ArtifactManager {
    fn new(driver_path: &Path) -> Self {
        Self {
            artifacts: RwLock::new(if driver_path.exists() {
                log::info!("Using DICE values from driver");
                UpdatableArtifacts::Driver(driver_path.to_path_buf())
            } else if Path::new(AVF_STRICT_BOOT).exists() {
                log::error!("Strict boot requires DICE value from driver but none were found");
                UpdatableArtifacts::Invalid
            } else {
                log::warn!("Using sample DICE values");
                let (cdi_attest, cdi_seal, bcc) = diced_sample_inputs::make_sample_bcc_and_cdis()
                    .expect("Failed to create sample dice artifacts.");
                UpdatableArtifacts::Updated(RawArtifacts {
                    cdi_attest: cdi_attest[..].try_into().unwrap(),
                    cdi_seal: cdi_seal[..].try_into().unwrap(),
                    bcc,
                })
            }),
        }
    }
}

impl DiceNodeImpl for ArtifactManager {
    fn sign(
        &self,
        client: BinderInputValues,
        input_values: &[BinderInputValues],
        message: &[u8],
    ) -> Result<Signature> {
        ensure!(input_values.is_empty(), "Extra input values not supported");
        let artifacts = self.artifacts.read().unwrap().clone();
        let (cdi_attest, _, _) =
            artifacts.get(&client).context("Failed to get signing artifacts.")?;
        let mut dice = OpenDiceCborContext::new();
        let seed = dice
            .derive_cdi_private_key_seed(
                cdi_attest[..].try_into().context("Failed to convert cdi_attest.")?,
            )
            .context("Failed to derive seed from cdi_attest.")?;
        let (_public_key, private_key) = dice
            .keypair_from_seed(seed[..].try_into().context("Failed to convert seed.")?)
            .context("Failed to derive keypair from seed.")?;
        let signature = dice
            .sign(message, private_key[..].try_into().context("Failed to convert private_key.")?)
            .context("Failed to sign.")?;
        Ok(Signature { data: signature })
    }

    fn get_attestation_chain(
        &self,
        client: BinderInputValues,
        input_values: &[BinderInputValues],
    ) -> Result<Bcc> {
        ensure!(input_values.is_empty(), "Extra input values not supported");
        let artifacts = self.artifacts.read().unwrap().clone();
        let (_, _, bcc) =
            artifacts.get(&client).context("Failed to get attestation chain artifacts.")?;
        Ok(Bcc { data: bcc })
    }

    fn derive(
        &self,
        client: BinderInputValues,
        input_values: &[BinderInputValues],
    ) -> Result<BccHandover> {
        ensure!(input_values.is_empty(), "Extra input values not supported");
        let artifacts = self.artifacts.read().unwrap().clone();
        let (cdi_attest, cdi_seal, bcc) =
            artifacts.get(&client).context("Failed to get attestation chain artifacts.")?;
        make_bcc_handover(
            &cdi_attest
                .to_vec()
                .as_slice()
                .try_into()
                .context("Trying to convert cdi_attest to sized array.")?,
            &cdi_seal
                .to_vec()
                .as_slice()
                .try_into()
                .context("Trying to convert cdi_seal to sized array.")?,
            &bcc,
        )
        .context("Trying to construct BccHandover.")
    }

    fn demote(
        &self,
        _client: BinderInputValues,
        _input_values: &[BinderInputValues],
    ) -> Result<()> {
        bail!("Demote not supported.");
    }

    fn demote_self(&self, input_values: &[BinderInputValues]) -> Result<()> {
        ensure!(input_values.len() == 1, "Can only demote_self one level.");
        let mut artifacts = self.artifacts.write().unwrap();
        *artifacts = (*artifacts).clone().update(&input_values[0])?;
        Ok(())
    }
}

fn main() {
    android_logger::init_once(
        android_logger::Config::default().with_tag("dice").with_min_level(log::Level::Debug),
    );
    // Redirect panic messages to logcat.
    panic::set_hook(Box::new(|panic_info| {
        log::error!("{}", panic_info);
    }));

    // Saying hi.
    log::info!("DICE service is starting.");

    let node_impl = Arc::new(ArtifactManager::new(Path::new("/dev/open-dice0")));

    let node = DiceNode::new_as_binder(node_impl.clone())
        .expect("Failed to create IDiceNode service instance.");

    let maintenance = DiceMaintenance::new_as_binder(node_impl)
        .expect("Failed to create IDiceMaintenance service instance.");

    binder::add_service(DICE_NODE_SERVICE_NAME, node.as_binder())
        .expect("Failed to register IDiceNode Service");

    binder::add_service(DICE_MAINTENANCE_SERVICE_NAME, maintenance.as_binder())
        .expect("Failed to register IDiceMaintenance Service");

    log::info!("Joining thread pool now.");
    binder::ProcessState::join_thread_pool();
}
