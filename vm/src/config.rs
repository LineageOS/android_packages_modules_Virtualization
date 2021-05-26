// Copyright 2021, The Android Open Source Project
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

//! Struct for VM configuration.

use android_system_virtualizationservice::{
    aidl::android::system::virtualizationservice::DiskImage::DiskImage as AidlDiskImage,
    aidl::android::system::virtualizationservice::VirtualMachineConfig::VirtualMachineConfig,
    binder::ParcelFileDescriptor,
};
use anyhow::{bail, Context, Error};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::BufReader;
use std::path::{Path, PathBuf};

/// Configuration for a particular VM to be started.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VmConfig {
    /// The filename of the kernel image, if any.
    pub kernel: Option<PathBuf>,
    /// The filename of the initial ramdisk for the kernel, if any.
    pub initrd: Option<PathBuf>,
    /// Parameters to pass to the kernel. As far as the VMM and boot protocol are concerned this is
    /// just a string, but typically it will contain multiple parameters separated by spaces.
    pub params: Option<String>,
    /// The bootloader to use. If this is supplied then the kernel and initrd must not be supplied;
    /// the bootloader is instead responsibly for loading the kernel from one of the disks.
    pub bootloader: Option<PathBuf>,
    /// Disk images to be made available to the VM.
    #[serde(default)]
    pub disks: Vec<DiskImage>,
}

impl VmConfig {
    /// Ensure that the configuration has a valid combination of fields set, or return an error if
    /// not.
    pub fn validate(&self) -> Result<(), Error> {
        if self.bootloader.is_none() && self.kernel.is_none() {
            bail!("VM must have either a bootloader or a kernel image.");
        }
        if self.bootloader.is_some() && (self.kernel.is_some() || self.initrd.is_some()) {
            bail!("Can't have both bootloader and kernel/initrd image.");
        }
        Ok(())
    }

    /// Load the configuration for a VM from the given JSON file, and check that it is valid.
    pub fn load(file: &File) -> Result<VmConfig, Error> {
        let buffered = BufReader::new(file);
        let config: VmConfig = serde_json::from_reader(buffered)?;
        config.validate()?;
        Ok(config)
    }

    /// Convert the `VmConfig` to a [`VirtualMachineConfig`] which can be passed to the Virt
    /// Manager.
    pub fn to_parcelable(&self) -> Result<VirtualMachineConfig, Error> {
        Ok(VirtualMachineConfig {
            kernel: maybe_open_parcel_file(&self.kernel)?,
            initrd: maybe_open_parcel_file(&self.initrd)?,
            params: self.params.clone(),
            bootloader: maybe_open_parcel_file(&self.bootloader)?,
            disks: self
                .disks
                .iter()
                .map(|disk| {
                    Ok(AidlDiskImage {
                        writable: disk.writable,
                        image: Some(open_parcel_file(&disk.image, disk.writable)?),
                    })
                })
                .collect::<Result<_, Error>>()?,
        })
    }
}

/// A disk image to be made available to the VM.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiskImage {
    /// The filename of the disk image.
    pub image: PathBuf,
    /// Whether this disk should be writable by the VM.
    pub writable: bool,
}

/// Try to open the given file and wrap it in a [`ParcelFileDescriptor`].
fn open_parcel_file(filename: &Path, writable: bool) -> Result<ParcelFileDescriptor, Error> {
    Ok(ParcelFileDescriptor::new(
        OpenOptions::new()
            .read(true)
            .write(writable)
            .open(filename)
            .with_context(|| format!("Failed to open {:?}", filename))?,
    ))
}

/// If the given filename is `Some`, try to open it and wrap it in a [`ParcelFileDescriptor`].
fn maybe_open_parcel_file(
    filename: &Option<PathBuf>,
) -> Result<Option<ParcelFileDescriptor>, Error> {
    filename.as_deref().map(|filename| open_parcel_file(filename, false)).transpose()
}
