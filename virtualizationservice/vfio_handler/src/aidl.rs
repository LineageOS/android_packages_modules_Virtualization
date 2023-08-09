// Copyright 2023, The Android Open Source Project
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

//! Implementation of the AIDL interface of the VirtualizationService.

use anyhow::{anyhow, Context};
use android_system_virtualizationservice_internal::aidl::android::system::virtualizationservice_internal::IVfioHandler::IVfioHandler;
use android_system_virtualizationservice_internal::binder::ParcelFileDescriptor;
use binder::{self, ExceptionCode, Interface, IntoBinderResult};
use lazy_static::lazy_static;
use std::fs::{read_link, write};
use std::io::Write;
use std::path::Path;

#[derive(Debug, Default)]
pub struct VfioHandler {}

impl VfioHandler {
    pub fn init() -> VfioHandler {
        VfioHandler::default()
    }
}

impl Interface for VfioHandler {}

impl IVfioHandler for VfioHandler {
    fn bindDevicesToVfioDriver(
        &self,
        devices: &[String],
        dtbo: &ParcelFileDescriptor,
    ) -> binder::Result<()> {
        // permission check is already done by IVirtualizationServiceInternal.
        if !*IS_VFIO_SUPPORTED {
            return Err(anyhow!("VFIO-platform not supported"))
                .or_binder_exception(ExceptionCode::UNSUPPORTED_OPERATION);
        }

        devices.iter().try_for_each(|x| bind_device(Path::new(x)))?;

        let mut dtbo = dtbo
            .as_ref()
            .try_clone()
            .context("Failed to clone File from ParcelFileDescriptor")
            .or_binder_exception(ExceptionCode::BAD_PARCELABLE)?;
        // TODO(b/291191362): write DTBO for devices to dtbo.
        dtbo.write(b"\n")
            .context("Can't write to ParcelFileDescriptor")
            .or_binder_exception(ExceptionCode::BAD_PARCELABLE)?;
        Ok(())
    }
}

const DEV_VFIO_PATH: &str = "/dev/vfio/vfio";
const SYSFS_PLATFORM_DEVICES_PATH: &str = "/sys/devices/platform/";
const VFIO_PLATFORM_DRIVER_PATH: &str = "/sys/bus/platform/drivers/vfio-platform";
const SYSFS_PLATFORM_DRIVERS_PROBE_PATH: &str = "/sys/bus/platform/drivers_probe";

lazy_static! {
    static ref IS_VFIO_SUPPORTED: bool = is_vfio_supported();
}

fn is_vfio_supported() -> bool {
    Path::new(DEV_VFIO_PATH).exists() && Path::new(VFIO_PLATFORM_DRIVER_PATH).exists()
}

fn check_platform_device(path: &Path) -> binder::Result<()> {
    if !path.exists() {
        return Err(anyhow!("no such device {path:?}"))
            .or_binder_exception(ExceptionCode::ILLEGAL_ARGUMENT);
    }

    if !path.starts_with(SYSFS_PLATFORM_DEVICES_PATH) {
        return Err(anyhow!("{path:?} is not a platform device"))
            .or_binder_exception(ExceptionCode::ILLEGAL_ARGUMENT);
    }

    Ok(())
}

fn get_device_iommu_group(path: &Path) -> Option<u64> {
    let group_path = read_link(path.join("iommu_group")).ok()?;
    let group = group_path.file_name()?;
    group.to_str()?.parse().ok()
}

fn is_bound_to_vfio_driver(path: &Path) -> bool {
    let Ok(driver_path) = read_link(path.join("driver")) else {
        return false;
    };
    let Some(driver) = driver_path.file_name() else {
        return false;
    };
    driver.to_str().unwrap_or("") == "vfio-platform"
}

fn bind_vfio_driver(path: &Path) -> binder::Result<()> {
    if is_bound_to_vfio_driver(path) {
        // already bound
        return Ok(());
    }

    // unbind
    let Some(device) = path.file_name() else {
        return Err(anyhow!("can't get device name from {path:?}"))
            .or_binder_exception(ExceptionCode::ILLEGAL_ARGUMENT);
    };
    let Some(device_str) = device.to_str() else {
        return Err(anyhow!("invalid filename {device:?}"))
            .or_binder_exception(ExceptionCode::ILLEGAL_ARGUMENT);
    };
    let unbind_path = path.join("driver/unbind");
    if unbind_path.exists() {
        write(&unbind_path, device_str.as_bytes())
            .with_context(|| format!("could not unbind {device_str}"))
            .or_service_specific_exception(-1)?;
    }

    // bind to VFIO
    write(path.join("driver_override"), b"vfio-platform")
        .with_context(|| format!("could not bind {device_str} to vfio-platform"))
        .or_service_specific_exception(-1)?;

    write(SYSFS_PLATFORM_DRIVERS_PROBE_PATH, device_str.as_bytes())
        .with_context(|| format!("could not write {device_str} to drivers-probe"))
        .or_service_specific_exception(-1)?;

    // final check
    if !is_bound_to_vfio_driver(path) {
        return Err(anyhow!("{path:?} still not bound to vfio driver"))
            .or_service_specific_exception(-1);
    }

    if get_device_iommu_group(path).is_none() {
        return Err(anyhow!("can't get iommu group for {path:?}"))
            .or_service_specific_exception(-1);
    }

    Ok(())
}

fn bind_device(path: &Path) -> binder::Result<()> {
    let path = path
        .canonicalize()
        .with_context(|| format!("can't canonicalize {path:?}"))
        .or_binder_exception(ExceptionCode::ILLEGAL_ARGUMENT)?;

    check_platform_device(&path)?;
    bind_vfio_driver(&path)
}
