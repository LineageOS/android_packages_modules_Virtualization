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

//! Service VM.

use android_system_virtualizationservice::{
    aidl::android::system::virtualizationservice::{
        CpuTopology::CpuTopology, DiskImage::DiskImage,
        IVirtualizationService::IVirtualizationService, Partition::Partition,
        PartitionType::PartitionType, VirtualMachineConfig::VirtualMachineConfig,
        VirtualMachineRawConfig::VirtualMachineRawConfig,
    },
    binder::ParcelFileDescriptor,
};
use anyhow::{Context, Result};
use log::info;
use std::fs::{File, OpenOptions};
use std::path::Path;
use vmclient::VmInstance;

const VIRT_DATA_DIR: &str = "/data/misc/apexdata/com.android.virt";
const RIALTO_PATH: &str = "/apex/com.android.virt/etc/rialto.bin";
const INSTANCE_IMG_NAME: &str = "service_vm_instance.img";
const INSTANCE_IMG_SIZE_BYTES: i64 = 1 << 20; // 1MB
const MEMORY_MB: i32 = 300;

/// Starts the service VM and returns its instance.
/// The same instance image is used for different VMs.
/// TODO(b/278858244): Allow only one service VM running at each time.
pub fn start() -> Result<VmInstance> {
    let virtmgr = vmclient::VirtualizationService::new().context("Failed to spawn VirtMgr")?;
    let service = virtmgr.connect().context("Failed to connect to VirtMgr")?;
    info!("Connected to VirtMgr for service VM");

    let vm = vm_instance(service.as_ref())?;

    vm.start().context("Failed to start service VM")?;
    info!("Service VM started");
    Ok(vm)
}

fn vm_instance(service: &dyn IVirtualizationService) -> Result<VmInstance> {
    let instance_img = instance_img(service)?;
    let writable_partitions = vec![Partition {
        label: "vm-instance".to_owned(),
        image: Some(instance_img),
        writable: true,
    }];
    let rialto = File::open(RIALTO_PATH).context("Failed to open Rialto kernel binary")?;
    let config = VirtualMachineConfig::RawConfig(VirtualMachineRawConfig {
        name: String::from("Service VM"),
        bootloader: Some(ParcelFileDescriptor::new(rialto)),
        disks: vec![DiskImage { image: None, partitions: writable_partitions, writable: true }],
        protectedVm: true,
        memoryMib: MEMORY_MB,
        cpuTopology: CpuTopology::ONE_CPU,
        platformVersion: "~1.0".to_string(),
        gdbPort: 0, // No gdb
        ..Default::default()
    });
    let console_out = None;
    let console_in = None;
    let log = None;
    let callback = None;
    VmInstance::create(service, &config, console_out, console_in, log, callback)
        .context("Failed to create service VM")
}

fn instance_img(service: &dyn IVirtualizationService) -> Result<ParcelFileDescriptor> {
    let instance_img_path = Path::new(VIRT_DATA_DIR).join(INSTANCE_IMG_NAME);
    if instance_img_path.exists() {
        // TODO(b/298174584): Try to recover if the service VM is triggered by rkpd.
        return Ok(OpenOptions::new()
            .read(true)
            .write(true)
            .open(instance_img_path)
            .map(ParcelFileDescriptor::new)?);
    }
    let instance_img = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(instance_img_path)
        .map(ParcelFileDescriptor::new)?;
    service.initializeWritablePartition(
        &instance_img,
        INSTANCE_IMG_SIZE_BYTES,
        PartitionType::ANDROID_VM_INSTANCE,
    )?;
    Ok(instance_img)
}
