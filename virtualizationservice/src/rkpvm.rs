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

//! Handles the RKP (Remote Key Provisioning) VM and host communication.
//! The RKP VM will be recognized and attested by the RKP server periodically and
//! serves as a trusted platform to attest a client VM.

use android_system_virtualizationservice::{
    aidl::android::system::virtualizationservice::{
        CpuTopology::CpuTopology, DiskImage::DiskImage, Partition::Partition,
        PartitionType::PartitionType, VirtualMachineConfig::VirtualMachineConfig,
        VirtualMachineRawConfig::VirtualMachineRawConfig,
    },
    binder::{ParcelFileDescriptor, ProcessState},
};
use anyhow::{anyhow, Context, Result};
use log::info;
use std::fs::File;
use std::time::Duration;
use vmclient::VmInstance;

const RIALTO_PATH: &str = "/apex/com.android.virt/etc/rialto.bin";

pub(crate) fn request_certificate(
    csr: &[u8],
    instance_img_fd: &ParcelFileDescriptor,
) -> Result<Vec<u8>> {
    // We need to start the thread pool for Binder to work properly, especially link_to_death.
    ProcessState::start_thread_pool();

    let virtmgr = vmclient::VirtualizationService::new().context("Failed to spawn virtmgr")?;
    let service = virtmgr.connect().context("virtmgr failed to connect")?;
    info!("service_vm: Connected to VirtualizationService");
    // TODO(b/272226230): Either turn rialto into the service VM or use an empty payload here.
    // If using an empty payload, the service code will be part of pvmfw.
    let rialto = File::open(RIALTO_PATH).context("Failed to open Rialto kernel binary")?;

    // TODO(b/272226230): Initialize the partition from virtualization manager.
    const INSTANCE_IMG_SIZE_BYTES: i64 = 1 << 20; // 1MB
    service
        .initializeWritablePartition(
            instance_img_fd,
            INSTANCE_IMG_SIZE_BYTES,
            PartitionType::ANDROID_VM_INSTANCE,
        )
        .context("Failed to initialize instange.img")?;
    let instance_img =
        instance_img_fd.as_ref().try_clone().context("Failed to clone instance.img")?;
    let instance_img = ParcelFileDescriptor::new(instance_img);
    let writable_partitions = vec![Partition {
        label: "vm-instance".to_owned(),
        image: Some(instance_img),
        writable: true,
    }];
    info!("service_vm: Finished initializing instance.img...");

    let config = VirtualMachineConfig::RawConfig(VirtualMachineRawConfig {
        name: String::from("Service VM"),
        kernel: None,
        initrd: None,
        params: None,
        bootloader: Some(ParcelFileDescriptor::new(rialto)),
        disks: vec![DiskImage { image: None, partitions: writable_partitions, writable: true }],
        protectedVm: true,
        memoryMib: 300,
        cpuTopology: CpuTopology::ONE_CPU,
        platformVersion: "~1.0".to_string(),
        gdbPort: 0, // No gdb
        ..Default::default()
    });
    let vm = VmInstance::create(service.as_ref(), &config, None, None, None, None)
        .context("Failed to create service VM")?;

    info!("service_vm: Starting Service VM...");
    vm.start().context("Failed to start service VM")?;

    // TODO(b/274441673): The host can send the CSR to the RKP VM for attestation.
    // Wait for VM to finish.
    vm.wait_for_death_with_timeout(Duration::from_secs(10))
        .ok_or_else(|| anyhow!("Timed out waiting for VM exit"))?;

    info!("service_vm: Finished getting the certificate");
    Ok([b"Return: ", csr].concat())
}
