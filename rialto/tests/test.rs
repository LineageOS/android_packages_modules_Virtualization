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

//! Integration test for Rialto.

use android_system_virtualizationservice::{
    aidl::android::system::virtualizationservice::{
        CpuTopology::CpuTopology, DiskImage::DiskImage, Partition::Partition,
        VirtualMachineConfig::VirtualMachineConfig,
        VirtualMachineRawConfig::VirtualMachineRawConfig,
    },
    binder::{ParcelFileDescriptor, ProcessState},
};
use anyhow::{Context, Result};
use log::info;
use service_vm_comm::{Request, Response, VmType};
use service_vm_manager::ServiceVm;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::os::unix::io::FromRawFd;
use std::panic;
use std::path::PathBuf;
use std::thread;
use vmclient::VmInstance;

const SIGNED_RIALTO_PATH: &str = "/data/local/tmp/rialto_test/arm64/rialto.bin";
const UNSIGNED_RIALTO_PATH: &str = "/data/local/tmp/rialto_test/arm64/rialto_unsigned.bin";
const INSTANCE_IMG_PATH: &str = "/data/local/tmp/rialto_test/arm64/instance.img";

fn rialto_path(vm_type: VmType) -> &'static str {
    match vm_type {
        VmType::ProtectedVm => SIGNED_RIALTO_PATH,
        VmType::NonProtectedVm => UNSIGNED_RIALTO_PATH,
    }
}

#[test]
fn process_requests_in_protected_vm() -> Result<()> {
    let mut vm = start_service_vm(VmType::ProtectedVm)?;

    check_processing_reverse_request(&mut vm)?;
    Ok(())
}

#[test]
fn process_requests_in_non_protected_vm() -> Result<()> {
    let mut vm = start_service_vm(VmType::NonProtectedVm)?;

    check_processing_reverse_request(&mut vm)?;
    Ok(())
}

fn check_processing_reverse_request(vm: &mut ServiceVm) -> Result<()> {
    // TODO(b/292080257): Test with message longer than the receiver's buffer capacity
    // 1024 bytes once the guest virtio-vsock driver fixes the credit update in recv().
    let message = "abc".repeat(166);
    let request = Request::Reverse(message.as_bytes().to_vec());

    let response = vm.process_request(&request)?;
    info!("Received response '{response:?}' for the request '{request:?}'.");

    let expected_response: Vec<u8> = message.as_bytes().iter().rev().cloned().collect();
    assert_eq!(Response::Reverse(expected_response), response);
    Ok(())
}

fn start_service_vm(vm_type: VmType) -> Result<ServiceVm> {
    android_logger::init_once(
        android_logger::Config::default().with_tag("rialto").with_min_level(log::Level::Debug),
    );
    // Redirect panic messages to logcat.
    panic::set_hook(Box::new(|panic_info| {
        log::error!("{}", panic_info);
    }));
    // We need to start the thread pool for Binder to work properly, especially link_to_death.
    ProcessState::start_thread_pool();
    ServiceVm::start_vm(vm_instance(vm_type)?, vm_type)
}

fn vm_instance(vm_type: VmType) -> Result<VmInstance> {
    let virtmgr =
        vmclient::VirtualizationService::new().context("Failed to spawn VirtualizationService")?;
    let service = virtmgr.connect().context("Failed to connect to VirtualizationService")?;

    let rialto = File::open(rialto_path(vm_type)).context("Failed to open Rialto kernel binary")?;
    let console = android_log_fd()?;
    let log = android_log_fd()?;

    let disks = match vm_type {
        VmType::ProtectedVm => {
            let instance_img = service_vm_manager::instance_img(
                service.as_ref(),
                PathBuf::from(INSTANCE_IMG_PATH),
            )?;
            let writable_partitions = vec![Partition {
                label: "vm-instance".to_owned(),
                image: Some(instance_img),
                writable: true,
            }];
            vec![DiskImage { image: None, partitions: writable_partitions, writable: true }]
        }
        VmType::NonProtectedVm => vec![],
    };
    let config = VirtualMachineConfig::RawConfig(VirtualMachineRawConfig {
        name: String::from("RialtoTest"),
        kernel: None,
        initrd: None,
        params: None,
        bootloader: Some(ParcelFileDescriptor::new(rialto)),
        disks,
        protectedVm: vm_type.is_protected(),
        memoryMib: 300,
        cpuTopology: CpuTopology::ONE_CPU,
        platformVersion: "~1.0".to_string(),
        gdbPort: 0, // No gdb
        ..Default::default()
    });
    VmInstance::create(
        service.as_ref(),
        &config,
        Some(console),
        /* consoleIn */ None,
        Some(log),
        None,
    )
    .context("Failed to create VM")
}

fn android_log_fd() -> io::Result<File> {
    let (reader_fd, writer_fd) = nix::unistd::pipe()?;

    // SAFETY: These are new FDs with no previous owner.
    let reader = unsafe { File::from_raw_fd(reader_fd) };
    // SAFETY: These are new FDs with no previous owner.
    let writer = unsafe { File::from_raw_fd(writer_fd) };

    thread::spawn(|| {
        for line in BufReader::new(reader).lines() {
            info!("{}", line.unwrap());
        }
    });
    Ok(writer)
}
