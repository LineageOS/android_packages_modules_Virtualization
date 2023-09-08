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
        VirtualMachineConfig::VirtualMachineConfig,
        VirtualMachineRawConfig::VirtualMachineRawConfig,
    },
    binder::{ParcelFileDescriptor, ProcessState},
};
use anyhow::{bail, Context, Result};
use log::info;
use service_vm_comm::{
    EcdsaP256KeyPair, GenerateCertificateRequestParams, Request, Response, VmType,
};
use service_vm_manager::ServiceVm;
use std::fs::File;
use std::panic;
use std::path::PathBuf;
use vmclient::VmInstance;

const UNSIGNED_RIALTO_PATH: &str = "/data/local/tmp/rialto_test/arm64/rialto_unsigned.bin";
const INSTANCE_IMG_PATH: &str = "/data/local/tmp/rialto_test/arm64/instance.img";

#[test]
fn process_requests_in_protected_vm() -> Result<()> {
    check_processing_requests(VmType::ProtectedVm)
}

#[test]
fn process_requests_in_non_protected_vm() -> Result<()> {
    check_processing_requests(VmType::NonProtectedVm)
}

fn check_processing_requests(vm_type: VmType) -> Result<()> {
    let mut vm = start_service_vm(vm_type)?;

    check_processing_reverse_request(&mut vm)?;
    check_processing_generating_key_pair_request(&mut vm)?;
    check_processing_generating_certificate_request(&mut vm)?;
    Ok(())
}

fn check_processing_reverse_request(vm: &mut ServiceVm) -> Result<()> {
    // TODO(b/292080257): Test with message longer than the receiver's buffer capacity
    // 1024 bytes once the guest virtio-vsock driver fixes the credit update in recv().
    let message = "abc".repeat(166);
    let request = Request::Reverse(message.as_bytes().to_vec());

    let response = vm.process_request(request)?;
    info!("Received response: {response:?}.");

    let expected_response: Vec<u8> = message.as_bytes().iter().rev().cloned().collect();
    assert_eq!(Response::Reverse(expected_response), response);
    Ok(())
}

fn check_processing_generating_key_pair_request(vm: &mut ServiceVm) -> Result<()> {
    let request = Request::GenerateEcdsaP256KeyPair;

    let response = vm.process_request(request)?;
    info!("Received response: {response:?}.");

    match response {
        Response::GenerateEcdsaP256KeyPair(EcdsaP256KeyPair { .. }) => Ok(()),
        _ => bail!("Incorrect response type"),
    }
}

fn check_processing_generating_certificate_request(vm: &mut ServiceVm) -> Result<()> {
    let params = GenerateCertificateRequestParams { keys_to_sign: vec![], challenge: vec![] };
    let request = Request::GenerateCertificateRequest(params);

    let response = vm.process_request(request)?;
    info!("Received response: {response:?}.");

    match response {
        Response::GenerateCertificateRequest(_) => Ok(()),
        _ => bail!("Incorrect response type"),
    }
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
    match vm_type {
        VmType::ProtectedVm => {
            service_vm_manager::protected_vm_instance(PathBuf::from(INSTANCE_IMG_PATH))
        }
        VmType::NonProtectedVm => nonprotected_vm_instance(),
    }
}

fn nonprotected_vm_instance() -> Result<VmInstance> {
    let rialto = File::open(UNSIGNED_RIALTO_PATH).context("Failed to open Rialto kernel binary")?;
    let config = VirtualMachineConfig::RawConfig(VirtualMachineRawConfig {
        name: String::from("Non protected rialto"),
        bootloader: Some(ParcelFileDescriptor::new(rialto)),
        protectedVm: false,
        memoryMib: 300,
        platformVersion: "~1.0".to_string(),
        ..Default::default()
    });
    let console = Some(service_vm_manager::android_log_fd()?);
    let log = Some(service_vm_manager::android_log_fd()?);
    let virtmgr = vmclient::VirtualizationService::new().context("Failed to spawn VirtMgr")?;
    let service = virtmgr.connect().context("Failed to connect to VirtMgr")?;
    info!("Connected to VirtMgr for service VM");
    VmInstance::create(service.as_ref(), &config, console, /* consoleIn */ None, log, None)
        .context("Failed to create VM")
}
