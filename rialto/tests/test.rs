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
use ciborium::value::Value;
use client_vm_csr::generate_attestation_key_and_csr;
use log::info;
use service_vm_comm::{
    ClientVmAttestationParams, EcdsaP256KeyPair, GenerateCertificateRequestParams, Request,
    RequestProcessingError, Response, VmType,
};
use service_vm_manager::ServiceVm;
use std::fs::File;
use std::io;
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
    let key_pair = check_processing_generating_key_pair_request(&mut vm)?;
    check_processing_generating_certificate_request(&mut vm, &key_pair.maced_public_key)?;
    check_attestation_request(&mut vm, &key_pair.key_blob)?;
    Ok(())
}

fn check_processing_reverse_request(vm: &mut ServiceVm) -> Result<()> {
    let message = "abc".repeat(500);
    let request = Request::Reverse(message.as_bytes().to_vec());

    let response = vm.process_request(request)?;
    info!("Received response: {response:?}.");

    let expected_response: Vec<u8> = message.as_bytes().iter().rev().cloned().collect();
    assert_eq!(Response::Reverse(expected_response), response);
    Ok(())
}

fn check_processing_generating_key_pair_request(vm: &mut ServiceVm) -> Result<EcdsaP256KeyPair> {
    let request = Request::GenerateEcdsaP256KeyPair;

    let response = vm.process_request(request)?;
    info!("Received response: {response:?}.");

    match response {
        Response::GenerateEcdsaP256KeyPair(key_pair) => {
            assert_array_has_nonzero(&key_pair.maced_public_key);
            assert_array_has_nonzero(&key_pair.key_blob);
            Ok(key_pair)
        }
        _ => bail!("Incorrect response type: {response:?}"),
    }
}

fn assert_array_has_nonzero(v: &[u8]) {
    assert!(v.iter().any(|&x| x != 0))
}

fn check_processing_generating_certificate_request(
    vm: &mut ServiceVm,
    maced_public_key: &[u8],
) -> Result<()> {
    let params = GenerateCertificateRequestParams {
        keys_to_sign: vec![maced_public_key.to_vec()],
        challenge: vec![],
    };
    let request = Request::GenerateCertificateRequest(params);

    let response = vm.process_request(request)?;
    info!("Received response: {response:?}.");

    match response {
        Response::GenerateCertificateRequest(csr) => check_csr(csr),
        _ => bail!("Incorrect response type: {response:?}"),
    }
}

fn check_attestation_request(vm: &mut ServiceVm, key_blob: &[u8]) -> Result<()> {
    /// The following data was generated randomly with urandom.
    const CHALLENGE: [u8; 16] = [
        0x7d, 0x86, 0x58, 0x79, 0x3a, 0x09, 0xdf, 0x1c, 0xa5, 0x80, 0x80, 0x15, 0x2b, 0x13, 0x17,
        0x5c,
    ];
    let dice_artifacts = diced_sample_inputs::make_sample_bcc_and_cdis()?;
    let attestation_data = generate_attestation_key_and_csr(&CHALLENGE, &dice_artifacts)?;

    let params = ClientVmAttestationParams {
        csr: attestation_data.csr.into_cbor_vec()?,
        remotely_provisioned_key_blob: key_blob.to_vec(),
    };
    let request = Request::RequestClientVmAttestation(params);

    let response = vm.process_request(request)?;
    info!("Received response: {response:?}.");

    match response {
        // TODO(b/309441500): Check the certificate once it is implemented.
        Response::Err(RequestProcessingError::OperationUnimplemented) => Ok(()),
        _ => bail!("Incorrect response type: {response:?}"),
    }
}

/// TODO(b/300625792): Check the CSR with libhwtrust once the CSR is complete.
fn check_csr(csr: Vec<u8>) -> Result<()> {
    let mut reader = io::Cursor::new(csr);
    let csr: Value = ciborium::from_reader(&mut reader)?;
    match csr {
        Value::Array(arr) => {
            assert_eq!(4, arr.len());
        }
        _ => bail!("Incorrect CSR format: {csr:?}"),
    }
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
