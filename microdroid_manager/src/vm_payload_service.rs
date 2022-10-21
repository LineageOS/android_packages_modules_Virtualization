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

//! Implementation of the AIDL interface `IVmPayloadService`.

use crate::dice::DiceContext;
use android_system_virtualization_payload::aidl::android::system::virtualization::payload::IVmPayloadService::{
    BnVmPayloadService, IVmPayloadService, VM_PAYLOAD_SERVICE_NAME};
use android_system_virtualmachineservice::aidl::android::system::virtualmachineservice::IVirtualMachineService::IVirtualMachineService;
use anyhow::{Context, Result};
use binder::{Interface, BinderFeatures, ExceptionCode, Status, Strong, add_service};
use log::error;
use openssl::hkdf::hkdf;
use openssl::md::Md;

/// Implementation of `IVmPayloadService`.
struct VmPayloadService {
    allow_restricted_apis: bool,
    virtual_machine_service: Strong<dyn IVirtualMachineService>,
    dice: DiceContext,
}

impl IVmPayloadService for VmPayloadService {
    fn notifyPayloadReady(&self) -> binder::Result<()> {
        self.virtual_machine_service.notifyPayloadReady()
    }

    fn getVmInstanceSecret(&self, identifier: &[u8], size: i32) -> binder::Result<Vec<u8>> {
        if !(0..=32).contains(&size) {
            return Err(Status::new_exception(ExceptionCode::ILLEGAL_ARGUMENT, None));
        }
        // Use a fixed salt to scope the derivation to this API. It was randomly generated.
        let salt = [
            0x8B, 0x0F, 0xF0, 0xD3, 0xB1, 0x69, 0x2B, 0x95, 0x84, 0x2C, 0x9E, 0x3C, 0x99, 0x56,
            0x7A, 0x22, 0x55, 0xF8, 0x08, 0x23, 0x81, 0x5F, 0xF5, 0x16, 0x20, 0x3E, 0xBE, 0xBA,
            0xB7, 0xA8, 0x43, 0x92,
        ];
        let mut secret = vec![0; size.try_into().unwrap()];
        hkdf(&mut secret, Md::sha256(), &self.dice.cdi_seal, &salt, identifier).map_err(|e| {
            error!("Failed to derive VM instance secret: {:?}", e);
            Status::new_service_specific_error(-1, None)
        })?;
        Ok(secret)
    }

    fn getDiceAttestationChain(&self) -> binder::Result<Vec<u8>> {
        self.check_restricted_apis_allowed()?;
        Ok(self.dice.bcc.clone())
    }

    fn getDiceAttestationCdi(&self) -> binder::Result<Vec<u8>> {
        self.check_restricted_apis_allowed()?;
        Ok(self.dice.cdi_attest.to_vec())
    }
}

impl Interface for VmPayloadService {}

impl VmPayloadService {
    /// Creates a new `VmPayloadService` instance from the `IVirtualMachineService` reference.
    fn new(
        allow_restricted_apis: bool,
        vm_service: Strong<dyn IVirtualMachineService>,
        dice: DiceContext,
    ) -> Self {
        Self { allow_restricted_apis, virtual_machine_service: vm_service, dice }
    }

    fn check_restricted_apis_allowed(&self) -> binder::Result<()> {
        if self.allow_restricted_apis {
            Ok(())
        } else {
            error!("Use of restricted APIs is not allowed");
            Err(Status::new_exception_str(ExceptionCode::SECURITY, Some("Use of restricted APIs")))
        }
    }
}

/// Registers the `IVmPayloadService` service.
pub(crate) fn register_vm_payload_service(
    allow_restricted_apis: bool,
    vm_service: Strong<dyn IVirtualMachineService>,
    dice: DiceContext,
) -> Result<()> {
    let vm_payload_binder = BnVmPayloadService::new_binder(
        VmPayloadService::new(allow_restricted_apis, vm_service, dice),
        BinderFeatures::default(),
    );
    add_service(VM_PAYLOAD_SERVICE_NAME, vm_payload_binder.as_binder())
        .with_context(|| format!("Failed to register service {}", VM_PAYLOAD_SERVICE_NAME))?;
    log::info!("{} is running", VM_PAYLOAD_SERVICE_NAME);
    Ok(())
}
