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

use android_system_virtualization_payload::aidl::android::system::virtualization::payload::IVmPayloadService::{BnVmPayloadService, IVmPayloadService};
use android_system_virtualmachineservice::aidl::android::system::virtualmachineservice::IVirtualMachineService::IVirtualMachineService;
use anyhow::{Context, Result};
use binder::{Interface, BinderFeatures, Strong, add_service};

const VM_PAYLOAD_SERVICE_NAME: &str = "virtual_machine_payload_service";

/// Implementation of `IVmPayloadService`.
struct VmPayloadService {
    virtual_machine_service: Strong<dyn IVirtualMachineService>,
}

impl IVmPayloadService for VmPayloadService {
    fn notifyPayloadReady(&self) -> binder::Result<()> {
        self.virtual_machine_service.notifyPayloadReady()
    }
}

impl Interface for VmPayloadService {}

impl VmPayloadService {
    /// Creates a new `VmPayloadService` instance from the `IVirtualMachineService` reference.
    fn new(vm_service: Strong<dyn IVirtualMachineService>) -> Self {
        Self { virtual_machine_service: vm_service }
    }
}

/// Registers the `IVmPayloadService` service.
pub(crate) fn register_vm_payload_service(
    vm_service: Strong<dyn IVirtualMachineService>,
) -> Result<()> {
    let vm_payload_binder = BnVmPayloadService::new_binder(
        VmPayloadService::new(vm_service),
        BinderFeatures::default(),
    );
    add_service(VM_PAYLOAD_SERVICE_NAME, vm_payload_binder.as_binder())
        .with_context(|| format!("Failed to register service {}", VM_PAYLOAD_SERVICE_NAME))?;
    log::info!("{} is running", VM_PAYLOAD_SERVICE_NAME);
    Ok(())
}
