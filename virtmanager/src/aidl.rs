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

//! Implementation of the AIDL interface of the Virt Manager.

use crate::config::load_vm_config;
use crate::crosvm::VmInstance;
use crate::{Cid, FIRST_GUEST_CID};
use android_system_virtmanager::aidl::android::system::virtmanager::IVirtManager::IVirtManager;
use android_system_virtmanager::aidl::android::system::virtmanager::IVirtualMachine::{
    BnVirtualMachine, IVirtualMachine,
};
use android_system_virtmanager::binder::{self, Interface, StatusCode, Strong};
use log::error;
use std::sync::{Arc, Mutex};

pub const BINDER_SERVICE_IDENTIFIER: &str = "android.system.virtmanager";

/// Implementation of `IVirtManager`, the entry point of the AIDL service.
#[derive(Debug, Default)]
pub struct VirtManager {
    state: Mutex<State>,
}

impl Interface for VirtManager {}

impl IVirtManager for VirtManager {
    /// Create and start a new VM with the given configuration, assigning it the next available CID.
    ///
    /// Returns a binder `IVirtualMachine` object referring to it, as a handle for the client.
    fn startVm(&self, config_path: &str) -> binder::Result<Strong<dyn IVirtualMachine>> {
        let state = &mut *self.state.lock().unwrap();
        let cid = state.next_cid;
        let instance = start_vm(config_path, cid)?;
        // TODO(qwandor): keep track of which CIDs are currently in use so that we can reuse them.
        state.next_cid = state.next_cid.checked_add(1).ok_or(StatusCode::UNKNOWN_ERROR)?;
        Ok(VirtualMachine::create(Arc::new(instance)))
    }
}

/// Implementation of the AIDL `IVirtualMachine` interface. Used as a handle to a VM.
#[derive(Debug)]
struct VirtualMachine {
    instance: Arc<VmInstance>,
}

impl VirtualMachine {
    fn create(instance: Arc<VmInstance>) -> Strong<dyn IVirtualMachine> {
        let binder = VirtualMachine { instance };
        BnVirtualMachine::new_binder(binder)
    }
}

impl Interface for VirtualMachine {}

impl IVirtualMachine for VirtualMachine {
    fn getCid(&self) -> binder::Result<i32> {
        Ok(self.instance.cid as i32)
    }
}

/// The mutable state of the Virt Manager. There should only be one instance of this struct.
#[derive(Debug)]
struct State {
    next_cid: Cid,
}

impl Default for State {
    fn default() -> Self {
        State { next_cid: FIRST_GUEST_CID }
    }
}

/// Start a new VM instance from the given VM config filename. This assumes the VM is not already
/// running.
fn start_vm(config_path: &str, cid: Cid) -> binder::Result<VmInstance> {
    let config = load_vm_config(config_path).map_err(|e| {
        error!("Failed to load VM config {}: {:?}", config_path, e);
        StatusCode::BAD_VALUE
    })?;
    Ok(VmInstance::start(&config, cid).map_err(|e| {
        error!("Failed to start VM {}: {:?}", config_path, e);
        StatusCode::UNKNOWN_ERROR
    })?)
}
