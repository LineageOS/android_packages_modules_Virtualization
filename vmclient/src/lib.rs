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

//! Client library for VirtualizationService.

mod death_reason;
mod errors;
mod sync;

pub use crate::death_reason::DeathReason;
pub use crate::errors::VmWaitError;
use crate::sync::Monitor;
use android_system_virtualizationservice::{
    aidl::android::system::virtualizationservice::{
        DeathReason::DeathReason as AidlDeathReason,
        IVirtualMachine::IVirtualMachine,
        IVirtualMachineCallback::{BnVirtualMachineCallback, IVirtualMachineCallback},
        IVirtualizationService::IVirtualizationService,
        VirtualMachineConfig::VirtualMachineConfig,
        VirtualMachineState::VirtualMachineState,
    },
    binder::{
        wait_for_interface, BinderFeatures, DeathRecipient, IBinder, Interface,
        ParcelFileDescriptor, Result as BinderResult, StatusCode, Strong,
    },
};
use log::warn;
use std::{
    fmt::{self, Debug, Formatter},
    fs::File,
    sync::Arc,
    time::Duration,
};

const VIRTUALIZATION_SERVICE_BINDER_SERVICE_IDENTIFIER: &str =
    "android.system.virtualizationservice";

/// Connects to the VirtualizationService AIDL service.
pub fn connect() -> Result<Strong<dyn IVirtualizationService>, StatusCode> {
    wait_for_interface(VIRTUALIZATION_SERVICE_BINDER_SERVICE_IDENTIFIER)
}

/// A virtual machine which has been started by the VirtualizationService.
pub struct VmInstance {
    /// The `IVirtualMachine` Binder object representing the VM.
    pub vm: Strong<dyn IVirtualMachine>,
    cid: i32,
    state: Arc<Monitor<VmState>>,
    // Ensure that the DeathRecipient isn't dropped while someone might call wait_for_death, as it
    // is removed from the Binder when it's dropped.
    _death_recipient: DeathRecipient,
}

impl VmInstance {
    /// Creates (but doesn't start) a new VM with the given configuration.
    pub fn create(
        service: &dyn IVirtualizationService,
        config: &VirtualMachineConfig,
        console: Option<File>,
        log: Option<File>,
    ) -> BinderResult<Self> {
        let console = console.map(ParcelFileDescriptor::new);
        let log = log.map(ParcelFileDescriptor::new);

        let vm = service.createVm(config, console.as_ref(), log.as_ref())?;

        let cid = vm.getCid()?;

        // Register callback before starting VM, in case it dies immediately.
        let state = Arc::new(Monitor::new(VmState::default()));
        let callback = BnVirtualMachineCallback::new_binder(
            VirtualMachineCallback { state: state.clone() },
            BinderFeatures::default(),
        );
        vm.registerCallback(&callback)?;
        let death_recipient = wait_for_binder_death(&mut vm.as_binder(), state.clone())?;

        Ok(Self { vm, cid, state, _death_recipient: death_recipient })
    }

    /// Starts the VM.
    pub fn start(&self) -> BinderResult<()> {
        self.vm.start()
    }

    /// Returns the CID used for vsock connections to the VM.
    pub fn cid(&self) -> i32 {
        self.cid
    }

    /// Returns the current lifecycle state of the VM.
    pub fn state(&self) -> BinderResult<VirtualMachineState> {
        self.vm.getState()
    }

    /// Blocks until the VM or the VirtualizationService itself dies, and then returns the reason
    /// why it died.
    pub fn wait_for_death(&self) -> DeathReason {
        self.state.wait_while(|state| state.death_reason.is_none()).unwrap().death_reason.unwrap()
    }

    /// Waits until the VM reports that it is ready.
    ///
    /// Returns an error if the VM dies first, or the `timeout` elapses before the VM is ready.
    pub fn wait_until_ready(&self, timeout: Duration) -> Result<(), VmWaitError> {
        let (state, timeout_result) = self
            .state
            .wait_timeout_while(timeout, |state| {
                state.reported_state < VirtualMachineState::READY && state.death_reason.is_none()
            })
            .unwrap();
        if timeout_result.timed_out() {
            Err(VmWaitError::TimedOut)
        } else if let Some(reason) = state.death_reason {
            Err(VmWaitError::Died { reason })
        } else if state.reported_state != VirtualMachineState::READY {
            Err(VmWaitError::Finished)
        } else {
            Ok(())
        }
    }
}

impl Debug for VmInstance {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_struct("VmInstance").field("cid", &self.cid).field("state", &self.state).finish()
    }
}

/// Notify the VmState when the given Binder object dies.
///
/// If the returned DeathRecipient is dropped then this will no longer do anything.
fn wait_for_binder_death(
    binder: &mut impl IBinder,
    state: Arc<Monitor<VmState>>,
) -> BinderResult<DeathRecipient> {
    let mut death_recipient = DeathRecipient::new(move || {
        warn!("VirtualizationService unexpectedly died");
        state.notify_death(DeathReason::VirtualizationServiceDied);
    });
    binder.link_to_death(&mut death_recipient)?;
    Ok(death_recipient)
}

#[derive(Debug, Default)]
struct VmState {
    death_reason: Option<DeathReason>,
    reported_state: VirtualMachineState,
}

impl Monitor<VmState> {
    fn notify_death(&self, reason: DeathReason) {
        let state = &mut *self.state.lock().unwrap();
        // In case this method is called more than once, ignore subsequent calls.
        if state.death_reason.is_none() {
            state.death_reason.replace(reason);
            self.cv.notify_all();
        }
    }

    fn notify_state(&self, state: VirtualMachineState) {
        self.state.lock().unwrap().reported_state = state;
        self.cv.notify_all();
    }
}

#[derive(Debug)]
struct VirtualMachineCallback {
    state: Arc<Monitor<VmState>>,
}

impl Interface for VirtualMachineCallback {}

impl IVirtualMachineCallback for VirtualMachineCallback {
    fn onPayloadStarted(
        &self,
        _cid: i32,
        _stream: Option<&ParcelFileDescriptor>,
    ) -> BinderResult<()> {
        self.state.notify_state(VirtualMachineState::STARTED);
        Ok(())
    }

    fn onPayloadReady(&self, _cid: i32) -> BinderResult<()> {
        self.state.notify_state(VirtualMachineState::READY);
        Ok(())
    }

    fn onPayloadFinished(&self, _cid: i32, _exit_code: i32) -> BinderResult<()> {
        self.state.notify_state(VirtualMachineState::FINISHED);
        Ok(())
    }

    fn onError(&self, _cid: i32, _error_code: i32, _message: &str) -> BinderResult<()> {
        self.state.notify_state(VirtualMachineState::FINISHED);
        Ok(())
    }

    fn onDied(&self, _cid: i32, reason: AidlDeathReason) -> BinderResult<()> {
        self.state.notify_death(reason.into());
        Ok(())
    }
}
