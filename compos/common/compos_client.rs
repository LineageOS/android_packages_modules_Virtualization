/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Support for starting CompOS in a VM and connecting to the service

use crate::{COMPOS_APEX_ROOT, COMPOS_DATA_ROOT, COMPOS_VSOCK_PORT};
use android_system_virtualizationservice::aidl::android::system::virtualizationservice::{
    IVirtualMachine::IVirtualMachine,
    IVirtualMachineCallback::{BnVirtualMachineCallback, IVirtualMachineCallback},
    IVirtualizationService::IVirtualizationService,
    VirtualMachineAppConfig::VirtualMachineAppConfig,
    VirtualMachineConfig::VirtualMachineConfig,
};
use android_system_virtualizationservice::binder::{
    wait_for_interface, BinderFeatures, DeathRecipient, IBinder, Interface, ParcelFileDescriptor,
    Result as BinderResult, Strong,
};
use anyhow::{anyhow, bail, Context, Result};
use binder::{
    unstable_api::{new_spibinder, AIBinder},
    FromIBinder,
};
use compos_aidl_interface::aidl::com::android::compos::ICompOsService::ICompOsService;
use std::fs::File;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

/// This owns an instance of the CompOS VM.
pub struct VmInstance {
    #[allow(dead_code)] // Keeps the vm alive even if we don`t touch it
    vm: Strong<dyn IVirtualMachine>,
    cid: i32,
}

impl VmInstance {
    /// Start a new CompOS VM instance using the specified instance image file.
    pub fn start(instance_image: &Path) -> Result<VmInstance> {
        let instance_image =
            File::open(instance_image).context("Failed to open instance image file")?;
        let instance_fd = ParcelFileDescriptor::new(instance_image);

        let apex_dir = Path::new(COMPOS_APEX_ROOT);
        let data_dir = Path::new(COMPOS_DATA_ROOT);

        let apk_fd = File::open(apex_dir.join("app/CompOSPayloadApp/CompOSPayloadApp.apk"))
            .context("Failed to open config APK file")?;
        let apk_fd = ParcelFileDescriptor::new(apk_fd);

        let idsig_fd = File::open(apex_dir.join("etc/CompOSPayloadApp.apk.idsig"))
            .context("Failed to open config APK idsig file")?;
        let idsig_fd = ParcelFileDescriptor::new(idsig_fd);

        // TODO: Send this to stdout instead? Or specify None?
        let log_fd = File::create(data_dir.join("vm.log")).context("Failed to create log file")?;
        let log_fd = ParcelFileDescriptor::new(log_fd);

        let config = VirtualMachineConfig::AppConfig(VirtualMachineAppConfig {
            apk: Some(apk_fd),
            idsig: Some(idsig_fd),
            instanceImage: Some(instance_fd),
            configPath: "assets/vm_config.json".to_owned(),
            ..Default::default()
        });

        let service = wait_for_interface::<dyn IVirtualizationService>(
            "android.system.virtualizationservice",
        )
        .context("Failed to find VirtualizationService")?;

        let vm = service.startVm(&config, Some(&log_fd)).context("Failed to start VM")?;
        let vm_state = Arc::new(VmStateMonitor::default());

        let vm_state_clone = Arc::clone(&vm_state);
        vm.as_binder().link_to_death(&mut DeathRecipient::new(move || {
            vm_state_clone.set_died();
            log::error!("VirtualizationService died");
        }))?;

        let vm_state_clone = Arc::clone(&vm_state);
        let callback = BnVirtualMachineCallback::new_binder(
            VmCallback(vm_state_clone),
            BinderFeatures::default(),
        );
        vm.registerCallback(&callback)?;

        let cid = vm_state.wait_for_start()?;

        // TODO: Use onPayloadReady to avoid this
        thread::sleep(Duration::from_secs(3));

        Ok(VmInstance { vm, cid })
    }

    /// Create and return an RPC Binder connection to the Comp OS service in the VM.
    pub fn get_service(&self) -> Result<Strong<dyn ICompOsService>> {
        let cid = self.cid as u32;
        // SAFETY: AIBinder returned by RpcClient has correct reference count, and the ownership
        // can be safely taken by new_spibinder.
        let ibinder = unsafe {
            new_spibinder(
                binder_rpc_unstable_bindgen::RpcClient(cid, COMPOS_VSOCK_PORT) as *mut AIBinder
            )
        }
        .ok_or_else(|| anyhow!("Failed to connect to CompOS service"))?;

        FromIBinder::try_from(ibinder).context("Connecting to CompOS service")
    }
}

#[derive(Debug)]
struct VmState {
    has_died: bool,
    cid: Option<i32>,
}

impl Default for VmState {
    fn default() -> Self {
        Self { has_died: false, cid: None }
    }
}

#[derive(Debug)]
struct VmStateMonitor {
    mutex: Mutex<VmState>,
    state_ready: Condvar,
}

impl Default for VmStateMonitor {
    fn default() -> Self {
        Self { mutex: Mutex::new(Default::default()), state_ready: Condvar::new() }
    }
}

impl VmStateMonitor {
    fn set_died(&self) {
        let mut state = self.mutex.lock().unwrap();
        state.has_died = true;
        state.cid = None;
        drop(state); // Unlock the mutex prior to notifying
        self.state_ready.notify_all();
    }

    fn set_started(&self, cid: i32) {
        let mut state = self.mutex.lock().unwrap();
        if state.has_died {
            return;
        }
        state.cid = Some(cid);
        drop(state); // Unlock the mutex prior to notifying
        self.state_ready.notify_all();
    }

    fn wait_for_start(&self) -> Result<i32> {
        let (state, result) = self
            .state_ready
            .wait_timeout_while(self.mutex.lock().unwrap(), Duration::from_secs(10), |state| {
                state.cid.is_none() && !state.has_died
            })
            .unwrap();
        if result.timed_out() {
            bail!("Timed out waiting for VM")
        }
        state.cid.ok_or_else(|| anyhow!("VM died"))
    }
}

#[derive(Debug)]
struct VmCallback(Arc<VmStateMonitor>);

impl Interface for VmCallback {}

impl IVirtualMachineCallback for VmCallback {
    fn onDied(&self, cid: i32) -> BinderResult<()> {
        self.0.set_died();
        log::warn!("VM died, cid = {}", cid);
        Ok(())
    }

    fn onPayloadStarted(
        &self,
        cid: i32,
        _stream: Option<&binder::parcel::ParcelFileDescriptor>,
    ) -> BinderResult<()> {
        self.0.set_started(cid);
        // TODO: Use the stream?
        log::info!("VM payload started, cid = {}", cid);
        Ok(())
    }

    fn onPayloadReady(&self, cid: i32) -> BinderResult<()> {
        // TODO: Use this to trigger vsock connection
        log::info!("VM payload ready, cid = {}", cid);
        Ok(())
    }

    fn onPayloadFinished(&self, cid: i32, exit_code: i32) -> BinderResult<()> {
        // This should probably never happen in our case, but if it does we means our VM is no
        // longer running
        self.0.set_died();
        log::warn!("VM payload finished, cid = {}, exit code = {}", cid, exit_code);
        Ok(())
    }
}
