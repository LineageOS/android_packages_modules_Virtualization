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
use log::{info, warn};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::os::raw;
use std::os::unix::io::IntoRawFd;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

/// This owns an instance of the CompOS VM.
pub struct VmInstance {
    #[allow(dead_code)] // Prevent service manager from killing the dynamic service
    service: Strong<dyn IVirtualizationService>,
    #[allow(dead_code)] // Keeps the VM alive even if we don`t touch it
    vm: Strong<dyn IVirtualMachine>,
    #[allow(dead_code)] // TODO: Do we need this?
    cid: i32,
}

impl VmInstance {
    /// Return a new connection to the Virtualization Service binder interface. This will start the
    /// service if necessary.
    pub fn connect_to_virtualization_service() -> Result<Strong<dyn IVirtualizationService>> {
        wait_for_interface::<dyn IVirtualizationService>("android.system.virtualizationservice")
            .context("Failed to find VirtualizationService")
    }

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

        let service = Self::connect_to_virtualization_service()?;

        let vm = service.createVm(&config, Some(&log_fd)).context("Failed to create VM")?;
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

        vm.start()?;

        let cid = vm_state.wait_until_ready()?;

        Ok(VmInstance { service, vm, cid })
    }

    /// Create and return an RPC Binder connection to the Comp OS service in the VM.
    pub fn get_service(&self) -> Result<Strong<dyn ICompOsService>> {
        let mut vsock_factory = VsockFactory::new(&*self.vm);

        let ibinder = vsock_factory
            .connect_rpc_client()
            .ok_or_else(|| anyhow!("Failed to connect to CompOS service"))?;

        FromIBinder::try_from(ibinder).context("Connecting to CompOS service")
    }

    /// Return the CID of the VM.
    pub fn cid(&self) -> i32 {
        self.cid
    }
}

struct VsockFactory<'a> {
    vm: &'a dyn IVirtualMachine,
}

impl<'a> VsockFactory<'a> {
    fn new(vm: &'a dyn IVirtualMachine) -> Self {
        Self { vm }
    }

    fn connect_rpc_client(&mut self) -> Option<binder::SpIBinder> {
        let param = self.as_void_ptr();

        unsafe {
            // SAFETY: AIBinder returned by RpcPreconnectedClient has correct reference count, and
            // the ownership can be safely taken by new_spibinder.
            // RpcPreconnectedClient does not take ownership of param, only passing it to
            // request_fd.
            let binder =
                binder_rpc_unstable_bindgen::RpcPreconnectedClient(Some(Self::request_fd), param)
                    as *mut AIBinder;
            new_spibinder(binder)
        }
    }

    fn as_void_ptr(&mut self) -> *mut raw::c_void {
        self as *mut _ as *mut raw::c_void
    }

    fn try_new_vsock_fd(&self) -> Result<i32> {
        let vsock = self.vm.connectVsock(COMPOS_VSOCK_PORT as i32)?;
        // Ownership of the fd is transferred to binder
        Ok(vsock.into_raw_fd())
    }

    fn new_vsock_fd(&self) -> i32 {
        self.try_new_vsock_fd().unwrap_or_else(|e| {
            warn!("Connecting vsock failed: {}", e);
            -1_i32
        })
    }

    unsafe extern "C" fn request_fd(param: *mut raw::c_void) -> raw::c_int {
        // SAFETY: This is only ever called by RpcPreconnectedClient, within the lifetime of the
        // VsockFactory, with param taking the value returned by as_void_ptr (so a properly aligned
        // non-null pointer to an initialized instance).
        let vsock_factory = param as *mut Self;
        vsock_factory.as_ref().unwrap().new_vsock_fd()
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

    fn set_ready(&self, cid: i32) {
        let mut state = self.mutex.lock().unwrap();
        if state.has_died {
            return;
        }
        state.cid = Some(cid);
        drop(state); // Unlock the mutex prior to notifying
        self.state_ready.notify_all();
    }

    fn wait_until_ready(&self) -> Result<i32> {
        let (state, result) = self
            .state_ready
            .wait_timeout_while(self.mutex.lock().unwrap(), Duration::from_secs(20), |state| {
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
        stream: Option<&ParcelFileDescriptor>,
    ) -> BinderResult<()> {
        if let Some(pfd) = stream {
            if let Err(e) = start_logging(pfd) {
                warn!("Can't log vm output: {}", e);
            };
        }
        log::info!("VM payload started, cid = {}", cid);
        Ok(())
    }

    fn onPayloadReady(&self, cid: i32) -> BinderResult<()> {
        self.0.set_ready(cid);
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

fn start_logging(pfd: &ParcelFileDescriptor) -> Result<()> {
    let reader = BufReader::new(pfd.as_ref().try_clone().context("Cloning fd failed")?);
    thread::spawn(move || {
        for line in reader.lines() {
            match line {
                Ok(line) => info!("VM: {}", line),
                Err(e) => {
                    warn!("Reading VM output failed: {}", e);
                    break;
                }
            }
        }
    });
    Ok(())
}
