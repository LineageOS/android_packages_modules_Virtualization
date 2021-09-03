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

//! A tool to verify whether a CompOs instance image and key pair are valid. It starts a CompOs VM
//! as part of this. The tool is intended to be run by odsign during boot.

use android_system_virtualizationservice::aidl::android::system::virtualizationservice::{
    IVirtualMachine::IVirtualMachine,
    IVirtualMachineCallback::{BnVirtualMachineCallback, IVirtualMachineCallback},
    IVirtualizationService::IVirtualizationService,
    VirtualMachineAppConfig::VirtualMachineAppConfig,
    VirtualMachineConfig::VirtualMachineConfig,
};
use android_system_virtualizationservice::binder::{
    wait_for_interface, BinderFeatures, DeathRecipient, IBinder, Interface, ParcelFileDescriptor,
    ProcessState, Result as BinderResult, Strong,
};
use anyhow::{anyhow, bail, Context, Result};
use binder::{
    unstable_api::{new_spibinder, AIBinder},
    FromIBinder,
};
use compos_aidl_interface::aidl::com::android::compos::ICompOsService::ICompOsService;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

const COMPOS_APEX_ROOT: &str = "/apex/com.android.compos";
const COMPOS_DATA_ROOT: &str = "/data/misc/apexdata/com.android.compos";
const CURRENT_DIR: &str = "current";
const PENDING_DIR: &str = "pending";
const PRIVATE_KEY_BLOB_FILE: &str = "key.blob";
const PUBLIC_KEY_FILE: &str = "key.pubkey";
const INSTANCE_IMAGE_FILE: &str = "instance.img";

const MAX_FILE_SIZE_BYTES: u64 = 8 * 1024;

const COMPOS_SERVICE_PORT: u32 = 6432;

fn main() -> Result<()> {
    let matches = clap::App::new("compos_verify_key")
        .arg(
            clap::Arg::with_name("instance")
                .long("instance")
                .takes_value(true)
                .required(true)
                .possible_values(&["pending", "current"]),
        )
        .get_matches();
    let do_pending = matches.value_of("instance").unwrap() == "pending";

    let instance_dir: PathBuf =
        [COMPOS_DATA_ROOT, if do_pending { PENDING_DIR } else { CURRENT_DIR }].iter().collect();

    if !instance_dir.is_dir() {
        bail!("{} is not a directory", instance_dir.display());
    }

    // We need to start the thread pool to be able to receive Binder callbacks
    ProcessState::start_thread_pool();

    let result = verify(&instance_dir).and_then(|_| {
        if do_pending {
            // If the pending instance is ok, then it must actually match the current system state,
            // so we promote it to current.
            println!("Promoting pending to current");
            promote_to_current(&instance_dir)
        } else {
            Ok(())
        }
    });

    if result.is_err() {
        // This is best efforts, and we still want to report the original error as our result
        println!("Removing {}", instance_dir.display());
        if let Err(e) = fs::remove_dir_all(&instance_dir) {
            eprintln!("Failed to remove directory: {}", e);
        }
    }

    result
}

fn verify(instance_dir: &Path) -> Result<()> {
    let blob = instance_dir.join(PRIVATE_KEY_BLOB_FILE);
    let public_key = instance_dir.join(PUBLIC_KEY_FILE);
    let instance = instance_dir.join(INSTANCE_IMAGE_FILE);

    let blob = read_small_file(blob).context("Failed to read key blob")?;
    let public_key = read_small_file(public_key).context("Failed to read public key")?;

    let instance = File::open(instance).context("Failed to open instance image file")?;
    let vm_instance = VmInstance::start(instance)?;
    let service = get_service(vm_instance.cid).context("Failed to connect to CompOs service")?;

    let result = service.verifySigningKey(&blob, &public_key).context("Verifying signing key")?;

    if !result {
        bail!("Key files are not valid");
    }

    Ok(())
}

fn read_small_file(file: PathBuf) -> Result<Vec<u8>> {
    let mut file = File::open(file)?;
    if file.metadata()?.len() > MAX_FILE_SIZE_BYTES {
        bail!("File is too big");
    }
    let mut data = vec![];
    file.read_to_end(&mut data)?;
    Ok(data)
}

fn get_service(cid: i32) -> Result<Strong<dyn ICompOsService>> {
    let cid = cid as u32;
    // SAFETY: AIBinder returned by RpcClient has correct reference count, and the ownership can be
    // safely taken by new_spibinder.
    let ibinder = unsafe {
        new_spibinder(
            binder_rpc_unstable_bindgen::RpcClient(cid, COMPOS_SERVICE_PORT) as *mut AIBinder
        )
    }
    .ok_or_else(|| anyhow!("Invalid raw AIBinder"))?;

    Ok(FromIBinder::try_from(ibinder)?)
}

fn promote_to_current(instance_dir: &Path) -> Result<()> {
    let current_dir: PathBuf = [COMPOS_DATA_ROOT, CURRENT_DIR].iter().collect();

    // This may fail if the directory doesn't exist - which is fine, we only care about the rename
    // succeeding.
    let _ = fs::remove_dir_all(&current_dir);

    fs::rename(&instance_dir, &current_dir)
        .context("Unable to promote pending instance to current")?;
    Ok(())
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

struct VmInstance {
    #[allow(dead_code)] // Keeps the vm alive even if we don`t touch it
    vm: Strong<dyn IVirtualMachine>,
    cid: i32,
}

impl VmInstance {
    fn start(instance_file: File) -> Result<VmInstance> {
        let instance_fd = ParcelFileDescriptor::new(instance_file);

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
            eprintln!("VirtualizationService died");
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
}

#[derive(Debug)]
struct VmCallback(Arc<VmStateMonitor>);

impl Interface for VmCallback {}

impl IVirtualMachineCallback for VmCallback {
    fn onDied(&self, cid: i32) -> BinderResult<()> {
        self.0.set_died();
        println!("VM died, cid = {}", cid);
        Ok(())
    }

    fn onPayloadStarted(
        &self,
        cid: i32,
        _stream: Option<&binder::parcel::ParcelFileDescriptor>,
    ) -> BinderResult<()> {
        self.0.set_started(cid);
        // TODO: Use the stream?
        println!("VM payload started, cid = {}", cid);
        Ok(())
    }

    fn onPayloadReady(&self, cid: i32) -> BinderResult<()> {
        // TODO: Use this to trigger vsock connection
        println!("VM payload ready, cid = {}", cid);
        Ok(())
    }

    fn onPayloadFinished(&self, cid: i32, exit_code: i32) -> BinderResult<()> {
        // This should probably never happen in our case, but if it does we means our VM is no
        // longer running
        self.0.set_died();
        println!("VM payload finished, cid = {}, exit code = {}", cid, exit_code);
        Ok(())
    }
}
