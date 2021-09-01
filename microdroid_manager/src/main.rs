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

//! Microdroid Manager

mod instance;
mod ioutil;
mod metadata;

use crate::instance::InstanceDisk;
use anyhow::{anyhow, bail, Context, Result};
use apkverify::verify;
use binder::unstable_api::{new_spibinder, AIBinder};
use binder::{FromIBinder, Strong};
use idsig::V4Signature;
use log::{debug, error, info, warn};
use microdroid_payload_config::{Task, TaskType, VmPayloadConfig};
use nix::ioctl_read_bad;
use rustutils::system_properties::PropertyWatcher;
use std::fs::{self, File, OpenOptions};
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
use std::path::Path;
use std::process::{Command, Stdio};
use std::str;
use std::time::Duration;
use vsock::VsockStream;

use android_system_virtualmachineservice::aidl::android::system::virtualmachineservice::IVirtualMachineService::IVirtualMachineService;

const WAIT_TIMEOUT: Duration = Duration::from_secs(10);
const DM_MOUNTED_APK_PATH: &str = "/dev/block/mapper/microdroid-apk";

/// The CID representing the host VM
const VMADDR_CID_HOST: u32 = 2;

/// Port number that virtualizationservice listens on connections from the guest VMs for the
/// VirtualMachineService binder service
/// Sync with virtualizationservice/src/aidl.rs
const PORT_VM_BINDER_SERVICE: u32 = 5000;

fn get_vms_rpc_binder() -> Result<Strong<dyn IVirtualMachineService>> {
    // SAFETY: AIBinder returned by RpcClient has correct reference count, and the ownership can be
    // safely taken by new_spibinder.
    let ibinder = unsafe {
        new_spibinder(binder_rpc_unstable_bindgen::RpcClient(
            VMADDR_CID_HOST,
            PORT_VM_BINDER_SERVICE,
        ) as *mut AIBinder)
    };
    if let Some(ibinder) = ibinder {
        <dyn IVirtualMachineService>::try_from(ibinder).context("Cannot connect to RPC service")
    } else {
        bail!("Invalid raw AIBinder")
    }
}

const IOCTL_VM_SOCKETS_GET_LOCAL_CID: usize = 0x7b9;
ioctl_read_bad!(
    /// Gets local cid from /dev/vsock
    vm_sockets_get_local_cid,
    IOCTL_VM_SOCKETS_GET_LOCAL_CID,
    u32
);

// TODO: remove this after VS can check the peer addresses of binder clients
fn get_local_cid() -> Result<u32> {
    let f = OpenOptions::new()
        .read(true)
        .write(false)
        .open("/dev/vsock")
        .context("failed to open /dev/vsock")?;
    let mut ret = 0;
    // SAFETY: the kernel only modifies the given u32 integer.
    unsafe { vm_sockets_get_local_cid(f.as_raw_fd(), &mut ret) }?;
    Ok(ret)
}

fn main() -> Result<()> {
    kernlog::init()?;
    info!("started.");

    let metadata = metadata::load()?;

    if let Err(err) = verify_payloads() {
        error!("failed to verify payload: {:#?}", err);
        return Err(err);
    }

    let mut instance = InstanceDisk::new()?;
    // TODO(jiyong): the data should have an internal structure
    if let Some(data) = instance.read_microdroid_data().context("Failed to read identity data")? {
        debug!("read apk root hash: {}", to_hex_string(&data));
        //TODO(jiyong) apkdmverity should use this root hash instead of the one read from the idsig
        //file, if the root hash is found in the instance image.
    } else {
        let data = get_apk_roothash()?;
        debug!("write apk root hash: {}", to_hex_string(&data));
        instance.write_microdroid_data(data.as_ref()).context("Failed to write identity data")?;
    }

    let service = get_vms_rpc_binder().expect("cannot connect to VirtualMachineService");

    if !metadata.payload_config_path.is_empty() {
        let config = load_config(Path::new(&metadata.payload_config_path))?;

        let fake_secret = "This is a placeholder for a value that is derived from the images that are loaded in the VM.";
        if let Err(err) = rustutils::system_properties::write("ro.vmsecret.keymint", fake_secret) {
            warn!("failed to set ro.vmsecret.keymint: {}", err);
        }

        // TODO(jooyung): wait until sys.boot_completed?
        if let Some(main_task) = &config.task {
            exec_task(main_task, &service).map_err(|e| {
                error!("failed to execute task: {}", e);
                e
            })?;
        }
    }

    Ok(())
}

// TODO(jooyung): v2/v3 full verification can be slow. Consider multithreading.
fn verify_payloads() -> Result<()> {
    // We don't verify APEXes since apexd does.

    // should wait APK to be dm-verity mounted by apkdmverity
    ioutil::wait_for_file(DM_MOUNTED_APK_PATH, WAIT_TIMEOUT)?;
    verify(DM_MOUNTED_APK_PATH).context(format!("failed to verify {}", DM_MOUNTED_APK_PATH))?;

    info!("payload verification succeeded.");
    // TODO(jooyung): collect public keys and store them in instance.img
    Ok(())
}

fn get_apk_roothash() -> Result<Box<[u8]>> {
    let mut idsig = File::open("/dev/block/by-name/microdroid-apk-idsig")?;
    let idsig = V4Signature::from(&mut idsig)?;
    Ok(idsig.hashing_info.raw_root_hash)
}

fn load_config(path: &Path) -> Result<VmPayloadConfig> {
    info!("loading config from {:?}...", path);
    let file = ioutil::wait_for_file(path, WAIT_TIMEOUT)?;
    Ok(serde_json::from_reader(file)?)
}

/// Executes the given task. Stdout of the task is piped into the vsock stream to the
/// virtualizationservice in the host side.
fn exec_task(task: &Task, service: &Strong<dyn IVirtualMachineService>) -> Result<()> {
    info!("executing main task {:?}...", task);
    let mut child = build_command(task)?.spawn()?;

    let local_cid = get_local_cid()?;
    info!("notifying payload started");
    service.notifyPayloadStarted(local_cid as i32)?;

    if let Some(code) = child.wait()?.code() {
        info!("notifying payload finished");
        service.notifyPayloadFinished(local_cid as i32, code)?;

        if code == 0 {
            info!("task successfully finished");
        } else {
            error!("task exited with exit code: {}", code);
        }
    } else {
        error!("task terminated by signal");
    }
    Ok(())
}

fn build_command(task: &Task) -> Result<Command> {
    const VMADDR_CID_HOST: u32 = 2;
    const PORT_VIRT_SVC: u32 = 3000;

    let mut command = match task.type_ {
        TaskType::Executable => {
            let mut command = Command::new(&task.command);
            command.args(&task.args);
            command
        }
        TaskType::MicrodroidLauncher => {
            let mut command = Command::new("/system/bin/microdroid_launcher");
            command.arg(find_library_path(&task.command)?).args(&task.args);
            command
        }
    };

    match VsockStream::connect_with_cid_port(VMADDR_CID_HOST, PORT_VIRT_SVC) {
        Ok(stream) => {
            // SAFETY: the ownership of the underlying file descriptor is transferred from stream
            // to the file object, and then into the Command object. When the command is finished,
            // the file descriptor is closed.
            let file = unsafe { File::from_raw_fd(stream.into_raw_fd()) };
            command
                .stdin(Stdio::from(file.try_clone()?))
                .stdout(Stdio::from(file.try_clone()?))
                .stderr(Stdio::from(file));
        }
        Err(e) => {
            error!("failed to connect to virtualization service: {}", e);
            // Don't fail hard here. Even if we failed to connect to the virtualizationservice,
            // we keep executing the task. This can happen if the owner of the VM doesn't register
            // callback to accept the stream. Use /dev/null as the stream so that the task can
            // make progress without waiting for someone to consume the output.
            command.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        }
    }

    Ok(command)
}

fn find_library_path(name: &str) -> Result<String> {
    let mut watcher = PropertyWatcher::new("ro.product.cpu.abilist")?;
    let value = watcher.read(|_name, value| Ok(value.trim().to_string()))?;
    let abi = value.split(',').next().ok_or_else(|| anyhow!("no abilist"))?;
    let path = format!("/mnt/apk/lib/{}/{}", abi, name);

    let metadata = fs::metadata(&path)?;
    if !metadata.is_file() {
        bail!("{} is not a file", &path);
    }

    Ok(path)
}

fn to_hex_string(buf: &[u8]) -> String {
    buf.iter().map(|b| format!("{:02X}", b)).collect()
}
