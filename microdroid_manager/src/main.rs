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
mod payload;

use crate::instance::{ApkData, InstanceDisk, MicrodroidData, RootHash};
use anyhow::{anyhow, bail, ensure, Context, Error, Result};
use apkverify::{get_public_key_der, verify};
use binder::unstable_api::{new_spibinder, AIBinder};
use binder::{FromIBinder, Strong};
use idsig::V4Signature;
use log::{error, info, warn};
use microdroid_metadata::{write_metadata, Metadata};
use microdroid_payload_config::{Task, TaskType, VmPayloadConfig};
use once_cell::sync::OnceCell;
use payload::{get_apex_data_from_payload, load_metadata, to_metadata};
use rustutils::system_properties;
use rustutils::system_properties::PropertyWatcher;
use std::fs::{self, File, OpenOptions};
use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::str;
use std::time::{Duration, SystemTime};
use vsock::VsockStream;

use android_system_virtualmachineservice::aidl::android::system::virtualmachineservice::IVirtualMachineService::{
    ERROR_PAYLOAD_CHANGED, ERROR_PAYLOAD_VERIFICATION_FAILED, ERROR_PAYLOAD_INVALID_CONFIG, ERROR_UNKNOWN, VM_BINDER_SERVICE_PORT, VM_STREAM_SERVICE_PORT, IVirtualMachineService,
};

const WAIT_TIMEOUT: Duration = Duration::from_secs(10);
const APK_DM_VERITY_ARGUMENT: ApkDmverityArgument = {
    ApkDmverityArgument {
        apk: "/dev/block/by-name/microdroid-apk",
        idsig: "/dev/block/by-name/microdroid-apk-idsig",
        name: "microdroid-apk",
    }
};
const DM_MOUNTED_APK_PATH: &str = "/dev/block/mapper/microdroid-apk";
const APKDMVERITY_BIN: &str = "/system/bin/apkdmverity";
const ZIPFUSE_BIN: &str = "/system/bin/zipfuse";

/// The CID representing the host VM
const VMADDR_CID_HOST: u32 = 2;

const APEX_CONFIG_DONE_PROP: &str = "apex_config.done";
const LOGD_ENABLED_PROP: &str = "ro.boot.logd.enabled";

#[derive(thiserror::Error, Debug)]
enum MicrodroidError {
    #[error("Payload has changed: {0}")]
    PayloadChanged(String),
    #[error("Payload verification has failed: {0}")]
    PayloadVerificationFailed(String),
    #[error("Payload config is invalid: {0}")]
    InvalidConfig(String),
}

fn translate_error(err: &Error) -> (i32, String) {
    if let Some(e) = err.downcast_ref::<MicrodroidError>() {
        match e {
            MicrodroidError::PayloadChanged(msg) => (ERROR_PAYLOAD_CHANGED, msg.to_string()),
            MicrodroidError::PayloadVerificationFailed(msg) => {
                (ERROR_PAYLOAD_VERIFICATION_FAILED, msg.to_string())
            }
            MicrodroidError::InvalidConfig(msg) => (ERROR_PAYLOAD_INVALID_CONFIG, msg.to_string()),
        }
    } else {
        (ERROR_UNKNOWN, err.to_string())
    }
}

fn get_vms_rpc_binder() -> Result<Strong<dyn IVirtualMachineService>> {
    // SAFETY: AIBinder returned by RpcClient has correct reference count, and the ownership can be
    // safely taken by new_spibinder.
    let ibinder = unsafe {
        new_spibinder(binder_rpc_unstable_bindgen::RpcClient(
            VMADDR_CID_HOST,
            VM_BINDER_SERVICE_PORT as u32,
        ) as *mut AIBinder)
    };
    if let Some(ibinder) = ibinder {
        <dyn IVirtualMachineService>::try_from(ibinder).context("Cannot connect to RPC service")
    } else {
        bail!("Invalid raw AIBinder")
    }
}

fn main() {
    if let Err(e) = try_main() {
        error!("Failed with {:?}. Shutting down...", e);
        if let Err(e) = system_properties::write("sys.powerctl", "shutdown") {
            error!("failed to shutdown {:?}", e);
        }
        std::process::exit(1);
    }
}

fn try_main() -> Result<()> {
    kernlog::init()?;
    info!("started.");

    let service = get_vms_rpc_binder().context("cannot connect to VirtualMachineService")?;
    match try_run_payload(&service) {
        Ok(code) => {
            info!("notifying payload finished");
            service.notifyPayloadFinished(code)?;
            if code == 0 {
                info!("task successfully finished");
            } else {
                error!("task exited with exit code: {}", code);
            }
            Ok(())
        }
        Err(err) => {
            error!("task terminated: {:?}", err);
            let (error_code, message) = translate_error(&err);
            service.notifyError(error_code, &message)?;
            Err(err)
        }
    }
}

fn try_run_payload(service: &Strong<dyn IVirtualMachineService>) -> Result<i32> {
    let metadata = load_metadata().context("Failed to load payload metadata")?;

    let mut instance = InstanceDisk::new().context("Failed to load instance.img")?;
    let saved_data = instance.read_microdroid_data().context("Failed to read identity data")?;

    // Verify the payload before using it.
    let verified_data =
        verify_payload(&metadata, saved_data.as_ref()).context("Payload verification failed")?;
    if let Some(saved_data) = saved_data {
        ensure!(
            saved_data == verified_data,
            MicrodroidError::PayloadChanged(String::from(
                "Detected an update of the payload which isn't supported yet."
            ))
        );
        info!("Saved data is verified.");
    } else {
        info!("Saving verified data.");
        instance.write_microdroid_data(&verified_data).context("Failed to write identity data")?;
    }

    // Before reading a file from the APK, start zipfuse
    run_zipfuse(
        "fscontext=u:object_r:zipfusefs:s0,context=u:object_r:system_file:s0",
        Path::new("/dev/block/mapper/microdroid-apk"),
        Path::new("/mnt/apk"),
    )
    .context("Failed to run zipfuse")?;

    ensure!(
        !metadata.payload_config_path.is_empty(),
        MicrodroidError::InvalidConfig("No payload_config_path in metadata".to_string())
    );
    let config = load_config(Path::new(&metadata.payload_config_path))?;

    let fake_secret = "This is a placeholder for a value that is derived from the images that are loaded in the VM.";
    if let Err(err) = rustutils::system_properties::write("ro.vmsecret.keymint", fake_secret) {
        warn!("failed to set ro.vmsecret.keymint: {}", err);
    }

    // Wait until apex config is done. (e.g. linker configuration for apexes)
    // TODO(jooyung): wait until sys.boot_completed?
    wait_for_apex_config_done()?;

    ensure!(
        config.task.is_some(),
        MicrodroidError::InvalidConfig("No task in VM config".to_string())
    );
    exec_task(&config.task.unwrap(), service)
}

struct ApkDmverityArgument<'a> {
    apk: &'a str,
    idsig: &'a str,
    name: &'a str,
}

fn run_apkdmverity(args: &[ApkDmverityArgument]) -> Result<Child> {
    let mut cmd = Command::new(APKDMVERITY_BIN);

    cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());

    for argument in args {
        cmd.arg("--apk").arg(argument.apk).arg(argument.idsig).arg(argument.name);
    }

    cmd.spawn().context("Spawn apkdmverity")
}

fn run_zipfuse(option: &str, zip_path: &Path, mount_dir: &Path) -> Result<Child> {
    Command::new(ZIPFUSE_BIN)
        .arg("-o")
        .arg(option)
        .arg(zip_path)
        .arg(mount_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("Spawn zipfuse")
}

// Verify payload before executing it. For APK payload, Full verification (which is slow) is done
// when the root_hash values from the idsig file and the instance disk are different. This function
// returns the verified root hash (for APK payload) and pubkeys (for APEX payloads) that can be
// saved to the instance disk.
fn verify_payload(
    metadata: &Metadata,
    saved_data: Option<&MicrodroidData>,
) -> Result<MicrodroidData> {
    let start_time = SystemTime::now();

    if let Some(saved_bootconfig) = saved_data.map(|d| &d.bootconfig) {
        ensure!(
            saved_bootconfig.as_ref() == get_bootconfig()?.as_slice(),
            MicrodroidError::PayloadChanged(String::from("Bootconfig has changed."))
        );
    }

    let root_hash = saved_data.map(|d| &d.apk_data.root_hash);
    let root_hash_from_idsig = get_apk_root_hash_from_idsig()?;
    let root_hash_trustful = root_hash == Some(&root_hash_from_idsig);

    // If root_hash can be trusted, pass it to apkdmverity so that it uses the passed root_hash
    // instead of the value read from the idsig file.
    if root_hash_trustful {
        let root_hash = to_hex_string(root_hash.unwrap());
        system_properties::write("microdroid_manager.apk_root_hash", &root_hash)?;
    }

    // Start apkdmverity and wait for the dm-verify block
    let mut apkdmverity_child = run_apkdmverity(&[APK_DM_VERITY_ARGUMENT])?;

    // While waiting for apkdmverity to mount APK, gathers public keys and root digests from
    // APEX payload.
    let apex_data_from_payload = get_apex_data_from_payload(metadata)?;
    if let Some(saved_data) = saved_data.map(|d| &d.apex_data) {
        // We don't support APEX updates. (assuming that update will change root digest)
        ensure!(
            saved_data == &apex_data_from_payload,
            MicrodroidError::PayloadChanged(String::from("APEXes have changed."))
        );
        let apex_metadata = to_metadata(&apex_data_from_payload);
        // Pass metadata(with public keys and root digests) to apexd so that it uses the passed
        // metadata instead of the default one (/dev/block/by-name/payload-metadata)
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .open("/apex/vm-payload-metadata")
            .context("Failed to open /apex/vm-payload-metadata")
            .and_then(|f| write_metadata(&apex_metadata, f))?;
    }
    // Start apexd to activate APEXes
    system_properties::write("ctl.start", "apexd-vm")?;

    // TODO(inseob): add timeout
    apkdmverity_child.wait()?;

    // Do the full verification if the root_hash is un-trustful. This requires the full scanning of
    // the APK file and therefore can be very slow if the APK is large. Note that this step is
    // taken only when the root_hash is un-trustful which can be either when this is the first boot
    // of the VM or APK was updated in the host.
    // TODO(jooyung): consider multithreading to make this faster
    let apk_pubkey = if !root_hash_trustful {
        verify(DM_MOUNTED_APK_PATH).context(MicrodroidError::PayloadVerificationFailed(format!(
            "failed to verify {}",
            DM_MOUNTED_APK_PATH
        )))?
    } else {
        get_public_key_der(DM_MOUNTED_APK_PATH)?
    };

    info!("payload verification successful. took {:#?}", start_time.elapsed().unwrap());

    // At this point, we can ensure that the root_hash from the idsig file is trusted, either by
    // fully verifying the APK or by comparing it with the saved root_hash.
    Ok(MicrodroidData {
        apk_data: ApkData { root_hash: root_hash_from_idsig, pubkey: apk_pubkey },
        apex_data: apex_data_from_payload,
        bootconfig: get_bootconfig()?.clone().into_boxed_slice(),
    })
}

// Waits until linker config is generated
fn wait_for_apex_config_done() -> Result<()> {
    let mut prop = PropertyWatcher::new(APEX_CONFIG_DONE_PROP)?;
    loop {
        prop.wait()?;
        let val = system_properties::read(APEX_CONFIG_DONE_PROP)?;
        if val == "true" {
            break;
        }
    }
    Ok(())
}

fn get_apk_root_hash_from_idsig() -> Result<Box<RootHash>> {
    let mut idsig = File::open("/dev/block/by-name/microdroid-apk-idsig")?;
    let idsig = V4Signature::from(&mut idsig)?;
    Ok(idsig.hashing_info.raw_root_hash)
}

fn get_bootconfig() -> Result<&'static Vec<u8>> {
    static VAL: OnceCell<Vec<u8>> = OnceCell::new();
    VAL.get_or_try_init(|| {
        fs::read("/proc/bootconfig").context("Failed to read bootconfig")
    })
}

fn load_config(path: &Path) -> Result<VmPayloadConfig> {
    info!("loading config from {:?}...", path);
    let file = ioutil::wait_for_file(path, WAIT_TIMEOUT)?;
    Ok(serde_json::from_reader(file)?)
}

/// Executes the given task. Stdout of the task is piped into the vsock stream to the
/// virtualizationservice in the host side.
fn exec_task(task: &Task, service: &Strong<dyn IVirtualMachineService>) -> Result<i32> {
    info!("executing main task {:?}...", task);
    let mut command = build_command(task)?;

    info!("notifying payload started");
    service.notifyPayloadStarted()?;

    // Start logging if enabled
    // TODO(b/200914564) set filterspec if debug_level is app_only
    if system_properties::read(LOGD_ENABLED_PROP)? == "1" {
        system_properties::write("ctl.start", "seriallogging")?;
    }

    let exit_status = command.spawn()?.wait()?;
    exit_status.code().ok_or_else(|| anyhow!("Failed to get exit_code from the paylaod."))
}

fn build_command(task: &Task) -> Result<Command> {
    const VMADDR_CID_HOST: u32 = 2;

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

    match VsockStream::connect_with_cid_port(VMADDR_CID_HOST, VM_STREAM_SERVICE_PORT as u32) {
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
