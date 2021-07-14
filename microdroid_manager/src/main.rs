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

mod ioutil;
mod metadata;

use anyhow::{anyhow, bail, Result};
use keystore2_system_property::PropertyWatcher;
use log::{error, info, warn};
use microdroid_payload_config::{Task, TaskType, VmPayloadConfig};
use std::fs::{self, File};
use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::path::Path;
use std::process::{Command, Stdio};
use std::str;
use std::time::Duration;
use vsock::VsockStream;

const WAIT_TIMEOUT: Duration = Duration::from_secs(10);

fn main() -> Result<()> {
    kernlog::init()?;
    info!("started.");

    let metadata = metadata::load()?;
    if !metadata.payload_config_path.is_empty() {
        let config = load_config(Path::new(&metadata.payload_config_path))?;

        let fake_secret = "This is a placeholder for a value that is derived from the images that are loaded in the VM.";
        if let Err(err) = keystore2_system_property::write("ro.vmsecret.keymint", fake_secret) {
            warn!("failed to set ro.vmsecret.keymint: {}", err);
        }

        // TODO(jooyung): wait until sys.boot_completed?
        if let Some(main_task) = &config.task {
            exec_task(main_task).map_err(|e| {
                error!("failed to execute task: {}", e);
                e
            })?;
        }
    }

    Ok(())
}

fn load_config(path: &Path) -> Result<VmPayloadConfig> {
    info!("loading config from {:?}...", path);
    let file = ioutil::wait_for_file(path, WAIT_TIMEOUT)?;
    Ok(serde_json::from_reader(file)?)
}

/// Executes the given task. Stdout of the task is piped into the vsock stream to the
/// virtualizationservice in the host side.
fn exec_task(task: &Task) -> Result<()> {
    const VMADDR_CID_HOST: u32 = 2;
    const PORT_VIRT_SVC: u32 = 3000;
    let stdout = match VsockStream::connect_with_cid_port(VMADDR_CID_HOST, PORT_VIRT_SVC) {
        Ok(stream) => {
            // SAFETY: the ownership of the underlying file descriptor is transferred from stream
            // to the file object, and then into the Command object. When the command is finished,
            // the file descriptor is closed.
            let f = unsafe { File::from_raw_fd(stream.into_raw_fd()) };
            Stdio::from(f)
        }
        Err(e) => {
            error!("failed to connect to virtualization service: {}", e);
            // Don't fail hard here. Even if we failed to connect to the virtualizationservice,
            // we keep executing the task. This can happen if the owner of the VM doesn't register
            // callback to accept the stream. Use /dev/null as the stdout so that the task can
            // make progress without waiting for someone to consume the output.
            Stdio::null()
        }
    };
    info!("executing main task {:?}...", task);
    // TODO(jiyong): consider piping the stream into stdio (and probably stderr) as well.
    let mut child = build_command(task)?.stdout(stdout).spawn()?;
    match child.wait()?.code() {
        Some(0) => {
            info!("task successfully finished");
            Ok(())
        }
        Some(code) => bail!("task exited with exit code: {}", code),
        None => bail!("task terminated by signal"),
    }
}

fn build_command(task: &Task) -> Result<Command> {
    Ok(match task.type_ {
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
    })
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
