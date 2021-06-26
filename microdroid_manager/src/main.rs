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
use log::info;
use microdroid_payload_config::{Task, TaskType, VmPayloadConfig};
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

const WAIT_TIMEOUT: Duration = Duration::from_secs(10);

fn main() -> Result<()> {
    kernlog::init()?;
    info!("started.");

    let metadata = metadata::load()?;
    if !metadata.payload_config_path.is_empty() {
        let config = load_config(Path::new(&metadata.payload_config_path))?;

        // TODO(jooyung): wait until sys.boot_completed?
        if let Some(main_task) = &config.task {
            exec_task(main_task)?;
        }
    }

    Ok(())
}

fn load_config(path: &Path) -> Result<VmPayloadConfig> {
    info!("loading config from {:?}...", path);
    let file = ioutil::wait_for_file(path, WAIT_TIMEOUT)?;
    Ok(serde_json::from_reader(file)?)
}

fn exec_task(task: &Task) -> Result<()> {
    info!("executing main task {:?}...", task);
    let exit_status = build_command(task)?.spawn()?.wait()?;
    if exit_status.success() {
        Ok(())
    } else {
        match exit_status.code() {
            Some(code) => bail!("task exited with exit code: {}", code),
            None => bail!("task terminated by signal"),
        }
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
