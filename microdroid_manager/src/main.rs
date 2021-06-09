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
mod payload_config;

use android_logger::Config;
use log::{info, Level};
use payload_config::{Task, VmPayloadConfig};
use std::io;
use std::path::Path;
use std::process::{Command, Stdio};

const LOG_TAG: &str = "MicrodroidManager";

fn main() -> io::Result<()> {
    android_logger::init_once(Config::default().with_tag(LOG_TAG).with_min_level(Level::Debug));

    info!("started.");

    let metadata = metadata::load()?;
    if !metadata.payload_config_path.is_empty() {
        let config = VmPayloadConfig::load_from(Path::new(&metadata.payload_config_path))?;
        if let Some(main_task) = &config.task {
            exec(main_task)?;
        }
    }

    Ok(())
}

/// executes a task
/// TODO(jooyung): fork a child process
fn exec(task: &Task) -> io::Result<()> {
    info!("executing main task {} {:?}...", task.command, task.args);
    let exit_status =
        Command::new(&task.command).args(&task.args).stdout(Stdio::inherit()).status()?;
    info!("exit with {}", &exit_status);
    Ok(())
}
