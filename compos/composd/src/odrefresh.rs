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

//! Handle the details of executing odrefresh to generate compiled artifacts.

// TODO: Delete

use anyhow::{bail, Context, Result};
use compos_common::odrefresh::{ExitCode, ODREFRESH_PATH};
use compos_common::timeouts::{need_extra_time, EXTENDED_TIMEOUTS};
use compos_common::VMADDR_CID_ANY;
use shared_child::SharedChild;
use std::process::Command;

pub struct Odrefresh {
    child: SharedChild,
}

impl Odrefresh {
    pub fn spawn_compile(target_dir: &str) -> Result<Self> {
        Self::spawn_odrefresh(target_dir, "--compile")
    }

    pub fn spawn_forced_compile(target_dir: &str) -> Result<Self> {
        Self::spawn_odrefresh(target_dir, "--force-compile")
    }

    fn spawn_odrefresh(target_dir: &str, compile_arg: &str) -> Result<Self> {
        // We don`t need to capture stdout/stderr - odrefresh writes to the log
        let mut cmdline = Command::new(ODREFRESH_PATH);
        if need_extra_time()? {
            cmdline
                .arg(format!(
                    "--max-execution-seconds={}",
                    EXTENDED_TIMEOUTS.odrefresh_max_execution_time.as_secs()
                ))
                .arg(format!(
                    "--max-child-process-seconds={}",
                    EXTENDED_TIMEOUTS.odrefresh_max_child_process_time.as_secs()
                ));
        }
        cmdline
            .arg(format!("--use-compilation-os={}", VMADDR_CID_ANY as i32))
            .arg(format!("--dalvik-cache={}", target_dir))
            .arg(compile_arg);
        let child = SharedChild::spawn(&mut cmdline).context("Running odrefresh")?;
        Ok(Odrefresh { child })
    }

    pub fn wait_for_exit(&self) -> Result<ExitCode> {
        // No timeout here - but clients can kill the process, which will end the wait.
        let status = self.child.wait()?;
        if let Some(exit_code) = status.code() {
            ExitCode::from_i32(exit_code)
        } else {
            bail!("odrefresh exited with {}", status)
        }
    }

    pub fn kill(&self) -> Result<()> {
        self.child.kill().context("Killing odrefresh process failed")
    }
}
