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

use crate::fd_server_helper::FdServerConfig;
use anyhow::{bail, Context, Result};
use compos_aidl_interface::aidl::com::android::compos::ICompOsService::ICompOsService;
use compos_aidl_interface::binder::Strong;
use compos_common::timeouts::{need_extra_time, EXTENDED_TIMEOUTS};
use compos_common::VMADDR_CID_ANY;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use rustutils::system_properties;
use shared_child::SharedChild;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::process::Command;

// TODO: What if this changes?
const EX_MAX: i8 = 78;
const ODREFRESH_BIN: &str = "/apex/com.android.art/bin/odrefresh";

#[derive(Debug, PartialEq, Eq, FromPrimitive)]
#[repr(i8)]
pub enum ExitCode {
    // Copied from art/odrefresh/include/odrefresh/odrefresh.h
    Okay = 0i8,
    CompilationRequired = EX_MAX + 1,
    CompilationSuccess = EX_MAX + 2,
    CompilationFailed = EX_MAX + 3,
    CleanupFailed = EX_MAX + 4,
}

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
        let mut cmdline = Command::new(ODREFRESH_BIN);
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
        if let Some(exit_code) = status.code().and_then(FromPrimitive::from_i32) {
            Ok(exit_code)
        } else {
            bail!("odrefresh exited with {}", status)
        }
    }

    pub fn kill(&self) -> Result<()> {
        self.child.kill().context("Killing odrefresh process failed")
    }
}

pub fn run_in_vm(service: Strong<dyn ICompOsService>, _target_dir_name: &str) -> Result<ExitCode> {
    // TODO: Use target_dir_name
    let staging_dir = open_dir(composd_native::palette_create_odrefresh_staging_directory()?)?;
    let system_dir = open_dir(Path::new("/system"))?;

    // Spawn a fd_server to serve the FDs.
    let fd_server_config = FdServerConfig {
        ro_dir_fds: vec![system_dir.as_raw_fd()],
        rw_dir_fds: vec![staging_dir.as_raw_fd()],
        ..Default::default()
    };
    let fd_server_raii = fd_server_config.into_fd_server()?;

    let zygote_arch = system_properties::read("ro.zygote")?;
    let exit_code =
        service.odrefresh(system_dir.as_raw_fd(), staging_dir.as_raw_fd(), &zygote_arch)?.exitCode;

    drop(fd_server_raii);
    if let Some(exit_code) = FromPrimitive::from_i8(exit_code) {
        Ok(exit_code)
    } else {
        bail!("odrefresh exited with {}", exit_code)
    }
}

/// Returns an owned FD of the directory. It currently returns a `File` as a FD owner, but
/// it's better to use `std::os::unix::io::OwnedFd` once/if it becomes standard.
fn open_dir(path: &Path) -> Result<File> {
    OpenOptions::new()
        .custom_flags(libc::O_DIRECTORY)
        .read(true) // O_DIRECTORY can only be opened with read
        .open(path)
        .with_context(|| format!("Failed to open {:?} directory as path fd", path))
}
