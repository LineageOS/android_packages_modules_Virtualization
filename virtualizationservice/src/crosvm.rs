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

//! Functions for running instances of `crosvm`.

use crate::aidl::VirtualMachineCallbacks;
use crate::Cid;
use anyhow::{bail, Error};
use command_fds::{CommandFdExt, FdMapping};
use log::{debug, error, info};
use shared_child::SharedChild;
use std::fs::{remove_dir_all, File};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

const CROSVM_PATH: &str = "/apex/com.android.virt/bin/crosvm";

/// Configuration for a VM to run with crosvm.
#[derive(Debug)]
pub struct CrosvmConfig<'a> {
    pub cid: Cid,
    pub bootloader: Option<&'a File>,
    pub kernel: Option<&'a File>,
    pub initrd: Option<&'a File>,
    pub disks: Vec<DiskFile>,
    pub params: Option<String>,
    pub protected: bool,
}

/// A disk image to pass to crosvm for a VM.
#[derive(Debug)]
pub struct DiskFile {
    pub image: File,
    pub writable: bool,
}

/// Information about a particular instance of a VM which is running.
#[derive(Debug)]
pub struct VmInstance {
    /// The crosvm child process.
    child: SharedChild,
    /// The CID assigned to the VM for vsock communication.
    pub cid: Cid,
    /// Whether the VM is a protected VM.
    pub protected: bool,
    /// Directory of temporary files used by the VM while it is running.
    pub temporary_directory: PathBuf,
    /// The UID of the process which requested the VM.
    pub requester_uid: u32,
    /// The SID of the process which requested the VM.
    pub requester_sid: String,
    /// The PID of the process which requested the VM. Note that this process may no longer exist
    /// and the PID may have been reused for a different process, so this should not be trusted.
    pub requester_debug_pid: i32,
    /// Whether the VM is still running.
    running: AtomicBool,
    /// Callbacks to clients of the VM.
    pub callbacks: VirtualMachineCallbacks,
}

impl VmInstance {
    /// Create a new `VmInstance` for the given process.
    fn new(
        child: SharedChild,
        cid: Cid,
        protected: bool,
        temporary_directory: PathBuf,
        requester_uid: u32,
        requester_sid: String,
        requester_debug_pid: i32,
    ) -> VmInstance {
        VmInstance {
            child,
            cid,
            protected,
            temporary_directory,
            requester_uid,
            requester_sid,
            requester_debug_pid,
            running: AtomicBool::new(true),
            callbacks: Default::default(),
        }
    }

    /// Start an instance of `crosvm` to manage a new VM. The `crosvm` instance will be killed when
    /// the `VmInstance` is dropped.
    pub fn start(
        config: &CrosvmConfig,
        log_fd: Option<File>,
        composite_disk_mappings: &[FdMapping],
        temporary_directory: PathBuf,
        requester_uid: u32,
        requester_sid: String,
        requester_debug_pid: i32,
    ) -> Result<Arc<VmInstance>, Error> {
        let child = run_vm(config, log_fd, composite_disk_mappings)?;
        let instance = Arc::new(VmInstance::new(
            child,
            config.cid,
            config.protected,
            temporary_directory,
            requester_uid,
            requester_sid,
            requester_debug_pid,
        ));

        let instance_clone = instance.clone();
        thread::spawn(move || {
            instance_clone.monitor();
        });

        Ok(instance)
    }

    /// Wait for the crosvm child process to finish, then mark the VM as no longer running and call
    /// any callbacks.
    fn monitor(&self) {
        match self.child.wait() {
            Err(e) => error!("Error waiting for crosvm instance to die: {}", e),
            Ok(status) => info!("crosvm exited with status {}", status),
        }
        self.running.store(false, Ordering::Release);
        self.callbacks.callback_on_died(self.cid);

        // Delete temporary files.
        if let Err(e) = remove_dir_all(&self.temporary_directory) {
            error!("Error removing temporary directory {:?}: {}", self.temporary_directory, e);
        }
    }

    /// Return whether `crosvm` is still running the VM.
    pub fn running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    /// Kill the crosvm instance.
    pub fn kill(&self) {
        // TODO: Talk to crosvm to shutdown cleanly.
        if let Err(e) = self.child.kill() {
            error!("Error killing crosvm instance: {}", e);
        }
    }
}

/// Start an instance of `crosvm` to manage a new VM.
fn run_vm(
    config: &CrosvmConfig,
    log_fd: Option<File>,
    composite_disk_mappings: &[FdMapping],
) -> Result<SharedChild, Error> {
    validate_config(config)?;

    let mut command = Command::new(CROSVM_PATH);
    // TODO(qwandor): Remove --disable-sandbox.
    command.arg("run").arg("--disable-sandbox").arg("--cid").arg(config.cid.to_string());

    if config.protected {
        command.arg("--protected-vm");
    }

    if let Some(log_fd) = log_fd {
        command.stdout(log_fd);
    } else {
        // Ignore console output.
        command.arg("--serial=type=sink");
    }

    // Keep track of what file descriptors should be mapped to the crosvm process.
    let mut fd_mappings = composite_disk_mappings.to_vec();

    if let Some(bootloader) = &config.bootloader {
        command.arg("--bios").arg(add_fd_mapping(&mut fd_mappings, bootloader));
    }

    if let Some(initrd) = &config.initrd {
        command.arg("--initrd").arg(add_fd_mapping(&mut fd_mappings, initrd));
    }

    if let Some(params) = &config.params {
        command.arg("--params").arg(params);
    }

    for disk in &config.disks {
        command
            .arg(if disk.writable { "--rwdisk" } else { "--disk" })
            .arg(add_fd_mapping(&mut fd_mappings, &disk.image));
    }

    if let Some(kernel) = &config.kernel {
        command.arg(add_fd_mapping(&mut fd_mappings, kernel));
    }

    debug!("Setting mappings {:?}", fd_mappings);
    command.fd_mappings(fd_mappings)?;

    info!("Running {:?}", command);
    let result = SharedChild::spawn(&mut command)?;
    Ok(result)
}

/// Ensure that the configuration has a valid combination of fields set, or return an error if not.
fn validate_config(config: &CrosvmConfig) -> Result<(), Error> {
    if config.bootloader.is_none() && config.kernel.is_none() {
        bail!("VM must have either a bootloader or a kernel image.");
    }
    if config.bootloader.is_some() && (config.kernel.is_some() || config.initrd.is_some()) {
        bail!("Can't have both bootloader and kernel/initrd image.");
    }
    Ok(())
}

/// Adds a mapping for `file` to `fd_mappings`, and returns a string of the form "/proc/self/fd/N"
/// where N is the file descriptor for the child process.
fn add_fd_mapping(fd_mappings: &mut Vec<FdMapping>, file: &File) -> String {
    let fd = file.as_raw_fd();
    fd_mappings.push(FdMapping { parent_fd: fd, child_fd: fd });
    format!("/proc/self/fd/{}", fd)
}
