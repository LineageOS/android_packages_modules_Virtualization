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

use anyhow::{bail, Context, Result};
use log::{debug, error, warn};
use nix::mount::{umount2, MntFlags};
use nix::sys::statfs::{statfs, FsType};
use shared_child::SharedChild;
use std::ffi::{OsStr, OsString};
use std::fs::{remove_dir, OpenOptions};
use std::path::PathBuf;
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, Instant};

use crate::common::new_binder_exception;
use authfs_aidl_interface::aidl::com::android::virt::fs::IAuthFs::{BnAuthFs, IAuthFs};
use authfs_aidl_interface::aidl::com::android::virt::fs::{
    AuthFsConfig::AuthFsConfig, InputFdAnnotation::InputFdAnnotation,
    OutputFdAnnotation::OutputFdAnnotation,
};
use authfs_aidl_interface::binder::{
    self, BinderFeatures, ExceptionCode, Interface, ParcelFileDescriptor, Strong,
};

const AUTHFS_BIN: &str = "/system/bin/authfs";
const AUTHFS_SETUP_POLL_INTERVAL_MS: Duration = Duration::from_millis(50);
const AUTHFS_SETUP_TIMEOUT_SEC: Duration = Duration::from_secs(10);
const FUSE_SUPER_MAGIC: FsType = FsType(0x65735546);

/// An `AuthFs` instance is supposed to be backed by an `authfs` process. When the lifetime of the
/// instance is over, it should leave no trace on the system: the process should be terminated, the
/// FUSE should be unmounted, and the mount directory should be deleted.
pub struct AuthFs {
    mountpoint: OsString,
    process: SharedChild,
}

impl Interface for AuthFs {}

impl IAuthFs for AuthFs {
    fn openFile(
        &self,
        remote_fd_name: i32,
        writable: bool,
    ) -> binder::Result<ParcelFileDescriptor> {
        let mut path = PathBuf::from(&self.mountpoint);
        path.push(remote_fd_name.to_string());
        let file = OpenOptions::new().read(true).write(writable).open(&path).map_err(|e| {
            new_binder_exception(
                ExceptionCode::SERVICE_SPECIFIC,
                format!("failed to open {:?} on authfs: {}", &path, e),
            )
        })?;
        Ok(ParcelFileDescriptor::new(file))
    }
}

impl AuthFs {
    /// Mount an authfs at `mountpoint` with specified FD annotations.
    pub fn mount_and_wait(
        mountpoint: OsString,
        config: &AuthFsConfig,
        debuggable: bool,
    ) -> Result<Strong<dyn IAuthFs>> {
        let child = run_authfs(
            &mountpoint,
            &config.inputFdAnnotations,
            &config.outputFdAnnotations,
            debuggable,
        )?;
        wait_until_authfs_ready(&mountpoint).map_err(|e| {
            debug!("Wait for authfs: {:?}", child.wait());
            e
        })?;

        let authfs = AuthFs { mountpoint, process: child };
        Ok(BnAuthFs::new_binder(authfs, BinderFeatures::default()))
    }
}

impl Drop for AuthFs {
    /// On drop, try to erase all the traces for this authfs mount.
    fn drop(&mut self) {
        debug!("Dropping AuthFs instance at mountpoint {:?}", &self.mountpoint);
        if let Err(e) = self.process.kill() {
            error!("Failed to kill authfs: {}", e);
        }
        match self.process.wait() {
            Ok(status) => debug!("authfs exit code: {}", status),
            Err(e) => warn!("Failed to wait for authfs: {}", e),
        }
        // The client may still hold the file descriptors that refer to this filesystem. Use
        // MNT_DETACH to detach the mountpoint, and automatically unmount when there is no more
        // reference.
        if let Err(e) = umount2(self.mountpoint.as_os_str(), MntFlags::MNT_DETACH) {
            error!("Failed to umount authfs at {:?}: {}", &self.mountpoint, e)
        }

        if let Err(e) = remove_dir(&self.mountpoint) {
            error!("Failed to clean up mount directory {:?}: {}", &self.mountpoint, e)
        }
    }
}

fn run_authfs(
    mountpoint: &OsStr,
    in_fds: &[InputFdAnnotation],
    out_fds: &[OutputFdAnnotation],
    debuggable: bool,
) -> Result<SharedChild> {
    let mut args = vec![mountpoint.to_owned(), OsString::from("--cid=2")];
    args.push(OsString::from("-o"));
    args.push(OsString::from("fscontext=u:object_r:authfs_fuse:s0"));
    for conf in in_fds {
        // TODO(b/185178698): Many input files need to be signed and verified.
        // or can we use debug cert for now, which is better than nothing?
        args.push(OsString::from("--remote-ro-file-unverified"));
        args.push(OsString::from(format!("{}:{}:{}", conf.fd, conf.fd, conf.fileSize)));
    }
    for conf in out_fds {
        args.push(OsString::from("--remote-new-rw-file"));
        args.push(OsString::from(format!("{}:{}", conf.fd, conf.fd)));
    }
    if debuggable {
        args.push(OsString::from("--debug"));
    }

    let mut command = Command::new(AUTHFS_BIN);
    command.args(&args);
    SharedChild::spawn(&mut command).context("Spawn authfs")
}

fn wait_until_authfs_ready(mountpoint: &OsStr) -> Result<()> {
    let start_time = Instant::now();
    loop {
        if is_fuse(mountpoint)? {
            break;
        }
        if start_time.elapsed() > AUTHFS_SETUP_TIMEOUT_SEC {
            bail!("Time out mounting authfs");
        }
        sleep(AUTHFS_SETUP_POLL_INTERVAL_MS);
    }
    Ok(())
}

fn is_fuse(path: &OsStr) -> Result<bool> {
    Ok(statfs(path)?.filesystem_type() == FUSE_SUPER_MAGIC)
}
