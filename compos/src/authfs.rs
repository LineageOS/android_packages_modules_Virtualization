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
use log::warn;
use minijail::Minijail;
use nix::sys::statfs::{statfs, FsType};
use std::fs::{File, OpenOptions};
use std::path::Path;
use std::thread::sleep;
use std::time::{Duration, Instant};

const AUTHFS_BIN: &str = "/system/bin/authfs";
const AUTHFS_SETUP_POLL_INTERVAL_MS: Duration = Duration::from_millis(50);
const AUTHFS_SETUP_TIMEOUT_SEC: Duration = Duration::from_secs(10);
const FUSE_SUPER_MAGIC: FsType = FsType(0x65735546);

/// The number that hints the future file descriptor. These are not really file descriptor, but
/// represents the file descriptor number to pass to the task.
pub type PseudoRawFd = i32;

/// Annotation of input file descriptor.
#[derive(Debug)]
pub struct InFdAnnotation {
    /// A number/file descriptor that is supposed to represent a remote file.
    pub fd: PseudoRawFd,

    /// The file size of the remote file. Remote input files are supposed to be immutable and
    /// to be verified with fs-verity by authfs.
    pub file_size: u64,
}

/// Annotation of output file descriptor.
#[derive(Debug)]
pub struct OutFdAnnotation {
    /// A number/file descriptor that is supposed to represent a remote file.
    pub fd: PseudoRawFd,
}

/// An `AuthFs` instance is supposed to be backed by the `authfs` process. When the lifetime of the
/// instance is over, the process is terminated and the FUSE is unmounted.
pub struct AuthFs {
    mountpoint: String,
    jail: Minijail,
}

impl AuthFs {
    /// Mount an authfs at `mountpoint` with specified FD annotations.
    pub fn mount_and_wait(
        mountpoint: &str,
        in_fds: &[InFdAnnotation],
        out_fds: &[OutFdAnnotation],
        debuggable: bool,
    ) -> Result<AuthFs> {
        let jail = jail_authfs(mountpoint, in_fds, out_fds, debuggable)?;
        wait_until_authfs_ready(mountpoint)?;
        Ok(AuthFs { mountpoint: mountpoint.to_string(), jail })
    }

    /// Open a file at authfs' root directory.
    pub fn open_file(&self, basename: PseudoRawFd, writable: bool) -> Result<File> {
        OpenOptions::new()
            .read(true)
            .write(writable)
            .open(format!("{}/{}", self.mountpoint, basename))
            .with_context(|| format!("open authfs file {}", basename))
    }
}

impl Drop for AuthFs {
    fn drop(&mut self) {
        if let Err(e) = self.jail.kill() {
            if !matches!(e, minijail::Error::Killed(_)) {
                warn!("Failed to kill authfs: {}", e);
            }
        }
    }
}

fn jail_authfs(
    mountpoint: &str,
    in_fds: &[InFdAnnotation],
    out_fds: &[OutFdAnnotation],
    debuggable: bool,
) -> Result<Minijail> {
    // TODO(b/185175567): Run in a more restricted sandbox.
    let jail = Minijail::new()?;

    let mut args = vec![
        AUTHFS_BIN.to_string(),
        mountpoint.to_string(),
        "--cid=2".to_string(), // Always use host unless we need to support other cases
    ];
    for conf in in_fds {
        // TODO(b/185178698): Many input files need to be signed and verified.
        // or can we use debug cert for now, which is better than nothing?
        args.push("--remote-ro-file-unverified".to_string());
        args.push(format!("{}:{}:{}", conf.fd, conf.fd, conf.file_size));
    }
    for conf in out_fds {
        args.push("--remote-new-rw-file".to_string());
        args.push(format!("{}:{}", conf.fd, conf.fd));
    }

    let preserve_fds = if debuggable {
        vec![1, 2] // inherit/redirect stdout/stderr for debugging
    } else {
        vec![]
    };

    let _pid = jail.run(Path::new(AUTHFS_BIN), &preserve_fds, &args)?;
    Ok(jail)
}

fn wait_until_authfs_ready(mountpoint: &str) -> Result<()> {
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

fn is_fuse(path: &str) -> Result<bool> {
    Ok(statfs(path)?.filesystem_type() == FUSE_SUPER_MAGIC)
}
