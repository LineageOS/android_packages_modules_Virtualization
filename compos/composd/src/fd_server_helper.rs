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

//! A helper library to start a fd_server.
//!
//! TODO(205750213): Make it easy to spawn a fd_server.

use anyhow::{Context, Result};
use log::debug;
use minijail::Minijail;
use nix::fcntl::OFlag;
use nix::unistd::pipe2;
use std::fs::File;
use std::io::Read;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::Path;

const FD_SERVER_BIN: &str = "/apex/com.android.virt/bin/fd_server";

#[allow(dead_code)]
fn spawn_fd_server(input_fds: &[i32], output_fds: &[i32], ready_file: File) -> Result<Minijail> {
    let mut inheritable_fds = Vec::new();
    let mut args = vec![FD_SERVER_BIN.to_string()];
    for fd in input_fds {
        args.push("--ro-fds".to_string());
        args.push(fd.to_string());
        inheritable_fds.push(*fd);
    }
    for fd in output_fds {
        args.push("--rw-fds".to_string());
        args.push(fd.to_string());
        inheritable_fds.push(*fd);
    }
    let ready_fd = ready_file.as_raw_fd();
    args.push("--ready-fd".to_string());
    args.push(ready_fd.to_string());
    inheritable_fds.push(ready_fd);

    let jail = Minijail::new()?;
    let _pid = jail.run(Path::new(FD_SERVER_BIN), &inheritable_fds, &args)?;
    Ok(jail)
}

#[allow(dead_code)]
fn create_pipe() -> Result<(File, File)> {
    let (raw_read, raw_write) = pipe2(OFlag::O_CLOEXEC)?;
    // SAFETY: We are the sole owners of these fds as they were just created.
    let read_fd = unsafe { File::from_raw_fd(raw_read) };
    let write_fd = unsafe { File::from_raw_fd(raw_write) };
    Ok((read_fd, write_fd))
}

#[allow(dead_code)]
fn wait_for_fd_server_ready(mut ready_fd: File) -> Result<()> {
    let mut buffer = [0];
    // When fd_server is ready it closes its end of the pipe. And if it exits, the pipe is also
    // closed. Either way this read will return 0 bytes at that point, and there's no point waiting
    // any longer.
    let _ = ready_fd.read(&mut buffer).context("Waiting for fd_server to be ready")?;
    debug!("fd_server is ready");
    Ok(())
}
