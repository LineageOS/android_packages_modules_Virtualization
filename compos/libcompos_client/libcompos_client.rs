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

//! A library for a client to send requests to the CompOS service in the VM.

use anyhow::{Context, Result};
use binder_common::rpc_client::connect_rpc_binder;
use libc::c_int;
use log::{debug, error, warn};
use minijail::Minijail;
use nix::fcntl::OFlag;
use nix::unistd::pipe2;
use std::fs::File;
use std::io::Read;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::Path;
use std::slice::from_raw_parts;

use android_system_composd::{
    aidl::android::system::composd::IIsolatedCompilationService::IIsolatedCompilationService,
    binder::wait_for_interface,
};
use compos_aidl_interface::aidl::com::android::compos::{
    FdAnnotation::FdAnnotation, ICompOsService::ICompOsService,
};
use compos_aidl_interface::binder::Strong;
use compos_common::{COMPOS_VSOCK_PORT, VMADDR_CID_ANY};

const FD_SERVER_BIN: &str = "/apex/com.android.virt/bin/fd_server";

fn get_composd() -> Result<Strong<dyn IIsolatedCompilationService>> {
    wait_for_interface::<dyn IIsolatedCompilationService>("android.system.composd")
        .context("Failed to find IIsolatedCompilationService")
}

fn spawn_fd_server(fd_annotation: &FdAnnotation, ready_file: File) -> Result<Minijail> {
    let mut inheritable_fds = Vec::new();
    let mut args = vec![FD_SERVER_BIN.to_string()];
    for fd in &fd_annotation.input_fds {
        args.push("--ro-fds".to_string());
        args.push(fd.to_string());
        inheritable_fds.push(*fd);
    }
    for fd in &fd_annotation.output_fds {
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

fn create_pipe() -> Result<(File, File)> {
    let (raw_read, raw_write) = pipe2(OFlag::O_CLOEXEC)?;
    // SAFETY: We are the sole owners of these fds as they were just created.
    let read_fd = unsafe { File::from_raw_fd(raw_read) };
    let write_fd = unsafe { File::from_raw_fd(raw_write) };
    Ok((read_fd, write_fd))
}

fn wait_for_fd_server_ready(mut ready_fd: File) -> Result<()> {
    let mut buffer = [0];
    // When fd_server is ready it closes its end of the pipe. And if it exits, the pipe is also
    // closed. Either way this read will return 0 bytes at that point, and there's no point waiting
    // any longer.
    let _ = ready_fd.read(&mut buffer).context("Waiting for fd_server to be ready")?;
    debug!("fd_server is ready");
    Ok(())
}

fn try_request(cid: c_int, marshaled: &[u8], fd_annotation: FdAnnotation) -> Result<c_int> {
    // 1. Spawn a fd_server to serve remote read/write requests.
    let (ready_read_fd, ready_write_fd) = create_pipe()?;
    let fd_server_jail = spawn_fd_server(&fd_annotation, ready_write_fd)?;
    let fd_server_lifetime = scopeguard::guard(fd_server_jail, |fd_server_jail| {
        if let Err(e) = fd_server_jail.kill() {
            if !matches!(e, minijail::Error::Killed(_)) {
                warn!("Failed to kill fd_server: {}", e);
            }
        }
    });

    // 2. Send the marshaled request the remote.
    let cid = cid as u32;
    let result = if cid == VMADDR_CID_ANY {
        // Sentinel value that indicates we should use composd
        let composd = get_composd()?;
        wait_for_fd_server_ready(ready_read_fd)?;
        composd.compile(marshaled, &fd_annotation)
    } else {
        // Call directly into the VM
        let compos_vm = connect_rpc_binder::<dyn ICompOsService>(cid, COMPOS_VSOCK_PORT)
            .context("Cannot connect to RPC binder")?;
        wait_for_fd_server_ready(ready_read_fd)?;
        compos_vm.compile(marshaled, &fd_annotation)
    };
    let result = result.context("Binder call failed")?;

    // Be explicit about the lifetime, which should last at least until the task is finished.
    drop(fd_server_lifetime);

    Ok(c_int::from(result))
}

/// A public C API. See libcompos_client.h for the canonical doc.
///
/// # Safety
///
/// The client must provide legitimate pointers with correct sizes to the backing arrays.
#[no_mangle]
pub unsafe extern "C" fn AComposClient_Request(
    cid: c_int,
    marshaled: *const u8,
    size: usize,
    ro_fds: *const c_int,
    ro_fds_num: usize,
    rw_fds: *const c_int,
    rw_fds_num: usize,
) -> c_int {
    if marshaled.is_null() || ro_fds.is_null() || rw_fds.is_null() {
        error!("Argument pointers should not be null");
        return -1;
    }

    // The unsafe parts.
    let ro_fd_slice = from_raw_parts(ro_fds, ro_fds_num);
    let rw_fd_slice = from_raw_parts(rw_fds, rw_fds_num);
    let marshaled_slice = from_raw_parts(marshaled, size);

    let fd_annotation =
        FdAnnotation { input_fds: ro_fd_slice.to_vec(), output_fds: rw_fd_slice.to_vec() };

    match try_request(cid, marshaled_slice, fd_annotation) {
        Ok(exit_code) => exit_code,
        Err(e) => {
            error!("AComposClient_Request failed: {:?}", e);
            -1
        }
    }
}
