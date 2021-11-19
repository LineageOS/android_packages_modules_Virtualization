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

//! pvm_exec is a proxy/wrapper command to run compilation task remotely. The most important task
//! for this program is to run a `fd_server` that serves remote file read/write requests.
//!
//! It currently works as a command line wrapper to make it easy to schedule an existing dex2oat
//! task to run in the VM.
//!
//! Example:
//! $ adb shell exec 3</input/dex 4<>/output/oat ... pvm_exec --in-fd 3 --out-fd 4 -- dex2oat64 ...
//!
//! Note the immediate argument "dex2oat64" right after "--" is not really used. It is only for
//! ergonomics.

use anyhow::{bail, Context, Result};
use binder::unstable_api::{new_spibinder, AIBinder};
use binder::FromIBinder;
use clap::{value_t, App, Arg};
use log::{debug, error, warn};
use minijail::Minijail;
use nix::fcntl::{fcntl, FcntlArg::F_GETFD, OFlag};
use nix::unistd::pipe2;
use std::fs::File;
use std::io::Read;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::Path;
use std::process::exit;

use android_system_composd_internal::{
    aidl::android::system::composd::internal::ICompilationInternal::ICompilationInternal,
    binder::wait_for_interface,
};
use compos_aidl_interface::aidl::com::android::compos::{
    FdAnnotation::FdAnnotation, ICompOsService::ICompOsService,
};
use compos_aidl_interface::binder::Strong;
use compos_common::{COMPOS_VSOCK_PORT, VMADDR_CID_ANY};

const FD_SERVER_BIN: &str = "/apex/com.android.virt/bin/fd_server";

fn get_composd() -> Result<Strong<dyn ICompilationInternal>> {
    wait_for_interface::<dyn ICompilationInternal>("android.system.composd.internal")
        .context("Failed to find ICompilationInternal")
}

fn get_rpc_binder(cid: u32) -> Result<Strong<dyn ICompOsService>> {
    // SAFETY: AIBinder returned by RpcClient has correct reference count, and the ownership can be
    // safely taken by new_spibinder.
    let ibinder = unsafe {
        new_spibinder(
            binder_rpc_unstable_bindgen::RpcClient(cid, COMPOS_VSOCK_PORT) as *mut AIBinder
        )
    };
    if let Some(ibinder) = ibinder {
        <dyn ICompOsService>::try_from(ibinder).context("Cannot connect to RPC service")
    } else {
        bail!("Invalid raw AIBinder")
    }
}

fn spawn_fd_server(
    fd_annotation: &FdAnnotation,
    ready_file: File,
    debuggable: bool,
) -> Result<Minijail> {
    let mut inheritable_fds = if debuggable {
        vec![1, 2] // inherit/redirect stdout/stderr for debugging
    } else {
        vec![]
    };

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

fn is_fd_valid(fd: RawFd) -> Result<bool> {
    let retval = fcntl(fd, F_GETFD)?;
    Ok(retval >= 0)
}

fn parse_arg_fd(arg: &str) -> Result<RawFd> {
    let fd = arg.parse::<RawFd>()?;
    if !is_fd_valid(fd)? {
        bail!("Bad FD: {}", fd);
    }
    Ok(fd)
}

struct Config {
    args: Vec<String>,
    fd_annotation: FdAnnotation,
    cid: u32,
    debuggable: bool,
}

fn parse_args() -> Result<Config> {
    #[rustfmt::skip]
    let matches = App::new("pvm_exec")
        .arg(Arg::with_name("in-fd")
             .long("in-fd")
             .takes_value(true)
             .multiple(true)
             .use_delimiter(true))
        .arg(Arg::with_name("out-fd")
             .long("out-fd")
             .takes_value(true)
             .multiple(true)
             .use_delimiter(true))
        .arg(Arg::with_name("cid")
             .takes_value(true)
             .required(true)
             .long("cid"))
        .arg(Arg::with_name("debug")
             .long("debug"))
        .arg(Arg::with_name("args")
             .last(true)
             .required(true)
             .multiple(true))
        .get_matches();

    let results: Result<Vec<_>> =
        matches.values_of("in-fd").unwrap_or_default().map(parse_arg_fd).collect();
    let input_fds = results?;

    let results: Result<Vec<_>> =
        matches.values_of("out-fd").unwrap_or_default().map(parse_arg_fd).collect();
    let output_fds = results?;

    let args: Vec<_> = matches.values_of("args").unwrap().map(|s| s.to_string()).collect();
    let cid = value_t!(matches, "cid", i32)? as u32;
    let debuggable = matches.is_present("debug");

    Ok(Config { args, fd_annotation: FdAnnotation { input_fds, output_fds }, cid, debuggable })
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

fn try_main() -> Result<()> {
    // 1. Parse the command line arguments for collect execution data.
    let Config { args, fd_annotation, cid, debuggable } = parse_args()?;

    // 2. Spawn and configure a fd_server to serve remote read/write requests.
    let (ready_read_fd, ready_write_fd) = create_pipe()?;
    let fd_server_jail = spawn_fd_server(&fd_annotation, ready_write_fd, debuggable)?;
    let fd_server_lifetime = scopeguard::guard(fd_server_jail, |fd_server_jail| {
        if let Err(e) = fd_server_jail.kill() {
            if !matches!(e, minijail::Error::Killed(_)) {
                warn!("Failed to kill fd_server: {}", e);
            }
        }
    });

    // 3. Send the command line args to the remote to execute.
    let result = if cid == VMADDR_CID_ANY {
        // Sentinel value that indicates we should use composd
        let composd = get_composd()?;
        wait_for_fd_server_ready(ready_read_fd)?;
        composd.compile_cmd(&args, &fd_annotation)
    } else {
        // Call directly into the VM
        let compos_vm = get_rpc_binder(cid)?;
        wait_for_fd_server_ready(ready_read_fd)?;
        compos_vm.compile_cmd(&args, &fd_annotation)
    };
    let result = result.context("Binder call failed")?;

    // TODO: store/use the signature
    debug!(
        "Signature length: oat {}, vdex {}, image {}",
        result.oatSignature.len(),
        result.vdexSignature.len(),
        result.imageSignature.len()
    );

    // Be explicit about the lifetime, which should last at least until the task is finished.
    drop(fd_server_lifetime);

    if result.exitCode != 0 {
        error!("remote execution failed with exit code {}", result.exitCode);
        exit(result.exitCode as i32);
    }
    Ok(())
}

fn main() {
    let debuggable = env!("TARGET_BUILD_VARIANT") != "user";
    let log_level = if debuggable { log::Level::Trace } else { log::Level::Info };
    android_logger::init_once(
        android_logger::Config::default().with_tag("pvm_exec").with_min_level(log_level),
    );

    // Make sure we log and indicate failure if we were unable to run the command and get its exit
    // code.
    if let Err(e) = try_main() {
        error!("{:?}", e);
        std::process::exit(-1)
    }
}
