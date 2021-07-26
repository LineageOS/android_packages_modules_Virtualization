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

//! This executable works as a child/worker for the main compsvc service. This worker is mainly
//! responsible for setting up the execution environment, e.g. to create file descriptors for
//! remote file access via an authfs mount.

mod authfs;

use anyhow::{bail, Result};
use minijail::Minijail;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::process::exit;

use crate::authfs::{AuthFs, InFdAnnotation, OutFdAnnotation, PseudoRawFd};

fn open_authfs_files_for_mapping(
    authfs: &AuthFs,
    config: &Config,
) -> Result<Vec<(File, PseudoRawFd)>> {
    let mut fd_mapping = Vec::with_capacity(config.in_fds.len() + config.out_fds.len());

    let results: Result<Vec<_>> =
        config.in_fds.iter().map(|conf| Ok((authfs.open_file(conf.fd, false)?, conf.fd))).collect();
    fd_mapping.append(&mut results?);

    let results: Result<Vec<_>> =
        config.out_fds.iter().map(|conf| Ok((authfs.open_file(conf.fd, true)?, conf.fd))).collect();
    fd_mapping.append(&mut results?);

    Ok(fd_mapping)
}

fn spawn_jailed_task(config: &Config, fd_mapping: Vec<(File, PseudoRawFd)>) -> Result<Minijail> {
    // TODO(b/185175567): Run in a more restricted sandbox.
    let jail = Minijail::new()?;
    let mut preserve_fds: Vec<_> = fd_mapping.iter().map(|(f, id)| (f.as_raw_fd(), *id)).collect();
    if config.debuggable {
        // inherit/redirect stdout/stderr for debugging
        preserve_fds.push((1, 1));
        preserve_fds.push((2, 2));
    }
    let _pid =
        jail.run_remap(&Path::new(&config.args[0]), preserve_fds.as_slice(), &config.args)?;
    Ok(jail)
}

struct Config {
    authfs_root: String,
    in_fds: Vec<InFdAnnotation>,
    out_fds: Vec<OutFdAnnotation>,
    args: Vec<String>,
    debuggable: bool,
}

fn parse_args() -> Result<Config> {
    #[rustfmt::skip]
    let matches = clap::App::new("compsvc_worker")
        .arg(clap::Arg::with_name("authfs-root")
             .long("authfs-root")
             .value_name("DIR")
             .required(true)
             .takes_value(true))
        .arg(clap::Arg::with_name("in-fd")
             .long("in-fd")
             .multiple(true)
             .takes_value(true)
             .requires("authfs-root"))
        .arg(clap::Arg::with_name("out-fd")
             .long("out-fd")
             .multiple(true)
             .takes_value(true)
             .requires("authfs-root"))
        .arg(clap::Arg::with_name("debug")
             .long("debug"))
        .arg(clap::Arg::with_name("args")
             .last(true)
             .required(true)
             .multiple(true))
        .get_matches();

    // Safe to unwrap since the arg is required by the clap rule
    let authfs_root = matches.value_of("authfs-root").unwrap().to_string();

    let results: Result<Vec<_>> = matches
        .values_of("in-fd")
        .unwrap_or_default()
        .into_iter()
        .map(|arg| {
            if let Some(index) = arg.find(':') {
                let (fd, size) = arg.split_at(index);
                Ok(InFdAnnotation { fd: fd.parse()?, file_size: size[1..].parse()? })
            } else {
                bail!("Invalid argument: {}", arg);
            }
        })
        .collect();
    let in_fds = results?;

    let results: Result<Vec<_>> = matches
        .values_of("out-fd")
        .unwrap_or_default()
        .into_iter()
        .map(|arg| Ok(OutFdAnnotation { fd: arg.parse()? }))
        .collect();
    let out_fds = results?;

    let args: Vec<_> = matches.values_of("args").unwrap().map(|s| s.to_string()).collect();
    let debuggable = matches.is_present("debug");

    Ok(Config { authfs_root, in_fds, out_fds, args, debuggable })
}

fn main() -> Result<()> {
    let log_level =
        if env!("TARGET_BUILD_VARIANT") == "eng" { log::Level::Trace } else { log::Level::Info };
    android_logger::init_once(
        android_logger::Config::default().with_tag("compsvc_worker").with_min_level(log_level),
    );

    let config = parse_args()?;

    let authfs = AuthFs::mount_and_wait(
        &config.authfs_root,
        &config.in_fds,
        &config.out_fds,
        config.debuggable,
    )?;
    let fd_mapping = open_authfs_files_for_mapping(&authfs, &config)?;

    let jail = spawn_jailed_task(&config, fd_mapping)?;
    let jail_result = jail.wait();

    // Be explicit about the lifetime, which should last at least until the task is finished.
    drop(authfs);

    match jail_result {
        Ok(_) => Ok(()),
        Err(minijail::Error::ReturnCode(exit_code)) => {
            exit(exit_code as i32);
        }
        Err(e) => {
            bail!("Unexpected minijail error: {}", e);
        }
    }
}
