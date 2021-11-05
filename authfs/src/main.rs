/*
 * Copyright (C) 2020 The Android Open Source Project
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

//! This crate implements AuthFS, a FUSE-based, non-generic filesystem where file access is
//! authenticated. This filesystem assumes the underlying layer is not trusted, e.g. file may be
//! provided by an untrusted host/VM, so that the content can't be simply trusted. However, with a
//! public key from a trusted party, this filesystem can still verify a (read-only) file signed by
//! the trusted party even if the host/VM as the blob provider is malicious. With the Merkle tree,
//! each read of file block can be verified individually only when needed.
//!
//! AuthFS only serve files that are specifically configured. A file configuration may include the
//! source (e.g. remote file server), verification method (e.g. certificate for fs-verity
//! verification, or no verification if expected to mount over dm-verity), and file ID. Regardless
//! of the actual file name, the exposed file names through AuthFS are currently integer, e.g.
//! /mountpoint/42.

use anyhow::{bail, Context, Result};
use log::error;
use std::collections::HashMap;
use std::convert::TryInto;
use std::path::PathBuf;
use structopt::StructOpt;

mod auth;
mod common;
mod crypto;
mod file;
mod fsverity;
mod fusefs;

use auth::FakeAuthenticator;
use file::{RemoteDirEditor, RemoteFileEditor, RemoteFileReader, RemoteMerkleTreeReader};
use fsverity::{VerifiedFileEditor, VerifiedFileReader};
use fusefs::AuthFsEntry;

#[derive(StructOpt)]
struct Args {
    /// Mount point of AuthFS.
    #[structopt(parse(from_os_str))]
    mount_point: PathBuf,

    /// CID of the VM where the service runs.
    #[structopt(long)]
    cid: u32,

    /// Extra options to FUSE
    #[structopt(short = "o")]
    extra_options: Option<String>,

    /// A read-only remote file with integrity check. Can be multiple.
    ///
    /// For example, `--remote-ro-file 5:/path/to/cert` tells the filesystem to associate the
    /// file $MOUNTPOINT/5 with a remote FD 5, and need to be verified against the /path/to/cert.
    #[structopt(long, parse(try_from_str = parse_remote_ro_file_option))]
    remote_ro_file: Vec<OptionRemoteRoFile>,

    /// A read-only remote file without integrity check. Can be multiple.
    ///
    /// For example, `--remote-ro-file-unverified 5` tells the filesystem to associate the file
    /// $MOUNTPOINT/5 with a remote FD 5.
    #[structopt(long)]
    remote_ro_file_unverified: Vec<i32>,

    /// A new read-writable remote file with integrity check. Can be multiple.
    ///
    /// For example, `--remote-new-rw-file 5` tells the filesystem to associate the file
    /// $MOUNTPOINT/5 with a remote FD 5.
    #[structopt(long)]
    remote_new_rw_file: Vec<i32>,

    /// A new directory that is assumed empty in the backing filesystem. New files created in this
    /// directory are integrity-protected in the same way as --remote-new-verified-file. Can be
    /// multiple.
    ///
    /// For example, `--remote-new-rw-dir 5` tells the filesystem to associate $MOUNTPOINT/5
    /// with a remote dir FD 5.
    #[structopt(long)]
    remote_new_rw_dir: Vec<i32>,

    /// Enable debugging features.
    #[structopt(long)]
    debug: bool,
}

struct OptionRemoteRoFile {
    /// ID to refer to the remote file.
    remote_fd: i32,

    /// Certificate to verify the authenticity of the file's fs-verity signature.
    /// TODO(170494765): Implement PKCS#7 signature verification.
    _certificate_path: PathBuf,
}

fn parse_remote_ro_file_option(option: &str) -> Result<OptionRemoteRoFile> {
    let strs: Vec<&str> = option.split(':').collect();
    if strs.len() != 2 {
        bail!("Invalid option: {}", option);
    }
    Ok(OptionRemoteRoFile {
        remote_fd: strs[0].parse::<i32>()?,
        _certificate_path: PathBuf::from(strs[1]),
    })
}

fn new_remote_verified_file_entry(
    service: file::VirtFdService,
    remote_fd: i32,
    file_size: u64,
) -> Result<AuthFsEntry> {
    let signature = service.readFsveritySignature(remote_fd).context("Failed to read signature")?;

    let authenticator = FakeAuthenticator::always_succeed();
    Ok(AuthFsEntry::VerifiedReadonly {
        reader: VerifiedFileReader::new(
            &authenticator,
            RemoteFileReader::new(service.clone(), remote_fd),
            file_size,
            signature,
            RemoteMerkleTreeReader::new(service.clone(), remote_fd),
        )?,
        file_size,
    })
}

fn new_remote_unverified_file_entry(
    service: file::VirtFdService,
    remote_fd: i32,
    file_size: u64,
) -> Result<AuthFsEntry> {
    let reader = RemoteFileReader::new(service, remote_fd);
    Ok(AuthFsEntry::UnverifiedReadonly { reader, file_size })
}

fn new_remote_new_verified_file_entry(
    service: file::VirtFdService,
    remote_fd: i32,
) -> Result<AuthFsEntry> {
    let remote_file = RemoteFileEditor::new(service, remote_fd);
    Ok(AuthFsEntry::VerifiedNew { editor: VerifiedFileEditor::new(remote_file) })
}

fn new_remote_new_verified_dir_entry(
    service: file::VirtFdService,
    remote_fd: i32,
) -> Result<AuthFsEntry> {
    let dir = RemoteDirEditor::new(service, remote_fd);
    Ok(AuthFsEntry::VerifiedNewDirectory { dir })
}

fn prepare_root_dir_entries(args: &Args) -> Result<HashMap<PathBuf, AuthFsEntry>> {
    let mut root_entries = HashMap::new();

    let service = file::get_rpc_binder_service(args.cid)?;

    for config in &args.remote_ro_file {
        root_entries.insert(
            remote_fd_to_path_buf(config.remote_fd),
            new_remote_verified_file_entry(
                service.clone(),
                config.remote_fd,
                service.getFileSize(config.remote_fd)?.try_into()?,
            )?,
        );
    }

    for remote_fd in &args.remote_ro_file_unverified {
        let remote_fd = *remote_fd;
        root_entries.insert(
            remote_fd_to_path_buf(remote_fd),
            new_remote_unverified_file_entry(
                service.clone(),
                remote_fd,
                service.getFileSize(remote_fd)?.try_into()?,
            )?,
        );
    }

    for remote_fd in &args.remote_new_rw_file {
        let remote_fd = *remote_fd;
        root_entries.insert(
            remote_fd_to_path_buf(remote_fd),
            new_remote_new_verified_file_entry(service.clone(), remote_fd)?,
        );
    }

    for remote_fd in &args.remote_new_rw_dir {
        let remote_fd = *remote_fd;
        root_entries.insert(
            remote_fd_to_path_buf(remote_fd),
            new_remote_new_verified_dir_entry(service.clone(), remote_fd)?,
        );
    }

    Ok(root_entries)
}

fn remote_fd_to_path_buf(fd: i32) -> PathBuf {
    PathBuf::from(fd.to_string())
}

fn try_main() -> Result<()> {
    let args = Args::from_args();

    let log_level = if args.debug { log::Level::Debug } else { log::Level::Info };
    android_logger::init_once(
        android_logger::Config::default().with_tag("authfs").with_min_level(log_level),
    );

    let root_entries = prepare_root_dir_entries(&args)?;
    fusefs::loop_forever(root_entries, &args.mount_point, &args.extra_options)?;
    bail!("Unexpected exit after the handler loop")
}

fn main() {
    if let Err(e) = try_main() {
        error!("failed with {:?}", e);
        std::process::exit(1);
    }
}
