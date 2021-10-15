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
use std::collections::BTreeMap;
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
use file::{RemoteFileEditor, RemoteFileReader, RemoteMerkleTreeReader};
use fsverity::{VerifiedFileEditor, VerifiedFileReader};
use fusefs::{FileConfig, Inode};

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
    /// For example, `--remote-verified-file 5:10:/path/to/cert` tells the filesystem to associate
    /// entry 5 with a remote file 10, and need to be verified against the /path/to/cert.
    #[structopt(long, parse(try_from_str = parse_remote_ro_file_option))]
    remote_ro_file: Vec<OptionRemoteRoFile>,

    /// A read-only remote file without integrity check. Can be multiple.
    ///
    /// For example, `--remote-unverified-file 5:10` tells the filesystem to associate entry 5
    /// with a remote file 10.
    #[structopt(long, parse(try_from_str = parse_remote_ro_file_unverified_option))]
    remote_ro_file_unverified: Vec<OptionRemoteRoFileUnverified>,

    /// A new read-writable remote file with integrity check. Can be multiple.
    ///
    /// For example, `--remote-new-verified-file 12:34` tells the filesystem to associate entry 12
    /// with a remote file 34.
    #[structopt(long, parse(try_from_str = parse_remote_new_rw_file_option))]
    remote_new_rw_file: Vec<OptionRemoteRwFile>,

    /// Enable debugging features.
    #[structopt(long)]
    debug: bool,
}

struct OptionRemoteRoFile {
    ino: Inode,

    /// ID to refer to the remote file.
    remote_id: i32,

    /// Certificate to verify the authenticity of the file's fs-verity signature.
    /// TODO(170494765): Implement PKCS#7 signature verification.
    _certificate_path: PathBuf,
}

struct OptionRemoteRoFileUnverified {
    ino: Inode,

    /// ID to refer to the remote file.
    remote_id: i32,
}

struct OptionRemoteRwFile {
    ino: Inode,

    /// ID to refer to the remote file.
    remote_id: i32,
}

fn parse_remote_ro_file_option(option: &str) -> Result<OptionRemoteRoFile> {
    let strs: Vec<&str> = option.split(':').collect();
    if strs.len() != 3 {
        bail!("Invalid option: {}", option);
    }
    Ok(OptionRemoteRoFile {
        ino: strs[0].parse::<Inode>()?,
        remote_id: strs[1].parse::<i32>()?,
        _certificate_path: PathBuf::from(strs[2]),
    })
}

fn parse_remote_ro_file_unverified_option(option: &str) -> Result<OptionRemoteRoFileUnverified> {
    let strs: Vec<&str> = option.split(':').collect();
    if strs.len() != 2 {
        bail!("Invalid option: {}", option);
    }
    Ok(OptionRemoteRoFileUnverified {
        ino: strs[0].parse::<Inode>()?,
        remote_id: strs[1].parse::<i32>()?,
    })
}

fn parse_remote_new_rw_file_option(option: &str) -> Result<OptionRemoteRwFile> {
    let strs: Vec<&str> = option.split(':').collect();
    if strs.len() != 2 {
        bail!("Invalid option: {}", option);
    }
    Ok(OptionRemoteRwFile {
        ino: strs[0].parse::<Inode>().unwrap(),
        remote_id: strs[1].parse::<i32>().unwrap(),
    })
}

fn new_config_remote_verified_file(
    service: file::VirtFdService,
    remote_id: i32,
    file_size: u64,
) -> Result<FileConfig> {
    let signature = service.readFsveritySignature(remote_id).context("Failed to read signature")?;

    let authenticator = FakeAuthenticator::always_succeed();
    Ok(FileConfig::VerifiedReadonly {
        reader: VerifiedFileReader::new(
            &authenticator,
            RemoteFileReader::new(service.clone(), remote_id),
            file_size,
            signature,
            RemoteMerkleTreeReader::new(service.clone(), remote_id),
        )?,
        file_size,
    })
}

fn new_config_remote_unverified_file(
    service: file::VirtFdService,
    remote_id: i32,
    file_size: u64,
) -> Result<FileConfig> {
    let reader = RemoteFileReader::new(service, remote_id);
    Ok(FileConfig::UnverifiedReadonly { reader, file_size })
}

fn new_config_remote_new_verified_file(
    service: file::VirtFdService,
    remote_id: i32,
) -> Result<FileConfig> {
    let remote_file = RemoteFileEditor::new(service, remote_id);
    Ok(FileConfig::VerifiedNew { editor: VerifiedFileEditor::new(remote_file) })
}

fn prepare_file_pool(args: &Args) -> Result<BTreeMap<Inode, FileConfig>> {
    let mut file_pool = BTreeMap::new();

    let service = file::get_rpc_binder_service(args.cid)?;

    for config in &args.remote_ro_file {
        file_pool.insert(
            config.ino,
            new_config_remote_verified_file(
                service.clone(),
                config.remote_id,
                service.getFileSize(config.remote_id)?.try_into()?,
            )?,
        );
    }

    for config in &args.remote_ro_file_unverified {
        file_pool.insert(
            config.ino,
            new_config_remote_unverified_file(
                service.clone(),
                config.remote_id,
                service.getFileSize(config.remote_id)?.try_into()?,
            )?,
        );
    }

    for config in &args.remote_new_rw_file {
        file_pool.insert(
            config.ino,
            new_config_remote_new_verified_file(service.clone(), config.remote_id)?,
        );
    }

    Ok(file_pool)
}

fn try_main() -> Result<()> {
    let args = Args::from_args();

    let log_level = if args.debug { log::Level::Debug } else { log::Level::Info };
    android_logger::init_once(
        android_logger::Config::default().with_tag("authfs").with_min_level(log_level),
    );

    let file_pool = prepare_file_pool(&args)?;
    fusefs::loop_forever(file_pool, &args.mount_point, &args.extra_options)?;
    bail!("Unexpected exit after the handler loop")
}

fn main() {
    if let Err(e) = try_main() {
        error!("failed with {:?}", e);
        std::process::exit(1);
    }
}
