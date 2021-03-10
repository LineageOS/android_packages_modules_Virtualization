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
//! source (e.g. local file or remote file server), verification method (e.g. certificate for
//! fs-verity verification, or no verification if expected to mount over dm-verity), and file ID.
//! Regardless of the actual file name, the exposed file names through AuthFS are currently integer,
//! e.g. /mountpoint/42.

use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use structopt::StructOpt;

mod auth;
mod common;
mod crypto;
mod fsverity;
mod fusefs;
mod reader;
mod remote_file;

use auth::FakeAuthenticator;
use fsverity::FsverityChunkedFileReader;
use fusefs::{FileConfig, Inode};
use reader::ChunkedFileReader;
use remote_file::{RemoteChunkedFileReader, RemoteFsverityMerkleTreeReader};

#[derive(StructOpt)]
struct Args {
    /// Mount point of AuthFS.
    #[structopt(parse(from_os_str))]
    mount_point: PathBuf,

    /// A verifiable read-only file. Can be multiple.
    ///
    /// For example, `--remote-verified-file 5:10:1234:/path/to/cert` tells the filesystem to
    /// associate entry 5 with a remote file 10 of size 1234 bytes, and need to be verified against
    /// the /path/to/cert.
    #[structopt(long, parse(try_from_str = parse_remote_verified_file_option))]
    remote_verified_file: Vec<RemoteVerifiedFileConfig>,

    /// An unverifiable read-only file. Can be multiple.
    ///
    /// For example, `--remote-unverified-file 5:10:1234` tells the filesystem to associate entry 5
    /// with a remote file 10 of size 1234 bytes.
    #[structopt(long, parse(try_from_str = parse_remote_unverified_file_option))]
    remote_unverified_file: Vec<RemoteUnverifiedFileConfig>,

    /// Debug only. A readonly file to be protected by fs-verity. Can be multiple.
    #[structopt(long, parse(try_from_str = parse_local_verified_file_option))]
    local_verified_file: Vec<LocalVerifiedFileConfig>,

    /// Debug only. An unverified read-only file. Can be multiple.
    #[structopt(long, parse(try_from_str = parse_local_unverified_file_option))]
    local_unverified_file: Vec<LocalUnverifiedFileConfig>,
}

struct RemoteVerifiedFileConfig {
    ino: Inode,

    /// ID to refer to the remote file.
    remote_id: i32,

    /// Expected size of the remote file. Necessary for signature check and Merkle tree
    /// verification.
    file_size: u64,

    /// Certificate to verify the authenticity of the file's fs-verity signature.
    /// TODO(170494765): Implement PKCS#7 signature verification.
    _certificate_path: PathBuf,
}

struct RemoteUnverifiedFileConfig {
    ino: Inode,

    /// ID to refer to the remote file.
    remote_id: i32,

    /// Expected size of the remote file.
    file_size: u64,
}

struct LocalVerifiedFileConfig {
    ino: Inode,

    /// Local path of the backing file.
    file_path: PathBuf,

    /// Local path of the backing file's fs-verity Merkle tree dump.
    merkle_tree_dump_path: PathBuf,

    /// Local path of fs-verity signature for the backing file.
    signature_path: PathBuf,

    /// Certificate to verify the authenticity of the file's fs-verity signature.
    /// TODO(170494765): Implement PKCS#7 signature verification.
    _certificate_path: PathBuf,
}

struct LocalUnverifiedFileConfig {
    ino: Inode,

    /// Local path of the backing file.
    file_path: PathBuf,
}

fn parse_remote_verified_file_option(option: &str) -> Result<RemoteVerifiedFileConfig> {
    let strs: Vec<&str> = option.split(':').collect();
    if strs.len() != 4 {
        bail!("Invalid option: {}", option);
    }
    Ok(RemoteVerifiedFileConfig {
        ino: strs[0].parse::<Inode>()?,
        remote_id: strs[1].parse::<i32>()?,
        file_size: strs[2].parse::<u64>()?,
        _certificate_path: PathBuf::from(strs[3]),
    })
}

fn parse_remote_unverified_file_option(option: &str) -> Result<RemoteUnverifiedFileConfig> {
    let strs: Vec<&str> = option.split(':').collect();
    if strs.len() != 3 {
        bail!("Invalid option: {}", option);
    }
    Ok(RemoteUnverifiedFileConfig {
        ino: strs[0].parse::<Inode>()?,
        remote_id: strs[1].parse::<i32>()?,
        file_size: strs[2].parse::<u64>()?,
    })
}

fn parse_local_verified_file_option(option: &str) -> Result<LocalVerifiedFileConfig> {
    let strs: Vec<&str> = option.split(':').collect();
    if strs.len() != 5 {
        bail!("Invalid option: {}", option);
    }
    Ok(LocalVerifiedFileConfig {
        ino: strs[0].parse::<Inode>()?,
        file_path: PathBuf::from(strs[1]),
        merkle_tree_dump_path: PathBuf::from(strs[2]),
        signature_path: PathBuf::from(strs[3]),
        _certificate_path: PathBuf::from(strs[4]),
    })
}

fn parse_local_unverified_file_option(option: &str) -> Result<LocalUnverifiedFileConfig> {
    let strs: Vec<&str> = option.split(':').collect();
    if strs.len() != 2 {
        bail!("Invalid option: {}", option);
    }
    Ok(LocalUnverifiedFileConfig {
        ino: strs[0].parse::<Inode>()?,
        file_path: PathBuf::from(strs[1]),
    })
}

fn new_config_remote_verified_file(remote_id: i32, file_size: u64) -> Result<FileConfig> {
    let service = remote_file::server::get_local_service();
    let signature = service.readFsveritySignature(remote_id).context("Failed to read signature")?;

    let service = Arc::new(Mutex::new(service));
    let authenticator = FakeAuthenticator::always_succeed();
    Ok(FileConfig::RemoteVerifiedFile(
        FsverityChunkedFileReader::new(
            &authenticator,
            RemoteChunkedFileReader::new(Arc::clone(&service), remote_id),
            file_size,
            signature,
            RemoteFsverityMerkleTreeReader::new(Arc::clone(&service), remote_id),
        )?,
        file_size,
    ))
}

fn new_config_remote_unverified_file(remote_id: i32, file_size: u64) -> Result<FileConfig> {
    let file_reader = RemoteChunkedFileReader::new(
        Arc::new(Mutex::new(remote_file::server::get_local_service())),
        remote_id,
    );
    Ok(FileConfig::RemoteUnverifiedFile(file_reader, file_size))
}

fn new_config_local_verified_file(
    protected_file: &PathBuf,
    merkle_tree_dump: &PathBuf,
    signature: &PathBuf,
) -> Result<FileConfig> {
    let file = File::open(&protected_file)?;
    let file_size = file.metadata()?.len();
    let file_reader = ChunkedFileReader::new(file)?;
    let merkle_tree_reader = ChunkedFileReader::new(File::open(merkle_tree_dump)?)?;
    let authenticator = FakeAuthenticator::always_succeed();
    let mut sig = Vec::new();
    let _ = File::open(signature)?.read_to_end(&mut sig)?;
    let file_reader = FsverityChunkedFileReader::new(
        &authenticator,
        file_reader,
        file_size,
        sig,
        merkle_tree_reader,
    )?;
    Ok(FileConfig::LocalVerifiedFile(file_reader, file_size))
}

fn new_config_local_unverified_file(file_path: &PathBuf) -> Result<FileConfig> {
    let file_reader = ChunkedFileReader::new(File::open(file_path)?)?;
    let file_size = file_reader.len();
    Ok(FileConfig::LocalUnverifiedFile(file_reader, file_size))
}

fn prepare_file_pool(args: &Args) -> Result<BTreeMap<Inode, FileConfig>> {
    let mut file_pool = BTreeMap::new();

    for config in &args.remote_verified_file {
        file_pool.insert(
            config.ino,
            new_config_remote_verified_file(config.remote_id, config.file_size)?,
        );
    }

    for config in &args.remote_unverified_file {
        file_pool.insert(
            config.ino,
            new_config_remote_unverified_file(config.remote_id, config.file_size)?,
        );
    }

    for config in &args.local_verified_file {
        file_pool.insert(
            config.ino,
            new_config_local_verified_file(
                &config.file_path,
                &config.merkle_tree_dump_path,
                &config.signature_path,
            )?,
        );
    }

    for config in &args.local_unverified_file {
        file_pool.insert(config.ino, new_config_local_unverified_file(&config.file_path)?);
    }

    Ok(file_pool)
}

fn main() -> Result<()> {
    let args = Args::from_args();
    let file_pool = prepare_file_pool(&args)?;
    fusefs::loop_forever(file_pool, &args.mount_point)?;
    bail!("Unexpected exit after the handler loop")
}
