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

use anyhow::Result;
use log::error;
use nix::errno::Errno;
use std::cmp::min;
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::os::unix::io::AsRawFd;

use crate::fsverity;
use authfs_aidl_interface::aidl::com::android::virt::fs::IVirtFdService::{
    BnVirtFdService, IVirtFdService, MAX_REQUESTING_DATA,
};
use authfs_aidl_interface::binder::{
    BinderFeatures, Interface, Result as BinderResult, Status, StatusCode, Strong,
};
use binder_common::new_binder_service_specific_error;

fn validate_and_cast_offset(offset: i64) -> Result<u64, Status> {
    offset.try_into().map_err(|_| new_errno_error(Errno::EINVAL))
}

fn validate_and_cast_size(size: i32) -> Result<usize, Status> {
    if size > MAX_REQUESTING_DATA {
        Err(new_errno_error(Errno::EFBIG))
    } else {
        size.try_into().map_err(|_| new_errno_error(Errno::EINVAL))
    }
}

/// Configuration of a file descriptor to be served/exposed/shared.
pub enum FdConfig {
    /// A read-only file to serve by this server. The file is supposed to be verifiable with the
    /// associated fs-verity metadata.
    Readonly {
        /// The file to read from. fs-verity metadata can be retrieved from this file's FD.
        file: File,

        /// Alternative Merkle tree stored in another file.
        alt_merkle_tree: Option<File>,

        /// Alternative signature stored in another file.
        alt_signature: Option<File>,
    },

    /// A readable/writable file to serve by this server. This backing file should just be a
    /// regular file and does not have any specific property.
    ReadWrite(File),
}

pub struct FdService {
    /// A pool of opened files, may be readonly or read-writable.
    fd_pool: BTreeMap<i32, FdConfig>,
}

impl FdService {
    pub fn new_binder(fd_pool: BTreeMap<i32, FdConfig>) -> Strong<dyn IVirtFdService> {
        BnVirtFdService::new_binder(FdService { fd_pool }, BinderFeatures::default())
    }

    /// Handles the requesting file `id` with `handler` if it is in the FD pool. This function
    /// returns whatever the handler returns.
    fn handle_fd<F, R>(&self, id: i32, handler: F) -> BinderResult<R>
    where
        F: FnOnce(&FdConfig) -> BinderResult<R>,
    {
        let fd_config = self.fd_pool.get(&id).ok_or_else(|| new_errno_error(Errno::EBADF))?;
        handler(fd_config)
    }
}

impl Interface for FdService {}

impl IVirtFdService for FdService {
    fn readFile(&self, id: i32, offset: i64, size: i32) -> BinderResult<Vec<u8>> {
        let size: usize = validate_and_cast_size(size)?;
        let offset: u64 = validate_and_cast_offset(offset)?;

        self.handle_fd(id, |config| match config {
            FdConfig::Readonly { file, .. } | FdConfig::ReadWrite(file) => {
                read_into_buf(file, size, offset).map_err(|e| {
                    error!("readFile: read error: {}", e);
                    new_errno_error(Errno::EIO)
                })
            }
        })
    }

    fn readFsverityMerkleTree(&self, id: i32, offset: i64, size: i32) -> BinderResult<Vec<u8>> {
        let size: usize = validate_and_cast_size(size)?;
        let offset: u64 = validate_and_cast_offset(offset)?;

        self.handle_fd(id, |config| match config {
            FdConfig::Readonly { file, alt_merkle_tree, .. } => {
                if let Some(tree_file) = &alt_merkle_tree {
                    read_into_buf(tree_file, size, offset).map_err(|e| {
                        error!("readFsverityMerkleTree: read error: {}", e);
                        new_errno_error(Errno::EIO)
                    })
                } else {
                    let mut buf = vec![0; size];
                    let s = fsverity::read_merkle_tree(file.as_raw_fd(), offset, &mut buf)
                        .map_err(|e| {
                            error!("readFsverityMerkleTree: failed to retrieve merkle tree: {}", e);
                            new_errno_error(Errno::EIO)
                        })?;
                    debug_assert!(s <= buf.len(), "Shouldn't return more bytes than asked");
                    buf.truncate(s);
                    Ok(buf)
                }
            }
            FdConfig::ReadWrite(_file) => {
                // For a writable file, Merkle tree is not expected to be served since Auth FS
                // doesn't trust it anyway. Auth FS may keep the Merkle tree privately for its own
                // use.
                Err(new_errno_error(Errno::ENOSYS))
            }
        })
    }

    fn readFsveritySignature(&self, id: i32) -> BinderResult<Vec<u8>> {
        self.handle_fd(id, |config| match config {
            FdConfig::Readonly { file, alt_signature, .. } => {
                if let Some(sig_file) = &alt_signature {
                    // Supposedly big enough buffer size to store signature.
                    let size = MAX_REQUESTING_DATA as usize;
                    let offset = 0;
                    read_into_buf(sig_file, size, offset).map_err(|e| {
                        error!("readFsveritySignature: read error: {}", e);
                        new_errno_error(Errno::EIO)
                    })
                } else {
                    let mut buf = vec![0; MAX_REQUESTING_DATA as usize];
                    let s = fsverity::read_signature(file.as_raw_fd(), &mut buf).map_err(|e| {
                        error!("readFsverityMerkleTree: failed to retrieve merkle tree: {}", e);
                        new_errno_error(Errno::EIO)
                    })?;
                    debug_assert!(s <= buf.len(), "Shouldn't return more bytes than asked");
                    buf.truncate(s);
                    Ok(buf)
                }
            }
            FdConfig::ReadWrite(_file) => {
                // There is no signature for a writable file.
                Err(new_errno_error(Errno::ENOSYS))
            }
        })
    }

    fn writeFile(&self, id: i32, buf: &[u8], offset: i64) -> BinderResult<i32> {
        self.handle_fd(id, |config| match config {
            FdConfig::Readonly { .. } => Err(StatusCode::INVALID_OPERATION.into()),
            FdConfig::ReadWrite(file) => {
                let offset: u64 = offset.try_into().map_err(|_| new_errno_error(Errno::EINVAL))?;
                // Check buffer size just to make `as i32` safe below.
                if buf.len() > i32::MAX as usize {
                    return Err(new_errno_error(Errno::EOVERFLOW));
                }
                Ok(file.write_at(buf, offset).map_err(|e| {
                    error!("writeFile: write error: {}", e);
                    new_errno_error(Errno::EIO)
                })? as i32)
            }
        })
    }

    fn resize(&self, id: i32, size: i64) -> BinderResult<()> {
        self.handle_fd(id, |config| match config {
            FdConfig::Readonly { .. } => Err(StatusCode::INVALID_OPERATION.into()),
            FdConfig::ReadWrite(file) => {
                if size < 0 {
                    return Err(new_errno_error(Errno::EINVAL));
                }
                file.set_len(size as u64).map_err(|e| {
                    error!("resize: set_len error: {}", e);
                    new_errno_error(Errno::EIO)
                })
            }
        })
    }

    fn getFileSize(&self, id: i32) -> BinderResult<i64> {
        self.handle_fd(id, |config| match config {
            FdConfig::Readonly { file, .. } => {
                let size = file
                    .metadata()
                    .map_err(|e| {
                        error!("getFileSize error: {}", e);
                        new_errno_error(Errno::EIO)
                    })?
                    .len();
                Ok(size.try_into().map_err(|e| {
                    error!("getFileSize: File too large: {}", e);
                    new_errno_error(Errno::EFBIG)
                })?)
            }
            FdConfig::ReadWrite(_file) => {
                // Content and metadata of a writable file needs to be tracked by authfs, since
                // fd_server isn't considered trusted. So there is no point to support getFileSize
                // for a writable file.
                Err(new_errno_error(Errno::ENOSYS))
            }
        })
    }
}

fn read_into_buf(file: &File, max_size: usize, offset: u64) -> io::Result<Vec<u8>> {
    let remaining = file.metadata()?.len().saturating_sub(offset);
    let buf_size = min(remaining, max_size as u64) as usize;
    let mut buf = vec![0; buf_size];
    file.read_exact_at(&mut buf, offset)?;
    Ok(buf)
}

fn new_errno_error(errno: Errno) -> Status {
    new_binder_service_specific_error(errno as i32, errno.desc())
}
