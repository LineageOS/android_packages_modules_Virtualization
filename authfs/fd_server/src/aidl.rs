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
use nix::{
    dir::Dir, errno::Errno, fcntl::openat, fcntl::OFlag, sys::stat::mkdirat, sys::stat::Mode,
    sys::statvfs::statvfs, sys::statvfs::Statvfs,
};
use std::cmp::min;
use std::collections::{btree_map, BTreeMap};
use std::convert::TryInto;
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::{Component, Path, PathBuf, MAIN_SEPARATOR};
use std::sync::{Arc, Mutex};

use crate::fsverity;
use authfs_aidl_interface::aidl::com::android::virt::fs::IVirtFdService::{
    BnVirtFdService, FsStat::FsStat, IVirtFdService, MAX_REQUESTING_DATA,
};
use authfs_aidl_interface::binder::{
    BinderFeatures, ExceptionCode, Interface, Result as BinderResult, Status, StatusCode, Strong,
};
use binder_common::{new_binder_exception, new_binder_service_specific_error};

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
        /// TODO(205987437): Replace with .fsv_meta file.
        alt_merkle_tree: Option<File>,

        /// Alternative signature stored in another file.
        /// TODO(205987437): Replace with .fsv_meta file.
        alt_signature: Option<File>,
    },

    /// A readable/writable file to serve by this server. This backing file should just be a
    /// regular file and does not have any specific property.
    ReadWrite(File),

    /// A read-only directory to serve by this server.
    InputDir(Dir),

    /// A writable directory to serve by this server.
    OutputDir(Dir),
}

pub struct FdService {
    /// A pool of opened files and directories, which can be looked up by the FD number.
    fd_pool: Arc<Mutex<BTreeMap<i32, FdConfig>>>,
}

impl FdService {
    pub fn new_binder(fd_pool: BTreeMap<i32, FdConfig>) -> Strong<dyn IVirtFdService> {
        BnVirtFdService::new_binder(
            FdService { fd_pool: Arc::new(Mutex::new(fd_pool)) },
            BinderFeatures::default(),
        )
    }

    /// Handles the requesting file `id` with `handle_fn` if it is in the FD pool. This function
    /// returns whatever `handle_fn` returns.
    fn handle_fd<F, R>(&self, id: i32, handle_fn: F) -> BinderResult<R>
    where
        F: FnOnce(&FdConfig) -> BinderResult<R>,
    {
        let fd_pool = self.fd_pool.lock().unwrap();
        let fd_config = fd_pool.get(&id).ok_or_else(|| new_errno_error(Errno::EBADF))?;
        handle_fn(fd_config)
    }

    /// Inserts a new FD and corresponding `FdConfig` created by `create_fn` to the FD pool, then
    /// returns the new FD number.
    fn insert_new_fd<F>(&self, fd: i32, create_fn: F) -> BinderResult<i32>
    where
        F: FnOnce(&mut FdConfig) -> BinderResult<(i32, FdConfig)>,
    {
        let mut fd_pool = self.fd_pool.lock().unwrap();
        let mut fd_config = fd_pool.get_mut(&fd).ok_or_else(|| new_errno_error(Errno::EBADF))?;
        let (new_fd, new_fd_config) = create_fn(&mut fd_config)?;
        if let btree_map::Entry::Vacant(entry) = fd_pool.entry(new_fd) {
            entry.insert(new_fd_config);
            Ok(new_fd)
        } else {
            Err(new_binder_exception(
                ExceptionCode::ILLEGAL_STATE,
                format!("The newly created FD {} is already in the pool unexpectedly", new_fd),
            ))
        }
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
            FdConfig::InputDir(_) | FdConfig::OutputDir(_) => Err(new_errno_error(Errno::EISDIR)),
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
            FdConfig::InputDir(_) | FdConfig::OutputDir(_) => Err(new_errno_error(Errno::EISDIR)),
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
            FdConfig::InputDir(_) | FdConfig::OutputDir(_) => Err(new_errno_error(Errno::EISDIR)),
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
            FdConfig::InputDir(_) | FdConfig::OutputDir(_) => Err(new_errno_error(Errno::EISDIR)),
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
            FdConfig::InputDir(_) | FdConfig::OutputDir(_) => Err(new_errno_error(Errno::EISDIR)),
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
            FdConfig::InputDir(_) | FdConfig::OutputDir(_) => Err(new_errno_error(Errno::EISDIR)),
        })
    }

    fn openFileInDirectory(&self, fd: i32, file_path: &str) -> BinderResult<i32> {
        let path_buf = PathBuf::from(file_path);
        // Checks if the path is a simple, related path.
        if path_buf.components().any(|c| !matches!(c, Component::Normal(_))) {
            return Err(new_errno_error(Errno::EINVAL));
        }

        self.insert_new_fd(fd, |config| match config {
            FdConfig::InputDir(dir) => {
                let file = open_readonly_at(dir.as_raw_fd(), &path_buf).map_err(new_errno_error)?;

                // TODO(205987437): Provide the corresponding ".fsv_meta" file when it's created.
                Ok((
                    file.as_raw_fd(),
                    FdConfig::Readonly { file, alt_merkle_tree: None, alt_signature: None },
                ))
            }
            FdConfig::OutputDir(_) => {
                Err(new_errno_error(Errno::ENOSYS)) // TODO: Implement when needed
            }
            _ => Err(new_errno_error(Errno::ENOTDIR)),
        })
    }

    fn createFileInDirectory(&self, fd: i32, basename: &str) -> BinderResult<i32> {
        if basename.contains(MAIN_SEPARATOR) {
            return Err(new_errno_error(Errno::EINVAL));
        }
        self.insert_new_fd(fd, |config| match config {
            FdConfig::InputDir(_) => Err(new_errno_error(Errno::EACCES)),
            FdConfig::OutputDir(dir) => {
                let new_fd = openat(
                    dir.as_raw_fd(),
                    basename,
                    // TODO(205172873): handle the case when the file already exist, e.g. truncate
                    // or fail, and possibly allow the client to specify. For now, always truncate.
                    OFlag::O_CREAT | OFlag::O_RDWR | OFlag::O_TRUNC,
                    Mode::S_IRUSR | Mode::S_IWUSR,
                )
                .map_err(new_errno_error)?;
                // SAFETY: new_fd is just created and not an error.
                let new_file = unsafe { File::from_raw_fd(new_fd) };
                Ok((new_fd, FdConfig::ReadWrite(new_file)))
            }
            _ => Err(new_errno_error(Errno::ENOTDIR)),
        })
    }

    fn createDirectoryInDirectory(&self, dir_fd: i32, basename: &str) -> BinderResult<i32> {
        if basename.contains(MAIN_SEPARATOR) {
            return Err(new_errno_error(Errno::EINVAL));
        }
        self.insert_new_fd(dir_fd, |config| match config {
            FdConfig::InputDir(_) => Err(new_errno_error(Errno::EACCES)),
            FdConfig::OutputDir(_) => {
                mkdirat(dir_fd, basename, Mode::S_IRWXU).map_err(new_errno_error)?;
                let new_dir = Dir::openat(
                    dir_fd,
                    basename,
                    OFlag::O_DIRECTORY | OFlag::O_RDONLY,
                    Mode::empty(),
                )
                .map_err(new_errno_error)?;
                Ok((new_dir.as_raw_fd(), FdConfig::OutputDir(new_dir)))
            }
            _ => Err(new_errno_error(Errno::ENOTDIR)),
        })
    }

    fn statfs(&self) -> BinderResult<FsStat> {
        let st = statvfs("/data").map_err(new_errno_error)?;
        try_into_fs_stat(st).map_err(|_e| new_errno_error(Errno::EINVAL))
    }
}

fn try_into_fs_stat(st: Statvfs) -> Result<FsStat, std::num::TryFromIntError> {
    Ok(FsStat {
        blockSize: st.block_size().try_into()?,
        fragmentSize: st.fragment_size().try_into()?,
        blockNumbers: st.blocks().try_into()?,
        blockAvailable: st.blocks_available().try_into()?,
        inodesAvailable: st.files_available().try_into()?,
        maxFilename: st.name_max().try_into()?,
    })
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

fn open_readonly_at(dir_fd: RawFd, path: &Path) -> nix::Result<File> {
    let new_fd = openat(dir_fd, path, OFlag::O_RDONLY, Mode::empty())?;
    // SAFETY: new_fd is just created successfully and not owned.
    let new_file = unsafe { File::from_raw_fd(new_fd) };
    Ok(new_file)
}
