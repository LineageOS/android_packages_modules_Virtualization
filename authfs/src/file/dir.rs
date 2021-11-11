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

use std::collections::{hash_map, HashMap};
use std::io;
use std::path::{Path, PathBuf};

use super::remote_file::RemoteFileEditor;
use super::{validate_basename, VirtFdService, VirtFdServiceStatus};
use crate::fsverity::VerifiedFileEditor;
use crate::fusefs::Inode;

const MAX_ENTRIES: u16 = 100; // Arbitrary limit

/// A remote directory backed by a remote directory FD, where the provider/fd_server is not
/// trusted.
///
/// The directory is assumed empty initially without the trust to the storage. Functionally, when
/// the backing storage is not clean, the fd_server can fail to create a file or directory when
/// there is name collision. From RemoteDirEditor's perspective of security, the creation failure
/// is just one of possible errors that can happen, and what matters is RemoteDirEditor maintains
/// the integrity itself.
///
/// When new files are created through RemoteDirEditor, the file integrity are maintained within the
/// VM. Similarly, integrity (namely the list of entries) of the directory, or new directories
/// created within such a directory, are also maintained within the VM. A compromised fd_server or
/// malicious client can't affect the view to the files and directories within such a directory in
/// the VM.
pub struct RemoteDirEditor {
    service: VirtFdService,
    remote_dir_fd: i32,

    /// Mapping of entry names to the corresponding inode number. The actual file/directory is
    /// stored in the global pool in fusefs.
    entries: HashMap<PathBuf, Inode>,
}

impl RemoteDirEditor {
    pub fn new(service: VirtFdService, remote_dir_fd: i32) -> Self {
        RemoteDirEditor { service, remote_dir_fd, entries: HashMap::new() }
    }

    /// Returns the number of entries created.
    pub fn number_of_entries(&self) -> u16 {
        self.entries.len() as u16 // limited to MAX_ENTRIES
    }

    /// Creates a remote file named `basename` with corresponding `inode` at the current directory.
    pub fn create_file(
        &mut self,
        basename: &Path,
        inode: Inode,
    ) -> io::Result<VerifiedFileEditor<RemoteFileEditor>> {
        self.validate_argument(basename)?;

        let basename_str =
            basename.to_str().ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        let new_fd = self
            .service
            .createFileInDirectory(self.remote_dir_fd, basename_str)
            .map_err(into_io_error)?;

        let new_remote_file =
            VerifiedFileEditor::new(RemoteFileEditor::new(self.service.clone(), new_fd));
        self.entries.insert(basename.to_path_buf(), inode);
        Ok(new_remote_file)
    }

    /// Creates a remote directory named `basename` with corresponding `inode` at the current
    /// directory.
    pub fn mkdir(&mut self, basename: &Path, inode: Inode) -> io::Result<RemoteDirEditor> {
        self.validate_argument(basename)?;

        let basename_str =
            basename.to_str().ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        let new_fd = self
            .service
            .createDirectoryInDirectory(self.remote_dir_fd, basename_str)
            .map_err(into_io_error)?;

        let new_remote_dir = RemoteDirEditor::new(self.service.clone(), new_fd);
        self.entries.insert(basename.to_path_buf(), inode);
        Ok(new_remote_dir)
    }

    /// Returns the inode number of a file or directory named `name` previously created through
    /// `RemoteDirEditor`.
    pub fn find_inode(&self, name: &Path) -> Option<Inode> {
        self.entries.get(name).copied()
    }

    fn validate_argument(&self, basename: &Path) -> io::Result<()> {
        // Kernel should only give us a basename.
        debug_assert!(validate_basename(basename).is_ok());

        if self.entries.contains_key(basename) {
            Err(io::Error::from_raw_os_error(libc::EEXIST))
        } else if self.entries.len() >= MAX_ENTRIES.into() {
            Err(io::Error::from_raw_os_error(libc::EMLINK))
        } else {
            Ok(())
        }
    }
}

/// An in-memory directory representation of a directory structure.
pub struct InMemoryDir(HashMap<PathBuf, Inode>);

impl InMemoryDir {
    /// Creates an empty instance of `InMemoryDir`.
    pub fn new() -> Self {
        // Hash map is empty since "." and ".." are excluded in entries.
        InMemoryDir(HashMap::new())
    }

    /// Returns the number of entries in the directory (not including "." and "..").
    pub fn number_of_entries(&self) -> u16 {
        self.0.len() as u16 // limited to MAX_ENTRIES
    }

    /// Adds an entry (name and the inode number) to the directory. Fails if already exists. The
    /// caller is responsible for ensure the inode uniqueness.
    pub fn add_entry(&mut self, basename: &Path, inode: Inode) -> io::Result<()> {
        validate_basename(basename)?;
        if self.0.len() >= MAX_ENTRIES.into() {
            return Err(io::Error::from_raw_os_error(libc::EMLINK));
        }

        if let hash_map::Entry::Vacant(entry) = self.0.entry(basename.to_path_buf()) {
            entry.insert(inode);
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(libc::EEXIST))
        }
    }

    /// Looks up an entry inode by name. `None` if not found.
    pub fn lookup_inode(&self, basename: &Path) -> Option<Inode> {
        self.0.get(basename).copied()
    }
}

fn into_io_error(e: VirtFdServiceStatus) -> io::Error {
    let maybe_errno = e.service_specific_error();
    if maybe_errno > 0 {
        io::Error::from_raw_os_error(maybe_errno)
    } else {
        io::Error::new(io::ErrorKind::Other, e.get_description())
    }
}
