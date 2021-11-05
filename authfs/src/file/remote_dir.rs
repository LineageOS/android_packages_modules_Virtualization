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

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

use super::remote_file::RemoteFileEditor;
use super::{VirtFdService, VirtFdServiceStatus};
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

    /// Creates a remote file at the current directory. If succeed, the returned remote FD is
    /// stored in `entries` as the inode number.
    pub fn create_file(
        &mut self,
        basename: &Path,
    ) -> io::Result<(Inode, VerifiedFileEditor<RemoteFileEditor>)> {
        self.validate_argument(basename)?;

        let basename_str =
            basename.to_str().ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        let new_fd = self
            .service
            .createFileInDirectory(self.remote_dir_fd, basename_str)
            .map_err(into_io_error)?;
        let new_inode = new_fd as Inode;

        let new_remote_file =
            VerifiedFileEditor::new(RemoteFileEditor::new(self.service.clone(), new_fd));
        self.entries.insert(basename.to_path_buf(), new_inode);
        Ok((new_inode, new_remote_file))
    }

    /// Creates a remote directory at the current directory. If succeed, the returned remote FD is
    /// stored in `entries` as the inode number.
    pub fn mkdir(&mut self, basename: &Path) -> io::Result<(Inode, RemoteDirEditor)> {
        self.validate_argument(basename)?;

        let basename_str =
            basename.to_str().ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        let new_fd = self
            .service
            .createDirectoryInDirectory(self.remote_dir_fd, basename_str)
            .map_err(into_io_error)?;
        let new_inode = new_fd as Inode;

        let new_remote_dir = RemoteDirEditor::new(self.service.clone(), new_fd);
        self.entries.insert(basename.to_path_buf(), new_inode);
        Ok((new_inode, new_remote_dir))
    }

    /// Returns the inode number of a file or directory named `name` previously created through
    /// `RemoteDirEditor`.
    pub fn find_inode(&self, name: &Path) -> Option<Inode> {
        self.entries.get(name).copied()
    }

    fn validate_argument(&self, basename: &Path) -> io::Result<()> {
        // Kernel should only give us a basename.
        debug_assert!(basename.parent().is_none());
        if self.entries.contains_key(basename) {
            Err(io::Error::from_raw_os_error(libc::EEXIST))
        } else if self.entries.len() >= MAX_ENTRIES.into() {
            Err(io::Error::from_raw_os_error(libc::EMLINK))
        } else {
            Ok(())
        }
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
