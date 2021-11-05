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
use log::{debug, error, warn};
use std::collections::{btree_map, BTreeMap, HashMap};
use std::convert::TryFrom;
use std::ffi::{CStr, OsStr};
use std::fs::OpenOptions;
use std::io;
use std::mem::MaybeUninit;
use std::option::Option;
use std::os::unix::{ffi::OsStrExt, io::AsRawFd};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use fuse::filesystem::{
    Context, DirEntry, DirectoryIterator, Entry, FileSystem, FsOptions, GetxattrReply,
    SetattrValid, ZeroCopyReader, ZeroCopyWriter,
};
use fuse::mount::MountOption;

use crate::common::{divide_roundup, ChunkedSizeIter, CHUNK_SIZE};
use crate::file::{
    RandomWrite, ReadByChunk, RemoteDirEditor, RemoteFileEditor, RemoteFileReader,
    RemoteMerkleTreeReader,
};
use crate::fsverity::{VerifiedFileEditor, VerifiedFileReader};

pub type Inode = u64;
type Handle = u64;

const DEFAULT_METADATA_TIMEOUT: Duration = Duration::from_secs(5);
const ROOT_INODE: Inode = 1;

/// `AuthFsEntry` defines the filesystem entry type supported by AuthFS.
pub enum AuthFsEntry {
    /// A file type that is verified against fs-verity signature (thus read-only). The file is
    /// served from a remote server.
    VerifiedReadonly {
        reader: VerifiedFileReader<RemoteFileReader, RemoteMerkleTreeReader>,
        file_size: u64,
    },
    /// A file type that is a read-only passthrough from a file on a remote serrver.
    UnverifiedReadonly { reader: RemoteFileReader, file_size: u64 },
    /// A file type that is initially empty, and the content is stored on a remote server. File
    /// integrity is guaranteed with private Merkle tree.
    VerifiedNew { editor: VerifiedFileEditor<RemoteFileEditor> },
    /// A directory type that is initially empty. One can create new file (`VerifiedNew`) and new
    /// directory (`VerifiedNewDirectory` itself) with integrity guaranteed within the VM.
    VerifiedNewDirectory { dir: RemoteDirEditor },
}

// AuthFS needs to be `Sync` to be accepted by fuse::worker::start_message_loop as a `FileSystem`.
struct AuthFs {
    /// Table for `Inode` to `AuthFsEntry` lookup. This needs to be `Sync` to be used in
    /// `fuse::worker::start_message_loop`.
    inode_table: Mutex<BTreeMap<Inode, AuthFsEntry>>,

    /// Root directory entry table for path to `Inode` lookup. The root directory content should
    /// remain constant throughout the filesystem's lifetime.
    root_entries: HashMap<PathBuf, Inode>,

    /// Maximum bytes in the write transaction to the FUSE device. This limits the maximum buffer
    /// size in a read request (including FUSE protocol overhead) that the filesystem writes to.
    max_write: u32,
}

impl AuthFs {
    pub fn new(root_entries_by_path: HashMap<PathBuf, AuthFsEntry>, max_write: u32) -> AuthFs {
        let mut next_inode = ROOT_INODE + 1;
        let mut inode_table = BTreeMap::new();
        let mut root_entries = HashMap::new();

        root_entries_by_path.into_iter().for_each(|(path_buf, entry)| {
            next_inode += 1;
            root_entries.insert(path_buf, next_inode);
            inode_table.insert(next_inode, entry);
        });

        AuthFs { inode_table: Mutex::new(inode_table), root_entries, max_write }
    }

    /// Handles the file associated with `inode` if found. This function returns whatever
    /// `handle_fn` returns.
    fn handle_inode<F, R>(&self, inode: &Inode, handle_fn: F) -> io::Result<R>
    where
        F: FnOnce(&AuthFsEntry) -> io::Result<R>,
    {
        let inode_table = self.inode_table.lock().unwrap();
        let config =
            inode_table.get(inode).ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))?;
        handle_fn(config)
    }

    /// Inserts a new inode and corresponding `AuthFsEntry` created by `create_fn` to the inode
    /// table, then returns the new inode number.
    fn insert_new_inode<F>(&self, inode: &Inode, create_fn: F) -> io::Result<Inode>
    where
        F: FnOnce(&mut AuthFsEntry) -> io::Result<(Inode, AuthFsEntry)>,
    {
        let mut inode_table = self.inode_table.lock().unwrap();
        let mut config =
            inode_table.get_mut(inode).ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))?;
        let (new_inode, new_file_config) = create_fn(&mut config)?;
        if let btree_map::Entry::Vacant(entry) = inode_table.entry(new_inode) {
            entry.insert(new_file_config);
            Ok(new_inode)
        } else {
            // We can't assume fd_server is trusted, so the returned FD may collide with existing
            // one, even when we are creating a new file. Do not override an existing FD. In terms
            // of security, it is better to "leak" the file created earlier, than returning an
            // existing inode as a new file.
            error!("Inode {} already exists, do not override", new_inode);
            Err(io::Error::from_raw_os_error(libc::EIO))
        }
    }
}

fn check_access_mode(flags: u32, mode: libc::c_int) -> io::Result<()> {
    if (flags & libc::O_ACCMODE as u32) == mode as u32 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(libc::EACCES))
    }
}

cfg_if::cfg_if! {
    if #[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))] {
        fn blk_size() -> libc::c_int { CHUNK_SIZE as libc::c_int }
    } else {
        fn blk_size() -> libc::c_long { CHUNK_SIZE as libc::c_long }
    }
}

#[allow(clippy::enum_variant_names)]
enum AccessMode {
    ReadOnly,
    ReadWrite,
}

fn create_stat(
    ino: libc::ino_t,
    file_size: u64,
    access_mode: AccessMode,
) -> io::Result<libc::stat64> {
    // SAFETY: stat64 is a plan C struct without pointer.
    let mut st = unsafe { MaybeUninit::<libc::stat64>::zeroed().assume_init() };

    st.st_ino = ino;
    st.st_mode = match access_mode {
        // Until needed, let's just grant the owner access.
        // TODO(205169366): Implement mode properly.
        AccessMode::ReadOnly => libc::S_IFREG | libc::S_IRUSR,
        AccessMode::ReadWrite => libc::S_IFREG | libc::S_IRUSR | libc::S_IWUSR,
    };
    st.st_nlink = 1;
    st.st_uid = 0;
    st.st_gid = 0;
    st.st_size = libc::off64_t::try_from(file_size)
        .map_err(|_| io::Error::from_raw_os_error(libc::EFBIG))?;
    st.st_blksize = blk_size();
    // Per man stat(2), st_blocks is "Number of 512B blocks allocated".
    st.st_blocks = libc::c_longlong::try_from(divide_roundup(file_size, 512))
        .map_err(|_| io::Error::from_raw_os_error(libc::EFBIG))?;
    Ok(st)
}

fn create_dir_stat(ino: libc::ino_t, file_number: u16) -> io::Result<libc::stat64> {
    // SAFETY: stat64 is a plan C struct without pointer.
    let mut st = unsafe { MaybeUninit::<libc::stat64>::zeroed().assume_init() };

    st.st_ino = ino;
    // TODO(205169366): Implement mode properly.
    st.st_mode = libc::S_IFDIR
        | libc::S_IXUSR
        | libc::S_IWUSR
        | libc::S_IRUSR
        | libc::S_IXGRP
        | libc::S_IXOTH;

    // 2 extra for . and ..
    st.st_nlink = file_number
        .checked_add(2)
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?
        .into();

    st.st_uid = 0;
    st.st_gid = 0;
    Ok(st)
}

fn offset_to_chunk_index(offset: u64) -> u64 {
    offset / CHUNK_SIZE
}

fn read_chunks<W: io::Write, T: ReadByChunk>(
    mut w: W,
    file: &T,
    file_size: u64,
    offset: u64,
    size: u32,
) -> io::Result<usize> {
    let remaining = file_size.saturating_sub(offset);
    let size_to_read = std::cmp::min(size as usize, remaining as usize);
    let total = ChunkedSizeIter::new(size_to_read, offset, CHUNK_SIZE as usize).try_fold(
        0,
        |total, (current_offset, planned_data_size)| {
            // TODO(victorhsieh): There might be a non-trivial way to avoid this copy. For example,
            // instead of accepting a buffer, the writer could expose the final destination buffer
            // for the reader to write to. It might not be generally applicable though, e.g. with
            // virtio transport, the buffer may not be continuous.
            let mut buf = [0u8; CHUNK_SIZE as usize];
            let read_size = file.read_chunk(offset_to_chunk_index(current_offset), &mut buf)?;
            if read_size < planned_data_size {
                return Err(io::Error::from_raw_os_error(libc::ENODATA));
            }

            let begin = (current_offset % CHUNK_SIZE) as usize;
            let end = begin + planned_data_size;
            let s = w.write(&buf[begin..end])?;
            if s != planned_data_size {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            Ok(total + s)
        },
    )?;

    Ok(total)
}

// No need to support enumerating directory entries.
struct EmptyDirectoryIterator {}

impl DirectoryIterator for EmptyDirectoryIterator {
    fn next(&mut self) -> Option<DirEntry> {
        None
    }
}

impl FileSystem for AuthFs {
    type Inode = Inode;
    type Handle = Handle;
    type DirIter = EmptyDirectoryIterator;

    fn max_buffer_size(&self) -> u32 {
        self.max_write
    }

    fn init(&self, _capable: FsOptions) -> io::Result<FsOptions> {
        // Enable writeback cache for better performance especially since our bandwidth to the
        // backend service is limited.
        Ok(FsOptions::WRITEBACK_CACHE)
    }

    fn lookup(&self, _ctx: Context, parent: Inode, name: &CStr) -> io::Result<Entry> {
        if parent == ROOT_INODE {
            let inode = *self
                .root_entries
                .get(cstr_to_path(name))
                .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))?;
            // Normally, `lookup` is required to increase a reference count for the inode (while
            // `forget` will decrease it). It is not yet necessary until we start to support
            // deletion (only for `VerifiedNewDirectory`).
            let st = self.handle_inode(&inode, |config| match config {
                AuthFsEntry::UnverifiedReadonly { file_size, .. }
                | AuthFsEntry::VerifiedReadonly { file_size, .. } => {
                    create_stat(inode, *file_size, AccessMode::ReadOnly)
                }
                AuthFsEntry::VerifiedNew { editor } => {
                    create_stat(inode, editor.size(), AccessMode::ReadWrite)
                }
                AuthFsEntry::VerifiedNewDirectory { dir } => {
                    create_dir_stat(inode, dir.number_of_entries())
                }
            })?;
            Ok(Entry {
                inode,
                generation: 0,
                attr: st,
                entry_timeout: DEFAULT_METADATA_TIMEOUT,
                attr_timeout: DEFAULT_METADATA_TIMEOUT,
            })
        } else {
            let inode = self.handle_inode(&parent, |config| match config {
                AuthFsEntry::VerifiedNewDirectory { dir } => {
                    let path: &Path = cstr_to_path(name);
                    dir.find_inode(path).ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))
                }
                _ => Err(io::Error::from_raw_os_error(libc::ENOTDIR)),
            })?;
            let st = self.handle_inode(&inode, |config| match config {
                AuthFsEntry::VerifiedNew { editor } => {
                    create_stat(inode, editor.size(), AccessMode::ReadWrite)
                }
                AuthFsEntry::VerifiedNewDirectory { dir } => {
                    create_dir_stat(inode, dir.number_of_entries())
                }
                _ => Err(io::Error::from_raw_os_error(libc::EBADF)),
            })?;
            Ok(Entry {
                inode,
                generation: 0,
                attr: st,
                entry_timeout: DEFAULT_METADATA_TIMEOUT,
                attr_timeout: DEFAULT_METADATA_TIMEOUT,
            })
        }
    }

    fn getattr(
        &self,
        _ctx: Context,
        inode: Inode,
        _handle: Option<Handle>,
    ) -> io::Result<(libc::stat64, Duration)> {
        self.handle_inode(&inode, |config| {
            Ok((
                match config {
                    AuthFsEntry::UnverifiedReadonly { file_size, .. }
                    | AuthFsEntry::VerifiedReadonly { file_size, .. } => {
                        create_stat(inode, *file_size, AccessMode::ReadOnly)?
                    }
                    AuthFsEntry::VerifiedNew { editor } => {
                        create_stat(inode, editor.size(), AccessMode::ReadWrite)?
                    }
                    AuthFsEntry::VerifiedNewDirectory { dir } => {
                        create_dir_stat(inode, dir.number_of_entries())?
                    }
                },
                DEFAULT_METADATA_TIMEOUT,
            ))
        })
    }

    fn open(
        &self,
        _ctx: Context,
        inode: Self::Inode,
        flags: u32,
    ) -> io::Result<(Option<Self::Handle>, fuse::sys::OpenOptions)> {
        // Since file handle is not really used in later operations (which use Inode directly),
        // return None as the handle.
        self.handle_inode(&inode, |config| {
            match config {
                AuthFsEntry::VerifiedReadonly { .. } | AuthFsEntry::UnverifiedReadonly { .. } => {
                    check_access_mode(flags, libc::O_RDONLY)?;
                }
                AuthFsEntry::VerifiedNew { .. } => {
                    // No need to check access modes since all the modes are allowed to the
                    // read-writable file.
                }
                AuthFsEntry::VerifiedNewDirectory { .. } => {
                    // TODO(victorhsieh): implement when needed.
                    return Err(io::Error::from_raw_os_error(libc::ENOSYS));
                }
            }
            // Always cache the file content. There is currently no need to support direct I/O or
            // avoid the cache buffer. Memory mapping is only possible with cache enabled.
            Ok((None, fuse::sys::OpenOptions::KEEP_CACHE))
        })
    }

    fn create(
        &self,
        _ctx: Context,
        parent: Self::Inode,
        name: &CStr,
        _mode: u32,
        _flags: u32,
        _umask: u32,
    ) -> io::Result<(Entry, Option<Self::Handle>, fuse::sys::OpenOptions)> {
        // TODO(205169366): Implement mode properly.
        // TODO(205172873): handle O_TRUNC and O_EXCL properly.
        let new_inode = self.insert_new_inode(&parent, |config| match config {
            AuthFsEntry::VerifiedNewDirectory { dir } => {
                let basename: &Path = cstr_to_path(name);
                if dir.find_inode(basename).is_some() {
                    return Err(io::Error::from_raw_os_error(libc::EEXIST));
                }
                let (new_inode, new_file) = dir.create_file(basename)?;
                Ok((new_inode, AuthFsEntry::VerifiedNew { editor: new_file }))
            }
            _ => Err(io::Error::from_raw_os_error(libc::EBADF)),
        })?;

        Ok((
            Entry {
                inode: new_inode,
                generation: 0,
                attr: create_stat(new_inode, /* file_size */ 0, AccessMode::ReadWrite)?,
                entry_timeout: DEFAULT_METADATA_TIMEOUT,
                attr_timeout: DEFAULT_METADATA_TIMEOUT,
            },
            // See also `open`.
            /* handle */ None,
            fuse::sys::OpenOptions::KEEP_CACHE,
        ))
    }

    fn read<W: io::Write + ZeroCopyWriter>(
        &self,
        _ctx: Context,
        inode: Inode,
        _handle: Handle,
        w: W,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _flags: u32,
    ) -> io::Result<usize> {
        self.handle_inode(&inode, |config| {
            match config {
                AuthFsEntry::VerifiedReadonly { reader, file_size } => {
                    read_chunks(w, reader, *file_size, offset, size)
                }
                AuthFsEntry::UnverifiedReadonly { reader, file_size } => {
                    read_chunks(w, reader, *file_size, offset, size)
                }
                AuthFsEntry::VerifiedNew { editor } => {
                    // Note that with FsOptions::WRITEBACK_CACHE, it's possible for the kernel to
                    // request a read even if the file is open with O_WRONLY.
                    read_chunks(w, editor, editor.size(), offset, size)
                }
                _ => Err(io::Error::from_raw_os_error(libc::EBADF)),
            }
        })
    }

    fn write<R: io::Read + ZeroCopyReader>(
        &self,
        _ctx: Context,
        inode: Self::Inode,
        _handle: Self::Handle,
        mut r: R,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _delayed_write: bool,
        _flags: u32,
    ) -> io::Result<usize> {
        self.handle_inode(&inode, |config| match config {
            AuthFsEntry::VerifiedNew { editor } => {
                let mut buf = vec![0; size as usize];
                r.read_exact(&mut buf)?;
                editor.write_at(&buf, offset)
            }
            _ => Err(io::Error::from_raw_os_error(libc::EBADF)),
        })
    }

    fn setattr(
        &self,
        _ctx: Context,
        inode: Inode,
        attr: libc::stat64,
        _handle: Option<Handle>,
        valid: SetattrValid,
    ) -> io::Result<(libc::stat64, Duration)> {
        self.handle_inode(&inode, |config| {
            match config {
                AuthFsEntry::VerifiedNew { editor } => {
                    // Initialize the default stat.
                    let mut new_attr = create_stat(inode, editor.size(), AccessMode::ReadWrite)?;
                    // `valid` indicates what fields in `attr` are valid. Update to return correctly.
                    if valid.contains(SetattrValid::SIZE) {
                        // st_size is i64, but the cast should be safe since kernel should not give a
                        // negative size.
                        debug_assert!(attr.st_size >= 0);
                        new_attr.st_size = attr.st_size;
                        editor.resize(attr.st_size as u64)?;
                    }

                    if valid.contains(SetattrValid::MODE) {
                        warn!("Changing st_mode is not currently supported");
                        return Err(io::Error::from_raw_os_error(libc::ENOSYS));
                    }
                    if valid.contains(SetattrValid::UID) {
                        warn!("Changing st_uid is not currently supported");
                        return Err(io::Error::from_raw_os_error(libc::ENOSYS));
                    }
                    if valid.contains(SetattrValid::GID) {
                        warn!("Changing st_gid is not currently supported");
                        return Err(io::Error::from_raw_os_error(libc::ENOSYS));
                    }
                    if valid.contains(SetattrValid::CTIME) {
                        debug!(
                            "Ignoring ctime change as authfs does not maintain timestamp currently"
                        );
                    }
                    if valid.intersects(SetattrValid::ATIME | SetattrValid::ATIME_NOW) {
                        debug!(
                            "Ignoring atime change as authfs does not maintain timestamp currently"
                        );
                    }
                    if valid.intersects(SetattrValid::MTIME | SetattrValid::MTIME_NOW) {
                        debug!(
                            "Ignoring mtime change as authfs does not maintain timestamp currently"
                        );
                    }
                    Ok((new_attr, DEFAULT_METADATA_TIMEOUT))
                }
                _ => Err(io::Error::from_raw_os_error(libc::EBADF)),
            }
        })
    }

    fn getxattr(
        &self,
        _ctx: Context,
        inode: Self::Inode,
        name: &CStr,
        size: u32,
    ) -> io::Result<GetxattrReply> {
        self.handle_inode(&inode, |config| {
            match config {
                AuthFsEntry::VerifiedNew { editor } => {
                    // FUSE ioctl is limited, thus we can't implement fs-verity ioctls without a kernel
                    // change (see b/196635431). Until it's possible, use xattr to expose what we need
                    // as an authfs specific API.
                    if name != CStr::from_bytes_with_nul(b"authfs.fsverity.digest\0").unwrap() {
                        return Err(io::Error::from_raw_os_error(libc::ENODATA));
                    }

                    if size == 0 {
                        // Per protocol, when size is 0, return the value size.
                        Ok(GetxattrReply::Count(editor.get_fsverity_digest_size() as u32))
                    } else {
                        let digest = editor.calculate_fsverity_digest()?;
                        if digest.len() > size as usize {
                            Err(io::Error::from_raw_os_error(libc::ERANGE))
                        } else {
                            Ok(GetxattrReply::Value(digest.to_vec()))
                        }
                    }
                }
                _ => Err(io::Error::from_raw_os_error(libc::ENODATA)),
            }
        })
    }

    fn mkdir(
        &self,
        _ctx: Context,
        parent: Self::Inode,
        name: &CStr,
        _mode: u32,
        _umask: u32,
    ) -> io::Result<Entry> {
        // TODO(205169366): Implement mode properly.
        let new_inode = self.insert_new_inode(&parent, |config| match config {
            AuthFsEntry::VerifiedNewDirectory { dir } => {
                let basename: &Path = cstr_to_path(name);
                if dir.find_inode(basename).is_some() {
                    return Err(io::Error::from_raw_os_error(libc::EEXIST));
                }
                let (new_inode, new_dir) = dir.mkdir(basename)?;
                Ok((new_inode, AuthFsEntry::VerifiedNewDirectory { dir: new_dir }))
            }
            _ => Err(io::Error::from_raw_os_error(libc::EBADF)),
        })?;

        Ok(Entry {
            inode: new_inode,
            generation: 0,
            attr: create_dir_stat(new_inode, /* file_number */ 0)?,
            entry_timeout: DEFAULT_METADATA_TIMEOUT,
            attr_timeout: DEFAULT_METADATA_TIMEOUT,
        })
    }
}

/// Mount and start the FUSE instance. This requires CAP_SYS_ADMIN.
pub fn loop_forever(
    root_entries: HashMap<PathBuf, AuthFsEntry>,
    mountpoint: &Path,
    extra_options: &Option<String>,
) -> Result<(), fuse::Error> {
    let max_read: u32 = 65536;
    let max_write: u32 = 65536;
    let dev_fuse = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/fuse")
        .expect("Failed to open /dev/fuse");

    let mut mount_options = vec![
        MountOption::FD(dev_fuse.as_raw_fd()),
        MountOption::RootMode(libc::S_IFDIR | libc::S_IXUSR | libc::S_IXGRP | libc::S_IXOTH),
        MountOption::AllowOther,
        MountOption::UserId(0),
        MountOption::GroupId(0),
        MountOption::MaxRead(max_read),
    ];
    if let Some(value) = extra_options {
        mount_options.push(MountOption::Extra(value));
    }

    fuse::mount(mountpoint, "authfs", libc::MS_NOSUID | libc::MS_NODEV, &mount_options)
        .expect("Failed to mount fuse");

    fuse::worker::start_message_loop(
        dev_fuse,
        max_write,
        max_read,
        AuthFs::new(root_entries, max_write),
    )
}

fn cstr_to_path(cstr: &CStr) -> &Path {
    OsStr::from_bytes(cstr.to_bytes()).as_ref()
}
