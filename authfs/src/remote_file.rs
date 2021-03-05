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

use std::convert::TryFrom;
use std::io;
use std::io::Write;
use std::sync::{Arc, Mutex};

use crate::common::CHUNK_SIZE;
use crate::reader::ReadOnlyDataByChunk;

use authfs_aidl_interface::aidl::com::android::virt::fs::IVirtFdService;
use authfs_aidl_interface::binder::Strong;

type VirtFdService = Strong<dyn IVirtFdService::IVirtFdService>;

pub mod server {
    // TODO(victorhsieh): use remote binder.
    pub fn get_local_service() -> super::VirtFdService {
        let service_name = "authfs_fd_server";
        authfs_aidl_interface::binder::get_interface(&service_name)
            .expect("Cannot reach authfs_fd_server binder service")
    }
}

pub struct RemoteChunkedFileReader {
    // This needs to have Sync trait to be used in fuse::worker::start_message_loop.
    service: Arc<Mutex<VirtFdService>>,
    file_fd: i32,
}

impl RemoteChunkedFileReader {
    pub fn new(service: Arc<Mutex<VirtFdService>>, file_fd: i32) -> Self {
        RemoteChunkedFileReader { service, file_fd }
    }
}

impl ReadOnlyDataByChunk for RemoteChunkedFileReader {
    fn read_chunk(&self, chunk_index: u64, mut buf: &mut [u8]) -> io::Result<usize> {
        let offset = i64::try_from(chunk_index * CHUNK_SIZE)
            .map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?;

        let service = Arc::clone(&self.service);
        let chunk = service
            .lock()
            .unwrap()
            .readFile(self.file_fd, offset, buf.len() as i32)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.get_description()))?;
        buf.write(&chunk)
    }
}

pub struct RemoteFsverityMerkleTreeReader {
    // This needs to be a Sync to be used in fuse::worker::start_message_loop.
    // TODO(victorhsieh): change to Strong<> once binder supports it.
    service: Arc<Mutex<VirtFdService>>,
    file_fd: i32,
}

impl RemoteFsverityMerkleTreeReader {
    pub fn new(service: Arc<Mutex<VirtFdService>>, file_fd: i32) -> Self {
        RemoteFsverityMerkleTreeReader { service, file_fd }
    }
}

impl ReadOnlyDataByChunk for RemoteFsverityMerkleTreeReader {
    fn read_chunk(&self, chunk_index: u64, mut buf: &mut [u8]) -> io::Result<usize> {
        let offset = i64::try_from(chunk_index * CHUNK_SIZE)
            .map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?;

        let service = Arc::clone(&self.service);
        let chunk = service
            .lock()
            .unwrap()
            .readFsverityMerkleTree(self.file_fd, offset, buf.len() as i32)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.get_description()))?;
        buf.write(&chunk)
    }
}
