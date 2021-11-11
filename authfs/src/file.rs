mod dir;
mod remote_file;

pub use dir::{InMemoryDir, RemoteDirEditor};
pub use remote_file::{RemoteFileEditor, RemoteFileReader, RemoteMerkleTreeReader};

use binder::unstable_api::{new_spibinder, AIBinder};
use binder::FromIBinder;
use std::io;
use std::path::{Path, MAIN_SEPARATOR};

use crate::common::CHUNK_SIZE;
use authfs_aidl_interface::aidl::com::android::virt::fs::IVirtFdService::IVirtFdService;
use authfs_aidl_interface::binder::{Status, Strong};

pub type VirtFdService = Strong<dyn IVirtFdService>;
pub type VirtFdServiceStatus = Status;

pub type ChunkBuffer = [u8; CHUNK_SIZE as usize];

pub const RPC_SERVICE_PORT: u32 = 3264;

pub fn get_rpc_binder_service(cid: u32) -> io::Result<VirtFdService> {
    // SAFETY: AIBinder returned by RpcClient has correct reference count, and the ownership can be
    // safely taken by new_spibinder.
    let ibinder = unsafe {
        new_spibinder(binder_rpc_unstable_bindgen::RpcClient(cid, RPC_SERVICE_PORT) as *mut AIBinder)
    };
    if let Some(ibinder) = ibinder {
        Ok(<dyn IVirtFdService>::try_from(ibinder).map_err(|e| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("Cannot connect to RPC service: {}", e),
            )
        })?)
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid raw AIBinder"))
    }
}

/// A trait for reading data by chunks. Chunks can be read by specifying the chunk index. Only the
/// last chunk may have incomplete chunk size.
pub trait ReadByChunk {
    /// Reads the `chunk_index`-th chunk to a `ChunkBuffer`. Returns the size read, which has to be
    /// `CHUNK_SIZE` except for the last incomplete chunk. Reading beyond the file size (including
    /// empty file) should return 0.
    fn read_chunk(&self, chunk_index: u64, buf: &mut ChunkBuffer) -> io::Result<usize>;
}

/// A trait to write a buffer to the destination at a given offset. The implementation does not
/// necessarily own or maintain the destination state.
///
/// NB: The trait is required in a member of `fusefs::AuthFs`, which is required to be Sync and
/// immutable (this the member).
pub trait RandomWrite {
    /// Writes `buf` to the destination at `offset`. Returns the written size, which may not be the
    /// full buffer.
    fn write_at(&self, buf: &[u8], offset: u64) -> io::Result<usize>;

    /// Writes the full `buf` to the destination at `offset`.
    fn write_all_at(&self, buf: &[u8], offset: u64) -> io::Result<()> {
        let mut input_offset = 0;
        let mut output_offset = offset;
        while input_offset < buf.len() {
            let size = self.write_at(&buf[input_offset..], output_offset)?;
            input_offset += size;
            output_offset += size as u64;
        }
        Ok(())
    }

    /// Resizes the file to the new size.
    fn resize(&self, size: u64) -> io::Result<()>;
}

/// Checks whether the path is a simple file name without any directory separator.
pub fn validate_basename(path: &Path) -> io::Result<()> {
    if matches!(path.to_str(), Some(path_str) if !path_str.contains(MAIN_SEPARATOR)) {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(libc::EINVAL))
    }
}
