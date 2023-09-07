// Copyright 2023, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! This module contains the functions to start, stop and communicate with the
//! Service VM.

use android_system_virtualizationservice::{
    aidl::android::system::virtualizationservice::{
        CpuTopology::CpuTopology, DiskImage::DiskImage,
        IVirtualizationService::IVirtualizationService, Partition::Partition,
        PartitionType::PartitionType, VirtualMachineConfig::VirtualMachineConfig,
        VirtualMachineRawConfig::VirtualMachineRawConfig,
    },
    binder::ParcelFileDescriptor,
};
use anyhow::{ensure, Context, Result};
use log::{info, warn};
use service_vm_comm::{Request, Response, VmType};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::os::unix::io::FromRawFd;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use vmclient::VmInstance;
use vsock::{VsockListener, VsockStream, VMADDR_CID_HOST};

const VIRT_DATA_DIR: &str = "/data/misc/apexdata/com.android.virt";
const RIALTO_PATH: &str = "/apex/com.android.virt/etc/rialto.bin";
const INSTANCE_IMG_NAME: &str = "service_vm_instance.img";
const INSTANCE_IMG_SIZE_BYTES: i64 = 1 << 20; // 1MB
const MEMORY_MB: i32 = 300;
const WRITE_BUFFER_CAPACITY: usize = 512;
const READ_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Service VM.
pub struct ServiceVm {
    vsock_stream: VsockStream,
    /// VmInstance will be dropped when ServiceVm goes out of scope, which will kill the VM.
    vm: VmInstance,
}

impl ServiceVm {
    /// Starts the service VM and returns its instance.
    /// The same instance image is used for different VMs.
    /// TODO(b/278858244): Allow only one service VM running at each time.
    pub fn start() -> Result<Self> {
        let instance_img_path = Path::new(VIRT_DATA_DIR).join(INSTANCE_IMG_NAME);
        let vm = protected_vm_instance(instance_img_path)?;
        Self::start_vm(vm, VmType::ProtectedVm)
    }

    /// Starts the given VM instance and sets up the vsock connection with it.
    /// Returns a `ServiceVm` instance.
    /// This function is exposed for testing.
    pub fn start_vm(vm: VmInstance, vm_type: VmType) -> Result<Self> {
        // Sets up the vsock server on the host.
        let vsock_listener = VsockListener::bind_with_cid_port(VMADDR_CID_HOST, vm_type.port())?;

        // Starts the service VM.
        vm.start().context("Failed to start service VM")?;
        info!("Service VM started");

        // Accepts the connection from the service VM.
        // TODO(b/299427101): Introduce a timeout for the accept.
        let (vsock_stream, peer_addr) = vsock_listener.accept().context("Failed to accept")?;
        info!("Accepted connection {:?}", vsock_stream);
        ensure!(
            peer_addr.cid() == u32::try_from(vm.cid()).unwrap(),
            "The CID of the peer address {} doesn't match the service VM CID {}",
            peer_addr,
            vm.cid()
        );
        vsock_stream.set_read_timeout(Some(READ_TIMEOUT))?;
        vsock_stream.set_write_timeout(Some(WRITE_TIMEOUT))?;

        Ok(Self { vsock_stream, vm })
    }

    /// Processes the request in the service VM.
    pub fn process_request(&mut self, request: &Request) -> Result<Response> {
        self.write_request(request)?;
        self.read_response()
    }

    /// Sends the request to the service VM.
    fn write_request(&mut self, request: &Request) -> Result<()> {
        let mut buffer = BufWriter::with_capacity(WRITE_BUFFER_CAPACITY, &mut self.vsock_stream);
        ciborium::into_writer(request, &mut buffer)?;
        buffer.flush().context("Failed to flush the buffer")?;
        info!("Sent request to the service VM.");
        Ok(())
    }

    /// Reads the response from the service VM.
    fn read_response(&mut self) -> Result<Response> {
        let response: Response = ciborium::from_reader(&mut self.vsock_stream)
            .context("Failed to read the response from the service VM")?;
        info!("Received response from the service VM.");
        Ok(response)
    }
}

impl Drop for ServiceVm {
    fn drop(&mut self) {
        // Wait till the service VM finishes releasing all the resources.
        match self.vm.wait_for_death_with_timeout(Duration::from_secs(10)) {
            Some(e) => info!("Exit the service VM: {e:?}"),
            None => warn!("Timed out waiting for service VM exit"),
        }
    }
}

/// Returns a `VmInstance` of a protected VM with the instance image from the given path.
pub fn protected_vm_instance(instance_img_path: PathBuf) -> Result<VmInstance> {
    let virtmgr = vmclient::VirtualizationService::new().context("Failed to spawn VirtMgr")?;
    let service = virtmgr.connect().context("Failed to connect to VirtMgr")?;
    info!("Connected to VirtMgr for service VM");

    let instance_img = instance_img(service.as_ref(), instance_img_path)?;
    let writable_partitions = vec![Partition {
        label: "vm-instance".to_owned(),
        image: Some(instance_img),
        writable: true,
    }];
    let rialto = File::open(RIALTO_PATH).context("Failed to open Rialto kernel binary")?;
    let config = VirtualMachineConfig::RawConfig(VirtualMachineRawConfig {
        name: String::from("Service VM"),
        bootloader: Some(ParcelFileDescriptor::new(rialto)),
        disks: vec![DiskImage { image: None, partitions: writable_partitions, writable: true }],
        protectedVm: true,
        memoryMib: MEMORY_MB,
        cpuTopology: CpuTopology::ONE_CPU,
        platformVersion: "~1.0".to_string(),
        gdbPort: 0, // No gdb
        ..Default::default()
    });
    let console_out = Some(android_log_fd()?);
    let console_in = None;
    let log = Some(android_log_fd()?);
    let callback = None;
    VmInstance::create(service.as_ref(), &config, console_out, console_in, log, callback)
        .context("Failed to create service VM")
}

/// Returns the file descriptor of the instance image at the given path.
fn instance_img(
    service: &dyn IVirtualizationService,
    instance_img_path: PathBuf,
) -> Result<ParcelFileDescriptor> {
    if instance_img_path.exists() {
        // TODO(b/298174584): Try to recover if the service VM is triggered by rkpd.
        return Ok(OpenOptions::new()
            .read(true)
            .write(true)
            .open(instance_img_path)
            .map(ParcelFileDescriptor::new)?);
    }
    let instance_img = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(instance_img_path)
        .map(ParcelFileDescriptor::new)?;
    service.initializeWritablePartition(
        &instance_img,
        INSTANCE_IMG_SIZE_BYTES,
        PartitionType::ANDROID_VM_INSTANCE,
    )?;
    Ok(instance_img)
}

/// This function is only exposed for testing.
pub fn android_log_fd() -> io::Result<File> {
    let (reader_fd, writer_fd) = nix::unistd::pipe()?;

    // SAFETY: These are new FDs with no previous owner.
    let reader = unsafe { File::from_raw_fd(reader_fd) };
    // SAFETY: These are new FDs with no previous owner.
    let writer = unsafe { File::from_raw_fd(writer_fd) };

    thread::spawn(|| {
        for line in BufReader::new(reader).lines() {
            match line {
                Ok(l) => info!("{}", l),
                Err(e) => {
                    warn!("Failed to read line: {e:?}");
                    break;
                }
            }
        }
    });
    Ok(writer)
}
