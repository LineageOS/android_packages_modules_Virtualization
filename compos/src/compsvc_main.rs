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

//! A tool to start a standalone compsvc server that serves over RPC binder.

mod compilation;
mod compos_key_service;
mod compsvc;
mod fsverity;
mod signer;

use android_system_virtualmachineservice::{
    aidl::android::system::virtualmachineservice::IVirtualMachineService::{
        IVirtualMachineService, VM_BINDER_SERVICE_PORT,
    },
    binder::Strong,
};
use anyhow::{anyhow, bail, Context, Result};
use binder::{
    unstable_api::{new_spibinder, AIBinder, AsNative},
    FromIBinder,
};
use compos_common::COMPOS_VSOCK_PORT;
use log::{debug, error};
use nix::ioctl_read_bad;
use std::fs::OpenOptions;
use std::os::raw;
use std::os::unix::io::AsRawFd;

/// The CID representing the host VM
const VMADDR_CID_HOST: u32 = 2;

fn main() -> Result<()> {
    let args = clap::App::new("compsvc")
        .arg(clap::Arg::with_name("log_to_stderr").long("log_to_stderr"))
        .get_matches();
    if args.is_present("log_to_stderr") {
        env_logger::builder().filter_level(log::LevelFilter::Debug).init();
    } else {
        android_logger::init_once(
            android_logger::Config::default().with_tag("compsvc").with_min_level(log::Level::Debug),
        );
    }

    let mut service = compsvc::new_binder()?.as_binder();
    debug!("compsvc is starting as a rpc service.");

    let mut ready_notifier = ReadyNotifier::new()?;

    // SAFETY: Service ownership is transferring to the server and won't be valid afterward.
    // Plus the binder objects are threadsafe.
    // RunRpcServerCallback does not retain a reference to ready_callback, and only ever
    // calls it with the param we provide during the lifetime of ready_notifier.
    let retval = unsafe {
        binder_rpc_unstable_bindgen::RunRpcServerCallback(
            service.as_native_mut() as *mut binder_rpc_unstable_bindgen::AIBinder,
            COMPOS_VSOCK_PORT,
            Some(ReadyNotifier::ready_callback),
            ready_notifier.as_void_ptr(),
        )
    };
    if retval {
        debug!("RPC server has shut down gracefully");
        Ok(())
    } else {
        bail!("Premature termination of RPC server");
    }
}

struct ReadyNotifier {
    vm_service: Strong<dyn IVirtualMachineService>,
    local_cid: u32,
}

impl ReadyNotifier {
    fn new() -> Result<Self> {
        Ok(Self { vm_service: Self::get_vm_service()?, local_cid: Self::get_local_cid()? })
    }

    fn notify(&self) {
        if let Err(e) = self.vm_service.notifyPayloadReady(self.local_cid as i32) {
            error!("Unable to notify ready: {}", e);
        }
    }

    fn as_void_ptr(&mut self) -> *mut raw::c_void {
        self as *mut _ as *mut raw::c_void
    }

    unsafe extern "C" fn ready_callback(param: *mut raw::c_void) {
        // SAFETY: This is only ever called by RunRpcServerCallback, within the lifetime of the
        // ReadyNotifier, with param taking the value returned by as_void_ptr (so a properly aligned
        // non-null pointer to an initialized instance).
        let ready_notifier = param as *mut Self;
        ready_notifier.as_ref().unwrap().notify()
    }

    fn get_vm_service() -> Result<Strong<dyn IVirtualMachineService>> {
        // SAFETY: AIBinder returned by RpcClient has correct reference count, and the ownership
        // can be safely taken by new_spibinder.
        let ibinder = unsafe {
            new_spibinder(binder_rpc_unstable_bindgen::RpcClient(
                VMADDR_CID_HOST,
                VM_BINDER_SERVICE_PORT as u32,
            ) as *mut AIBinder)
        }
        .ok_or_else(|| anyhow!("Failed to connect to IVirtualMachineService"))?;

        FromIBinder::try_from(ibinder).context("Connecting to IVirtualMachineService")
    }

    // TODO(b/199259751): remove this after VS can check the peer addresses of binder clients
    fn get_local_cid() -> Result<u32> {
        let f = OpenOptions::new()
            .read(true)
            .write(false)
            .open("/dev/vsock")
            .context("Failed to open /dev/vsock")?;
        let mut cid = 0;
        // SAFETY: the kernel only modifies the given u32 integer.
        unsafe { vm_sockets_get_local_cid(f.as_raw_fd(), &mut cid) }
            .context("Failed to get local CID")?;
        Ok(cid)
    }
}

// TODO(b/199259751): remove this after VS can check the peer addresses of binder clients
const IOCTL_VM_SOCKETS_GET_LOCAL_CID: usize = 0x7b9;
ioctl_read_bad!(
    /// Gets local cid from /dev/vsock
    vm_sockets_get_local_cid,
    IOCTL_VM_SOCKETS_GET_LOCAL_CID,
    u32
);
