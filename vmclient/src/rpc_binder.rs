// Copyright 2022, The Android Open Source Project
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

use crate::errors::ConnectServiceError;
use android_system_virtualizationservice::{
    aidl::android::system::virtualizationservice::IVirtualMachine::IVirtualMachine,
};
use binder::unstable_api::{new_spibinder, AIBinder};
use log::warn;
use std::os::{raw, unix::io::IntoRawFd};

pub struct VsockFactory<'a> {
    vm: &'a dyn IVirtualMachine,
    port: u32,
}

impl<'a> VsockFactory<'a> {
    pub fn new(vm: &'a dyn IVirtualMachine, port: u32) -> Self {
        Self { vm, port }
    }

    pub fn connect_rpc_client(&mut self) -> Result<binder::SpIBinder, ConnectServiceError> {
        let param = self.as_void_ptr();

        unsafe {
            // SAFETY: AIBinder returned by RpcPreconnectedClient has correct reference count, and
            // the ownership can be safely taken by new_spibinder.
            // RpcPreconnectedClient does not take ownership of param, only passing it to
            // request_fd.
            let binder =
                binder_rpc_unstable_bindgen::RpcPreconnectedClient(Some(Self::request_fd), param)
                    as *mut AIBinder;
            new_spibinder(binder).ok_or(ConnectServiceError::ConnectionFailed)
        }
    }

    fn as_void_ptr(&mut self) -> *mut raw::c_void {
        self as *mut _ as *mut raw::c_void
    }

    fn new_vsock_fd(&self) -> i32 {
        match self.vm.connectVsock(self.port as i32) {
            Ok(vsock) => {
                // Ownership of the fd is transferred to binder
                vsock.into_raw_fd()
            }
            Err(e) => {
                warn!("Vsock connection failed: {}", e);
                -1
            }
        }
    }

    unsafe extern "C" fn request_fd(param: *mut raw::c_void) -> raw::c_int {
        // SAFETY: This is only ever called by RpcPreconnectedClient, within the lifetime of the
        // VsockFactory, with param taking the value returned by as_void_ptr (so a properly aligned
        // non-null pointer to an initialized instance).
        let vsock_factory = param as *mut Self;
        vsock_factory.as_ref().unwrap().new_vsock_fd()
    }
}
