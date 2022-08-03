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

//! Helpers for implementing an RPC Binder client.

use binder::unstable_api::{new_spibinder, AIBinder};
use binder::{FromIBinder, StatusCode, Strong};
use std::os::{raw, unix::io::RawFd};

/// Connects to a binder RPC server.
pub fn connect_rpc_binder<T: FromIBinder + ?Sized>(
    cid: u32,
    port: u32,
) -> Result<Strong<T>, StatusCode> {
    // SAFETY: AIBinder returned by RpcClient has correct reference count, and the ownership can be
    // safely taken by new_spibinder.
    let ibinder = unsafe {
        new_spibinder(binder_rpc_unstable_bindgen::RpcClient(cid, port) as *mut AIBinder)
    };
    if let Some(ibinder) = ibinder {
        <T>::try_from(ibinder)
    } else {
        Err(StatusCode::BAD_VALUE)
    }
}

type RequestFd<'a> = &'a mut dyn FnMut() -> Option<RawFd>;

/// Connects to a Binder RPC server, using the given callback to get (and take ownership of) file
/// descriptors already connected to it.
pub fn connect_preconnected_rpc_binder<T: FromIBinder + ?Sized>(
    mut request_fd: impl FnMut() -> Option<RawFd>,
) -> Result<Strong<T>, StatusCode> {
    // Double reference the factory because trait objects aren't FFI safe.
    let mut request_fd_ref: RequestFd = &mut request_fd;
    let param = &mut request_fd_ref as *mut RequestFd as *mut raw::c_void;

    // SAFETY: AIBinder returned by RpcPreconnectedClient has correct reference count, and the
    // ownership can be safely taken by new_spibinder. RpcPreconnectedClient does not take ownership
    // of param, only passing it to request_fd_wrapper.
    let ibinder = unsafe {
        new_spibinder(binder_rpc_unstable_bindgen::RpcPreconnectedClient(
            Some(request_fd_wrapper),
            param,
        ) as *mut AIBinder)
    };

    if let Some(ibinder) = ibinder {
        <T>::try_from(ibinder)
    } else {
        Err(StatusCode::BAD_VALUE)
    }
}

unsafe extern "C" fn request_fd_wrapper(param: *mut raw::c_void) -> raw::c_int {
    // SAFETY: This is only ever called by RpcPreconnectedClient, within the lifetime of the
    // BinderFdFactory reference, with param being a properly aligned non-null pointer to an
    // initialized instance.
    let request_fd_ptr = param as *mut RequestFd;
    let request_fd = request_fd_ptr.as_mut().unwrap();
    request_fd().unwrap_or(-1)
}
