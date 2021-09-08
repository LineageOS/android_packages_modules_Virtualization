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

use anyhow::{bail, Result};
use binder::unstable_api::AsNative;
use compos_common::COMPOS_VSOCK_PORT;
use log::debug;

fn main() -> Result<()> {
    android_logger::init_once(
        android_logger::Config::default().with_tag("compsvc").with_min_level(log::Level::Debug),
    );

    let mut service = compsvc::new_binder()?.as_binder();
    debug!("compsvc is starting as a rpc service.");
    // SAFETY: Service ownership is transferring to the server and won't be valid afterward.
    // Plus the binder objects are threadsafe.
    let retval = unsafe {
        binder_rpc_unstable_bindgen::RunRpcServer(
            service.as_native_mut() as *mut binder_rpc_unstable_bindgen::AIBinder,
            COMPOS_VSOCK_PORT,
        )
    };
    if retval {
        debug!("RPC server has shut down gracefully");
        Ok(())
    } else {
        bail!("Premature termination of RPC server");
    }
}
