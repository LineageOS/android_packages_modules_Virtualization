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

mod artifact_signer;
mod compilation;
mod compos_key;
mod compsvc;
mod fsverity;

use anyhow::{bail, Result};
use compos_common::COMPOS_VSOCK_PORT;
use log::{debug, error, warn};
use rpcbinder::run_vsock_rpc_server;
use std::panic;
use vm_payload_bindgen::{AVmPayload_notifyPayloadReady, AVmPayload_setupStdioProxy};

fn main() {
    if let Err(e) = try_main() {
        error!("failed with {:?}", e);
        std::process::exit(1);
    }
}

fn try_main() -> Result<()> {
    android_logger::init_once(
        android_logger::Config::default().with_tag("compsvc").with_min_level(log::Level::Debug),
    );
    // Redirect panic messages to logcat.
    panic::set_hook(Box::new(|panic_info| {
        error!("{}", panic_info);
    }));
    // Redirect stdio to the host.
    if !unsafe { AVmPayload_setupStdioProxy() } {
        warn!("Failed to setup stdio proxy");
    }

    let service = compsvc::new_binder()?.as_binder();
    debug!("compsvc is starting as a rpc service.");
    // SAFETY: Invokes a method from the bindgen library `vm_payload_bindgen`.
    let retval = run_vsock_rpc_server(service, COMPOS_VSOCK_PORT, || unsafe {
        AVmPayload_notifyPayloadReady();
    });
    if retval {
        debug!("RPC server has shut down gracefully");
        Ok(())
    } else {
        bail!("Premature termination of RPC server");
    }
}
