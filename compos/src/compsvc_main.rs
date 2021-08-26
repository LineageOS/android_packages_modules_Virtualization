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

//! A tool to start a standalone compsvc server, either in the host using Binder or in a VM using
//! RPC binder over vsock.

mod common;
mod compilation;
mod compos_key_service;
mod compsvc;
mod fsverity;
mod signer;

use crate::common::{SERVICE_NAME, VSOCK_PORT};
use anyhow::{bail, Context, Result};
use binder::unstable_api::AsNative;
use compos_aidl_interface::binder::{add_service, ProcessState};
use log::debug;

struct Config {
    rpc_binder: bool,
}

fn parse_args() -> Result<Config> {
    #[rustfmt::skip]
    let matches = clap::App::new("compsvc")
        .arg(clap::Arg::with_name("rpc_binder")
             .long("rpc-binder"))
        .get_matches();

    Ok(Config { rpc_binder: matches.is_present("rpc_binder") })
}

fn main() -> Result<()> {
    android_logger::init_once(
        android_logger::Config::default().with_tag("compsvc").with_min_level(log::Level::Debug),
    );

    let config = parse_args()?;
    let mut service = compsvc::new_binder(config.rpc_binder)?.as_binder();
    if config.rpc_binder {
        debug!("compsvc is starting as a rpc service.");
        // SAFETY: Service ownership is transferring to the server and won't be valid afterward.
        // Plus the binder objects are threadsafe.
        let retval = unsafe {
            binder_rpc_unstable_bindgen::RunRpcServer(
                service.as_native_mut() as *mut binder_rpc_unstable_bindgen::AIBinder,
                VSOCK_PORT,
            )
        };
        if retval {
            debug!("RPC server has shut down gracefully");
            Ok(())
        } else {
            bail!("Premature termination of RPC server");
        }
    } else {
        ProcessState::start_thread_pool();
        debug!("compsvc is starting as a local service.");
        add_service(SERVICE_NAME, service)
            .with_context(|| format!("Failed to register service {}", SERVICE_NAME))?;
        ProcessState::join_thread_pool();
        bail!("Unexpected exit after join_thread_pool")
    }
}
