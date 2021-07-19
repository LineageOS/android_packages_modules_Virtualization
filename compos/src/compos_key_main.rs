// Copyright 2021, The Android Open Source Project
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

//! Run the CompOS key management service, either in the host using normal Binder or in the
//! VM using RPC Binder.

mod compos_key_service;

use crate::compos_key_service::{CompOsKeyService, KeystoreNamespace};
use anyhow::{bail, Context, Result};
use binder::unstable_api::AsNative;
use compos_aidl_interface::aidl::com::android::compos::ICompOsKeyService::BnCompOsKeyService;
use compos_aidl_interface::binder::{add_service, BinderFeatures, ProcessState};
use log::{info, Level};

const LOG_TAG: &str = "CompOsKeyService";
const OUR_SERVICE_NAME: &str = "android.system.composkeyservice";
const OUR_VSOCK_PORT: u32 = 3142;

fn main() -> Result<()> {
    android_logger::init_once(
        android_logger::Config::default().with_tag(LOG_TAG).with_min_level(Level::Info),
    );

    let matches = clap::App::new("compos_key_main")
        .arg(clap::Arg::with_name("rpc_binder").long("rpc-binder"))
        .get_matches();

    let rpc_binder = matches.is_present("rpc_binder");

    let key_namespace =
        if rpc_binder { KeystoreNamespace::VmPayload } else { KeystoreNamespace::Odsign };
    let service = CompOsKeyService::new(key_namespace)?;
    let mut service =
        BnCompOsKeyService::new_binder(service, BinderFeatures::default()).as_binder();

    if rpc_binder {
        info!("Starting RPC service");
        // SAFETY: Service ownership is transferring to the server and won't be valid afterward.
        // Plus the binder objects are threadsafe.
        let retval = unsafe {
            binder_rpc_unstable_bindgen::RunRpcServer(
                service.as_native_mut() as *mut binder_rpc_unstable_bindgen::AIBinder,
                OUR_VSOCK_PORT,
            )
        };
        if retval {
            info!("RPC server has shut down gracefully");
        } else {
            bail!("Premature termination of RPC server");
        }
    } else {
        info!("Starting binder service");
        add_service(OUR_SERVICE_NAME, service).context("Adding service failed")?;
        info!("It's alive!");

        ProcessState::join_thread_pool();
    }

    Ok(())
}
