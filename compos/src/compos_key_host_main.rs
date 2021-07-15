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

//! Run the CompOS key management service in the host, using normal Binder.

mod compos_key_service;

use crate::compos_key_service::CompOsKeyService;
use anyhow::{Context, Result};
use compos_aidl_interface::aidl::com::android::compos::ICompOsKeyService::BnCompOsKeyService;
use compos_aidl_interface::binder::{add_service, BinderFeatures, ProcessState};
use log::{info, Level};

const LOG_TAG: &str = "CompOsKeyService";
const OUR_SERVICE_NAME: &str = "android.system.composkeyservice";

fn main() -> Result<()> {
    android_logger::init_once(
        android_logger::Config::default().with_tag(LOG_TAG).with_min_level(Level::Trace),
    );

    // We need to start the thread pool for Binder to work properly.
    ProcessState::start_thread_pool();

    let service = CompOsKeyService::new()?;
    let service = BnCompOsKeyService::new_binder(service, BinderFeatures::default());

    add_service(OUR_SERVICE_NAME, service.as_binder()).context("Adding service failed")?;
    info!("It's alive!");

    ProcessState::join_thread_pool();

    Ok(())
}
