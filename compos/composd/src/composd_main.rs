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

//! Exposes an on-demand binder service to perform system compilation tasks using CompOS. It is
//! responsible for managing the lifecycle of the CompOS VM instances, providing key management for
//! them, and orchestrating trusted compilation.

mod service;

use android_system_composd::binder::{register_lazy_service, ProcessState};
use anyhow::{Context, Result};
use log::{error, info};

fn try_main() -> Result<()> {
    android_logger::init_once(
        android_logger::Config::default().with_tag("composd").with_min_level(log::Level::Info),
    );

    let service = service::new_binder();
    register_lazy_service("android.system.composd", service.as_binder())
        .context("Registering service")?;

    info!("Registered service, joining threadpool");
    ProcessState::join_thread_pool();

    info!("Exiting");
    Ok(())
}

fn main() {
    if let Err(e) = try_main() {
        error!("{}", e);
        std::process::exit(1)
    }
}
