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

//! Simple command-line tool to drive composd for testing and debugging.

use android_system_composd::{
    aidl::android::system::composd::IIsolatedCompilationService::IIsolatedCompilationService,
    binder::{wait_for_interface, ProcessState},
};
use anyhow::{Context, Result};

fn main() -> Result<()> {
    ProcessState::start_thread_pool();

    let service = wait_for_interface::<dyn IIsolatedCompilationService>("android.system.composd")
        .context("Failed to connect to composd service")?;

    service.runForcedCompile().context("Compilation failed")?;

    println!("All Ok!");

    Ok(())
}
