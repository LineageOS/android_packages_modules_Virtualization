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
    let app = clap::App::new("composd_cmd").arg(
        clap::Arg::with_name("command")
            .index(1)
            .takes_value(true)
            .required(true)
            .possible_values(&["forced-compile-test"]),
    );
    let args = app.get_matches();
    let command = args.value_of("command").unwrap();

    ProcessState::start_thread_pool();

    let service = wait_for_interface::<dyn IIsolatedCompilationService>("android.system.composd")
        .context("Failed to connect to composd service")?;

    match command {
        "forced-compile-test" => service.runForcedCompileForTest().context("Compilation failed")?,
        _ => panic!("Unexpected command {}", command),
    }

    println!("All Ok!");

    Ok(())
}
