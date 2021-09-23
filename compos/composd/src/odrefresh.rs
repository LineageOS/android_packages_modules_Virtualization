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

//! Handle the details of executing odrefresh to generate compiled artifacts.

use anyhow::{bail, Context, Result};
use compos_common::VMADDR_CID_ANY;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use std::process::Command;

// TODO: What if this changes?
const EX_MAX: i32 = 78;
const ODREFRESH_BIN: &str = "/apex/com.android.art/bin/odrefresh";

#[derive(Debug, PartialEq, Eq, FromPrimitive)]
#[repr(i32)]
pub enum ExitCode {
    // Copied from art/odrefresh/include/odrefresh/odrefresh.h
    Okay = 0i32,
    CompilationRequired = EX_MAX + 1,
    CompilationSuccess = EX_MAX + 2,
    CompilationFailed = EX_MAX + 3,
    CleanupFailed = EX_MAX + 4,
}

pub fn run_forced_compile() -> Result<ExitCode> {
    // We don`t need to capture stdout/stderr - odrefresh writes to the log
    let mut odrefresh = Command::new(ODREFRESH_BIN)
        .arg(format!("--use-compilation-os={}", VMADDR_CID_ANY))
        .arg("--force-compile")
        .spawn()
        .context("Running odrefresh")?;

    // TODO: timeout?
    let status = odrefresh.wait()?;

    if let Some(exit_code) = status.code().and_then(FromPrimitive::from_i32) {
        Ok(exit_code)
    } else {
        bail!("odrefresh exited with {}", status)
    }
}
