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

//! Implementation of IIsolatedCompilationService, called from system server when compilation is
//! desired.

use crate::compos_instance::CompOsInstance;
use crate::odrefresh;
use android_system_composd::aidl::android::system::composd::IIsolatedCompilationService::{
    BnIsolatedCompilationService, IIsolatedCompilationService,
};
use android_system_composd::binder::{self, BinderFeatures, Interface, Status, Strong};
use anyhow::{bail, Context, Result};
use log::{error, info};
use std::ffi::CString;

pub struct IsolatedCompilationService {}

pub fn new_binder() -> Strong<dyn IIsolatedCompilationService> {
    let service = IsolatedCompilationService {};
    BnIsolatedCompilationService::new_binder(service, BinderFeatures::default())
}

impl Interface for IsolatedCompilationService {}

impl IIsolatedCompilationService for IsolatedCompilationService {
    fn runForcedCompile(&self) -> binder::Result<()> {
        to_binder_result(self.do_run_forced_compile())
    }
}

fn to_binder_result<T>(result: Result<T>) -> binder::Result<T> {
    result.map_err(|e| {
        error!("Returning binder error: {:#}", e);
        Status::new_service_specific_error(-1, CString::new(format!("{:#}", e)).ok().as_deref())
    })
}

impl IsolatedCompilationService {
    fn do_run_forced_compile(&self) -> Result<()> {
        info!("runForcedCompile");

        // TODO: Create instance if need be, handle instance failure, prevent
        // multiple instances running
        let comp_os = CompOsInstance::start_current_instance().context("Starting CompOS")?;

        let exit_code = odrefresh::run_forced_compile(comp_os.cid())?;

        if exit_code != odrefresh::ExitCode::CompilationSuccess {
            bail!("Unexpected odrefresh result: {:?}", exit_code);
        }

        Ok(())
    }
}
