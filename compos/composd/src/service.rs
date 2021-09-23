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

use crate::instance_manager::InstanceManager;
use crate::odrefresh;
use android_system_composd::aidl::android::system::composd::IIsolatedCompilationService::{
    BnIsolatedCompilationService, IIsolatedCompilationService,
};
use android_system_composd::binder::{self, BinderFeatures, Interface, Status, Strong};
use anyhow::{bail, Context, Result};
use compos_aidl_interface::aidl::com::android::compos::{
    CompilationResult::CompilationResult, FdAnnotation::FdAnnotation,
};
use log::{error, info};
use std::ffi::CString;

#[derive(Default)]
pub struct IsolatedCompilationService {
    instance_manager: InstanceManager,
}

pub fn new_binder() -> Strong<dyn IIsolatedCompilationService> {
    let service = IsolatedCompilationService::default();
    BnIsolatedCompilationService::new_binder(service, BinderFeatures::default())
}

impl Interface for IsolatedCompilationService {}

impl IIsolatedCompilationService for IsolatedCompilationService {
    fn runForcedCompile(&self) -> binder::Result<()> {
        // TODO - check caller is system or shell/root?
        to_binder_result(self.do_run_forced_compile())
    }

    fn compile(
        &self,
        args: &[String],
        fd_annotation: &FdAnnotation,
    ) -> binder::Result<CompilationResult> {
        // TODO - check caller is odrefresh
        to_binder_result(self.do_compile(args, fd_annotation))
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

        let comp_os = self.instance_manager.start_current_instance().context("Starting CompOS")?;

        let exit_code = odrefresh::run_forced_compile()?;

        if exit_code != odrefresh::ExitCode::CompilationSuccess {
            bail!("Unexpected odrefresh result: {:?}", exit_code);
        }

        // The instance is needed until odrefresh is finished
        drop(comp_os);

        Ok(())
    }

    fn do_compile(
        &self,
        args: &[String],
        fd_annotation: &FdAnnotation,
    ) -> Result<CompilationResult> {
        let compos = self.instance_manager.get_running_service()?;
        compos.compile(args, fd_annotation).context("Compiling")
    }
}
