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

//! Implementation of ICompilationInternal, called from odrefresh during compilation.

use crate::instance_manager::InstanceManager;
use compos_common::binder::to_binder_result;
use android_system_composd_internal::aidl::android::system::composd::internal::ICompilationInternal::{
    BnCompilationInternal, ICompilationInternal,
};
use android_system_composd::binder::{
    self, BinderFeatures, ExceptionCode, Interface, Status, Strong, ThreadState,
};
use anyhow::{Context, Result};
use binder_common::new_binder_service_specific_error;
use compos_aidl_interface::aidl::com::android::compos::{
    CompilationResult::CompilationResult, FdAnnotation::FdAnnotation,
};
use rustutils::users::AID_ROOT;
use std::sync::Arc;

pub struct CompilationInternalService {
    instance_manager: Arc<InstanceManager>,
}

pub fn new_binder(instance_manager: Arc<InstanceManager>) -> Strong<dyn ICompilationInternal> {
    let service = CompilationInternalService { instance_manager };
    BnCompilationInternal::new_binder(service, BinderFeatures::default())
}

impl Interface for CompilationInternalService {}

impl ICompilationInternal for CompilationInternalService {
    fn compile_cmd(
        &self,
        args: &[String],
        fd_annotation: &FdAnnotation,
    ) -> binder::Result<CompilationResult> {
        let calling_uid = ThreadState::get_calling_uid();
        // This should only be called by odrefresh, which runs as root
        if calling_uid != AID_ROOT {
            return Err(Status::new_exception(ExceptionCode::SECURITY, None));
        }
        to_binder_result(self.do_compile_cmd(args, fd_annotation))
    }

    fn compile(&self, _marshaled: &[u8], _fd_annotation: &FdAnnotation) -> binder::Result<i8> {
        Err(new_binder_service_specific_error(-1, "Not yet implemented"))
    }
}

impl CompilationInternalService {
    fn do_compile_cmd(
        &self,
        args: &[String],
        fd_annotation: &FdAnnotation,
    ) -> Result<CompilationResult> {
        let compos = self.instance_manager.get_running_service()?;
        compos.compile_cmd(args, fd_annotation).context("Compiling")
    }
}
