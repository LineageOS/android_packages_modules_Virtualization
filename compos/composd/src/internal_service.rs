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

use android_system_composd_internal::aidl::android::system::composd::internal::ICompilationInternal::{
    BnCompilationInternal, ICompilationInternal,
};
use android_system_composd::binder::{self, BinderFeatures, Interface, Strong};
use binder_common::new_binder_service_specific_error;
use compos_aidl_interface::aidl::com::android::compos::FdAnnotation::FdAnnotation;

pub struct CompilationInternalService {}

pub fn new_binder() -> Strong<dyn ICompilationInternal> {
    let service = CompilationInternalService {};
    BnCompilationInternal::new_binder(service, BinderFeatures::default())
}

impl Interface for CompilationInternalService {}

impl ICompilationInternal for CompilationInternalService {
    fn compile(&self, _marshaled: &[u8], _fd_annotation: &FdAnnotation) -> binder::Result<i8> {
        Err(new_binder_service_specific_error(-1, "Not yet implemented"))
    }
}
