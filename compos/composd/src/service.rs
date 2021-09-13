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

use android_system_composd::aidl::android::system::composd::IIsolatedCompilationService::{
    BnIsolatedCompilationService, IIsolatedCompilationService,
};
use android_system_composd::binder::{self, BinderFeatures, Interface, Strong};

pub struct IsolatedCompilationService {}

pub fn new_binder() -> Strong<dyn IIsolatedCompilationService> {
    let service = IsolatedCompilationService {};
    BnIsolatedCompilationService::new_binder(service, BinderFeatures::default())
}

impl IsolatedCompilationService {}

impl Interface for IsolatedCompilationService {}

impl IIsolatedCompilationService for IsolatedCompilationService {
    fn doSomething(&self) -> binder::Result<()> {
        Ok(())
    }
}
