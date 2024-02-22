// Copyright 2024 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use android_system_virtualizationmaintenance::aidl::android::system::virtualizationmaintenance;
use anyhow::anyhow;
use binder::{BinderFeatures, ExceptionCode, Interface, IntoBinderResult, Strong};
use virtualizationmaintenance::IVirtualizationMaintenance::{
    BnVirtualizationMaintenance, IVirtualizationMaintenance,
};

pub(crate) fn new_binder() -> Strong<dyn IVirtualizationMaintenance> {
    BnVirtualizationMaintenance::new_binder(
        VirtualizationMaintenanceService {},
        BinderFeatures::default(),
    )
}

pub struct VirtualizationMaintenanceService;

impl Interface for VirtualizationMaintenanceService {}

#[allow(non_snake_case)]
impl IVirtualizationMaintenance for VirtualizationMaintenanceService {
    fn appRemoved(&self, _user_id: i32, _app_id: i32) -> binder::Result<()> {
        Err(anyhow!("appRemoved not supported"))
            .or_binder_exception(ExceptionCode::UNSUPPORTED_OPERATION)
    }

    fn userRemoved(&self, _user_id: i32) -> binder::Result<()> {
        Err(anyhow!("userRemoved not supported"))
            .or_binder_exception(ExceptionCode::UNSUPPORTED_OPERATION)
    }
}
