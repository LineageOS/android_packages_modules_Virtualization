/*
 * Copyright 2021 The Android Open Source Project
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

use android_system_composd::binder::Result as BinderResult;
use anyhow::Result;
use binder_common::new_binder_service_specific_error;
use log::error;
use std::fmt::Debug;

pub fn to_binder_result<T, E: Debug>(result: Result<T, E>) -> BinderResult<T> {
    result.map_err(|e| {
        let message = format!("{:?}", e);
        error!("Returning binder error: {}", &message);
        new_binder_service_specific_error(-1, message)
    })
}
