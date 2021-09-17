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

//! Starts and manages instances of the CompOS VM.

use anyhow::{Context, Result};
use compos_aidl_interface::aidl::com::android::compos::ICompOsService::ICompOsService;
use compos_aidl_interface::binder::Strong;
use compos_common::compos_client::VmInstance;
use compos_common::{COMPOS_DATA_ROOT, CURRENT_DIR, INSTANCE_IMAGE_FILE, PRIVATE_KEY_BLOB_FILE};
use std::fs;
use std::path::PathBuf;

#[allow(dead_code)]
pub struct CompOsInstance {
    instance: VmInstance,
    service: Strong<dyn ICompOsService>,
}

impl CompOsInstance {
    pub fn start_current_instance() -> Result<CompOsInstance> {
        let instance_image: PathBuf =
            [COMPOS_DATA_ROOT, CURRENT_DIR, INSTANCE_IMAGE_FILE].iter().collect();

        let instance = VmInstance::start(&instance_image).context("Starting VM")?;
        let service = instance.get_service().context("Connecting to CompOS")?;

        let key_blob: PathBuf =
            [COMPOS_DATA_ROOT, CURRENT_DIR, PRIVATE_KEY_BLOB_FILE].iter().collect();
        let key_blob = fs::read(key_blob).context("Reading private key")?;
        service.initializeSigningKey(&key_blob).context("Loading key")?;

        Ok(CompOsInstance { instance, service })
    }

    pub fn cid(&self) -> i32 {
        self.instance.cid()
    }
}
