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

//! compsvc is a service to run compilation tasks in a PVM upon request. It is able to set up
//! file descriptors backed by authfs (via authfs_service) and pass the file descriptors to the
//! actual compiler.

use anyhow::Result;
use std::ffi::CString;
use std::path::PathBuf;

use crate::compilation::compile;
use crate::compos_key_service::{CompOsKeyService, KeystoreNamespace};
use crate::signer::Signer;
use authfs_aidl_interface::aidl::com::android::virt::fs::IAuthFsService::IAuthFsService;
use compos_aidl_interface::aidl::com::android::compos::ICompOsService::{
    BnCompOsService, ICompOsService,
};
use compos_aidl_interface::aidl::com::android::compos::Metadata::Metadata;
use compos_aidl_interface::binder::{
    BinderFeatures, ExceptionCode, Interface, Result as BinderResult, Status, Strong,
};

const AUTHFS_SERVICE_NAME: &str = "authfs_service";
const DEX2OAT_PATH: &str = "/apex/com.android.art/bin/dex2oat64";

/// Constructs a binder object that implements ICompOsService.
pub fn new_binder(
    rpc_binder: bool,
    signer: Option<Box<dyn Signer>>,
) -> Result<Strong<dyn ICompOsService>> {
    let namespace =
        if rpc_binder { KeystoreNamespace::VmPayload } else { KeystoreNamespace::Odsign };
    let key_service = CompOsKeyService::new(namespace)?;

    let service = CompOsService { dex2oat_path: PathBuf::from(DEX2OAT_PATH), signer, key_service };
    Ok(BnCompOsService::new_binder(service, BinderFeatures::default()))
}

struct CompOsService {
    dex2oat_path: PathBuf,
    #[allow(dead_code)] // TODO: Make use of this
    signer: Option<Box<dyn Signer>>,
    #[allow(dead_code)] // TODO: Make use of this
    key_service: CompOsKeyService,
}

impl Interface for CompOsService {}

impl ICompOsService for CompOsService {
    fn execute(&self, args: &[String], metadata: &Metadata) -> BinderResult<i8> {
        let authfs_service = get_authfs_service()?;
        compile(&self.dex2oat_path, args, authfs_service, metadata).map_err(|e| {
            new_binder_exception(
                ExceptionCode::SERVICE_SPECIFIC,
                format!("Compilation failed: {}", e),
            )
        })
    }
}

fn get_authfs_service() -> BinderResult<Strong<dyn IAuthFsService>> {
    Ok(authfs_aidl_interface::binder::get_interface(AUTHFS_SERVICE_NAME)?)
}

fn new_binder_exception<T: AsRef<str>>(exception: ExceptionCode, message: T) -> Status {
    Status::new_exception(exception, CString::new(message.as_ref()).as_deref().ok())
}
