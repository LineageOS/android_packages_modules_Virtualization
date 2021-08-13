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
use log::{debug, warn};
use std::ffi::CString;
use std::path::PathBuf;

use crate::compilation::{compile, CompilerOutput};
use crate::compos_key_service::CompOsKeyService;
use authfs_aidl_interface::aidl::com::android::virt::fs::IAuthFsService::IAuthFsService;
use compos_aidl_interface::aidl::com::android::compos::{
    CompOsKeyData::CompOsKeyData,
    ICompOsService::{BnCompOsService, ICompOsService},
    Metadata::Metadata,
};
use compos_aidl_interface::binder::{
    BinderFeatures, ExceptionCode, Interface, Result as BinderResult, Status, Strong,
};

const AUTHFS_SERVICE_NAME: &str = "authfs_service";
const DEX2OAT_PATH: &str = "/apex/com.android.art/bin/dex2oat64";

/// Constructs a binder object that implements ICompOsService.
pub fn new_binder(rpc_binder: bool) -> Result<Strong<dyn ICompOsService>> {
    let service = CompOsService {
        dex2oat_path: PathBuf::from(DEX2OAT_PATH),
        key_service: CompOsKeyService::new(rpc_binder)?,
    };
    Ok(BnCompOsService::new_binder(service, BinderFeatures::default()))
}

struct CompOsService {
    dex2oat_path: PathBuf,
    key_service: CompOsKeyService,
}

impl Interface for CompOsService {}

impl ICompOsService for CompOsService {
    fn execute(&self, args: &[String], metadata: &Metadata) -> BinderResult<i8> {
        let authfs_service = get_authfs_service()?;
        let output = compile(&self.dex2oat_path, args, authfs_service, metadata).map_err(|e| {
            new_binder_exception(
                ExceptionCode::SERVICE_SPECIFIC,
                format!("Compilation failed: {}", e),
            )
        })?;
        match output {
            CompilerOutput::Digests { oat, vdex, image } => {
                // TODO(b/161471326): Sign the output on succeed.
                debug!("oat fs-verity digest: {:02x?}", oat);
                debug!("vdex fs-verity digest: {:02x?}", vdex);
                debug!("image fs-verity digest: {:02x?}", image);
                Ok(0)
            }
            CompilerOutput::ExitCode(exit_code) => Ok(exit_code),
        }
    }

    fn generateSigningKey(&self) -> BinderResult<CompOsKeyData> {
        self.key_service
            .do_generate()
            .map_err(|e| new_binder_exception(ExceptionCode::ILLEGAL_STATE, e.to_string()))
    }

    fn verifySigningKey(&self, key_blob: &[u8], public_key: &[u8]) -> BinderResult<bool> {
        Ok(if let Err(e) = self.key_service.do_verify(key_blob, public_key) {
            warn!("Signing key verification failed: {}", e.to_string());
            false
        } else {
            true
        })
    }

    fn sign(&self, key_blob: &[u8], data: &[u8]) -> BinderResult<Vec<u8>> {
        self.key_service
            .do_sign(key_blob, data)
            .map_err(|e| new_binder_exception(ExceptionCode::ILLEGAL_STATE, e.to_string()))
    }
}

fn get_authfs_service() -> BinderResult<Strong<dyn IAuthFsService>> {
    Ok(authfs_aidl_interface::binder::get_interface(AUTHFS_SERVICE_NAME)?)
}

fn new_binder_exception<T: AsRef<str>>(exception: ExceptionCode, message: T) -> Status {
    Status::new_exception(exception, CString::new(message.as_ref()).as_deref().ok())
}
