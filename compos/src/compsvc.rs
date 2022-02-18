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

use anyhow::{bail, Context, Result};
use binder_common::new_binder_exception;
use compos_common::binder::to_binder_result;
use log::warn;
use std::default::Default;
use std::fs::read_dir;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use crate::artifact_signer::ArtifactSigner;
use crate::compilation::{odrefresh, OdrefreshContext};
use crate::compos_key;
use crate::dice::Dice;
use crate::signing_key::DiceSigningKey;
use authfs_aidl_interface::aidl::com::android::virt::fs::IAuthFsService::IAuthFsService;
use compos_aidl_interface::aidl::com::android::compos::{
    CompOsKeyData::CompOsKeyData,
    ICompOsService::{BnCompOsService, CompilationMode::CompilationMode, ICompOsService},
};
use compos_aidl_interface::binder::{
    BinderFeatures, ExceptionCode, Interface, Result as BinderResult, Strong,
};
use compos_common::odrefresh::ODREFRESH_PATH;

const AUTHFS_SERVICE_NAME: &str = "authfs_service";

/// Constructs a binder object that implements ICompOsService.
pub fn new_binder() -> Result<Strong<dyn ICompOsService>> {
    let service = CompOsService {
        odrefresh_path: PathBuf::from(ODREFRESH_PATH),
        signing_key: DiceSigningKey::new(Dice::new()?),
        key_blob: RwLock::new(Vec::new()),
    };
    Ok(BnCompOsService::new_binder(service, BinderFeatures::default()))
}

struct CompOsService {
    odrefresh_path: PathBuf,
    signing_key: DiceSigningKey,
    key_blob: RwLock<Vec<u8>>,
}

impl Interface for CompOsService {}

impl ICompOsService for CompOsService {
    fn initializeSigningKey(&self, key_blob: &[u8]) -> BinderResult<()> {
        let mut w = self.key_blob.write().unwrap();
        if w.is_empty() {
            *w = Vec::from(key_blob);
            Ok(())
        } else {
            Err(new_binder_exception(ExceptionCode::ILLEGAL_STATE, "Cannot re-initialize the key"))
        }
    }

    fn odrefresh(
        &self,
        compilation_mode: CompilationMode,
        system_dir_fd: i32,
        output_dir_fd: i32,
        staging_dir_fd: i32,
        target_dir_name: &str,
        zygote_arch: &str,
        system_server_compiler_filter: &str,
    ) -> BinderResult<i8> {
        let key = &*self.key_blob.read().unwrap();
        if key.is_empty() {
            return Err(new_binder_exception(
                ExceptionCode::ILLEGAL_STATE,
                "Key is not initialized",
            ));
        }

        let context = to_binder_result(OdrefreshContext::new(
            compilation_mode,
            system_dir_fd,
            output_dir_fd,
            staging_dir_fd,
            target_dir_name,
            zygote_arch,
            system_server_compiler_filter,
        ))?;

        let authfs_service = get_authfs_service()?;
        let exit_code = to_binder_result(
            odrefresh(&self.odrefresh_path, context, authfs_service, |output_dir| {
                // authfs only shows us the files we created, so it's ok to just sign everything
                // under the output directory.
                let mut artifact_signer = ArtifactSigner::new(&output_dir);
                add_artifacts(&output_dir, &mut artifact_signer)?;

                artifact_signer.write_info_and_signature(&output_dir.join("compos.info"))
            })
            .context("odrefresh failed"),
        )?;
        Ok(exit_code as i8)
    }

    fn generateSigningKey(&self) -> BinderResult<CompOsKeyData> {
        to_binder_result(self.signing_key.generate())
    }

    fn verifySigningKey(&self, key_blob: &[u8], public_key: &[u8]) -> BinderResult<bool> {
        Ok(if let Err(e) = self.signing_key.verify(key_blob, public_key) {
            warn!("Signing key verification failed: {:?}", e);
            false
        } else {
            true
        })
    }

    fn getPublicKey(&self) -> BinderResult<Vec<u8>> {
        to_binder_result(compos_key::get_public_key())
    }
}

fn get_authfs_service() -> BinderResult<Strong<dyn IAuthFsService>> {
    Ok(authfs_aidl_interface::binder::get_interface(AUTHFS_SERVICE_NAME)?)
}

fn add_artifacts(target_dir: &Path, artifact_signer: &mut ArtifactSigner) -> Result<()> {
    for entry in
        read_dir(&target_dir).with_context(|| format!("Traversing {}", target_dir.display()))?
    {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            add_artifacts(&entry.path(), artifact_signer)?;
        } else if file_type.is_file() {
            artifact_signer.add_artifact(&entry.path())?;
        } else {
            // authfs shouldn't create anything else, but just in case
            bail!("Unexpected file type in artifacts: {:?}", entry);
        }
    }
    Ok(())
}
