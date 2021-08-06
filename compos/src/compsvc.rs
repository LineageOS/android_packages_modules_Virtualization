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

//! compsvc is a service to run computational tasks in a PVM upon request. It is able to set up
//! file descriptors backed by authfs (via authfs_service) and pass the file descriptors to the
//! actual tasks.

use anyhow::Result;
use log::error;
use minijail::{self, Minijail};
use std::ffi::CString;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use crate::signer::Signer;
use authfs_aidl_interface::aidl::com::android::virt::fs::{
    AuthFsConfig::AuthFsConfig, IAuthFs::IAuthFs, IAuthFsService::IAuthFsService,
    InputFdAnnotation::InputFdAnnotation, OutputFdAnnotation::OutputFdAnnotation,
};
use authfs_aidl_interface::binder::ParcelFileDescriptor;
use compos_aidl_interface::aidl::com::android::compos::ICompService::{
    BnCompService, ICompService,
};
use compos_aidl_interface::aidl::com::android::compos::Metadata::Metadata;
use compos_aidl_interface::binder::{
    BinderFeatures, ExceptionCode, Interface, Result as BinderResult, Status, StatusCode, Strong,
};

const AUTHFS_SERVICE_NAME: &str = "authfs_service";

/// The number that represents the file descriptor number expecting by the task. The number may be
/// meaningless in the current process.
pub type PseudoRawFd = i32;

/// Constructs a binder object that implements ICompService. task_bin is the path to the binary that will
/// be run when execute() is called. If debuggable is true then stdout/stderr from the binary will be
/// available for debugging.
pub fn new_binder(
    task_bin: String,
    debuggable: bool,
    signer: Option<Box<dyn Signer>>,
) -> Strong<dyn ICompService> {
    let service = CompService { task_bin: PathBuf::from(task_bin), debuggable, signer };
    BnCompService::new_binder(service, BinderFeatures::default())
}

struct CompService {
    task_bin: PathBuf,
    debuggable: bool,
    #[allow(dead_code)] // TODO: Make use of this
    signer: Option<Box<dyn Signer>>,
}

impl Interface for CompService {}

impl ICompService for CompService {
    fn execute(&self, args: &[String], metadata: &Metadata) -> BinderResult<i8> {
        // Mount authfs (via authfs_service).
        let authfs_config = build_authfs_config(metadata);
        let authfs = get_authfs_service()?.mount(&authfs_config)?;

        // The task expects to receive FD numbers that match its flags (e.g. --zip-fd=42) prepared
        // on the host side. Since the local FD opened from authfs (e.g. /authfs/42) may not match
        // the task's expectation, prepare a FD mapping and let minijail prepare the correct FD
        // setup.
        let fd_mapping =
            open_authfs_files_for_fd_mapping(&authfs, &authfs_config).map_err(|e| {
                new_binder_exception(
                    ExceptionCode::SERVICE_SPECIFIC,
                    format!("Failed to create FDs on authfs: {:?}", e),
                )
            })?;

        let jail =
            spawn_jailed_task(&self.task_bin, args, fd_mapping, self.debuggable).map_err(|e| {
                new_binder_exception(
                    ExceptionCode::SERVICE_SPECIFIC,
                    format!("Failed to spawn the task: {:?}", e),
                )
            })?;
        let jail_result = jail.wait();

        // Be explicit about the lifetime, which should last at least until the task is finished.
        drop(authfs);

        match jail_result {
            Ok(_) => Ok(0), // TODO(b/161471326): Sign the output on succeed.
            Err(minijail::Error::ReturnCode(exit_code)) => {
                error!("Task failed with exit code {}", exit_code);
                Err(Status::from(StatusCode::FAILED_TRANSACTION))
            }
            Err(e) => {
                error!("Unexpected minijail error: {}", e);
                Err(Status::from(StatusCode::UNKNOWN_ERROR))
            }
        }
    }
}

fn get_authfs_service() -> BinderResult<Strong<dyn IAuthFsService>> {
    Ok(authfs_aidl_interface::binder::get_interface(AUTHFS_SERVICE_NAME)?)
}

fn build_authfs_config(metadata: &Metadata) -> AuthFsConfig {
    AuthFsConfig {
        port: 3264, // TODO: support dynamic port
        inputFdAnnotations: metadata
            .input_fd_annotations
            .iter()
            .map(|x| InputFdAnnotation { fd: x.fd, fileSize: x.file_size })
            .collect(),
        outputFdAnnotations: metadata
            .output_fd_annotations
            .iter()
            .map(|x| OutputFdAnnotation { fd: x.fd })
            .collect(),
    }
}

fn open_authfs_files_for_fd_mapping(
    authfs: &Strong<dyn IAuthFs>,
    config: &AuthFsConfig,
) -> Result<Vec<(ParcelFileDescriptor, PseudoRawFd)>> {
    let mut fd_mapping = Vec::new();

    let results: Result<Vec<_>> = config
        .inputFdAnnotations
        .iter()
        .map(|annotation| Ok((authfs.openFile(annotation.fd, false)?, annotation.fd)))
        .collect();
    fd_mapping.append(&mut results?);

    let results: Result<Vec<_>> = config
        .outputFdAnnotations
        .iter()
        .map(|annotation| Ok((authfs.openFile(annotation.fd, true)?, annotation.fd)))
        .collect();
    fd_mapping.append(&mut results?);

    Ok(fd_mapping)
}

fn spawn_jailed_task(
    executable: &Path,
    args: &[String],
    fd_mapping: Vec<(ParcelFileDescriptor, PseudoRawFd)>,
    debuggable: bool,
) -> Result<Minijail> {
    // TODO(b/185175567): Run in a more restricted sandbox.
    let jail = Minijail::new()?;

    let mut preserve_fds = if debuggable {
        // Inherit/redirect stdout/stderr for debugging, assuming no conflict
        vec![(1, 1), (2, 2)]
    } else {
        vec![]
    };

    preserve_fds.extend(fd_mapping.iter().map(|(f, id)| (f.as_raw_fd(), *id)));

    let _pid = jail.run_remap(executable, preserve_fds.as_slice(), args)?;
    Ok(jail)
}

fn new_binder_exception<T: AsRef<str>>(exception: ExceptionCode, message: T) -> Status {
    Status::new_exception(exception, CString::new(message.as_ref()).as_deref().ok())
}
