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

use anyhow::{bail, Context, Result};
use log::error;
use minijail::{self, Minijail};
use std::os::unix::io::AsRawFd;
use std::path::Path;

use authfs_aidl_interface::aidl::com::android::virt::fs::{
    AuthFsConfig::AuthFsConfig, IAuthFs::IAuthFs, IAuthFsService::IAuthFsService,
    InputFdAnnotation::InputFdAnnotation, OutputFdAnnotation::OutputFdAnnotation,
};
use authfs_aidl_interface::binder::{ParcelFileDescriptor, Strong};
use compos_aidl_interface::aidl::com::android::compos::Metadata::Metadata;

/// The number that represents the file descriptor number expecting by the task. The number may be
/// meaningless in the current process.
pub type PseudoRawFd = i32;

/// Runs the compiler with given flags with file descriptors described in `metadata` retrieved via
/// `authfs_service`. Returns exit code of the compiler process.
pub fn compile(
    compiler_path: &Path,
    compiler_args: &[String],
    authfs_service: Strong<dyn IAuthFsService>,
    metadata: &Metadata,
) -> Result<i8> {
    // Mount authfs (via authfs_service).
    let authfs_config = build_authfs_config(metadata);
    let authfs = authfs_service.mount(&authfs_config)?;

    // The task expects to receive FD numbers that match its flags (e.g. --zip-fd=42) prepared
    // on the host side. Since the local FD opened from authfs (e.g. /authfs/42) may not match
    // the task's expectation, prepare a FD mapping and let minijail prepare the correct FD
    // setup.
    let fd_mapping =
        open_authfs_files_for_fd_mapping(&authfs, &authfs_config).context("Open on authfs")?;

    let jail =
        spawn_jailed_task(compiler_path, compiler_args, fd_mapping).context("Spawn dex2oat")?;
    let jail_result = jail.wait();

    // Be explicit about the lifetime, which should last at least until the task is finished.
    drop(authfs);

    match jail_result {
        Ok(()) => Ok(0), // TODO(b/161471326): Sign the output on succeed.
        Err(minijail::Error::ReturnCode(exit_code)) => {
            error!("Task failed with exit code {}", exit_code);
            Ok(exit_code as i8)
        }
        Err(e) => {
            bail!("Unexpected minijail error: {}", e)
        }
    }
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
) -> Result<Minijail> {
    // TODO(b/185175567): Run in a more restricted sandbox.
    let jail = Minijail::new()?;
    let preserve_fds: Vec<_> = fd_mapping.iter().map(|(f, id)| (f.as_raw_fd(), *id)).collect();
    let _pid = jail.run_remap(executable, preserve_fds.as_slice(), args)?;
    Ok(jail)
}
