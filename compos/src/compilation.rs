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

use anyhow::{anyhow, bail, Context, Result};
use log::error;
use minijail::{self, Minijail};
use std::env;
use std::fs::{create_dir, File};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};

use crate::fsverity;
use authfs_aidl_interface::aidl::com::android::virt::fs::{
    AuthFsConfig::{
        AuthFsConfig, InputDirFdAnnotation::InputDirFdAnnotation,
        InputFdAnnotation::InputFdAnnotation, OutputDirFdAnnotation::OutputDirFdAnnotation,
        OutputFdAnnotation::OutputFdAnnotation,
    },
    IAuthFs::IAuthFs,
    IAuthFsService::IAuthFsService,
};
use authfs_aidl_interface::binder::{ParcelFileDescriptor, Strong};
use compos_aidl_interface::aidl::com::android::compos::FdAnnotation::FdAnnotation;

const FD_SERVER_PORT: i32 = 3264; // TODO: support dynamic port

/// The number that represents the file descriptor number expecting by the task. The number may be
/// meaningless in the current process.
pub type PseudoRawFd = i32;

pub enum CompilerOutput {
    /// Fs-verity digests of output files, if the compiler finishes successfully.
    Digests {
        oat: fsverity::Sha256Digest,
        vdex: fsverity::Sha256Digest,
        image: fsverity::Sha256Digest,
    },
    /// Exit code returned by the compiler, if not 0.
    ExitCode(i8),
}

struct CompilerOutputParcelFds {
    oat: ParcelFileDescriptor,
    vdex: ParcelFileDescriptor,
    image: ParcelFileDescriptor,
}

pub fn odrefresh(
    odrefresh_path: &Path,
    system_dir_fd: i32,
    output_dir_fd: i32,
    zygote_arch: &str,
    authfs_service: Strong<dyn IAuthFsService>,
) -> Result<CompilerOutput> {
    // Mount authfs (via authfs_service). The authfs instance unmounts once the `authfs` variable
    // is out of scope.
    let authfs_config = AuthFsConfig {
        port: FD_SERVER_PORT,
        inputDirFdAnnotations: vec![InputDirFdAnnotation {
            fd: system_dir_fd,
            // TODO(206869687): Replace /dev/null with the real path when possible.
            manifestPath: "/dev/null".to_string(),
            prefix: "/system".to_string(),
        }],
        outputDirFdAnnotations: vec![OutputDirFdAnnotation { fd: output_dir_fd }],
        ..Default::default()
    };
    let authfs = authfs_service.mount(&authfs_config)?;
    let mountpoint = PathBuf::from(authfs.getMountPoint()?);

    let mut android_root = mountpoint.clone();
    android_root.push(system_dir_fd.to_string());
    android_root.push("system");
    env::set_var("ANDROID_ROOT", &android_root);

    let mut staging_dir = mountpoint;
    staging_dir.push(output_dir_fd.to_string());
    staging_dir.push("staging");
    create_dir(&staging_dir).context("Create staging directory")?;

    let args = vec![
        "odrefresh".to_string(),
        format!("--zygote-arch={}", zygote_arch),
        format!("--staging-dir={}", staging_dir.display()),
        "--force-compile".to_string(),
    ];
    let jail = spawn_jailed_task(odrefresh_path, &args, Vec::new() /* fd_mapping */)
        .context("Spawn odrefresh")?;
    match jail.wait() {
        // TODO(161471326): On success, sign all files in the output directory.
        Ok(()) => Ok(CompilerOutput::ExitCode(0)),
        Err(minijail::Error::ReturnCode(exit_code)) => {
            error!("dex2oat failed with exit code {}", exit_code);
            Ok(CompilerOutput::ExitCode(exit_code as i8))
        }
        Err(e) => {
            bail!("Unexpected minijail error: {}", e)
        }
    }
}

/// Runs the compiler with given flags with file descriptors described in `fd_annotation` retrieved
/// via `authfs_service`. Returns exit code of the compiler process.
pub fn compile_cmd(
    compiler_path: &Path,
    compiler_args: &[String],
    authfs_service: Strong<dyn IAuthFsService>,
    fd_annotation: &FdAnnotation,
) -> Result<CompilerOutput> {
    // Mount authfs (via authfs_service). The authfs instance unmounts once the `authfs` variable
    // is out of scope.
    let authfs_config = build_authfs_config(fd_annotation);
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

    let parcel_fds = parse_compiler_args(&authfs, compiler_args)?;
    let oat_file: &File = parcel_fds.oat.as_ref();
    let vdex_file: &File = parcel_fds.vdex.as_ref();
    let image_file: &File = parcel_fds.image.as_ref();

    match jail_result {
        Ok(()) => Ok(CompilerOutput::Digests {
            oat: fsverity::measure(oat_file.as_raw_fd())?,
            vdex: fsverity::measure(vdex_file.as_raw_fd())?,
            image: fsverity::measure(image_file.as_raw_fd())?,
        }),
        Err(minijail::Error::ReturnCode(exit_code)) => {
            error!("dex2oat failed with exit code {}", exit_code);
            Ok(CompilerOutput::ExitCode(exit_code as i8))
        }
        Err(e) => {
            bail!("Unexpected minijail error: {}", e)
        }
    }
}

fn parse_compiler_args(
    authfs: &Strong<dyn IAuthFs>,
    args: &[String],
) -> Result<CompilerOutputParcelFds> {
    const OAT_FD_PREFIX: &str = "--oat-fd=";
    const VDEX_FD_PREFIX: &str = "--output-vdex-fd=";
    const IMAGE_FD_PREFIX: &str = "--image-fd=";
    const APP_IMAGE_FD_PREFIX: &str = "--app-image-fd=";

    let mut oat = None;
    let mut vdex = None;
    let mut image = None;

    for arg in args {
        if let Some(value) = arg.strip_prefix(OAT_FD_PREFIX) {
            let fd = value.parse::<RawFd>().context("Invalid --oat-fd flag")?;
            debug_assert!(oat.is_none());
            oat = Some(authfs.openFile(fd, false)?);
        } else if let Some(value) = arg.strip_prefix(VDEX_FD_PREFIX) {
            let fd = value.parse::<RawFd>().context("Invalid --output-vdex-fd flag")?;
            debug_assert!(vdex.is_none());
            vdex = Some(authfs.openFile(fd, false)?);
        } else if let Some(value) = arg.strip_prefix(IMAGE_FD_PREFIX) {
            let fd = value.parse::<RawFd>().context("Invalid --image-fd flag")?;
            debug_assert!(image.is_none());
            image = Some(authfs.openFile(fd, false)?);
        } else if let Some(value) = arg.strip_prefix(APP_IMAGE_FD_PREFIX) {
            let fd = value.parse::<RawFd>().context("Invalid --app-image-fd flag")?;
            debug_assert!(image.is_none());
            image = Some(authfs.openFile(fd, false)?);
        }
    }

    Ok(CompilerOutputParcelFds {
        oat: oat.ok_or_else(|| anyhow!("Missing --oat-fd"))?,
        vdex: vdex.ok_or_else(|| anyhow!("Missing --vdex-fd"))?,
        image: image.ok_or_else(|| anyhow!("Missing --image-fd or --app-image-fd"))?,
    })
}

fn build_authfs_config(fd_annotation: &FdAnnotation) -> AuthFsConfig {
    AuthFsConfig {
        port: FD_SERVER_PORT,
        inputFdAnnotations: fd_annotation
            .input_fds
            .iter()
            .map(|fd| InputFdAnnotation { fd: *fd })
            .collect(),
        outputFdAnnotations: fd_annotation
            .output_fds
            .iter()
            .map(|fd| OutputFdAnnotation { fd: *fd })
            .collect(),
        ..Default::default()
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
