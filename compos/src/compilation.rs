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
use log::{debug, error, info};
use minijail::{self, Minijail};
use std::env;
use std::fs::{read_dir, File};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{self, Path, PathBuf};

use crate::artifact_signer::ArtifactSigner;
use crate::compos_key_service::Signer;
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
use compos_common::odrefresh::ExitCode;

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

pub struct OdrefreshContext<'a> {
    system_dir_fd: i32,
    output_dir_fd: i32,
    staging_dir_fd: i32,
    target_dir_name: &'a str,
    zygote_arch: &'a str,
}

impl<'a> OdrefreshContext<'a> {
    pub fn new(
        system_dir_fd: i32,
        output_dir_fd: i32,
        staging_dir_fd: i32,
        target_dir_name: &'a str,
        zygote_arch: &'a str,
    ) -> Result<Self> {
        if system_dir_fd < 0 || output_dir_fd < 0 || staging_dir_fd < 0 {
            bail!("The remote FDs are expected to be non-negative");
        }
        if zygote_arch != "zygote64" && zygote_arch != "zygote64_32" {
            bail!("Invalid zygote arch");
        }
        // Disallow any sort of path traversal
        if target_dir_name.contains(path::MAIN_SEPARATOR) {
            bail!("Invalid target directory {}", target_dir_name);
        }

        Ok(Self { system_dir_fd, output_dir_fd, staging_dir_fd, target_dir_name, zygote_arch })
    }
}

pub fn odrefresh(
    odrefresh_path: &Path,
    context: OdrefreshContext,
    authfs_service: Strong<dyn IAuthFsService>,
    signer: Signer,
) -> Result<ExitCode> {
    // Mount authfs (via authfs_service). The authfs instance unmounts once the `authfs` variable
    // is out of scope.
    let authfs_config = AuthFsConfig {
        port: FD_SERVER_PORT,
        inputDirFdAnnotations: vec![InputDirFdAnnotation {
            fd: context.system_dir_fd,
            // TODO(206869687): Replace /dev/null with the real path when possible.
            manifestPath: "/dev/null".to_string(),
            prefix: "/system".to_string(),
        }],
        outputDirFdAnnotations: vec![
            OutputDirFdAnnotation { fd: context.output_dir_fd },
            OutputDirFdAnnotation { fd: context.staging_dir_fd },
        ],
        ..Default::default()
    };
    let authfs = authfs_service.mount(&authfs_config)?;
    let mountpoint = PathBuf::from(authfs.getMountPoint()?);

    let mut android_root = mountpoint.clone();
    android_root.push(context.system_dir_fd.to_string());
    android_root.push("system");
    env::set_var("ANDROID_ROOT", &android_root);
    debug!("ANDROID_ROOT={:?}", &android_root);

    let art_apex_data = mountpoint.join(context.output_dir_fd.to_string());
    env::set_var("ART_APEX_DATA", &art_apex_data);
    debug!("ART_APEX_DATA={:?}", &art_apex_data);

    let staging_dir = mountpoint.join(context.staging_dir_fd.to_string());

    let args = vec![
        "odrefresh".to_string(),
        format!("--zygote-arch={}", context.zygote_arch),
        format!("--dalvik-cache={}", context.target_dir_name),
        "--no-refresh".to_string(),
        format!("--staging-dir={}", staging_dir.display()),
        "--force-compile".to_string(),
    ];
    debug!("Running odrefresh with args: {:?}", &args);
    let jail = spawn_jailed_task(odrefresh_path, &args, Vec::new() /* fd_mapping */)
        .context("Spawn odrefresh")?;
    let exit_code = match jail.wait() {
        Ok(_) => Result::<u8>::Ok(0),
        Err(minijail::Error::ReturnCode(exit_code)) => Ok(exit_code),
        Err(e) => {
            bail!("Unexpected minijail error: {}", e)
        }
    }?;

    let exit_code = ExitCode::from_i32(exit_code.into())?;
    info!("odrefresh exited with {:?}", exit_code);

    if exit_code == ExitCode::CompilationSuccess {
        // authfs only shows us the files we created, so it's ok to just sign everything under
        // the target directory.
        let target_dir = art_apex_data.join(context.target_dir_name);
        let mut artifact_signer = ArtifactSigner::new(&target_dir);
        add_artifacts(&target_dir, &mut artifact_signer)?;

        artifact_signer.write_info_and_signature(signer, &target_dir.join("compos.info"))?;
    }

    Ok(exit_code)
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
