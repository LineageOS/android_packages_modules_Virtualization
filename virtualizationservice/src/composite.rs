// Copyright 2021, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Functions for running `mk_cdisk`.

mod config;

use android_system_virtualizationservice::aidl::android::system::virtualizationservice::Partition::Partition as AidlPartition;
use anyhow::{bail, Context, Error};
use command_fds::{CommandFdExt, FdMapping};
use config::{Config, Partition};
use log::info;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::panic;
use std::path::Path;
use std::process::{Command, Stdio};
use std::str;
use std::thread;

const MK_CDISK_PATH: &str = "/apex/com.android.virt/bin/mk_cdisk";

/// Calls `mk_cdisk` to construct a composite disk image for the given list of partitions, and opens
/// it ready to use. Returns the composite disk image file, and a list of FD mappings which must be
/// applied to any process which wants to use it. This is necessary because the composite image
/// contains paths of the form `/proc/self/fd/N` for the partition images.
pub fn make_composite_image(
    partitions: &[AidlPartition],
    output_filename: &Path,
) -> Result<(File, Vec<File>), Error> {
    let (config_json, files) = make_config_json(partitions)?;
    let fd_mappings: Vec<_> = files
        .iter()
        .map(|file| FdMapping { parent_fd: file.as_raw_fd(), child_fd: file.as_raw_fd() })
        .collect();

    let mut command = Command::new(MK_CDISK_PATH);
    command
        .arg("-") // Read config JSON from stdin.
        .arg(&output_filename)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.fd_mappings(fd_mappings)?;
    let mut child = command.spawn().context("Failed to spawn mk_cdisk")?;
    let stdin = child.stdin.take().unwrap();

    // Write config to stdin of mk_cdisk on a separate thread to avoid deadlock, as it may not read
    // all of stdin before it blocks on writing to stdout.
    let writer_thread = thread::spawn(move || config_json.write_json(&stdin));
    info!("Running {:?}", command);
    let output = child.wait_with_output()?;
    match writer_thread.join() {
        Ok(result) => result?,
        Err(panic_payload) => panic::resume_unwind(panic_payload),
    }

    if !output.status.success() {
        info!("mk_cdisk stdout: {}", str::from_utf8(&output.stdout)?);
        info!("mk_cdisk stderr: {}", str::from_utf8(&output.stderr)?);
        bail!("mk_cdisk exited with error {}", output.status);
    }

    let composite_image = File::open(&output_filename)
        .with_context(|| format!("Failed to open composite image {:?}", output_filename))?;

    Ok((composite_image, files))
}

/// Given the AIDL config containing a list of partitions, with a [`ParcelFileDescriptor`] for each
/// partition, return the list of file descriptors which must be passed to the mk_cdisk child
/// process and the JSON configuration for it.
fn make_config_json(partitions: &[AidlPartition]) -> Result<(Config, Vec<File>), Error> {
    // File descriptors to pass to child process.
    let mut files = vec![];

    let partitions = partitions
        .iter()
        .map(|partition| {
            // TODO(b/187187765): This shouldn't be an Option.
            let file = partition
                .image
                .as_ref()
                .context("Invalid partition image file descriptor")?
                .as_ref()
                .try_clone()
                .context("Failed to clone partition image file descriptor")?;
            let fd = file.as_raw_fd();
            files.push(file);

            Ok(Partition {
                writable: partition.writable,
                label: partition.label.to_owned(),
                path: format!("/proc/self/fd/{}", fd).into(),
            })
        })
        .collect::<Result<_, Error>>()?;
    let config_json = Config { partitions };

    Ok((config_json, files))
}
