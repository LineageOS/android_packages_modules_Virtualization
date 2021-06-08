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

// `loopdevice` module provides `attach` and `detach` functions that are for attaching and
// detaching a regular file to and from a loop device. Note that
// `loopdev`(https://crates.io/crates/loopdev) is a public alternative to this. In-house
// implementation was chosen to make Android-specific changes (like the use of the new
// LOOP_CONFIGURE instead of the legacy LOOP_SET_FD + LOOP_SET_STATUS64 combo which is considerably
// slower than the former).

mod sys;

use anyhow::{Context, Result};
use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use crate::loopdevice::sys::*;
use crate::util::*;

// These are old-style ioctls, thus *_bad.
nix::ioctl_none_bad!(_loop_ctl_get_free, LOOP_CTL_GET_FREE);
nix::ioctl_write_ptr_bad!(_loop_configure, LOOP_CONFIGURE, loop_config);
#[cfg(test)]
nix::ioctl_none_bad!(_loop_clr_fd, LOOP_CLR_FD);

fn loop_ctl_get_free(ctrl_file: &File) -> Result<i32> {
    // SAFETY: this ioctl changes the state in kernel, but not the state in this process.
    // The returned device number is a global resource; not tied to this process. So, we don't
    // need to keep track of it.
    Ok(unsafe { _loop_ctl_get_free(ctrl_file.as_raw_fd()) }?)
}

fn loop_configure(device_file: &File, config: &loop_config) -> Result<i32> {
    // SAFETY: this ioctl changes the state in kernel, but not the state in this process.
    Ok(unsafe { _loop_configure(device_file.as_raw_fd(), config) }?)
}

#[cfg(test)]
fn loop_clr_fd(device_file: &File) -> Result<i32> {
    // SAFETY: this ioctl disassociates the loop device with `device_file`, where the FD will
    // remain opened afterward. The association itself is kept for open FDs.
    Ok(unsafe { _loop_clr_fd(device_file.as_raw_fd()) }?)
}

/// Creates a loop device and attach the given file at `path` as the backing store.
pub fn attach<P: AsRef<Path>>(path: P, offset: u64, size_limit: u64) -> Result<PathBuf> {
    // Attaching a file to a loop device can make a race condition; a loop device number obtained
    // from LOOP_CTL_GET_FREE might have been used by another thread or process. In that case the
    // subsequet LOOP_CONFIGURE ioctl returns with EBUSY. Try until it succeeds.
    //
    // Note that the timing parameters below are chosen rather arbitrarily. In practice (i.e.
    // inside Microdroid) we can't experience the race condition because `apkverity` is the only
    // user of /dev/loop-control at the moment. This loop is mostly for testing where multiple
    // tests run concurrently.
    const TIMEOUT: Duration = Duration::from_secs(1);
    const INTERVAL: Duration = Duration::from_millis(10);

    let begin = Instant::now();
    loop {
        match try_attach(&path, offset, size_limit) {
            Ok(loop_dev) => return Ok(loop_dev),
            Err(e) => {
                if begin.elapsed() > TIMEOUT {
                    return Err(e);
                }
            }
        };
        thread::sleep(INTERVAL);
    }
}

#[cfg(not(target_os = "android"))]
const LOOP_DEV_PREFIX: &str = "/dev/loop";

#[cfg(target_os = "android")]
const LOOP_DEV_PREFIX: &str = "/dev/block/loop";

fn try_attach<P: AsRef<Path>>(path: P, offset: u64, size_limit: u64) -> Result<PathBuf> {
    // Get a free loop device
    wait_for_path(LOOP_CONTROL)?;
    let ctrl_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(LOOP_CONTROL)
        .context("Failed to open loop control")?;
    let num = loop_ctl_get_free(&ctrl_file).context("Failed to get free loop device")?;

    // Construct the loop_config struct
    let backing_file = OpenOptions::new()
        .read(true)
        .open(&path)
        .context(format!("failed to open {:?}", path.as_ref()))?;
    // SAFETY: zero initialized C structs is safe
    let mut config = unsafe { std::mem::MaybeUninit::<loop_config>::zeroed().assume_init() };
    config.fd = backing_file.as_raw_fd() as u32;
    config.block_size = 4096;
    config.info.lo_offset = offset;
    config.info.lo_sizelimit = size_limit;
    config.info.lo_flags |= Flag::LO_FLAGS_DIRECT_IO | Flag::LO_FLAGS_READ_ONLY;

    // Special case: don't use direct IO when the backing file is already a loop device, which
    // happens only during test. DirectIO-on-loop-over-loop makes the outer loop device
    // unaccessible.
    #[cfg(test)]
    if path.as_ref().to_str().unwrap().starts_with(LOOP_DEV_PREFIX) {
        config.info.lo_flags.remove(Flag::LO_FLAGS_DIRECT_IO);
    }

    // Configure the loop device to attach the backing file
    let device_path = format!("{}{}", LOOP_DEV_PREFIX, num);
    wait_for_path(&device_path)?;
    let device_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&device_path)
        .context(format!("failed to open {:?}", &device_path))?;
    loop_configure(&device_file, &config)
        .context(format!("Failed to configure {:?}", &device_path))?;

    Ok(PathBuf::from(device_path))
}

/// Detaches backing file from the loop device `path`.
#[cfg(test)]
pub fn detach<P: AsRef<Path>>(path: P) -> Result<()> {
    let device_file = OpenOptions::new().read(true).write(true).open(&path)?;
    loop_clr_fd(&device_file)?;
    Ok(())
}
