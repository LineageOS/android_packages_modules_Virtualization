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

//! A tool to verify whether a CompOS instance image and key pair are valid. It starts a CompOS VM
//! as part of this. The tool is intended to be run by odsign during boot.

use anyhow::{bail, Context, Result};
use compos_aidl_interface::binder::ProcessState;
use compos_common::compos_client::{VmInstance, VmParameters};
use compos_common::{
    COMPOS_DATA_ROOT, CURRENT_INSTANCE_DIR, IDSIG_FILE, IDSIG_MANIFEST_APK_FILE,
    INSTANCE_IMAGE_FILE, PENDING_INSTANCE_DIR, PRIVATE_KEY_BLOB_FILE, PUBLIC_KEY_FILE,
    TEST_INSTANCE_DIR,
};
use std::fs::{self, File};
use std::io::Read;
use std::panic;
use std::path::{Path, PathBuf};

const MAX_FILE_SIZE_BYTES: u64 = 8 * 1024;

fn main() {
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("compos_verify_key")
            .with_min_level(log::Level::Info),
    );

    // Redirect panic messages to logcat.
    panic::set_hook(Box::new(|panic_info| {
        log::error!("{}", panic_info);
    }));

    if let Err(e) = try_main() {
        log::error!("{:?}", e);
        std::process::exit(-1)
    }
}

fn try_main() -> Result<()> {
    let matches = clap::App::new("compos_verify_key")
        .arg(
            clap::Arg::with_name("instance")
                .long("instance")
                .takes_value(true)
                .required(true)
                .possible_values(&["pending", "current", "test"]),
        )
        .arg(clap::Arg::with_name("debug").long("debug"))
        .get_matches();

    let debug_mode = matches.is_present("debug");
    let (promote_if_valid, instance_dir) = match matches.value_of("instance").unwrap() {
        "pending" => (true, PENDING_INSTANCE_DIR),
        "current" => (false, CURRENT_INSTANCE_DIR),
        "test" => (false, TEST_INSTANCE_DIR),
        _ => unreachable!("Unexpected instance name"),
    };

    let instance_dir: PathBuf = [COMPOS_DATA_ROOT, instance_dir].iter().collect();

    if !instance_dir.is_dir() {
        bail!("{:?} is not a directory", instance_dir);
    }

    // We need to start the thread pool to be able to receive Binder callbacks
    ProcessState::start_thread_pool();

    let result = verify(debug_mode, &instance_dir).and_then(|_| {
        log::info!("Verified {:?}", instance_dir);
        if promote_if_valid {
            // If the instance is ok, then it must actually match the current system state,
            // so we promote it to current.
            log::info!("Promoting to current");
            promote_to_current(&instance_dir)
        } else {
            Ok(())
        }
    });

    if result.is_err() {
        // This is best efforts, and we still want to report the original error as our result
        log::info!("Removing {:?}", instance_dir);
        if let Err(e) = fs::remove_dir_all(&instance_dir) {
            log::warn!("Failed to remove directory: {}", e);
        }
    }

    result
}

fn verify(debug_mode: bool, instance_dir: &Path) -> Result<()> {
    let blob = instance_dir.join(PRIVATE_KEY_BLOB_FILE);
    let public_key = instance_dir.join(PUBLIC_KEY_FILE);
    let instance_image = instance_dir.join(INSTANCE_IMAGE_FILE);
    let idsig = instance_dir.join(IDSIG_FILE);
    let idsig_manifest_apk = instance_dir.join(IDSIG_MANIFEST_APK_FILE);

    let blob = read_small_file(blob).context("Failed to read key blob")?;
    let public_key = read_small_file(public_key).context("Failed to read public key")?;
    let instance_image = File::open(instance_image).context("Failed to open instance image")?;

    let virtualization_service = VmInstance::connect_to_virtualization_service()?;
    let vm_instance = VmInstance::start(
        &*virtualization_service,
        instance_image,
        &idsig,
        &idsig_manifest_apk,
        &VmParameters { debug_mode, ..Default::default() },
    )?;
    let service = vm_instance.get_service()?;

    let result = service.verifySigningKey(&blob, &public_key).context("Verifying signing key")?;

    if !result {
        bail!("Key files are not valid");
    }

    Ok(())
}

fn promote_to_current(instance_dir: &Path) -> Result<()> {
    let current_dir: PathBuf = [COMPOS_DATA_ROOT, CURRENT_INSTANCE_DIR].iter().collect();

    // This may fail if the directory doesn't exist - which is fine, we only care about the rename
    // succeeding.
    let _ = fs::remove_dir_all(&current_dir);

    fs::rename(&instance_dir, &current_dir).context("Unable to promote instance to current")?;
    Ok(())
}

fn read_small_file(file: PathBuf) -> Result<Vec<u8>> {
    let mut file = File::open(file)?;
    if file.metadata()?.len() > MAX_FILE_SIZE_BYTES {
        bail!("File is too big");
    }
    let mut data = vec![];
    file.read_to_end(&mut data)?;
    Ok(data)
}
