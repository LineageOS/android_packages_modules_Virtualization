// Copyright 2023, The Android Open Source Project
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

//! Main executable of Service VM client.

use anyhow::Result;
use log::{error, info};
use std::{ffi::c_void, panic};
use vm_payload_bindgen::AVmPayload_requestAttestation;

/// Entry point of the Service VM client.
#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn AVmPayload_main() {
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("service_vm_client")
            .with_min_level(log::Level::Debug),
    );
    // Redirect panic messages to logcat.
    panic::set_hook(Box::new(|panic_info| {
        error!("{}", panic_info);
    }));
    if let Err(e) = try_main() {
        error!("failed with {:?}", e);
        std::process::exit(1);
    }
}

fn try_main() -> Result<()> {
    info!("Welcome to Service VM Client!");
    // The data below is only a placeholder generated randomly with urandom
    let challenge = &[
        0x6c, 0xad, 0x52, 0x50, 0x15, 0xe7, 0xf4, 0x1d, 0xa5, 0x60, 0x7e, 0xd2, 0x7d, 0xf1, 0x51,
        0x67, 0xc3, 0x3e, 0x73, 0x9b, 0x30, 0xbd, 0x04, 0x20, 0x2e, 0xde, 0x3b, 0x1d, 0xc8, 0x07,
        0x11, 0x7b,
    ];
    info!("Sending challenge: {:?}", challenge);
    let certificate = request_attestation(challenge);
    info!("Certificate: {:?}", certificate);
    Ok(())
}

fn request_attestation(challenge: &[u8]) -> Vec<u8> {
    // SAFETY: It is safe as we only request the size of the certificate in this call.
    let certificate_size = unsafe {
        AVmPayload_requestAttestation(
            challenge.as_ptr() as *const c_void,
            challenge.len(),
            [].as_mut_ptr(),
            0,
        )
    };
    let mut certificate = vec![0u8; certificate_size];
    // SAFETY: It is safe as we only write the data into the given buffer within the buffer
    // size in this call.
    unsafe {
        AVmPayload_requestAttestation(
            challenge.as_ptr() as *const c_void,
            challenge.len(),
            certificate.as_mut_ptr() as *mut c_void,
            certificate.len(),
        );
    };
    certificate
}
