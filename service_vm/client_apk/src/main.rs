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
use vm_payload_bindgen::AVmPayload_requestCertificate;

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
    let csr = b"Hello from Service VM";
    let certificate = request_certificate(csr);
    info!("Certificate: {:?}", certificate);
    Ok(())
}

fn request_certificate(csr: &[u8]) -> Vec<u8> {
    // SAFETY: It is safe as we only request the size of the certificate in this call.
    let certificate_size = unsafe {
        AVmPayload_requestCertificate(csr.as_ptr() as *const c_void, csr.len(), [].as_mut_ptr(), 0)
    };
    let mut certificate = vec![0u8; certificate_size];
    // SAFETY: It is safe as we only write the data into the given buffer within the buffer
    // size in this call.
    unsafe {
        AVmPayload_requestCertificate(
            csr.as_ptr() as *const c_void,
            csr.len(),
            certificate.as_mut_ptr() as *mut c_void,
            certificate.len(),
        );
    };
    certificate
}
