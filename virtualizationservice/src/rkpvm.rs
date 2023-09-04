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

//! Handles the RKP (Remote Key Provisioning) VM and host communication.
//! The RKP VM will be recognized and attested by the RKP server periodically and
//! serves as a trusted platform to attest a client VM.

use crate::service_vm;
use anyhow::{anyhow, Result};
use log::info;
use std::time::Duration;

pub(crate) fn request_certificate(csr: &[u8]) -> Result<Vec<u8>> {
    let vm = service_vm::start()?;

    // TODO(b/274441673): The host can send the CSR to the RKP VM for attestation.
    // Wait for VM to finish.
    vm.wait_for_death_with_timeout(Duration::from_secs(10))
        .ok_or_else(|| anyhow!("Timed out waiting for VM exit"))?;

    info!("service_vm: Finished getting the certificate");
    Ok([b"Return: ", csr].concat())
}
