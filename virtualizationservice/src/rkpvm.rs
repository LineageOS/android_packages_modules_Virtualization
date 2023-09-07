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

use anyhow::{bail, Context, Result};
use service_vm_comm::{Request, Response};
use service_vm_manager::ServiceVm;

pub(crate) fn request_certificate(csr: &[u8]) -> Result<Vec<u8>> {
    let mut vm = ServiceVm::start()?;

    // TODO(b/271275206): Send the correct request type with client VM's
    // information to be attested.
    let request = Request::Reverse(csr.to_vec());
    match vm.process_request(&request).context("Failed to process request")? {
        Response::Reverse(cert) => Ok(cert),
        _ => bail!("Incorrect response type"),
    }
}
