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

//! This module contains the main API for the request processing module.

use super::rkp;
use crate::error::Result;
use alloc::vec::Vec;
use service_vm_comm::{Request, Response};

/// Processes a request and returns the corresponding response.
/// This function serves as the entry point for the request processing
/// module.
pub fn process_request(request: Request) -> Result<Response> {
    let response = match request {
        Request::Reverse(v) => Response::Reverse(reverse(v)),
        Request::GenerateEcdsaP256KeyPair => {
            let res = rkp::generate_ecdsa_p256_key_pair()?;
            Response::GenerateEcdsaP256KeyPair(res)
        }
        Request::GenerateCertificateRequest(p) => {
            let res = rkp::generate_certificate_request(p)?;
            Response::GenerateCertificateRequest(res)
        }
    };
    Ok(response)
}

fn reverse(payload: Vec<u8>) -> Vec<u8> {
    payload.into_iter().rev().collect()
}
