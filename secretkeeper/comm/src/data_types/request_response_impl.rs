/*
 * Copyright (C) 2023 The Android Open Source Project
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

//! Implementation of request & response like data structures.

// derive(N) generates a method that is missing a docstring.
#![allow(missing_docs)]

use crate::cbor_convert::value_to_integer;
use crate::data_types::error::Error;
use crate::data_types::error::ERROR_OK;
use crate::data_types::request::Request;
use crate::data_types::response::Response;
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use ciborium::Value;
use enumn::N;

/// Set of all possible `Opcode` supported by SecretManagement API of the HAL.
/// See `Opcode` in SecretManagement.cddl
#[derive(Clone, Copy, Debug, N, PartialEq)]
#[non_exhaustive]
pub enum Opcode {
    /// Get version of the SecretManagement API.
    GetVersion = 1,
    /// Store a secret
    StoreSecret = 2,
    /// Get the secret
    GetSecret = 3,
}

/// Corresponds to `GetVersionRequestPacket` defined in SecretManagement.cddl
#[derive(Debug, Eq, PartialEq)]
pub struct GetVersionRequest;

impl Request for GetVersionRequest {
    const OPCODE: Opcode = Opcode::GetVersion;

    fn new(args: Vec<Value>) -> Result<Box<Self>, Error> {
        if !args.is_empty() {
            return Err(Error::RequestMalformed);
        }
        Ok(Box::new(Self))
    }

    fn args(&self) -> Vec<Value> {
        Vec::new()
    }
}

/// Success response corresponding to `GetVersionResponsePacket`.
#[derive(Debug, Eq, PartialEq)]
pub struct GetVersionResponse {
    /// Version of SecretManagement API
    version: u64,
}

impl GetVersionResponse {
    pub fn new(version: u64) -> Self {
        Self { version }
    }
    pub fn version(&self) -> u64 {
        self.version
    }
}

impl Response for GetVersionResponse {
    fn new(res: Vec<Value>) -> Result<Box<Self>, Error> {
        if res.len() != 2 {
            return Err(Error::ResponseMalformed);
        }
        let error_code: u16 = value_to_integer(&res[0])?.try_into()?;
        if error_code != ERROR_OK {
            return Err(Error::ResponseMalformed);
        }
        let version: u64 = value_to_integer(&res[1])?.try_into()?;
        Ok(Box::new(Self::new(version)))
    }

    fn result(&self) -> Vec<Value> {
        vec![self.version.into()]
    }
}
