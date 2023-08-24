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

//! This module contains the requests and responses definitions exchanged
//! between the host and the service VM.

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

/// Represents a request to be sent to the service VM.
///
/// Each request has a corresponding response item.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Request {
    /// Reverse the order of the bytes in the provided byte array.
    /// Currently this is only used for testing.
    Reverse(Vec<u8>),
}

/// Represents a response to a request sent to the service VM.
///
/// Each response corresponds to a specific request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    /// Reverse the order of the bytes in the provided byte array.
    Reverse(Vec<u8>),
}
