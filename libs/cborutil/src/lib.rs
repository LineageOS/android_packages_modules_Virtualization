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

//! Utility functions for CBOR serialization/deserialization.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use coset::{CoseError, Result};
use serde::{de::DeserializeOwned, Serialize};

/// Serializes the given data to a CBOR-encoded byte vector.
pub fn serialize<T: ?Sized + Serialize>(v: &T) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    ciborium::into_writer(v, &mut data)?;
    Ok(data)
}

/// Deserializes the given type from a CBOR-encoded byte slice, failing if any extra
/// data remains after the type has been read.
pub fn deserialize<T: DeserializeOwned>(mut data: &[u8]) -> Result<T> {
    let res = ciborium::from_reader(&mut data)?;
    if data.is_empty() {
        Ok(res)
    } else {
        Err(CoseError::ExtraneousData)
    }
}
