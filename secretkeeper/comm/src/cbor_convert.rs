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

//! Implements various useful CBOR conversion method.

use crate::data_types::error::Error;
use alloc::vec::Vec;
use ciborium::Value;

/// Decodes the provided binary CBOR-encoded value and returns a
/// [`ciborium::Value`] struct wrapped in Result.
pub fn value_from_bytes(mut bytes: &[u8]) -> Result<Value, Error> {
    let value = ciborium::de::from_reader(&mut bytes).map_err(|_| Error::ConversionError)?;
    // Ciborium tries to read one Value, but doesn't care if there is trailing data after it. We do
    if !bytes.is_empty() {
        return Err(Error::ConversionError);
    }
    Ok(value)
}

/// Encodes a [`ciborium::Value`] into bytes.
pub fn value_to_bytes(value: &Value) -> Result<Vec<u8>, Error> {
    let mut bytes: Vec<u8> = Vec::new();
    ciborium::ser::into_writer(&value, &mut bytes).map_err(|_| Error::UnexpectedError)?;
    Ok(bytes)
}

// Useful to convert [`ciborium::Value`] to integer, we return largest integer range for
// convenience, callers should downcast into appropriate type.
pub fn value_to_integer(value: &Value) -> Result<i128, Error> {
    let num = value.as_integer().ok_or(Error::ConversionError)?.into();
    Ok(num)
}
