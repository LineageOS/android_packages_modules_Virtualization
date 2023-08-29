// Copyright 2022, The Android Open Source Project
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

//! This module contains the error thrown by the payload verification API
//! and other errors used in the library.

use core::fmt;

/// Wrapper around `avb::SlotVerifyError` to add custom pvmfw errors.
/// It is the error thrown by the payload verification API `verify_payload()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PvmfwVerifyError {
    /// Passthrough avb::SlotVerifyError.
    AvbError(avb::SlotVerifyError),
    /// VBMeta has invalid descriptors.
    InvalidDescriptors(avb::IoError),
    /// Unknown vbmeta property.
    UnknownVbmetaProperty,
}

/// It's always possible to convert from an `avb::SlotVerifyError` since we are
/// a superset.
impl From<avb::SlotVerifyError> for PvmfwVerifyError {
    fn from(error: avb::SlotVerifyError) -> Self {
        Self::AvbError(error)
    }
}

impl fmt::Display for PvmfwVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::AvbError(e) => write!(f, "{}", e),
            Self::InvalidDescriptors(e) => {
                write!(f, "VBMeta has invalid descriptors. Error: {:?}", e)
            }
            Self::UnknownVbmetaProperty => write!(f, "Unknown vbmeta property"),
        }
    }
}
