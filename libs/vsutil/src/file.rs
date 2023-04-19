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

//! Functions to process files.

use binder::{self, ExceptionCode, ParcelFileDescriptor, Status};
use std::fs::File;

/// Converts a `&ParcelFileDescriptor` to a `File` by cloning the file.
pub fn clone_file(fd: &ParcelFileDescriptor) -> binder::Result<File> {
    fd.as_ref().try_clone().map_err(|e| {
        Status::new_exception_str(
            ExceptionCode::BAD_PARCELABLE,
            Some(format!("Failed to clone File from ParcelFileDescriptor: {:?}", e)),
        )
    })
}
