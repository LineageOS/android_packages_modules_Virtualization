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

//! Common utility functions.

use avb::{IoError, IoResult};

pub(crate) fn is_not_null<T>(ptr: *const T) -> IoResult<()> {
    if ptr.is_null() {
        Err(IoError::NoSuchValue)
    } else {
        Ok(())
    }
}

pub(crate) fn to_usize<T: TryInto<usize>>(num: T) -> IoResult<usize> {
    num.try_into().map_err(|_| IoError::InvalidValueSize)
}

pub(crate) fn usize_checked_add(x: usize, y: usize) -> IoResult<usize> {
    x.checked_add(y).ok_or(IoError::InvalidValueSize)
}
