// Copyright 2021, The Android Open Source Project
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

//! JSON configuration for composite disks, as used for running `mk_cdisk` and by the `vm` tool.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Configuration for running `mk_cdisk`.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    /// The set of partitions to be assembled into a composite image.
    pub partitions: Vec<Partition>,
}

/// A partition to be assembled into a composite image.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Partition {
    /// A label for the partition.
    pub label: String,
    /// The filename of the partition image.
    pub path: PathBuf,
    /// Whether the partition should be writable.
    #[serde(default)]
    pub writable: bool,
}
