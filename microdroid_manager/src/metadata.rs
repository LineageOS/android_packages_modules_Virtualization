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

//! Payload metadata from /dev/block/by-name/metadata

use log::info;
use microdroid_metadata::{read_metadata, Metadata};
use std::fs::File;
use std::io;

const METADATA_PATH: &str = "/dev/block/by-name/metadata";

/// loads payload metadata from /dev/block/by-name/metadata
pub fn load() -> io::Result<Metadata> {
    info!("loading payload metadata...");
    read_metadata(File::open(METADATA_PATH)?)
}
