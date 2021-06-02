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

//! VM Payload Config

use log::info;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VmPayloadConfig {
    #[serde(default)]
    pub task: Option<Task>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Task {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
}

impl VmPayloadConfig {
    pub fn load_from(path: &str) -> io::Result<VmPayloadConfig> {
        info!("loading config from {}...", path);
        let file = File::open(path)?;
        Ok(serde_json::from_reader(file)?)
    }
}
