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

//! MicrodroidSignature from /dev/block/by-name/signature
//! TODO(jooyung): migrate to "metadata" partition

use log::info;
use microdroid_signature::microdroid_signature::MicrodroidSignature;
use protobuf::Message;
use std::fs::File;
use std::io;
use std::io::Read;

const SIGNATURE_PATH: &str = "/dev/block/by-name/signature";

/// loads microdroid_signature from /dev/block/by-name/signature
pub fn load() -> io::Result<MicrodroidSignature> {
    info!("loading signature...");

    let mut f = File::open(SIGNATURE_PATH)?;
    // signature partition is
    //  4 bytes : size(N) in big endian
    //  N bytes : message for MicrodroidSignature
    let mut buf = [0u8; 4];
    f.read_exact(&mut buf)?;
    let size = i32::from_be_bytes(buf);

    Ok(MicrodroidSignature::parse_from_reader(&mut f.take(size as u64))?)
}
