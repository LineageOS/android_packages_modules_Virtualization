/*
 * Copyright (C) 2021 The Android Open Source Project
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

//! Verifies APK/APEX signing with v2/v3 scheme

mod algorithms;
mod bytes_ext;
mod sigutil;
#[allow(dead_code)]
pub mod testing;
mod v3;
mod ziputil;

// TODO(jooyung) fallback to v2 when v3 not found
pub use v3::{get_public_key_der, pick_v4_apk_digest, verify};
