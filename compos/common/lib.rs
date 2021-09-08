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

//! Common items used by CompOS server and/or clients

pub mod compos_client;

/// VSock port that the CompOS server listens on for RPC binder connections. This should be out of
/// future port range (if happens) that microdroid may reserve for system components.
pub const COMPOS_VSOCK_PORT: u32 = 6432;

/// The root directory where the CompOS APEX is mounted (read only).
pub const COMPOS_APEX_ROOT: &str = "/apex/com.android.compos";

/// The root of the  data directory available for private use by the CompOS APEX.
pub const COMPOS_DATA_ROOT: &str = "/data/misc/apexdata/com.android.compos";
