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

use super::DeathReason;
use android_system_virtualizationservice::binder::StatusCode;
use thiserror::Error;

/// An error while waiting for a VM to do something.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum VmWaitError {
    /// Timed out waiting for the VM.
    #[error("Timed out waiting for VM.")]
    TimedOut,
    /// The VM died before it was ready.
    #[error("VM died. ({reason})")]
    Died {
        /// The reason why the VM died.
        reason: DeathReason,
    },
    /// The VM payload finished before becoming ready.
    #[error("VM payload finished.")]
    Finished,
}

/// An error connecting to a VM RPC Binder service.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConnectServiceError {
    /// The RPC binder connection failed.
    #[error("Vsock connection to RPC binder failed.")]
    ConnectionFailed,
    /// The AIDL service type didn't match.
    #[error("Service type didn't match ({0}).")]
    WrongServiceType(StatusCode),
}
