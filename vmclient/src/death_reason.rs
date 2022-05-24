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

use std::fmt::{self, Debug, Display, Formatter};
use android_system_virtualizationservice::{
        aidl::android::system::virtualizationservice::{
            DeathReason::DeathReason as AidlDeathReason}};

/// The reason why a VM died.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeathReason {
    /// VirtualizationService died.
    VirtualizationServiceDied,
    /// There was an error waiting for the VM.
    InfrastructureError,
    /// The VM was killed.
    Killed,
    /// The VM died for an unknown reason.
    Unknown,
    /// The VM requested to shut down.
    Shutdown,
    /// crosvm had an error starting the VM.
    Error,
    /// The VM requested to reboot, possibly as the result of a kernel panic.
    Reboot,
    /// The VM or crosvm crashed.
    Crash,
    /// The pVM firmware failed to verify the VM because the public key doesn't match.
    PvmFirmwarePublicKeyMismatch,
    /// The pVM firmware failed to verify the VM because the instance image changed.
    PvmFirmwareInstanceImageChanged,
    /// The bootloader failed to verify the VM because the public key doesn't match.
    BootloaderPublicKeyMismatch,
    /// The bootloader failed to verify the VM because the instance image changed.
    BootloaderInstanceImageChanged,
    /// VirtualizationService sent a death reason which was not recognised by the client library.
    Unrecognised(AidlDeathReason),
}

impl From<AidlDeathReason> for DeathReason {
    fn from(reason: AidlDeathReason) -> Self {
        match reason {
            AidlDeathReason::INFRASTRUCTURE_ERROR => Self::InfrastructureError,
            AidlDeathReason::KILLED => Self::Killed,
            AidlDeathReason::UNKNOWN => Self::Unknown,
            AidlDeathReason::SHUTDOWN => Self::Shutdown,
            AidlDeathReason::ERROR => Self::Error,
            AidlDeathReason::REBOOT => Self::Reboot,
            AidlDeathReason::CRASH => Self::Crash,
            AidlDeathReason::PVM_FIRMWARE_PUBLIC_KEY_MISMATCH => Self::PvmFirmwarePublicKeyMismatch,
            AidlDeathReason::PVM_FIRMWARE_INSTANCE_IMAGE_CHANGED => {
                Self::PvmFirmwareInstanceImageChanged
            }
            AidlDeathReason::BOOTLOADER_PUBLIC_KEY_MISMATCH => Self::BootloaderPublicKeyMismatch,
            AidlDeathReason::BOOTLOADER_INSTANCE_IMAGE_CHANGED => {
                Self::BootloaderInstanceImageChanged
            }
            _ => Self::Unrecognised(reason),
        }
    }
}

impl Display for DeathReason {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let s = match self {
            Self::VirtualizationServiceDied => "VirtualizationService died.",
            Self::InfrastructureError => "Error waiting for VM to finish.",
            Self::Killed => "VM was killed.",
            Self::Unknown => "VM died for an unknown reason.",
            Self::Shutdown => "VM shutdown cleanly.",
            Self::Error => "Error starting VM.",
            Self::Reboot => "VM tried to reboot, possibly due to a kernel panic.",
            Self::Crash => "VM crashed.",
            Self::PvmFirmwarePublicKeyMismatch => {
                "pVM firmware failed to verify the VM because the public key doesn't match."
            }
            Self::PvmFirmwareInstanceImageChanged => {
                "pVM firmware failed to verify the VM because the instance image changed."
            }
            Self::BootloaderPublicKeyMismatch => {
                "Bootloader failed to verify the VM because the public key doesn't match."
            }
            Self::BootloaderInstanceImageChanged => {
                "Bootloader failed to verify the VM because the instance image changed."
            }
            Self::Unrecognised(reason) => {
                return write!(f, "Unrecognised death reason {:?}.", reason);
            }
        };
        f.write_str(s)
    }
}
