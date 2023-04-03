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

//! Support for the debug policy overlay in pvmfw

use core::fmt;
use libfdt::FdtError;

#[derive(Debug, Clone)]
pub enum DebugPolicyError {
    /// The provided baseline FDT was invalid or malformed, so cannot access certain node/prop
    Fdt(&'static str, FdtError),
    /// The provided debug policy FDT was invalid or malformed.
    DebugPolicyFdt(&'static str, FdtError),
    /// The overlaid result FDT is invalid or malformed, and may be corrupted.
    OverlaidFdt(&'static str, FdtError),
}

impl fmt::Display for DebugPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Fdt(s, e) => write!(f, "Invalid baseline FDT. {s}: {e}"),
            Self::DebugPolicyFdt(s, e) => write!(f, "Invalid overlay FDT. {s}: {e}"),
            Self::OverlaidFdt(s, e) => write!(f, "Invalid overlaid FDT. {s}: {e}"),
        }
    }
}

/// Applies the debug policy device tree overlay to the pVM DT.
///
/// # Safety
///
/// When an error is returned by this function, the input `Fdt` should be
/// discarded as it may have have been partially corrupted during the overlay
/// application process.
unsafe fn apply_debug_policy(
    fdt: &mut libfdt::Fdt,
    debug_policy: &mut [u8],
) -> Result<(), DebugPolicyError> {
    let overlay = libfdt::Fdt::from_mut_slice(debug_policy)
        .map_err(|e| DebugPolicyError::DebugPolicyFdt("Failed to load debug policy overlay", e))?;

    fdt.unpack().map_err(|e| DebugPolicyError::Fdt("Failed to unpack", e))?;

    let fdt = fdt
        .apply_overlay(overlay)
        .map_err(|e| DebugPolicyError::DebugPolicyFdt("Failed to apply overlay", e))?;

    fdt.pack().map_err(|e| DebugPolicyError::OverlaidFdt("Failed to re-pack", e))
}

/// Handles debug policies.
///
/// # Safety
///
/// This may corrupt the input `Fdt` when overlaying debug policy or applying
/// ramdump configuration.
pub unsafe fn handle_debug_policy(
    fdt: &mut libfdt::Fdt,
    debug_policy: Option<&mut [u8]>,
) -> Result<(), DebugPolicyError> {
    if let Some(dp) = debug_policy {
        apply_debug_policy(fdt, dp)?;
    }

    Ok(())
}
