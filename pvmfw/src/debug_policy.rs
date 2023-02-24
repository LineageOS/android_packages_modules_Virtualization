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

use alloc::{vec, vec::Vec};
use core::ffi::CStr;
use core::fmt;
use libfdt::FdtError;
use log::info;

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

/// Disables ramdump by removing crashkernel from bootargs in /chosen.
fn disable_ramdump(fdt: &mut libfdt::Fdt) -> Result<(), DebugPolicyError> {
    let chosen_path = CStr::from_bytes_with_nul(b"/chosen\0").unwrap();
    let bootargs_name = CStr::from_bytes_with_nul(b"bootargs\0").unwrap();

    let chosen = match fdt
        .node(chosen_path)
        .map_err(|e| DebugPolicyError::Fdt("Failed to find /chosen", e))?
    {
        Some(node) => node,
        None => return Ok(()),
    };

    let bootargs = match chosen
        .getprop_str(bootargs_name)
        .map_err(|e| DebugPolicyError::Fdt("Failed to find bootargs prop", e))?
    {
        Some(value) if !value.to_bytes().is_empty() => value,
        _ => return Ok(()),
    };

    // TODO: Improve add 'crashkernel=17MB' only when it's unnecessary.
    //       Currently 'crashkernel=17MB' in virtualizationservice and passed by
    //       chosen node, because it's not exactly a debug policy but a
    //       configuration. However, it's actually microdroid specific
    //       so we need a way to generalize it.
    let mut args = vec![];
    for arg in bootargs.to_bytes().split(|byte| byte.is_ascii_whitespace()) {
        if arg.is_empty() || arg.starts_with(b"crashkernel=") {
            continue;
        }
        args.push(arg);
    }
    let mut new_bootargs = args.as_slice().join(&b" "[..]);
    new_bootargs.push(b'\0');

    // We've checked existence of /chosen node at the beginning.
    let mut chosen_mut = fdt.node_mut(chosen_path).unwrap().unwrap();
    chosen_mut.setprop(bootargs_name, new_bootargs.as_slice()).map_err(|e| {
        DebugPolicyError::OverlaidFdt("Failed to remove crashkernel. FDT might be corrupted", e)
    })
}

/// Returns true only if fdt has ramdump prop in the /avf/guest/common node with value <1>
fn is_ramdump_enabled(fdt: &libfdt::Fdt) -> Result<bool, DebugPolicyError> {
    let common = match fdt
        .node(CStr::from_bytes_with_nul(b"/avf/guest/common\0").unwrap())
        .map_err(|e| DebugPolicyError::DebugPolicyFdt("Failed to find /avf/guest/common node", e))?
    {
        Some(node) => node,
        None => return Ok(false),
    };

    match common
        .getprop_u32(CStr::from_bytes_with_nul(b"ramdump\0").unwrap())
        .map_err(|e| DebugPolicyError::DebugPolicyFdt("Failed to find ramdump prop", e))?
    {
        Some(1) => Ok(true),
        _ => Ok(false),
    }
}

/// Enables console output by adding kernel.printk.devkmsg and kernel.console to bootargs.
/// This uses hardcoded console name 'hvc0' and it should be match with microdroid's bootconfig.debuggable.
fn enable_console_output(fdt: &mut libfdt::Fdt) -> Result<(), DebugPolicyError> {
    let chosen_path = CStr::from_bytes_with_nul(b"/chosen\0").unwrap();
    let bootargs_name = CStr::from_bytes_with_nul(b"bootargs\0").unwrap();

    let chosen = match fdt
        .node(chosen_path)
        .map_err(|e| DebugPolicyError::Fdt("Failed to find /chosen", e))?
    {
        Some(node) => node,
        None => return Ok(()),
    };

    let bootargs = match chosen
        .getprop_str(bootargs_name)
        .map_err(|e| DebugPolicyError::Fdt("Failed to find bootargs prop", e))?
    {
        Some(value) if !value.to_bytes().is_empty() => value,
        _ => return Ok(()),
    };

    let mut new_bootargs = Vec::from(bootargs.to_bytes());
    new_bootargs.extend_from_slice(b" printk.devkmsg=on console=hvc0\0");

    // We'll set larger prop, and need to prepare some room first.
    fdt.unpack().map_err(|e| DebugPolicyError::OverlaidFdt("Failed to unpack", e))?;

    // We've checked existence of /chosen node at the beginning.
    let mut chosen_mut = fdt.node_mut(chosen_path).unwrap().unwrap();
    chosen_mut.setprop(bootargs_name, new_bootargs.as_slice()).map_err(|e| {
        DebugPolicyError::OverlaidFdt("Failed to enabled console output. FDT might be corrupted", e)
    })?;

    fdt.pack().map_err(|e| DebugPolicyError::OverlaidFdt("Failed to pack", e))?;
    Ok(())
}

/// Returns true only if fdt has log prop in the /avf/guest/common node with value <1>
fn is_console_output_enabled(fdt: &libfdt::Fdt) -> Result<bool, DebugPolicyError> {
    let common = match fdt
        .node(CStr::from_bytes_with_nul(b"/avf/guest/common\0").unwrap())
        .map_err(|e| DebugPolicyError::DebugPolicyFdt("Failed to find /avf/guest/common node", e))?
    {
        Some(node) => node,
        None => return Ok(false),
    };

    match common
        .getprop_u32(CStr::from_bytes_with_nul(b"log\0").unwrap())
        .map_err(|e| DebugPolicyError::DebugPolicyFdt("Failed to find log prop", e))?
    {
        Some(1) => Ok(true),
        _ => Ok(false),
    }
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

    // Handles ramdump in the debug policy
    if is_ramdump_enabled(fdt)? {
        info!("ramdump is enabled by debug policy");
    } else {
        disable_ramdump(fdt)?;
    }

    // Handles conseole output in the debug policy
    if is_console_output_enabled(fdt)? {
        enable_console_output(fdt)?;
        info!("console output is enabled by debug policy");
    }
    Ok(())
}
