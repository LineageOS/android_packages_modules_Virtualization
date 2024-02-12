// Copyright 2024, The Android Open Source Project
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

//! This module support creating AFV related overlays, that can then be appended to DT by VM.

use anyhow::{anyhow, Result};
use cstr::cstr;
use fsfdt::FsFdt;
use libfdt::Fdt;
use std::ffi::CStr;
use std::path::Path;

pub(crate) const AVF_NODE_NAME: &CStr = cstr!("avf");
pub(crate) const UNTRUSTED_NODE_NAME: &CStr = cstr!("untrusted");
pub(crate) const VM_REFERENCE_DT_ON_HOST_PATH: &str = "/proc/device-tree/avf/reference";
pub(crate) const VM_DT_OVERLAY_PATH: &str = "vm_dt_overlay.dtbo";
pub(crate) const VM_DT_OVERLAY_MAX_SIZE: usize = 2000;

/// Provide ways to modify the device tree.
#[derive(PartialEq, Eq)]
pub(crate) enum DtAddition<'a> {
    /// Include the device tree at given path.
    FromPath(&'a Path),
    /// Include a property in /avf/untrusted node. This node is used to specify host provided
    /// properties such as `instance-id`.
    /// pVM firmware does minimal validation of properties in this node.
    AvfUntrustedProp(&'a CStr, &'a [u8]),
}

/// Given a list of `dt_additions`, return a Device tree overlay containing those!
/// Example: with `create_device_tree_overlay(_, DtAddition::AvfUntrustedProp("instance-id", _))`
/// ```
///   {
///     fragment@0 {
///         target-path = "/";
///         __overlay__ {
///             avf {
///                 untrusted { instance-id = [0x01 0x23 .. ] }
///               }
///             };
///         };
///     };
/// };
/// ```
pub(crate) fn create_device_tree_overlay<'a>(
    buffer: &'a mut [u8],
    dt_additions: &[DtAddition],
) -> Result<&'a mut Fdt> {
    if dt_additions.is_empty() {
        return Err(anyhow!("Expected non empty list of device tree additions"));
    }

    let (additional_properties, additional_paths): (Vec<_>, _) =
        dt_additions.iter().partition(|o| matches!(o, DtAddition::AvfUntrustedProp(_, _)));

    let fdt =
        Fdt::create_empty_tree(buffer).map_err(|e| anyhow!("Failed to create empty Fdt: {e:?}"))?;
    let mut root = fdt.root_mut().map_err(|e| anyhow!("Failed to get root: {e:?}"))?;
    let mut node =
        root.add_subnode(cstr!("fragment@0")).map_err(|e| anyhow!("Failed to fragment: {e:?}"))?;
    node.setprop(cstr!("target-path"), b"/\0")
        .map_err(|e| anyhow!("Failed to set target-path: {e:?}"))?;
    let mut node = node
        .add_subnode(cstr!("__overlay__"))
        .map_err(|e| anyhow!("Failed to __overlay__ node: {e:?}"))?;

    if !additional_properties.is_empty() {
        let mut node = node
            .add_subnode(AVF_NODE_NAME)
            .map_err(|e| anyhow!("Failed to add avf node: {e:?}"))?;
        let mut node = node
            .add_subnode(UNTRUSTED_NODE_NAME)
            .map_err(|e| anyhow!("Failed to add /avf/untrusted node: {e:?}"))?;
        for prop in additional_properties {
            if let DtAddition::AvfUntrustedProp(name, value) = prop {
                node.setprop(name, value).map_err(|e| anyhow!("Failed to set property: {e:?}"))?;
            }
        }
    }

    for path in additional_paths {
        if let DtAddition::FromPath(path) = path {
            fdt.append(cstr!("/fragment@0/__overlay__"), path)?;
        }
    }
    fdt.pack().map_err(|e| anyhow!("Failed to pack DT overlay, {e:?}"))?;

    Ok(fdt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_overlays_not_allowed() {
        let mut buffer = vec![0_u8; VM_DT_OVERLAY_MAX_SIZE];
        let res = create_device_tree_overlay(&mut buffer, &[]);
        assert!(res.is_err());
    }

    #[test]
    fn untrusted_prop_test() {
        let mut buffer = vec![0_u8; VM_DT_OVERLAY_MAX_SIZE];
        let prop_name = cstr!("XOXO");
        let prop_val_input = b"OXOX";
        let fdt = create_device_tree_overlay(
            &mut buffer,
            &[DtAddition::AvfUntrustedProp(prop_name, prop_val_input)],
        )
        .unwrap();

        let prop_value_dt = fdt
            .node(cstr!("/fragment@0/__overlay__/avf/untrusted"))
            .unwrap()
            .expect("/avf/untrusted node doesn't exist")
            .getprop(prop_name)
            .unwrap()
            .expect("Prop not found!");
        assert_eq!(prop_value_dt, prop_val_input, "Unexpected property value");
    }
}
