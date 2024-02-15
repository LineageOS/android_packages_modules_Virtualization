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

//! Functions for VM reference DT

use anyhow::{anyhow, Result};
use cstr::cstr;
use fsfdt::FsFdt;
use libfdt::Fdt;
use std::fs;
use std::fs::File;
use std::path::Path;

const VM_REFERENCE_DT_ON_HOST_PATH: &str = "/proc/device-tree/avf/reference";
const VM_REFERENCE_DT_NAME: &str = "vm_reference_dt.dtbo";
const VM_REFERENCE_DT_MAX_SIZE: usize = 2000;

// Parses to VM reference if exists.
// TODO(b/318431695): Allow to parse from custom VM reference DT
pub(crate) fn parse_reference_dt(out_dir: &Path) -> Result<Option<File>> {
    parse_reference_dt_internal(
        Path::new(VM_REFERENCE_DT_ON_HOST_PATH),
        &out_dir.join(VM_REFERENCE_DT_NAME),
    )
}

fn parse_reference_dt_internal(dir_path: &Path, fdt_path: &Path) -> Result<Option<File>> {
    if !dir_path.exists() || fs::read_dir(dir_path)?.next().is_none() {
        return Ok(None);
    }

    let mut data = vec![0_u8; VM_REFERENCE_DT_MAX_SIZE];

    let fdt = Fdt::create_empty_tree(&mut data)
        .map_err(|e| anyhow!("Failed to create an empty DT, {e:?}"))?;
    let mut root = fdt.root_mut().map_err(|e| anyhow!("Failed to find the DT root, {e:?}"))?;
    let mut fragment = root
        .add_subnode(cstr!("fragment@0"))
        .map_err(|e| anyhow!("Failed to create the fragment@0, {e:?}"))?;
    fragment
        .setprop(cstr!("target-path"), b"/\0")
        .map_err(|e| anyhow!("Failed to set target-path, {e:?}"))?;
    fragment
        .add_subnode(cstr!("__overlay__"))
        .map_err(|e| anyhow!("Failed to create the __overlay__, {e:?}"))?;

    fdt.overlay_onto(cstr!("/fragment@0/__overlay__"), dir_path)?;

    fdt.pack().map_err(|e| anyhow!("Failed to pack VM reference DT, {e:?}"))?;
    fs::write(fdt_path, fdt.as_slice())?;

    Ok(Some(File::open(fdt_path)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_reference_dt_from_empty_dir() {
        let empty_dir = tempfile::TempDir::new().unwrap();
        let test_dir = tempfile::TempDir::new().unwrap();

        let empty_dir_path = empty_dir.path();
        let fdt_path = test_dir.path().join("test.dtb");

        let fdt_file = parse_reference_dt_internal(empty_dir_path, &fdt_path).unwrap();

        assert!(fdt_file.is_none());
    }

    #[test]
    fn test_parse_reference_dt_from_empty_reference() {
        let fdt_file = parse_reference_dt_internal(
            Path::new("/this/path/would/not/exists"),
            Path::new("test.dtb"),
        )
        .unwrap();

        assert!(fdt_file.is_none());
    }
}
