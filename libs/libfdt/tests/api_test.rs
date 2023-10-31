/*
 * Copyright (C) 2023 The Android Open Source Project
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

//! Integration tests of the library libfdt.

use libfdt::{Fdt, FdtError, Phandle};
use std::ffi::{CStr, CString};
use std::fs;
use std::ops::Range;

macro_rules! cstr {
    ($str:literal) => {{
        CStr::from_bytes_with_nul(concat!($str, "\0").as_bytes()).unwrap()
    }};
}

const TEST_TREE_WITH_ONE_MEMORY_RANGE_PATH: &str = "data/test_tree_one_memory_range.dtb";
const TEST_TREE_WITH_MULTIPLE_MEMORY_RANGES_PATH: &str =
    "data/test_tree_multiple_memory_ranges.dtb";
const TEST_TREE_WITH_EMPTY_MEMORY_RANGE_PATH: &str = "data/test_tree_empty_memory_range.dtb";
const TEST_TREE_WITH_NO_MEMORY_NODE_PATH: &str = "data/test_tree_no_memory_node.dtb";
const TEST_TREE_PHANDLE_PATH: &str = "data/test_tree_phandle.dtb";

#[test]
fn retrieving_memory_from_fdt_with_one_memory_range_succeeds() {
    let data = fs::read(TEST_TREE_WITH_ONE_MEMORY_RANGE_PATH).unwrap();
    let fdt = Fdt::from_slice(&data).unwrap();

    const EXPECTED_FIRST_MEMORY_RANGE: Range<usize> = 0..256;
    let mut memory = fdt.memory().unwrap();
    assert_eq!(memory.next(), Some(EXPECTED_FIRST_MEMORY_RANGE));
    assert_eq!(memory.next(), None);
    assert_eq!(fdt.first_memory_range(), Ok(EXPECTED_FIRST_MEMORY_RANGE));
}

#[test]
fn retrieving_memory_from_fdt_with_multiple_memory_ranges_succeeds() {
    let data = fs::read(TEST_TREE_WITH_MULTIPLE_MEMORY_RANGES_PATH).unwrap();
    let fdt = Fdt::from_slice(&data).unwrap();

    const EXPECTED_FIRST_MEMORY_RANGE: Range<usize> = 0..256;
    const EXPECTED_SECOND_MEMORY_RANGE: Range<usize> = 512..1024;
    let mut memory = fdt.memory().unwrap();
    assert_eq!(memory.next(), Some(EXPECTED_FIRST_MEMORY_RANGE));
    assert_eq!(memory.next(), Some(EXPECTED_SECOND_MEMORY_RANGE));
    assert_eq!(memory.next(), None);
    assert_eq!(fdt.first_memory_range(), Ok(EXPECTED_FIRST_MEMORY_RANGE));
}

#[test]
fn retrieving_first_memory_from_fdt_with_empty_memory_range_fails() {
    let data = fs::read(TEST_TREE_WITH_EMPTY_MEMORY_RANGE_PATH).unwrap();
    let fdt = Fdt::from_slice(&data).unwrap();

    let mut memory = fdt.memory().unwrap();
    assert_eq!(memory.next(), None);
    assert_eq!(fdt.first_memory_range(), Err(FdtError::NotFound));
}

#[test]
fn retrieving_memory_from_fdt_with_no_memory_node_fails() {
    let data = fs::read(TEST_TREE_WITH_NO_MEMORY_NODE_PATH).unwrap();
    let fdt = Fdt::from_slice(&data).unwrap();

    assert_eq!(fdt.memory().unwrap_err(), FdtError::NotFound);
    assert_eq!(fdt.first_memory_range(), Err(FdtError::NotFound));
}

#[test]
fn node_name() {
    let data = fs::read(TEST_TREE_WITH_NO_MEMORY_NODE_PATH).unwrap();
    let fdt = Fdt::from_slice(&data).unwrap();

    let root = fdt.root().unwrap();
    assert_eq!(root.name(), Ok(cstr!("")));

    let chosen = fdt.chosen().unwrap().unwrap();
    assert_eq!(chosen.name(), Ok(cstr!("chosen")));

    let nested_node_path = cstr!("/cpus/PowerPC,970@0");
    let nested_node = fdt.node(nested_node_path).unwrap().unwrap();
    assert_eq!(nested_node.name(), Ok(cstr!("PowerPC,970@0")));
}

#[test]
fn node_subnodes() {
    let data = fs::read(TEST_TREE_WITH_NO_MEMORY_NODE_PATH).unwrap();
    let fdt = Fdt::from_slice(&data).unwrap();
    let root = fdt.root().unwrap();
    let expected = [cstr!("cpus"), cstr!("randomnode"), cstr!("chosen")];

    for (node, name) in root.subnodes().unwrap().zip(expected) {
        assert_eq!(node.name(), Ok(name));
    }
}

#[test]
fn node_properties() {
    let data = fs::read(TEST_TREE_WITH_NO_MEMORY_NODE_PATH).unwrap();
    let fdt = Fdt::from_slice(&data).unwrap();
    let root = fdt.root().unwrap();
    let one_be = 0x1_u32.to_be_bytes();
    let expected = [
        (cstr!("model"), b"MyBoardName\0".as_ref()),
        (cstr!("compatible"), b"MyBoardName\0MyBoardFamilyName\0".as_ref()),
        (cstr!("#address-cells"), &one_be),
        (cstr!("#size-cells"), &one_be),
        (cstr!("empty_prop"), &[]),
    ];

    let properties = root.properties().unwrap();
    for (prop, (name, value)) in properties.zip(expected.into_iter()) {
        assert_eq!((prop.name(), prop.value()), (Ok(name), Ok(value)));
    }
}

#[test]
fn node_supernode_at_depth() {
    let data = fs::read(TEST_TREE_WITH_NO_MEMORY_NODE_PATH).unwrap();
    let fdt = Fdt::from_slice(&data).unwrap();
    let node = fdt.node(cstr!("/cpus/PowerPC,970@1")).unwrap().unwrap();
    let expected = [cstr!(""), cstr!("cpus"), cstr!("PowerPC,970@1")];

    for (depth, name) in expected.into_iter().enumerate() {
        let supernode = node.supernode_at_depth(depth).unwrap();
        assert_eq!(supernode.name(), Ok(name));
    }
}

#[test]
fn phandle_new() {
    let valid_phandles = [
        u32::from(Phandle::MIN),
        u32::from(Phandle::MIN).checked_add(1).unwrap(),
        0x55,
        u32::from(Phandle::MAX).checked_sub(1).unwrap(),
        u32::from(Phandle::MAX),
    ];

    for value in valid_phandles {
        let phandle = Phandle::new(value).unwrap();

        assert_eq!(value.try_into(), Ok(phandle));
        assert_eq!(u32::from(phandle), value);
    }

    let bad_phandles = [
        u32::from(Phandle::MIN).checked_sub(1).unwrap(),
        u32::from(Phandle::MAX).checked_add(1).unwrap(),
    ];

    for value in bad_phandles {
        assert_eq!(Phandle::new(value), None);
        assert_eq!(Phandle::try_from(value), Err(FdtError::BadPhandle));
    }
}

#[test]
fn max_phandle() {
    let data = fs::read(TEST_TREE_PHANDLE_PATH).unwrap();
    let fdt = Fdt::from_slice(&data).unwrap();
    let phandle = Phandle::new(0xFF).unwrap();

    assert_eq!(fdt.max_phandle(), Ok(phandle));
}

#[test]
fn node_with_phandle() {
    let data = fs::read(TEST_TREE_PHANDLE_PATH).unwrap();
    let fdt = Fdt::from_slice(&data).unwrap();

    // Test linux,phandle
    let phandle = Phandle::new(0xFF).unwrap();
    let node = fdt.node_with_phandle(phandle).unwrap().unwrap();
    assert_eq!(node.name(), Ok(cstr!("node_zz")));

    // Test phandle
    let phandle = Phandle::new(0x22).unwrap();
    let node = fdt.node_with_phandle(phandle).unwrap().unwrap();
    assert_eq!(node.name(), Ok(cstr!("node_abc")));
}

#[test]
fn node_nop() {
    let mut data = fs::read(TEST_TREE_PHANDLE_PATH).unwrap();
    let fdt = Fdt::from_mut_slice(&mut data).unwrap();
    let phandle = Phandle::new(0xFF).unwrap();
    let path = cstr!("/node_z/node_zz");

    fdt.node_with_phandle(phandle).unwrap().unwrap();
    let node = fdt.node_mut(path).unwrap().unwrap();

    node.nop().unwrap();

    assert_eq!(fdt.node_with_phandle(phandle), Ok(None));
    assert_eq!(fdt.node(path), Ok(None));

    fdt.unpack().unwrap();
    fdt.pack().unwrap();

    assert_eq!(fdt.node_with_phandle(phandle), Ok(None));
    assert_eq!(fdt.node(path), Ok(None));
}

#[test]
fn node_add_subnode_with_namelen() {
    let mut data = fs::read(TEST_TREE_PHANDLE_PATH).unwrap();
    data.resize(data.len() * 2, 0_u8);

    let fdt = Fdt::from_mut_slice(&mut data).unwrap();
    fdt.unpack().unwrap();

    let node_path = cstr!("/node_z/node_zz");
    let subnode_name = cstr!("123456789");

    for len in 0..subnode_name.to_bytes().len() {
        let mut node = fdt.node_mut(node_path).unwrap().unwrap();
        assert!(node.subnode_with_namelen(subnode_name, len).unwrap().is_none());

        let mut node = fdt.node_mut(node_path).unwrap().unwrap();
        node.add_subnode_with_namelen(subnode_name, len).unwrap();

        let mut node = fdt.node_mut(node_path).unwrap().unwrap();
        assert!(node.subnode_with_namelen(subnode_name, len).unwrap().is_some());
    }

    let node_path = node_path.to_str().unwrap();
    for len in 1..subnode_name.to_bytes().len() {
        let name = String::from_utf8(subnode_name.to_bytes()[..len].to_vec()).unwrap();
        let path = CString::new(format!("{node_path}/{name}")).unwrap();
        let name = CString::new(name).unwrap();
        let subnode = fdt.node(&path).unwrap().unwrap();
        assert_eq!(subnode.name(), Ok(name.as_c_str()));
    }
}
