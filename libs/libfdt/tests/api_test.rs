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

use core::ffi::CStr;
use cstr::cstr;
use libfdt::{Fdt, FdtError, FdtNodeMut, Phandle};
use std::ffi::CString;
use std::fs;
use std::ops::Range;

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
    let expected = [Ok(cstr!("cpus")), Ok(cstr!("randomnode")), Ok(cstr!("chosen"))];

    let root_subnodes = root.subnodes().unwrap();
    let subnode_names: Vec<_> = root_subnodes.map(|node| node.name()).collect();
    assert_eq!(subnode_names, expected);
}

#[test]
fn node_properties() {
    let data = fs::read(TEST_TREE_WITH_NO_MEMORY_NODE_PATH).unwrap();
    let fdt = Fdt::from_slice(&data).unwrap();
    let root = fdt.root().unwrap();
    let one_be = 0x1_u32.to_be_bytes();
    type Result<T> = core::result::Result<T, FdtError>;
    let expected: Vec<(Result<&CStr>, Result<&[u8]>)> = vec![
        (Ok(cstr!("model")), Ok(b"MyBoardName\0".as_ref())),
        (Ok(cstr!("compatible")), Ok(b"MyBoardName\0MyBoardFamilyName\0".as_ref())),
        (Ok(cstr!("#address-cells")), Ok(&one_be)),
        (Ok(cstr!("#size-cells")), Ok(&one_be)),
        (Ok(cstr!("empty_prop")), Ok(&[])),
    ];

    let properties = root.properties().unwrap();
    let subnode_properties: Vec<_> = properties.map(|prop| (prop.name(), prop.value())).collect();

    assert_eq!(subnode_properties, expected);
}

#[test]
fn node_supernode_at_depth() {
    let data = fs::read(TEST_TREE_WITH_NO_MEMORY_NODE_PATH).unwrap();
    let fdt = Fdt::from_slice(&data).unwrap();
    let node = fdt.node(cstr!("/cpus/PowerPC,970@1")).unwrap().unwrap();
    let expected = vec![Ok(cstr!("")), Ok(cstr!("cpus")), Ok(cstr!("PowerPC,970@1"))];

    let mut supernode_names = vec![];
    let mut depth = 0;
    while let Ok(supernode) = node.supernode_at_depth(depth) {
        supernode_names.push(supernode.name());
        depth += 1;
    }

    assert_eq!(supernode_names, expected);
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
fn node_mut_with_phandle() {
    let mut data = fs::read(TEST_TREE_PHANDLE_PATH).unwrap();
    let fdt = Fdt::from_mut_slice(&mut data).unwrap();

    // Test linux,phandle
    let phandle = Phandle::new(0xFF).unwrap();
    let node: FdtNodeMut = fdt.node_mut_with_phandle(phandle).unwrap().unwrap();
    assert_eq!(node.as_node().name(), Ok(cstr!("node_zz")));

    // Test phandle
    let phandle = Phandle::new(0x22).unwrap();
    let node: FdtNodeMut = fdt.node_mut_with_phandle(phandle).unwrap().unwrap();
    assert_eq!(node.as_node().name(), Ok(cstr!("node_abc")));
}

#[test]
fn node_get_phandle() {
    let data = fs::read(TEST_TREE_PHANDLE_PATH).unwrap();
    let fdt = Fdt::from_slice(&data).unwrap();

    // Test linux,phandle
    let node = fdt.node(cstr!("/node_z/node_zz")).unwrap().unwrap();
    assert_eq!(node.get_phandle(), Ok(Phandle::new(0xFF)));

    // Test phandle
    let node = fdt.node(cstr!("/node_a/node_ab/node_abc")).unwrap().unwrap();
    assert_eq!(node.get_phandle(), Ok(Phandle::new(0x22)));

    // Test no phandle
    let node = fdt.node(cstr!("/node_b")).unwrap().unwrap();
    assert_eq!(node.get_phandle(), Ok(None));
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

#[test]
fn fdt_symbols() {
    let mut data = fs::read(TEST_TREE_PHANDLE_PATH).unwrap();
    let fdt = Fdt::from_mut_slice(&mut data).unwrap();

    let symbols = fdt.symbols().unwrap().unwrap();
    assert_eq!(symbols.name(), Ok(cstr!("__symbols__")));

    // Validates type.
    let _symbols: FdtNodeMut = fdt.symbols_mut().unwrap().unwrap();
}

#[test]
fn node_mut_as_node() {
    let mut data = fs::read(TEST_TREE_WITH_ONE_MEMORY_RANGE_PATH).unwrap();
    let fdt = Fdt::from_mut_slice(&mut data).unwrap();

    let mut memory = fdt.node_mut(cstr!("/memory")).unwrap().unwrap();
    {
        let memory = memory.as_node();
        assert_eq!(memory.name(), Ok(cstr!("memory")));
    }

    // Just check whether borrow checker doesn't complain this.
    memory.setprop_inplace(cstr!("device_type"), b"MEMORY\0").unwrap();
}
