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

//! VM bootloader example.

#![no_main]
#![no_std]
#![feature(default_alloc_error_handler)]

mod exceptions;
mod layout;

extern crate alloc;

use crate::layout::{
    dtb_range, print_addresses, rodata_range, text_range, writable_region, DEVICE_REGION,
};
use aarch64_paging::{idmap::IdMap, paging::Attributes};
use alloc::{vec, vec::Vec};
use buddy_system_allocator::LockedHeap;
use log::{info, LevelFilter};
use vmbase::{logger, main, println};

static INITIALISED_DATA: [u32; 4] = [1, 2, 3, 4];
static mut ZEROED_DATA: [u32; 10] = [0; 10];
static mut MUTABLE_DATA: [u32; 4] = [1, 2, 3, 4];

const ASID: usize = 1;
const ROOT_LEVEL: usize = 1;

#[global_allocator]
static HEAP_ALLOCATOR: LockedHeap<32> = LockedHeap::<32>::new();

static mut HEAP: [u8; 65536] = [0; 65536];

main!(main);

/// Entry point for VM bootloader.
pub fn main(arg0: u64, arg1: u64, arg2: u64, arg3: u64) {
    logger::init(LevelFilter::Debug).unwrap();

    println!("Hello world");
    info!("x0={:#018x}, x1={:#018x}, x2={:#018x}, x3={:#018x}", arg0, arg1, arg2, arg3);
    print_addresses();
    assert_eq!(arg0, dtb_range().start.0 as u64);
    check_data();

    unsafe {
        HEAP_ALLOCATOR.lock().init(&mut HEAP as *mut u8 as usize, HEAP.len());
    }

    check_alloc();

    let mut idmap = IdMap::new(ASID, ROOT_LEVEL);
    idmap.map_range(&DEVICE_REGION, Attributes::DEVICE_NGNRE | Attributes::EXECUTE_NEVER).unwrap();
    idmap
        .map_range(
            &text_range().into(),
            Attributes::NORMAL | Attributes::NON_GLOBAL | Attributes::READ_ONLY,
        )
        .unwrap();
    idmap
        .map_range(
            &rodata_range().into(),
            Attributes::NORMAL
                | Attributes::NON_GLOBAL
                | Attributes::READ_ONLY
                | Attributes::EXECUTE_NEVER,
        )
        .unwrap();
    idmap
        .map_range(
            &writable_region(),
            Attributes::NORMAL | Attributes::NON_GLOBAL | Attributes::EXECUTE_NEVER,
        )
        .unwrap();

    info!("Activating IdMap...");
    info!("{:?}", idmap);
    idmap.activate();
    info!("Activated.");

    check_data();
}

fn check_data() {
    info!("INITIALISED_DATA: {:#010x}", &INITIALISED_DATA as *const u32 as usize);
    unsafe {
        info!("ZEROED_DATA: {:#010x}", &ZEROED_DATA as *const u32 as usize);
        info!("MUTABLE_DATA: {:#010x}", &MUTABLE_DATA as *const u32 as usize);
        info!("HEAP: {:#010x}", &HEAP as *const u8 as usize);
    }

    assert_eq!(INITIALISED_DATA[0], 1);
    assert_eq!(INITIALISED_DATA[1], 2);
    assert_eq!(INITIALISED_DATA[2], 3);
    assert_eq!(INITIALISED_DATA[3], 4);

    unsafe {
        for element in ZEROED_DATA.iter() {
            assert_eq!(*element, 0);
        }
        ZEROED_DATA[0] = 13;
        assert_eq!(ZEROED_DATA[0], 13);
        ZEROED_DATA[0] = 0;
        assert_eq!(ZEROED_DATA[0], 0);

        assert_eq!(MUTABLE_DATA[0], 1);
        assert_eq!(MUTABLE_DATA[1], 2);
        assert_eq!(MUTABLE_DATA[2], 3);
        assert_eq!(MUTABLE_DATA[3], 4);
        MUTABLE_DATA[0] += 41;
        assert_eq!(MUTABLE_DATA[0], 42);
        MUTABLE_DATA[0] -= 41;
        assert_eq!(MUTABLE_DATA[0], 1);
    }
    info!("Data looks good");
}

fn check_alloc() {
    info!("Allocating a Vec...");
    let mut vector: Vec<u32> = vec![1, 2, 3, 4];
    assert_eq!(vector[0], 1);
    assert_eq!(vector[1], 2);
    assert_eq!(vector[2], 3);
    assert_eq!(vector[3], 4);
    vector[2] = 42;
    assert_eq!(vector[2], 42);
    info!("Vec seems to work.");
}
