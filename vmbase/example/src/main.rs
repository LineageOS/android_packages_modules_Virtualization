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

mod exceptions;

use vmbase::{main, println};

main!(main);

/// Entry point for VM bootloader.
pub fn main() {
    println!("Hello world");
    print_addresses();
}

fn print_addresses() {
    unsafe {
        println!(
            "dtb:        {:#010x}-{:#010x} ({} bytes)",
            &dtb_begin as *const u8 as usize,
            &dtb_end as *const u8 as usize,
            &dtb_end as *const u8 as usize - &dtb_begin as *const u8 as usize,
        );
        println!(
            "text:       {:#010x}-{:#010x} ({} bytes)",
            &text_begin as *const u8 as usize,
            &text_end as *const u8 as usize,
            &text_end as *const u8 as usize - &text_begin as *const u8 as usize,
        );
        println!(
            "rodata:     {:#010x}-{:#010x} ({} bytes)",
            &rodata_begin as *const u8 as usize,
            &rodata_end as *const u8 as usize,
            &rodata_end as *const u8 as usize - &rodata_begin as *const u8 as usize,
        );
        println!(
            "data:       {:#010x}-{:#010x} ({} bytes, loaded at {:#010x})",
            &data_begin as *const u8 as usize,
            &data_end as *const u8 as usize,
            &data_end as *const u8 as usize - &data_begin as *const u8 as usize,
            &data_lma as *const u8 as usize,
        );
        println!(
            "bss:        {:#010x}-{:#010x} ({} bytes)",
            &bss_begin as *const u8 as usize,
            &bss_end as *const u8 as usize,
            &bss_end as *const u8 as usize - &bss_begin as *const u8 as usize,
        );
        println!(
            "boot_stack: {:#010x}-{:#010x} ({} bytes)",
            &boot_stack_begin as *const u8 as usize,
            &boot_stack_end as *const u8 as usize,
            &boot_stack_end as *const u8 as usize - &boot_stack_begin as *const u8 as usize,
        );
    }
}

extern "C" {
    static dtb_begin: u8;
    static dtb_end: u8;
    static text_begin: u8;
    static text_end: u8;
    static rodata_begin: u8;
    static rodata_end: u8;
    static data_begin: u8;
    static data_end: u8;
    static data_lma: u8;
    static bss_begin: u8;
    static bss_end: u8;
    static boot_stack_begin: u8;
    static boot_stack_end: u8;
}
