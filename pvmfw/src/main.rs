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

//! pVM firmware.

#![no_main]
#![no_std]
#![feature(default_alloc_error_handler)]

mod avb;
mod entry;
mod exceptions;
mod fdt;
mod heap;
mod helpers;
mod memory;
mod mmio_guard;
mod mmu;
mod smccc;

use avb::PUBLIC_KEY;
use log::{debug, info};

fn main(fdt: &libfdt::Fdt, signed_kernel: &[u8], ramdisk: Option<&[u8]>, bcc: &[u8]) {
    info!("pVM firmware");
    debug!("FDT: {:?}", fdt as *const libfdt::Fdt);
    debug!("Signed kernel: {:?} ({:#x} bytes)", signed_kernel.as_ptr(), signed_kernel.len());
    if let Some(rd) = ramdisk {
        debug!("Ramdisk: {:?} ({:#x} bytes)", rd.as_ptr(), rd.len());
    } else {
        debug!("Ramdisk: None");
    }
    debug!("BCC: {:?} ({:#x} bytes)", bcc.as_ptr(), bcc.len());
    debug!("AVB public key: addr={:?}, size={:#x} ({1})", PUBLIC_KEY.as_ptr(), PUBLIC_KEY.len());
    info!("Starting payload...");
}
