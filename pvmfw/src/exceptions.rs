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

//! Exception handlers.

use crate::{helpers::page_4kb_of, read_sysreg};
use vmbase::console;
use vmbase::{console::emergency_write_str, eprintln, power::reboot};

const ESR_32BIT_EXT_DABT: usize = 0x96000010;
const UART_PAGE: usize = page_4kb_of(console::BASE_ADDRESS);

#[no_mangle]
extern "C" fn sync_exception_current(_elr: u64, _spsr: u64) {
    let esr = read_sysreg!("esr_el1");
    let far = read_sysreg!("far_el1");
    // Don't print to the UART if we're handling the exception it could raise.
    if esr != ESR_32BIT_EXT_DABT || page_4kb_of(far) != UART_PAGE {
        emergency_write_str("sync_exception_current\n");
        eprintln!("esr={esr:#08x}");
    }
    reboot();
}

#[no_mangle]
extern "C" fn irq_current(_elr: u64, _spsr: u64) {
    emergency_write_str("irq_current\n");
    reboot();
}

#[no_mangle]
extern "C" fn fiq_current(_elr: u64, _spsr: u64) {
    emergency_write_str("fiq_current\n");
    reboot();
}

#[no_mangle]
extern "C" fn serr_current(_elr: u64, _spsr: u64) {
    let esr = read_sysreg!("esr_el1");
    emergency_write_str("serr_current\n");
    eprintln!("esr={esr:#08x}");
    reboot();
}

#[no_mangle]
extern "C" fn sync_lower(_elr: u64, _spsr: u64) {
    let esr = read_sysreg!("esr_el1");
    emergency_write_str("sync_lower\n");
    eprintln!("esr={esr:#08x}");
    reboot();
}

#[no_mangle]
extern "C" fn irq_lower(_elr: u64, _spsr: u64) {
    emergency_write_str("irq_lower\n");
    reboot();
}

#[no_mangle]
extern "C" fn fiq_lower(_elr: u64, _spsr: u64) {
    emergency_write_str("fiq_lower\n");
    reboot();
}

#[no_mangle]
extern "C" fn serr_lower(_elr: u64, _spsr: u64) {
    let esr = read_sysreg!("esr_el1");
    emergency_write_str("serr_lower\n");
    eprintln!("esr={esr:#08x}");
    reboot();
}
