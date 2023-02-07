/*
 * Copyright 2022 The Android Open Source Project
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

//! Wrapper around dice/android/bcc.h.

use core::mem;
use core::ptr;

use open_dice_bcc_bindgen::BccHandoverMainFlow;
use open_dice_bcc_bindgen::BccHandoverParse;

use crate::check_result;
use crate::Cdi;
use crate::DiceError;
use crate::InputValues;
use crate::Result;

/// Boot Chain Certificate handover format combining the BCC and CDIs in a single CBOR object.
#[derive(Clone, Debug)]
pub struct Handover<'a> {
    buffer: &'a [u8],
    /// Attestation CDI.
    pub cdi_attest: &'a Cdi,
    /// Sealing CDI.
    pub cdi_seal: &'a Cdi,
    /// Boot Chain Certificate (optional).
    pub bcc: Option<&'a [u8]>,
}

impl<'a> Handover<'a> {
    /// Validates and extracts the fields of a BCC handover buffer.
    pub fn new(buffer: &'a [u8]) -> Result<Self> {
        let mut cdi_attest: *const u8 = ptr::null();
        let mut cdi_seal: *const u8 = ptr::null();
        let mut bcc: *const u8 = ptr::null();
        let mut bcc_size: usize = 0;

        // SAFETY - The buffer is only read and never stored and the returned pointers should all
        // point within the address range of the buffer or be NULL.
        check_result(unsafe {
            BccHandoverParse(
                buffer.as_ptr(),
                buffer.len(),
                &mut cdi_attest as *mut *const u8,
                &mut cdi_seal as *mut *const u8,
                &mut bcc as *mut *const u8,
                &mut bcc_size as *mut usize,
            )
        })?;

        let cdi_attest = {
            let i = index_from_ptr(buffer, cdi_attest).ok_or(DiceError::PlatformError)?;
            let s = buffer.get(i..(i + mem::size_of::<Cdi>())).ok_or(DiceError::PlatformError)?;
            s.try_into().map_err(|_| DiceError::PlatformError)?
        };
        let cdi_seal = {
            let i = index_from_ptr(buffer, cdi_seal).ok_or(DiceError::PlatformError)?;
            let s = buffer.get(i..(i + mem::size_of::<Cdi>())).ok_or(DiceError::PlatformError)?;
            s.try_into().map_err(|_| DiceError::PlatformError)?
        };
        let bcc = if bcc.is_null() {
            None
        } else {
            let i = index_from_ptr(buffer, bcc).ok_or(DiceError::PlatformError)?;
            Some(buffer.get(i..(i + bcc_size)).ok_or(DiceError::PlatformError)?)
        };

        Ok(Self { buffer, cdi_attest, cdi_seal, bcc })
    }

    /// Executes the main BCC handover flow.
    pub fn main_flow(&self, input_values: &InputValues, buffer: &mut [u8]) -> Result<usize> {
        let context = ptr::null_mut();
        let mut size: usize = 0;
        // SAFETY - The function only reads `self.buffer`, writes to `buffer` within its bounds,
        // reads `input_values` as a constant input and doesn't store any pointer.
        check_result(unsafe {
            BccHandoverMainFlow(
                context,
                self.buffer.as_ptr(),
                self.buffer.len(),
                input_values.as_ptr(),
                buffer.len(),
                buffer.as_mut_ptr(),
                &mut size as *mut usize,
            )
        })?;

        Ok(size)
    }
}

fn index_from_ptr(slice: &[u8], pointer: *const u8) -> Option<usize> {
    if slice.as_ptr_range().contains(&pointer) {
        (pointer as usize).checked_sub(slice.as_ptr() as usize)
    } else {
        None
    }
}
