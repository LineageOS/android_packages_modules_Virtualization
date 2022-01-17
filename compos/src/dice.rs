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

//! Handles the use of DICE as the source of our unique signing key via diced / IDiceNode.

use android_security_dice::aidl::android::security::dice::IDiceNode::IDiceNode;
use android_security_dice::binder::{wait_for_interface, Strong};
use anyhow::{Context, Result};

pub struct Dice {
    node: Strong<dyn IDiceNode>,
}

impl Dice {
    pub fn new() -> Result<Self> {
        let dice_service = wait_for_interface::<dyn IDiceNode>("android.security.dice.IDiceNode")
            .context("No IDiceNode service")?;
        Ok(Self { node: dice_service })
    }

    pub fn get_boot_certificate_chain(&self) -> Result<Vec<u8>> {
        let input_values = []; // Get our BCC, not a child's
        let bcc = self
            .node
            .getAttestationChain(&input_values)
            .context("Getting attestation chain failed")?;
        Ok(bcc.data)
    }
}
