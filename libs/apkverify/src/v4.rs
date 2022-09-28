/*
 * Copyright (C) 2022 The Android Open Source Project
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

//! API for APK Signature Scheme [v4].
//!
//! [v4]: https://source.android.com/security/apksigning/v4

use anyhow::{ensure, Context, Result};
use std::io::{Read, Seek};

use crate::algorithms::SignatureAlgorithmID;
use crate::v3::extract_signer_and_apk_sections;

/// Gets the v4 [apk_digest]. If `verify` is true, we verify that digest computed
/// with the extracted algorithm is equal to the digest extracted directly from apk.
/// Otherwise, the extracted digest will be returned directly.
///
/// [apk_digest]: https://source.android.com/docs/security/apksigning/v4#apk-digest
pub fn get_apk_digest<R: Read + Seek>(
    apk: R,
    verify: bool,
) -> Result<(SignatureAlgorithmID, Box<[u8]>)> {
    let (signer, mut sections) = extract_signer_and_apk_sections(apk)?;
    let strongest_algorithm_id = signer
        .strongest_signature()?
        .signature_algorithm_id
        .context("Strongest signature should contain a valid signature algorithm.")?;
    let extracted_digest = signer.find_digest_by_algorithm(strongest_algorithm_id)?;
    if verify {
        let computed_digest = sections.compute_digest(strongest_algorithm_id)?;
        ensure!(
            computed_digest == extracted_digest.as_ref(),
            "Computed digest does not match the extracted digest."
        );
    }
    Ok((strongest_algorithm_id, extracted_digest))
}
