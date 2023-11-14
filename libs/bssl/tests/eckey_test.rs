// Copyright 2023, The Android Open Source Project
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

use bssl_avf::{EcKey, Result};

#[test]
fn ec_private_key_serialization() -> Result<()> {
    let ec_key = EcKey::new_p256()?;
    let der_encoded_ec_private_key = ec_key.ec_private_key()?;
    let deserialized_ec_key = EcKey::from_ec_private_key(der_encoded_ec_private_key.as_slice())?;

    assert_eq!(ec_key.cose_public_key()?, deserialized_ec_key.cose_public_key()?);
    Ok(())
}
