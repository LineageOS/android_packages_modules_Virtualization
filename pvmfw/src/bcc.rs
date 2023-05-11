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

//! Code to inspect/manipulate the BCC (DICE Chain) we receive from our loader (the hypervisor).

// TODO(b/279910232): Unify this, somehow, with the similar but different code in hwtrust.

use alloc::vec::Vec;
use ciborium::value::Value;
use core::fmt;
use diced_open_dice::DiceMode;
use log::trace;

type Result<T> = core::result::Result<T, BccError>;

pub enum BccError {
    CborDecodeError(ciborium::de::Error<ciborium_io::EndOfFile>),
    ExtraneousBytes,
    MalformedBcc(&'static str),
    MissingBcc,
}

impl fmt::Display for BccError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CborDecodeError(e) => write!(f, "Error parsing BCC CBOR: {e:?}"),
            Self::ExtraneousBytes => write!(f, "Unexpected trailing data in BCC"),
            Self::MalformedBcc(s) => {
                write!(f, "BCC does not have the expected CBOR structure: {s}")
            }
            Self::MissingBcc => write!(f, "Missing BCC"),
        }
    }
}

/// Represents a (partially) decoded BCC DICE chain.
pub struct Bcc {
    is_debug_mode: bool,
}

impl Bcc {
    /// Returns whether any node in the received DICE chain is marked as debug (and hence is not
    /// secure).
    pub fn new(received_bcc: Option<&[u8]>) -> Result<Bcc> {
        let received_bcc = received_bcc.unwrap_or(&[]);
        if received_bcc.is_empty() {
            return Err(BccError::MissingBcc);
        }

        // We don't attempt to fully validate the BCC (e.g. we don't check the signatures) - we
        // have to trust our loader. But if it's invalid CBOR or otherwise clearly ill-formed,
        // something is very wrong, so we fail.
        let bcc_cbor = value_from_bytes(received_bcc)?;

        // Bcc = [
        //   PubKeyEd25519 / PubKeyECDSA256, // DK_pub
        //   + BccEntry,                     // Root -> leaf (KM_pub)
        // ]
        let bcc = match bcc_cbor {
            Value::Array(v) if v.len() >= 2 => v,
            _ => return Err(BccError::MalformedBcc("Invalid top level value")),
        };
        // Decode all the entries to make sure they are well-formed.
        let entries: Vec<_> = bcc.into_iter().skip(1).map(BccEntry::new).collect();

        let is_debug_mode = is_any_entry_debug_mode(entries.as_slice())?;
        Ok(Self { is_debug_mode })
    }

    pub fn is_debug_mode(&self) -> bool {
        self.is_debug_mode
    }
}

fn is_any_entry_debug_mode(entries: &[BccEntry]) -> Result<bool> {
    // Check if any entry in the chain is marked as Debug mode, which means the device is not
    // secure. (Normal means it is a secure boot, for that stage at least; we ignore recovery
    // & not configured /invalid values, since it's not clear what they would mean in this
    // context.)
    for entry in entries {
        if entry.payload()?.is_debug_mode()? {
            return Ok(true);
        }
    }
    Ok(false)
}

#[repr(transparent)]
struct BccEntry(Value);

#[repr(transparent)]
struct BccPayload(Value);

impl BccEntry {
    pub fn new(entry: Value) -> Self {
        Self(entry)
    }

    pub fn payload(&self) -> Result<BccPayload> {
        // BccEntry = [                                  // COSE_Sign1 (untagged)
        //     protected : bstr .cbor {
        //         1 : AlgorithmEdDSA / AlgorithmES256,  // Algorithm
        //     },
        //     unprotected: {},
        //     payload: bstr .cbor BccPayload,
        //     signature: bstr // PureEd25519(SigningKey, bstr .cbor BccEntryInput) /
        //                     // ECDSA(SigningKey, bstr .cbor BccEntryInput)
        //     // See RFC 8032 for details of how to encode the signature value for Ed25519.
        // ]
        let payload =
            self.payload_bytes().ok_or(BccError::MalformedBcc("Invalid payload in BccEntry"))?;
        let payload = value_from_bytes(payload)?;
        trace!("Bcc payload: {payload:?}");
        Ok(BccPayload(payload))
    }

    fn payload_bytes(&self) -> Option<&Vec<u8>> {
        let entry = self.0.as_array()?;
        if entry.len() != 4 {
            return None;
        };
        entry[2].as_bytes()
    }
}

const KEY_MODE: i32 = -4670551;
const MODE_DEBUG: u8 = DiceMode::kDiceModeDebug as u8;

impl BccPayload {
    pub fn is_debug_mode(&self) -> Result<bool> {
        // BccPayload = {                     // CWT
        // ...
        //     ? -4670551 : bstr,             // Mode
        // ...
        // }

        let Some(value) = self.value_from_key(KEY_MODE) else { return Ok(false) };

        // Mode is supposed to be encoded as a 1-byte bstr, but some implementations instead
        // encode it as an integer. Accept either. See b/273552826.
        // If Mode is omitted, it should be treated as if it was Unknown, according to the Open
        // Profile for DICE spec.
        let mode = if let Some(bytes) = value.as_bytes() {
            if bytes.len() != 1 {
                return Err(BccError::MalformedBcc("Invalid mode bstr"));
            }
            bytes[0].into()
        } else {
            value.as_integer().ok_or(BccError::MalformedBcc("Invalid type for mode"))?
        };
        Ok(mode == MODE_DEBUG.into())
    }

    fn value_from_key(&self, key: i32) -> Option<&Value> {
        // BccPayload is just a map; we only use integral keys, but in general it's legitimate
        // for other things to be present, or for the key we care about not to be present.
        // Ciborium represents the map as a Vec, preserving order (and allowing duplicate keys,
        // which we ignore) but preventing fast lookup.
        let payload = self.0.as_map()?;
        for (k, v) in payload {
            if k.as_integer() == Some(key.into()) {
                return Some(v);
            }
        }
        None
    }
}

/// Decodes the provided binary CBOR-encoded value and returns a
/// ciborium::Value struct wrapped in Result.
fn value_from_bytes(mut bytes: &[u8]) -> Result<Value> {
    let value = ciborium::de::from_reader(&mut bytes).map_err(BccError::CborDecodeError)?;
    // Ciborium tries to read one Value, but doesn't care if there is trailing data after it. We do.
    if !bytes.is_empty() {
        return Err(BccError::ExtraneousBytes);
    }
    Ok(value)
}
