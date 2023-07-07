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

//! Functions and drivers for obtaining true entropy.

use crate::hvc::{self, TrngRng64Entropy};
use core::fmt;
use core::mem::size_of;
use smccc::{self, Hvc};

/// Error type for rand operations.
pub enum Error {
    /// No source of entropy found.
    NoEntropySource,
    /// Error during architectural SMCCC call.
    Smccc(smccc::arch::Error),
    /// Error during SMCCC TRNG call.
    Trng(hvc::trng::Error),
    /// Unsupported SMCCC version.
    UnsupportedSmcccVersion(smccc::arch::Version),
    /// Unsupported SMCCC TRNG version.
    UnsupportedTrngVersion(hvc::trng::Version),
}

impl From<smccc::arch::Error> for Error {
    fn from(e: smccc::arch::Error) -> Self {
        Self::Smccc(e)
    }
}

impl From<hvc::trng::Error> for Error {
    fn from(e: hvc::trng::Error) -> Self {
        Self::Trng(e)
    }
}

/// Result type for rand operations.
pub type Result<T> = core::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::NoEntropySource => write!(f, "No source of entropy available"),
            Self::Smccc(e) => write!(f, "Architectural SMCCC error: {e}"),
            Self::Trng(e) => write!(f, "SMCCC TRNG error: {e}"),
            Self::UnsupportedSmcccVersion(v) => write!(f, "Unsupported SMCCC version {v}"),
            Self::UnsupportedTrngVersion(v) => write!(f, "Unsupported SMCCC TRNG version {v}"),
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self}")
    }
}

/// Configure the source of entropy.
pub(crate) fn init() -> Result<()> {
    // SMCCC TRNG requires SMCCC v1.1.
    match smccc::arch::version::<Hvc>()? {
        smccc::arch::Version { major: 1, minor } if minor >= 1 => (),
        version => return Err(Error::UnsupportedSmcccVersion(version)),
    }

    // TRNG_RND requires SMCCC TRNG v1.0.
    match hvc::trng_version()? {
        hvc::trng::Version { major: 1, minor: _ } => (),
        version => return Err(Error::UnsupportedTrngVersion(version)),
    }

    // TRNG_RND64 doesn't define any special capabilities so ignore the successful result.
    let _ = hvc::trng_features(hvc::ARM_SMCCC_TRNG_RND64).map_err(|e| {
        if e == hvc::trng::Error::NotSupported {
            // SMCCC TRNG is currently our only source of entropy.
            Error::NoEntropySource
        } else {
            e.into()
        }
    })?;

    Ok(())
}

/// Fills a slice of bytes with true entropy.
pub fn fill_with_entropy(s: &mut [u8]) -> Result<()> {
    const MAX_BYTES_PER_CALL: usize = size_of::<TrngRng64Entropy>();

    let (aligned, remainder) = s.split_at_mut(s.len() - s.len() % MAX_BYTES_PER_CALL);

    for chunk in aligned.chunks_exact_mut(MAX_BYTES_PER_CALL) {
        let (r, s, t) = repeat_trng_rnd(chunk.len())?;

        let mut words = chunk.chunks_exact_mut(size_of::<u64>());
        words.next().unwrap().clone_from_slice(&t.to_ne_bytes());
        words.next().unwrap().clone_from_slice(&s.to_ne_bytes());
        words.next().unwrap().clone_from_slice(&r.to_ne_bytes());
    }

    if !remainder.is_empty() {
        let mut entropy = [0; MAX_BYTES_PER_CALL];
        let (r, s, t) = repeat_trng_rnd(remainder.len())?;

        let mut words = entropy.chunks_exact_mut(size_of::<u64>());
        words.next().unwrap().clone_from_slice(&t.to_ne_bytes());
        words.next().unwrap().clone_from_slice(&s.to_ne_bytes());
        words.next().unwrap().clone_from_slice(&r.to_ne_bytes());

        remainder.clone_from_slice(&entropy[..remainder.len()]);
    }

    Ok(())
}

fn repeat_trng_rnd(n_bytes: usize) -> Result<TrngRng64Entropy> {
    let bits = usize::try_from(u8::BITS).unwrap();
    let n_bits = (n_bytes * bits).try_into().unwrap();
    loop {
        match hvc::trng_rnd64(n_bits) {
            Ok(entropy) => return Ok(entropy),
            Err(hvc::trng::Error::NoEntropy) => (),
            Err(e) => return Err(e.into()),
        }
    }
}

/// Generate an array of fixed-size initialized with true-random bytes.
pub fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut arr = [0; N];
    fill_with_entropy(&mut arr)?;
    Ok(arr)
}

#[no_mangle]
extern "C" fn CRYPTO_sysrand_for_seed(out: *mut u8, req: usize) {
    CRYPTO_sysrand(out, req)
}

#[no_mangle]
extern "C" fn CRYPTO_sysrand(out: *mut u8, req: usize) {
    // SAFETY: We need to assume that out points to valid memory of size req.
    let s = unsafe { core::slice::from_raw_parts_mut(out, req) };
    fill_with_entropy(s).unwrap()
}
