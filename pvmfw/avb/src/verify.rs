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

//! This module handles the pvmfw payload verification.

use crate::descriptor::{Descriptors, Digest};
use crate::ops::{Ops, Payload};
use crate::partition::PartitionName;
use crate::PvmfwVerifyError;
use alloc::vec;
use alloc::vec::Vec;
use avb::{PartitionData, SlotVerifyError, SlotVerifyNoDataResult, VbmetaData};

// We use this for the rollback_index field if SlotVerifyData has empty rollback_indexes
const DEFAULT_ROLLBACK_INDEX: u64 = 0;

/// Verified data returned when the payload verification succeeds.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedBootData<'a> {
    /// DebugLevel of the VM.
    pub debug_level: DebugLevel,
    /// Kernel digest.
    pub kernel_digest: Digest,
    /// Initrd digest if initrd exists.
    pub initrd_digest: Option<Digest>,
    /// Trusted public key.
    pub public_key: &'a [u8],
    /// VM capabilities.
    pub capabilities: Vec<Capability>,
    /// Rollback index of kernel.
    pub rollback_index: u64,
}

impl VerifiedBootData<'_> {
    /// Returns whether the kernel have the given capability
    pub fn has_capability(&self, cap: Capability) -> bool {
        self.capabilities.contains(&cap)
    }
}

/// This enum corresponds to the `DebugLevel` in `VirtualMachineConfig`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DebugLevel {
    /// Not debuggable at all.
    None,
    /// Fully debuggable.
    Full,
}

/// VM Capability.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Capability {
    /// Remote attestation.
    RemoteAttest,
    /// Secretkeeper protected secrets.
    SecretkeeperProtection,
}

impl Capability {
    const KEY: &'static [u8] = b"com.android.virt.cap";
    const REMOTE_ATTEST: &'static [u8] = b"remote_attest";
    const SECRETKEEPER_PROTECTION: &'static [u8] = b"secretkeeper_protection";
    const SEPARATOR: u8 = b'|';

    fn get_capabilities(property_value: &[u8]) -> Result<Vec<Self>, PvmfwVerifyError> {
        let mut res = Vec::new();

        for v in property_value.split(|b| *b == Self::SEPARATOR) {
            let cap = match v {
                Self::REMOTE_ATTEST => Self::RemoteAttest,
                Self::SECRETKEEPER_PROTECTION => Self::SecretkeeperProtection,
                _ => return Err(PvmfwVerifyError::UnknownVbmetaProperty),
            };
            if res.contains(&cap) {
                return Err(SlotVerifyError::InvalidMetadata.into());
            }
            res.push(cap);
        }
        Ok(res)
    }
}

fn verify_only_one_vbmeta_exists(vbmeta_data: &[VbmetaData]) -> SlotVerifyNoDataResult<()> {
    if vbmeta_data.len() == 1 {
        Ok(())
    } else {
        Err(SlotVerifyError::InvalidMetadata)
    }
}

fn verify_vbmeta_is_from_kernel_partition(vbmeta_image: &VbmetaData) -> SlotVerifyNoDataResult<()> {
    match vbmeta_image.partition_name().try_into() {
        Ok(PartitionName::Kernel) => Ok(()),
        _ => Err(SlotVerifyError::InvalidMetadata),
    }
}

fn verify_vbmeta_has_only_one_hash_descriptor(
    descriptors: &Descriptors,
) -> SlotVerifyNoDataResult<()> {
    if descriptors.num_hash_descriptor() == 1 {
        Ok(())
    } else {
        Err(SlotVerifyError::InvalidMetadata)
    }
}

fn verify_loaded_partition_has_expected_length(
    loaded_partitions: &[PartitionData],
    partition_name: PartitionName,
    expected_len: usize,
) -> SlotVerifyNoDataResult<()> {
    if loaded_partitions.len() != 1 {
        // Only one partition should be loaded in each verify result.
        return Err(SlotVerifyError::Io);
    }
    let loaded_partition = &loaded_partitions[0];
    if !PartitionName::try_from(loaded_partition.partition_name())
        .map_or(false, |p| p == partition_name)
    {
        // Only the requested partition should be loaded.
        return Err(SlotVerifyError::Io);
    }
    if loaded_partition.data().len() == expected_len {
        Ok(())
    } else {
        Err(SlotVerifyError::Verification(None))
    }
}

/// Verifies that the vbmeta contains at most one property descriptor and it indicates the
/// vm type is service VM.
fn verify_property_and_get_capabilities(
    descriptors: &Descriptors,
) -> Result<Vec<Capability>, PvmfwVerifyError> {
    if !descriptors.has_property_descriptor() {
        return Ok(vec![]);
    }
    descriptors
        .find_property_value(Capability::KEY)
        .ok_or(PvmfwVerifyError::UnknownVbmetaProperty)
        .and_then(Capability::get_capabilities)
}

/// Verifies the given initrd partition, and checks that the resulting contents looks like expected.
fn verify_initrd(
    ops: &mut Ops,
    partition_name: PartitionName,
    expected_initrd: &[u8],
) -> SlotVerifyNoDataResult<()> {
    let result =
        ops.verify_partition(partition_name.as_cstr()).map_err(|e| e.without_verify_data())?;
    verify_loaded_partition_has_expected_length(
        result.partition_data(),
        partition_name,
        expected_initrd.len(),
    )
}

/// Verifies the payload (signed kernel + initrd) against the trusted public key.
pub fn verify_payload<'a>(
    kernel: &[u8],
    initrd: Option<&[u8]>,
    trusted_public_key: &'a [u8],
) -> Result<VerifiedBootData<'a>, PvmfwVerifyError> {
    let payload = Payload::new(kernel, initrd, trusted_public_key);
    let mut ops = Ops::new(&payload);
    let kernel_verify_result = ops.verify_partition(PartitionName::Kernel.as_cstr())?;

    let vbmeta_images = kernel_verify_result.vbmeta_data();
    // TODO(b/302093437): Use explicit rollback_index_location instead of default
    // location (first element).
    let rollback_index =
        *kernel_verify_result.rollback_indexes().first().unwrap_or(&DEFAULT_ROLLBACK_INDEX);
    verify_only_one_vbmeta_exists(vbmeta_images)?;
    let vbmeta_image = &vbmeta_images[0];
    verify_vbmeta_is_from_kernel_partition(vbmeta_image)?;
    let descriptors = Descriptors::from_vbmeta(vbmeta_image)?;
    let capabilities = verify_property_and_get_capabilities(&descriptors)?;
    let kernel_descriptor = descriptors.find_hash_descriptor(PartitionName::Kernel)?;

    if initrd.is_none() {
        verify_vbmeta_has_only_one_hash_descriptor(&descriptors)?;
        return Ok(VerifiedBootData {
            debug_level: DebugLevel::None,
            kernel_digest: *kernel_descriptor.digest,
            initrd_digest: None,
            public_key: trusted_public_key,
            capabilities,
            rollback_index,
        });
    }

    let initrd = initrd.unwrap();
    let mut initrd_ops = Ops::new(&payload);
    let (debug_level, initrd_partition_name) =
        if verify_initrd(&mut initrd_ops, PartitionName::InitrdNormal, initrd).is_ok() {
            (DebugLevel::None, PartitionName::InitrdNormal)
        } else if verify_initrd(&mut initrd_ops, PartitionName::InitrdDebug, initrd).is_ok() {
            (DebugLevel::Full, PartitionName::InitrdDebug)
        } else {
            return Err(SlotVerifyError::Verification(None).into());
        };
    let initrd_descriptor = descriptors.find_hash_descriptor(initrd_partition_name)?;
    Ok(VerifiedBootData {
        debug_level,
        kernel_digest: *kernel_descriptor.digest,
        initrd_digest: Some(*initrd_descriptor.digest),
        public_key: trusted_public_key,
        capabilities,
        rollback_index,
    })
}
