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

//! Functions to process partitions.

use crate::file::clone_file;
use android_system_virtualizationservice::aidl::android::system::virtualizationservice::{
    PartitionType::PartitionType,
};
use binder::{self, ExceptionCode, ParcelFileDescriptor, Status};
use disk::QcowFile;
use std::io::{Error, ErrorKind, Write};

/// crosvm requires all partitions to be a multiple of 4KiB.
const PARTITION_GRANULE_BYTES: u64 = 4096;

/// Initialize an empty partition image of the given size to be used as a writable partition.
pub fn init_writable_partition(
    image_fd: &ParcelFileDescriptor,
    size_bytes: i64,
    partition_type: PartitionType,
) -> binder::Result<()> {
    let size_bytes = size_bytes.try_into().map_err(|e| {
        Status::new_exception_str(
            ExceptionCode::ILLEGAL_ARGUMENT,
            Some(format!("Invalid size {}: {:?}", size_bytes, e)),
        )
    })?;
    let size_bytes = round_up(size_bytes, PARTITION_GRANULE_BYTES);
    let image = clone_file(image_fd)?;
    // initialize the file. Any data in the file will be erased.
    image.set_len(0).map_err(|e| {
        Status::new_service_specific_error_str(-1, Some(format!("Failed to reset a file: {:?}", e)))
    })?;
    let mut part = QcowFile::new(image, size_bytes).map_err(|e| {
        Status::new_service_specific_error_str(
            -1,
            Some(format!("Failed to create QCOW2 image: {:?}", e)),
        )
    })?;

    match partition_type {
        PartitionType::RAW => Ok(()),
        PartitionType::ANDROID_VM_INSTANCE => format_as_android_vm_instance(&mut part),
        PartitionType::ENCRYPTEDSTORE => format_as_encryptedstore(&mut part),
        _ => Err(Error::new(
            ErrorKind::Unsupported,
            format!("Unsupported partition type {:?}", partition_type),
        )),
    }
    .map_err(|e| {
        Status::new_service_specific_error_str(
            -1,
            Some(format!("Failed to initialize partition as {:?}: {:?}", partition_type, e)),
        )
    })
}

fn round_up(input: u64, granule: u64) -> u64 {
    if granule == 0 {
        return input;
    }
    // If the input is absurdly large we round down instead of up; it's going to fail anyway.
    let result = input.checked_add(granule - 1).unwrap_or(input);
    (result / granule) * granule
}

fn format_as_android_vm_instance(part: &mut dyn Write) -> std::io::Result<()> {
    const ANDROID_VM_INSTANCE_MAGIC: &str = "Android-VM-instance";
    const ANDROID_VM_INSTANCE_VERSION: u16 = 1;

    part.write_all(ANDROID_VM_INSTANCE_MAGIC.as_bytes())?;
    part.write_all(&ANDROID_VM_INSTANCE_VERSION.to_le_bytes())?;
    part.flush()
}

fn format_as_encryptedstore(part: &mut dyn Write) -> std::io::Result<()> {
    const UNFORMATTED_STORAGE_MAGIC: &str = "UNFORMATTED-STORAGE";

    part.write_all(UNFORMATTED_STORAGE_MAGIC.as_bytes())?;
    part.flush()
}
