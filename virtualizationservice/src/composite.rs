// Copyright 2021, The Android Open Source Project
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

//! Functions for creating a composite disk image.

use crate::gpt::{
    write_gpt_header, write_protective_mbr, GptPartitionEntry, GPT_BEGINNING_SIZE, GPT_END_SIZE,
    GPT_HEADER_SIZE, GPT_NUM_PARTITIONS, GPT_PARTITION_ENTRY_SIZE, SECTOR_SIZE,
};
use android_system_virtualizationservice::aidl::android::system::virtualizationservice::Partition::Partition;
use anyhow::{anyhow, bail, Context, Error};
use crc32fast::Hasher;
use disk::create_disk_file;
use log::{trace, warn};
use protobuf::Message;
use protos::cdisk_spec::{ComponentDisk, CompositeDisk, ReadWriteCapability};
use std::convert::TryInto;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// A magic string placed at the beginning of a composite disk file to identify it.
const CDISK_MAGIC: &str = "composite_disk\x1d";
/// The version of the composite disk format supported by this implementation.
const COMPOSITE_DISK_VERSION: u64 = 1;
/// The amount of padding needed between the last partition entry and the first partition, to align
/// the partition appropriately. The two sectors are for the MBR and the GPT header.
const PARTITION_ALIGNMENT_SIZE: usize = GPT_BEGINNING_SIZE as usize
    - 2 * SECTOR_SIZE as usize
    - GPT_NUM_PARTITIONS as usize * GPT_PARTITION_ENTRY_SIZE as usize;
const HEADER_PADDING_LENGTH: usize = SECTOR_SIZE as usize - GPT_HEADER_SIZE as usize;
// Keep all partitions 4k aligned for performance.
const PARTITION_SIZE_SHIFT: u8 = 12;
// Keep the disk size a multiple of 64k for crosvm's virtio_blk driver.
const DISK_SIZE_SHIFT: u8 = 16;

const LINUX_FILESYSTEM_GUID: Uuid = Uuid::from_u128(0x0FC63DAF_8483_4772_8E79_3D69D8477DE4);
const EFI_SYSTEM_PARTITION_GUID: Uuid = Uuid::from_u128(0xC12A7328_F81F_11D2_BA4B_00A0C93EC93B);

/// Information about a single image file to be included in a partition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartitionFileInfo {
    path: PathBuf,
    size: u64,
}

/// Information about a partition to create, including the set of image files which make it up.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartitionInfo {
    label: String,
    files: Vec<PartitionFileInfo>,
    partition_type: ImagePartitionType,
    writable: bool,
}

/// Round `val` up to the next multiple of 2**`align_log`.
fn align_to_power_of_2(val: u64, align_log: u8) -> u64 {
    let align = 1 << align_log;
    ((val + (align - 1)) / align) * align
}

impl PartitionInfo {
    fn aligned_size(&self) -> u64 {
        align_to_power_of_2(self.files.iter().map(|file| file.size).sum(), PARTITION_SIZE_SHIFT)
    }
}

/// The type of partition.
#[allow(dead_code)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ImagePartitionType {
    LinuxFilesystem,
    EfiSystemPartition,
}

impl ImagePartitionType {
    fn guid(self) -> Uuid {
        match self {
            Self::LinuxFilesystem => LINUX_FILESYSTEM_GUID,
            Self::EfiSystemPartition => EFI_SYSTEM_PARTITION_GUID,
        }
    }
}

/// Write protective MBR and primary GPT table.
fn write_beginning(
    file: &mut impl Write,
    disk_guid: Uuid,
    partitions: &[u8],
    partition_entries_crc32: u32,
    secondary_table_offset: u64,
    disk_size: u64,
) -> Result<(), Error> {
    // Write the protective MBR to the first sector.
    write_protective_mbr(file, disk_size)?;

    // Write the GPT header, and pad out to the end of the sector.
    write_gpt_header(file, disk_guid, partition_entries_crc32, secondary_table_offset, false)?;
    file.write_all(&[0; HEADER_PADDING_LENGTH])?;

    // Write partition entries, including unused ones.
    file.write_all(partitions)?;

    // Write zeroes to align the first partition appropriately.
    file.write_all(&[0; PARTITION_ALIGNMENT_SIZE])?;

    Ok(())
}

/// Write secondary GPT table.
fn write_end(
    file: &mut impl Write,
    disk_guid: Uuid,
    partitions: &[u8],
    partition_entries_crc32: u32,
    secondary_table_offset: u64,
    disk_size: u64,
) -> Result<(), Error> {
    // Write partition entries, including unused ones.
    file.write_all(partitions)?;

    // Write the GPT header, and pad out to the end of the sector.
    write_gpt_header(file, disk_guid, partition_entries_crc32, secondary_table_offset, true)?;
    file.write_all(&[0; HEADER_PADDING_LENGTH])?;

    // Pad out to the aligned disk size.
    let used_disk_size = secondary_table_offset + GPT_END_SIZE;
    let padding = disk_size - used_disk_size;
    file.write_all(&vec![0; padding as usize])?;

    Ok(())
}

/// Create the `GptPartitionEntry` for the given partition.
fn create_gpt_entry(partition: &PartitionInfo, offset: u64) -> GptPartitionEntry {
    let mut partition_name: Vec<u16> = partition.label.encode_utf16().collect();
    partition_name.resize(36, 0);

    GptPartitionEntry {
        partition_type_guid: partition.partition_type.guid(),
        unique_partition_guid: Uuid::new_v4(),
        first_lba: offset / SECTOR_SIZE,
        last_lba: (offset + partition.aligned_size()) / SECTOR_SIZE - 1,
        attributes: 0,
        partition_name: partition_name.try_into().unwrap(),
    }
}

/// Create one or more `ComponentDisk` proto messages for the given partition.
fn create_component_disks(
    partition: &PartitionInfo,
    offset: u64,
    header_path: &str,
) -> Result<Vec<ComponentDisk>, Error> {
    let aligned_size = partition.aligned_size();

    if partition.files.is_empty() {
        bail!("No image files for partition {:?}", partition);
    }
    let mut file_size_sum = 0;
    let mut component_disks = vec![];
    for file in &partition.files {
        component_disks.push(ComponentDisk {
            offset: offset + file_size_sum,
            file_path: file.path.to_str().context("Invalid partition path")?.to_string(),
            read_write_capability: if partition.writable {
                ReadWriteCapability::READ_WRITE
            } else {
                ReadWriteCapability::READ_ONLY
            },
            ..ComponentDisk::new()
        });
        file_size_sum += file.size;
    }

    if file_size_sum != aligned_size {
        if partition.writable {
            bail!(
                "Read-write partition {:?} size is not a multiple of {}.",
                partition,
                1 << PARTITION_SIZE_SHIFT
            );
        } else {
            // Fill in the gap by reusing the header file, because we know it is always bigger
            // than the alignment size (i.e. GPT_BEGINNING_SIZE > 1 << PARTITION_SIZE_SHIFT).
            warn!(
                "Read-only partition {:?} size is not a multiple of {}, filling gap.",
                partition,
                1 << PARTITION_SIZE_SHIFT
            );
            component_disks.push(ComponentDisk {
                offset: offset + file_size_sum,
                file_path: header_path.to_owned(),
                read_write_capability: ReadWriteCapability::READ_ONLY,
                ..ComponentDisk::new()
            });
        }
    }

    Ok(component_disks)
}

/// Create a new composite disk containing the given partitions, and write it out to the given
/// files.
pub fn create_composite_disk(
    partitions: &[PartitionInfo],
    header_path: &Path,
    header_file: &mut File,
    footer_path: &Path,
    footer_file: &mut File,
    output_composite: &mut File,
) -> Result<(), Error> {
    let header_path = header_path.to_str().context("Invalid header path")?.to_string();
    let footer_path = footer_path.to_str().context("Invalid footer path")?.to_string();

    let mut composite_proto = CompositeDisk::new();
    composite_proto.version = COMPOSITE_DISK_VERSION;
    composite_proto.component_disks.push(ComponentDisk {
        file_path: header_path.clone(),
        offset: 0,
        read_write_capability: ReadWriteCapability::READ_ONLY,
        ..ComponentDisk::new()
    });

    // Write partitions to a temporary buffer so that we can calculate the CRC, and construct the
    // ComponentDisk proto messages at the same time.
    let mut partitions_buffer =
        [0u8; GPT_NUM_PARTITIONS as usize * GPT_PARTITION_ENTRY_SIZE as usize];
    let mut writer: &mut [u8] = &mut partitions_buffer;
    let mut next_disk_offset = GPT_BEGINNING_SIZE;
    for partition in partitions {
        create_gpt_entry(partition, next_disk_offset).write_bytes(&mut writer)?;

        for component_disk in create_component_disks(partition, next_disk_offset, &header_path)? {
            composite_proto.component_disks.push(component_disk);
        }

        next_disk_offset += partition.aligned_size();
    }
    let secondary_table_offset = next_disk_offset;
    let disk_size = align_to_power_of_2(secondary_table_offset + GPT_END_SIZE, DISK_SIZE_SHIFT);
    trace!("Partitions: {:#?}", partitions);
    trace!("Secondary table offset: {} disk size: {}", secondary_table_offset, disk_size);

    composite_proto.component_disks.push(ComponentDisk {
        file_path: footer_path,
        offset: secondary_table_offset,
        read_write_capability: ReadWriteCapability::READ_ONLY,
        ..ComponentDisk::new()
    });

    // Calculate CRC32 of partition entries.
    let mut hasher = Hasher::new();
    hasher.update(&partitions_buffer);
    let partition_entries_crc32 = hasher.finalize();

    let disk_guid = Uuid::new_v4();
    write_beginning(
        header_file,
        disk_guid,
        &partitions_buffer,
        partition_entries_crc32,
        secondary_table_offset,
        disk_size,
    )?;
    write_end(
        footer_file,
        disk_guid,
        &partitions_buffer,
        partition_entries_crc32,
        secondary_table_offset,
        disk_size,
    )?;

    composite_proto.length = disk_size;
    output_composite.write_all(CDISK_MAGIC.as_bytes())?;
    composite_proto.write_to_writer(output_composite)?;

    Ok(())
}

/// Constructs a composite disk image for the given list of partitions, and opens it ready to use.
///
/// Returns the composite disk image file, and a list of FD mappings which must be applied to any
/// process which wants to use it. This is necessary because the composite image contains paths of
/// the form `/proc/self/fd/N` for the partition images.
pub fn make_composite_image(
    partitions: &[Partition],
    output_path: &Path,
    header_path: &Path,
    footer_path: &Path,
) -> Result<(File, Vec<File>), Error> {
    let (partitions, files) = convert_partitions(partitions)?;

    let mut composite_image = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(output_path)
        .with_context(|| format!("Failed to create composite image {:?}", output_path))?;
    let mut header_file =
        OpenOptions::new().create_new(true).read(true).write(true).open(header_path).with_context(
            || format!("Failed to create composite image header {:?}", header_path),
        )?;
    let mut footer_file =
        OpenOptions::new().create_new(true).read(true).write(true).open(footer_path).with_context(
            || format!("Failed to create composite image header {:?}", footer_path),
        )?;

    create_composite_disk(
        &partitions,
        header_path,
        &mut header_file,
        footer_path,
        &mut footer_file,
        &mut composite_image,
    )?;

    // Re-open the composite image as read-only.
    let composite_image = File::open(&output_path)
        .with_context(|| format!("Failed to open composite image {:?}", output_path))?;

    Ok((composite_image, files))
}

/// Given the AIDL config containing a list of partitions, with a [`ParcelFileDescriptor`] for each
/// partition, return the list of file descriptors which must be passed to the mk_cdisk child
/// process and the composite disk image partition configuration for it.
fn convert_partitions(partitions: &[Partition]) -> Result<(Vec<PartitionInfo>, Vec<File>), Error> {
    // File descriptors to pass to child process.
    let mut files = vec![];

    let partitions = partitions
        .iter()
        .map(|partition| {
            // TODO(b/187187765): This shouldn't be an Option.
            let file = partition
                .image
                .as_ref()
                .context("Invalid partition image file descriptor")?
                .as_ref()
                .try_clone()
                .context("Failed to clone partition image file descriptor")?;
            let size = get_partition_size(&file)?;
            let fd = file.as_raw_fd();
            files.push(file);

            Ok(PartitionInfo {
                label: partition.label.to_owned(),
                files: vec![PartitionFileInfo {
                    path: format!("/proc/self/fd/{}", fd).into(),
                    size,
                }],
                partition_type: ImagePartitionType::LinuxFilesystem,
                writable: partition.writable,
            })
        })
        .collect::<Result<_, Error>>()?;

    Ok((partitions, files))
}

/// Find the size of the partition image in the given file by parsing the header.
///
/// This will work for raw, QCOW2, composite and Android sparse images.
fn get_partition_size(partition: &File) -> Result<u64, Error> {
    // TODO: Use `context` once disk::Error implements std::error::Error.
    Ok(create_disk_file(partition.try_clone()?)
        .map_err(|e| anyhow!("Failed to open partition image: {}", e))?
        .get_len()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beginning_size() {
        let mut buffer = vec![];
        let partitions = [0u8; GPT_NUM_PARTITIONS as usize * GPT_PARTITION_ENTRY_SIZE as usize];
        let disk_size = 1000 * SECTOR_SIZE;
        write_beginning(
            &mut buffer,
            Uuid::from_u128(0x12345678_1234_5678_abcd_12345678abcd),
            &partitions,
            42,
            disk_size - GPT_END_SIZE,
            disk_size,
        )
        .unwrap();

        assert_eq!(buffer.len(), GPT_BEGINNING_SIZE as usize);
    }

    #[test]
    fn end_size() {
        let mut buffer = vec![];
        let partitions = [0u8; GPT_NUM_PARTITIONS as usize * GPT_PARTITION_ENTRY_SIZE as usize];
        let disk_size = 1000 * SECTOR_SIZE;
        write_end(
            &mut buffer,
            Uuid::from_u128(0x12345678_1234_5678_abcd_12345678abcd),
            &partitions,
            42,
            disk_size - GPT_END_SIZE,
            disk_size,
        )
        .unwrap();

        assert_eq!(buffer.len(), GPT_END_SIZE as usize);
    }

    #[test]
    fn end_size_with_padding() {
        let mut buffer = vec![];
        let partitions = [0u8; GPT_NUM_PARTITIONS as usize * GPT_PARTITION_ENTRY_SIZE as usize];
        let disk_size = 1000 * SECTOR_SIZE;
        let padding = 3 * SECTOR_SIZE;
        write_end(
            &mut buffer,
            Uuid::from_u128(0x12345678_1234_5678_abcd_12345678abcd),
            &partitions,
            42,
            disk_size - GPT_END_SIZE - padding,
            disk_size,
        )
        .unwrap();

        assert_eq!(buffer.len(), GPT_END_SIZE as usize + padding as usize);
    }
}
