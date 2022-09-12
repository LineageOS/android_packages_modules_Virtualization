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

//! Append bootconfig to initrd image
use anyhow::Result;
use clap::Parser;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;

const FOOTER_ALIGNMENT: usize = 4;
const ZEROS: [u8; 4] = [0u8; 4_usize];

#[derive(Parser, Debug)]
struct Args {
    /// Initrd (without bootconfig)
    initrd: PathBuf,
    /// Bootconfig
    bootconfigs: Vec<PathBuf>,
    /// Output
    #[clap(long = "output")]
    output: PathBuf,
}

fn get_checksum(file_path: &PathBuf) -> Result<u32> {
    File::open(file_path)?.bytes().map(|x| Ok(x? as u32)).sum()
}

// Bootconfig is attached to the initrd in the following way:
// [initrd][bootconfig][padding][size(le32)][checksum(le32)][#BOOTCONFIG\n]
fn attach_bootconfig(initrd: PathBuf, bootconfigs: Vec<PathBuf>, output: PathBuf) -> Result<()> {
    let mut output_file = File::create(&output)?;
    let mut initrd_file = File::open(&initrd)?;
    let initrd_size: usize = initrd_file.metadata()?.len().try_into()?;
    let mut bootconfig_size: usize = 0;
    let mut checksum: u32 = 0;

    std::io::copy(&mut initrd_file, &mut output_file)?;
    for bootconfig in bootconfigs {
        let mut bootconfig_file = File::open(&bootconfig)?;
        std::io::copy(&mut bootconfig_file, &mut output_file)?;
        bootconfig_size += bootconfig_file.metadata()?.len() as usize;
        checksum += get_checksum(&bootconfig)?;
    }

    let padding_size: usize = FOOTER_ALIGNMENT - (initrd_size + bootconfig_size) % FOOTER_ALIGNMENT;
    output_file.write_all(&ZEROS[..padding_size])?;
    output_file.write_all(&((padding_size + bootconfig_size) as u32).to_le_bytes())?;
    output_file.write_all(&checksum.to_le_bytes())?;
    output_file.write_all(b"#BOOTCONFIG\n")?;
    output_file.flush()?;
    Ok(())
}

fn try_main() -> Result<()> {
    let args = Args::parse();
    attach_bootconfig(args.initrd, args.bootconfigs, args.output)?;
    Ok(())
}

fn main() {
    try_main().unwrap()
}
