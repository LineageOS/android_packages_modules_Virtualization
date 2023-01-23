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

//! Tool for handling AVMD blobs.

use anyhow::{anyhow, bail, Result};
use apexutil::get_payload_vbmeta_image_hash;
use apkverify::get_apk_digest;
use avmd::{ApkDescriptor, Avmd, Descriptor, ResourceIdentifier, VbMetaDescriptor};
use clap::{
    builder::ValueParser,
    parser::{Indices, ValuesRef},
    Arg, ArgAction, ArgMatches, Command,
};
use serde::ser::Serialize;
use std::{fs::File, path::PathBuf};
use vbmeta::VbMetaImage;

fn get_vbmeta_image_hash(file: &str) -> Result<Vec<u8>> {
    let img = VbMetaImage::verify_path(file)?;
    Ok(img.hash().ok_or_else(|| anyhow!("No hash as VBMeta image isn't signed"))?.to_vec())
}

/// Iterate over a set of argument values, that could be empty or come in
/// (<index>, <namespace>, <name>, <file>) tuple.
struct NamespaceNameFileIterator<'a> {
    indices: Option<Indices<'a>>,
    values: Option<ValuesRef<'a, String>>,
}

impl<'a> NamespaceNameFileIterator<'a> {
    fn new(args: &'a ArgMatches, name: &'a str) -> Self {
        NamespaceNameFileIterator { indices: args.indices_of(name), values: args.get_many(name) }
    }
}

impl<'a> Iterator for NamespaceNameFileIterator<'a> {
    type Item = (usize, &'a str, &'a str, &'a str);

    fn next(&mut self) -> Option<Self::Item> {
        match (self.indices.as_mut(), self.values.as_mut()) {
            (Some(indices), Some(values)) => {
                match (indices.nth(2), values.next(), values.next(), values.next()) {
                    (Some(index), Some(namespace), Some(name), Some(file)) => {
                        Some((index, namespace, name, file))
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }
}

fn create(args: &ArgMatches) -> Result<()> {
    // Store descriptors in the order they were given in the arguments
    // TODO: instead, group them by namespace?
    let mut descriptors = std::collections::BTreeMap::new();
    for (i, namespace, name, file) in NamespaceNameFileIterator::new(args, "vbmeta") {
        descriptors.insert(
            i,
            Descriptor::VbMeta(VbMetaDescriptor {
                resource: ResourceIdentifier::new(namespace, name),
                vbmeta_digest: get_vbmeta_image_hash(file)?,
            }),
        );
    }
    for (i, namespace, name, file) in NamespaceNameFileIterator::new(args, "apk") {
        let file = File::open(file)?;
        let (signature_algorithm_id, apk_digest) = get_apk_digest(file, /*verify=*/ true)?;
        descriptors.insert(
            i,
            Descriptor::Apk(ApkDescriptor {
                resource: ResourceIdentifier::new(namespace, name),
                signature_algorithm_id,
                apk_digest: apk_digest.to_vec(),
            }),
        );
    }
    for (i, namespace, name, file) in NamespaceNameFileIterator::new(args, "apex-payload") {
        descriptors.insert(
            i,
            Descriptor::VbMeta(VbMetaDescriptor {
                resource: ResourceIdentifier::new(namespace, name),
                vbmeta_digest: get_payload_vbmeta_image_hash(file)?,
            }),
        );
    }
    let avmd = Avmd::new(descriptors.into_values().collect());
    let mut bytes = Vec::new();
    avmd.serialize(
        &mut serde_cbor::Serializer::new(&mut serde_cbor::ser::IoWrite::new(&mut bytes))
            .packed_format()
            .legacy_enums(),
    )?;
    std::fs::write(args.get_one::<PathBuf>("file").unwrap(), &bytes)?;
    Ok(())
}

fn dump(args: &ArgMatches) -> Result<()> {
    let file = std::fs::read(args.get_one::<PathBuf>("file").unwrap())?;
    let avmd: Avmd = serde_cbor::from_slice(&file)?;
    println!("{}", avmd);
    Ok(())
}

fn clap_command() -> Command {
    let namespace_name_file = ["namespace", "name", "file"];

    Command::new("avmdtool")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("create")
                .arg_required_else_help(true)
                .arg(Arg::new("file").value_parser(ValueParser::path_buf()).required(true))
                .arg(
                    Arg::new("vbmeta")
                        .long("vbmeta")
                        .value_names(namespace_name_file)
                        .num_args(3)
                        .action(ArgAction::Append),
                )
                .arg(
                    Arg::new("apk")
                        .long("apk")
                        .value_names(namespace_name_file)
                        .num_args(3)
                        .action(ArgAction::Append),
                )
                .arg(
                    Arg::new("apex-payload")
                        .long("apex-payload")
                        .value_names(namespace_name_file)
                        .num_args(3)
                        .action(ArgAction::Append),
                ),
        )
        .subcommand(
            Command::new("dump")
                .arg_required_else_help(true)
                .arg(Arg::new("file").value_parser(ValueParser::path_buf()).required(true)),
        )
}

fn main() -> Result<()> {
    let args = clap_command().get_matches();
    match args.subcommand() {
        Some(("create", sub_args)) => create(sub_args)?,
        Some(("dump", sub_args)) => dump(sub_args)?,
        _ => bail!("Invalid arguments"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_command() {
        // Check that the command parsing has been configured in a valid way.
        clap_command().debug_assert();
    }
}
