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
use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use serde::ser::Serialize;
use std::fs::File;
use vbmeta::VbMetaImage;

fn get_vbmeta_image_hash(file: &str) -> Result<Vec<u8>> {
    let img = VbMetaImage::verify_path(file)?;
    Ok(img.hash().ok_or_else(|| anyhow!("No hash as VBMeta image isn't signed"))?.to_vec())
}

/// Iterate over a set of argument values, that could be empty or come in
/// (<index>, <namespace>, <name>, <file>) tuple.
struct NamespaceNameFileIterator<'a> {
    indices: Option<clap::Indices<'a>>,
    values: Option<clap::Values<'a>>,
}

impl<'a> NamespaceNameFileIterator<'a> {
    fn new(args: &'a ArgMatches, name: &'a str) -> Self {
        NamespaceNameFileIterator { indices: args.indices_of(name), values: args.values_of(name) }
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
        let (signature_algorithm_id, apk_digest) = get_apk_digest(file, /*verify=*/ false)?;
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
    std::fs::write(args.value_of("file").unwrap(), &bytes)?;
    Ok(())
}

fn dump(args: &ArgMatches) -> Result<()> {
    let file = std::fs::read(args.value_of("file").unwrap())?;
    let avmd: Avmd = serde_cbor::from_slice(&file)?;
    println!("{}", avmd);
    Ok(())
}

fn main() -> Result<()> {
    let namespace_name_file = ["namespace", "name", "file"];
    let app = App::new("avmdtool")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(
            SubCommand::with_name("create")
                .setting(AppSettings::ArgRequiredElseHelp)
                .arg(Arg::with_name("file").required(true).takes_value(true))
                .arg(
                    Arg::with_name("vbmeta")
                        .long("vbmeta")
                        .takes_value(true)
                        .value_names(&namespace_name_file)
                        .multiple(true),
                )
                .arg(
                    Arg::with_name("apk")
                        .long("apk")
                        .takes_value(true)
                        .value_names(&namespace_name_file)
                        .multiple(true),
                )
                .arg(
                    Arg::with_name("apex-payload")
                        .long("apex-payload")
                        .takes_value(true)
                        .value_names(&namespace_name_file)
                        .multiple(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("dump")
                .setting(AppSettings::ArgRequiredElseHelp)
                .arg(Arg::with_name("file").required(true).takes_value(true)),
        );

    let args = app.get_matches();
    match args.subcommand() {
        Some(("create", sub_args)) => create(sub_args)?,
        Some(("dump", sub_args)) => dump(sub_args)?,
        _ => bail!("Invalid arguments"),
    }
    Ok(())
}
