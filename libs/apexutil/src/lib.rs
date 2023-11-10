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

//! Routines for handling APEX payload

use apex_manifest::apex_manifest::ApexManifest;
use protobuf::Message;
use std::fs::File;
use std::io::{self, Read};
use thiserror::Error;
use vbmeta::VbMetaImage;
use zip::result::ZipError;
use zip::ZipArchive;

const APEX_PUBKEY_ENTRY: &str = "apex_pubkey";
const APEX_PAYLOAD_ENTRY: &str = "apex_payload.img";
const APEX_MANIFEST_ENTRY: &str = "apex_manifest.pb";

/// Errors from parsing an APEX.
#[derive(Debug, Error)]
pub enum ApexParseError {
    /// There was an IO error.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    /// The Zip archive was invalid.
    #[error("Cannot read zip archive: {0}")]
    InvalidZip(&'static str),
    /// An expected file was missing from the APEX.
    #[error("APEX doesn't contain {0}")]
    MissingFile(&'static str),
    /// There was no hashtree descriptor in the APEX payload's VBMeta image.
    #[error("Non-hashtree descriptor found in payload's VBMeta image")]
    DescriptorNotHashtree,
    /// There was an error parsing the APEX payload's VBMeta image.
    #[error("Could not parse payload's VBMeta image: {0}")]
    PayloadVbmetaError(#[from] vbmeta::VbMetaImageParseError),
    /// Data was missing from the VBMeta
    #[error("Data missing from VBMeta: {0}")]
    VbmetaMissingData(&'static str),
    /// An error occurred parsing the APEX manifest as a protobuf
    #[error("Error parsing manifest protobuf: {0}")]
    ManifestProtobufError(#[from] protobuf::Error),
}

/// Errors from verifying an APEX.
#[derive(Debug, Error)]
pub enum ApexVerificationError {
    /// There was an error parsing the APEX.
    #[error("Cannot parse APEX file")]
    ParseError(#[from] ApexParseError),
    /// There was an error validating the APEX payload's VBMeta image.
    #[error("Could not parse payload's VBMeta image")]
    PayloadVbmetaError(#[from] vbmeta::VbMetaImageVerificationError),
    /// The APEX payload was not verified with the apex_pubkey.
    #[error("APEX pubkey mismatch")]
    ApexPubkeyMismatch,
}

/// Information extracted from the APEX during verification.
pub struct ApexVerificationResult {
    /// The name of the APEX, from its manifest. Unverified, but apexd will reject
    /// an APEX where the unsigned manifest isn't the same as the signed one.
    pub name: String,
    /// The version of the APEX, from its manifest. Unverified, but apexd will reject
    /// an APEX where the unsigned manifest isn't the same as the signed one.
    pub version: i64,
    /// The public key that verifies the payload signature.
    pub public_key: Vec<u8>,
    /// The root digest of the payload hashtree.
    pub root_digest: Vec<u8>,
    /// The hash of the verified VBMeta image data.
    /// TODO(alanstokes): Delete this if we don't have a use for it.
    pub image_hash: Vec<u8>,
}

/// Verify APEX payload by AVB verification and return information about the APEX.
pub fn verify(path: &str) -> Result<ApexVerificationResult, ApexVerificationError> {
    let apex_file = File::open(path).map_err(ApexParseError::Io)?;
    let ApexZipInfo { public_key, image_offset, image_size, manifest } =
        get_apex_zip_info(&apex_file)?;
    let vbmeta = VbMetaImage::verify_reader_region(apex_file, image_offset, image_size)?;
    let root_digest = find_root_digest(&vbmeta)?;
    let vbmeta_public_key =
        vbmeta.public_key().ok_or(ApexParseError::VbmetaMissingData("public key"))?;
    if vbmeta_public_key != public_key {
        return Err(ApexVerificationError::ApexPubkeyMismatch);
    }
    let image_hash = vbmeta.hash().ok_or(ApexParseError::VbmetaMissingData("hash"))?.to_vec();
    let ApexManifestInfo { name, version } = decode_manifest(&manifest)?;

    Ok(ApexVerificationResult { name, version, public_key, root_digest, image_hash })
}

fn find_root_digest(vbmeta: &VbMetaImage) -> Result<Vec<u8>, ApexParseError> {
    // APEXs use the root digest from the first hashtree descriptor to describe the payload.
    for descriptor in vbmeta.descriptors()?.iter() {
        if let vbmeta::Descriptor::Hashtree(_) = descriptor {
            return Ok(descriptor.to_hashtree()?.root_digest().to_vec());
        }
    }
    Err(ApexParseError::DescriptorNotHashtree)
}

struct ApexZipInfo {
    public_key: Vec<u8>,
    image_offset: u64,
    image_size: u64,
    manifest: Vec<u8>,
}

fn get_apex_zip_info(apex_file: &File) -> Result<ApexZipInfo, ApexParseError> {
    let mut z = ZipArchive::new(apex_file).map_err(|err| from_zip_error(err, "?"))?;

    let mut public_key = Vec::new();
    z.by_name(APEX_PUBKEY_ENTRY)
        .map_err(|err| from_zip_error(err, APEX_PUBKEY_ENTRY))?
        .read_to_end(&mut public_key)?;

    let (image_offset, image_size) = z
        .by_name(APEX_PAYLOAD_ENTRY)
        .map(|f| (f.data_start(), f.size()))
        .map_err(|err| from_zip_error(err, APEX_PAYLOAD_ENTRY))?;

    let mut manifest = Vec::new();
    z.by_name(APEX_MANIFEST_ENTRY)
        .map_err(|err| from_zip_error(err, APEX_MANIFEST_ENTRY))?
        .read_to_end(&mut manifest)?;

    Ok(ApexZipInfo { public_key, image_offset, image_size, manifest })
}

struct ApexManifestInfo {
    name: String,
    version: i64,
}

fn decode_manifest(mut manifest: &[u8]) -> Result<ApexManifestInfo, ApexParseError> {
    let manifest = ApexManifest::parse_from_reader(&mut manifest)?;
    Ok(ApexManifestInfo { name: manifest.name, version: manifest.version })
}

fn from_zip_error(err: ZipError, name: &'static str) -> ApexParseError {
    match err {
        ZipError::Io(err) => ApexParseError::Io(err),
        ZipError::InvalidArchive(s) | ZipError::UnsupportedArchive(s) => {
            ApexParseError::InvalidZip(s)
        }
        ZipError::FileNotFound => ApexParseError::MissingFile(name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apex_verification_returns_valid_result() {
        let res = verify("tests/data/test.apex").unwrap();
        // The expected hex is generated when we ran the method the first time.
        assert_eq!(res.name, "com.android.apex.cts.shim");
        assert_eq!(res.version, 1);
        assert_eq!(
            hex::encode(res.public_key),
            "000010007093e081b637735012c7f2\
            fdacba9b1c01ee2eaa78e7fb69fa810a0e3fff8d70cd69c60eb6458c54c56c6a40e2f68\
            60c69343c1373eb1785c4e81eca1c8921390da5997115668ef4c5f5cb90d74df3fc29dd\
            d05d45e298761beba76276669540d5cfe9c79ed1e001637871db4f0d0083d56332fe328\
            9f1f3aec8d00b06a7db25104d5a05226ab499cd6536434ff8f1d01ca1c653a91d58ee41\
            a848571abf9ba555610a1dc3555911386f07109c3c9e420a17b8f63c58c74410a94cedd\
            2e3e8203f4e638b620836742331049c96423c01fbe2609962e35d38d127730692f7e947\
            80bb21017b4583c9fb59e9f7421a92cff4d4dd6095d5aca2f5f13b9c5320ff0f3fc84bb\
            b347bbe7fc08b6081d2157bddae97845e2c58da58d9d56732dd90d5b59116db404b859c\
            b68b4c51790d06337bf939201f5ab356a50242d7e50e29f53f0525ab1693d6b1db1acbd\
            540dd8eb310accee7b3938b471a1768163c226a44483e0e4453cde393f5495bfe10297d\
            68f1bfed44b386c5c2ecde221607635ef14aadcba153f1f916d7c1fc92fab1b04f964f8\
            5660033024084d5b27760e61967c9df5e2a099bdc63e3c3864b15fd3caa85274ab7b02d\
            8933c2a5e4460adbf95aae0774945e9a5c0abb15f2d533259cb090ea5be513572bd75cc\
            5eaf23fe4f5dbe4b8fee525059ae0d8c7813704f2b9fc641525075d2ce6e44bd0955c10\
            f8383f87b0d3a07f524893b78bb67d5428cfa430e863f121c1de0205d3dd64f3a78c5d8\
            e802dfaa078f07c4626c4a280224816958a1e621d05184214f675a7cd1c55b6c5a2b18e\
            358f84c4b1068b8d2aace966c47674204ada4b5376b55fd9c145b1224ddb4f578f6279d\
            d92a381f3a11235be8331ce15754374426a35aa6f17586f1658d48f30c3220fec43b3d5\
            ca7ed0f8de14225b19ab699fb75c95299b8f81559fe41df31e4d591692d86482c50c3ba\
            ccfeb002ead775eca116b5674bd8f4f2c5db54bd21596d980f2067e331bc0e30a56c25f\
            6fd7d5f2a03651198f0c7494add16889dbb49cc79038fd8bc2e7540c3101e5cbbb1f8d6\
            f0eab86f83eb76ef5d6df29f0c718019c26f8e38d86a54f2b992a17a0c9e00a298e866d\
            53e2ff78f35de1ccdf166375309397a43b74cf7a34a647a3ee0234dbf4744c6db5f44f7\
            1a366d87024ec3a5ec4185ac7cc0342460160632f21b791e12b656c71c248cce5fbb45f\
            3c624852ea9c29264c6b8ad58ac36bf99cf5254d1e69c628bdf1707136475230bbedf1f\
            ac25849b249795456d5d99214800e44a6d71c460eb495d9926145606d7cbb986044c9f0\
            11b6d6be5c79f89a6f90ad39676489eac632b105cbf3da29bf7e4e72bf82600bcafc867\
            f4cb6e0ade8f532d9620b82001c69493ff5679cf0393285aa67b3e4382c8e785e43efe9\
            7e56fbd24357eec0b19697194f0b91ee46ab82dfeea788"
        );
        assert_eq!(
            hex::encode(res.root_digest),
            "fe11ab17da0a3a738b54bdc3a13f6139cbdf91ec32f001f8d4bbbf8938e04e39"
        );
        assert_eq!(
            hex::encode(res.image_hash),
            "296e32a76544de9da01713e471403ab4667705ad527bb4f1fac0cf61e7ce122d"
        );
    }
}
