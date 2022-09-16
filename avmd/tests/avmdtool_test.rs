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

//! Tests for avmdtool.

use std::fs;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn test_dump() {
    let filename = "tests/data/test.avmd";
    assert!(
        fs::metadata(filename).is_ok(),
        "File '{}' does not exist. You can re-create it with:
    avmdtool create {} \\
    --apex-payload microdroid vbmeta tests/data/test.apex \\
    --apk microdroid_manager apk \\
    tests/data/v3-only-with-rsa-pkcs1-sha256-4096.apk \\
    --apk microdroid_manager extra-apk tests/data/v3-only-with-stamp.apk",
        filename,
        filename
    );
    let output = Command::new("./avmdtool").args(["dump", filename]).output().unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, fs::read("tests/data/test.avmd.dump").unwrap());
}

#[test]
fn test_create() {
    let test_dir = TempDir::new().unwrap();
    let test_file_path = test_dir.path().join("tmp_test.amvd");
    let output = Command::new("./avmdtool")
        .args([
            "create",
            test_file_path.to_str().unwrap(),
            "--apex-payload",
            "microdroid",
            "vbmeta",
            "tests/data/test.apex",
            "--apk",
            "microdroid_manager",
            "apk",
            "tests/data/v3-only-with-rsa-pkcs1-sha256-4096.apk",
            "--apk",
            "microdroid_manager",
            "extra-apk",
            "tests/data/v3-only-with-stamp.apk",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(fs::read(test_file_path).unwrap(), fs::read("tests/data/test.avmd").unwrap());
}
