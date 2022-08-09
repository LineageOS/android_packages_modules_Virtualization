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

#[test]
fn test_dump() {
    // test.avmd is generated with
    // ```
    // avmdtool create /tmp/test.amvd \
    // --apex-payload microdroid vbmeta ./libs/apexutil/tests/data/test.apex \
    // --apk microdroid_manager apk \
    // ./libs/apkverify/tests/data/v3-only-with-rsa-pkcs1-sha256-4096.apk \
    // --apk microdroid_manager extra-apk ./libs/apkverify/tests/data/v3-only-with-stamp.apk
    //```
    let output =
        Command::new("./avmdtool").args(["dump", "tests/data/test.avmd"]).output().unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, fs::read("tests/data/test.avmd.dump").unwrap());
}
