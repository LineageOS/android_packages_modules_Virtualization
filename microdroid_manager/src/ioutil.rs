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

//! IO utilities

use std::fs::File;
use std::io;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

const SLEEP_DURATION: Duration = Duration::from_millis(5);

/// waits for a file with a timeout and returns it
pub fn wait_for_file<P: AsRef<Path>>(path: P, timeout: Duration) -> io::Result<File> {
    let begin = Instant::now();
    loop {
        match File::open(&path) {
            Ok(file) => return Ok(file),
            Err(error) => {
                if error.kind() != io::ErrorKind::NotFound {
                    return Err(error);
                }
                if begin.elapsed() > timeout {
                    return Err(io::Error::from(io::ErrorKind::NotFound));
                }
                thread::sleep(SLEEP_DURATION);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn test_wait_for_file() -> io::Result<()> {
        let test_dir = tempfile::TempDir::new().unwrap();
        let test_file = test_dir.path().join("test.txt");
        thread::spawn(move || -> io::Result<()> {
            thread::sleep(Duration::from_secs(1));
            File::create(test_file)?.write_all(b"test")
        });

        let test_file = test_dir.path().join("test.txt");
        let mut file = wait_for_file(&test_file, Duration::from_secs(5))?;
        let mut buffer = String::new();
        file.read_to_string(&mut buffer)?;
        assert_eq!("test", buffer);
        Ok(())
    }

    #[test]
    fn test_wait_for_file_fails() {
        let test_dir = tempfile::TempDir::new().unwrap();
        let test_file = test_dir.path().join("test.txt");
        let file = wait_for_file(&test_file, Duration::from_secs(1));
        assert!(file.is_err());
        assert_eq!(io::ErrorKind::NotFound, file.unwrap_err().kind());
    }
}
