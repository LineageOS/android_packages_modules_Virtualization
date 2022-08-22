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

//! Integration test for VM bootloader.

use android_system_virtualizationservice::{
    aidl::android::system::virtualizationservice::{
        VirtualMachineConfig::VirtualMachineConfig,
        VirtualMachineRawConfig::VirtualMachineRawConfig,
    },
    binder::{ParcelFileDescriptor, ProcessState},
};
use anyhow::{Context, Error};
use log::info;
use std::{
    fs::File,
    io,
    os::unix::io::{AsRawFd, FromRawFd},
};
use vmclient::{DeathReason, VmInstance};

const VMBASE_EXAMPLE_PATH: &str =
    "/data/local/tmp/vmbase_example.integration_test/arm64/vmbase_example.bin";

/// Runs the vmbase_example VM as an unprotected VM via VirtualizationService.
#[test]
fn test_run_example_vm() -> Result<(), Error> {
    env_logger::init();

    // We need to start the thread pool for Binder to work properly, especially link_to_death.
    ProcessState::start_thread_pool();

    let service = vmclient::connect().context("Failed to find VirtualizationService")?;

    // Start example VM.
    let bootloader = ParcelFileDescriptor::new(
        File::open(VMBASE_EXAMPLE_PATH)
            .with_context(|| format!("Failed to open VM image {}", VMBASE_EXAMPLE_PATH))?,
    );

    let config = VirtualMachineConfig::RawConfig(VirtualMachineRawConfig {
        name: String::from("VmBaseTest"),
        kernel: None,
        initrd: None,
        params: None,
        bootloader: Some(bootloader),
        disks: vec![],
        protectedVm: false,
        memoryMib: 300,
        numCpus: 1,
        cpuAffinity: None,
        platformVersion: "~1.0".to_string(),
        taskProfiles: vec![],
    });
    let console = duplicate_stdout()?;
    let log = duplicate_stdout()?;
    let vm = VmInstance::create(service.as_ref(), &config, Some(console), Some(log), None)
        .context("Failed to create VM")?;
    vm.start().context("Failed to start VM")?;
    info!("Started example VM.");

    // Wait for VM to finish, and check that it shut down cleanly.
    let death_reason = vm.wait_for_death();
    assert_eq!(death_reason, DeathReason::Shutdown);

    Ok(())
}

/// Safely duplicate the standard output file descriptor.
fn duplicate_stdout() -> io::Result<File> {
    let stdout_fd = io::stdout().as_raw_fd();
    // Safe because this just duplicates a file descriptor which we know to be valid, and we check
    // for an error.
    let dup_fd = unsafe { libc::dup(stdout_fd) };
    if dup_fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // Safe because we have just duplicated the file descriptor so we own it, and `from_raw_fd`
        // takes ownership of it.
        Ok(unsafe { File::from_raw_fd(dup_fd) })
    }
}
