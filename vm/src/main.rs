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

//! Android VM control tool.

mod sync;

use android_system_virtmanager::aidl::android::system::virtmanager::IVirtManager::IVirtManager;
use android_system_virtmanager::binder::{get_interface, ProcessState, Strong};
use anyhow::{bail, Context, Error};
// TODO: Import these via android_system_virtmanager::binder once https://r.android.com/1619403 is
// submitted.
use binder::{DeathRecipient, IBinder};
use std::env;
use std::process::exit;
use sync::AtomicFlag;

const VIRT_MANAGER_BINDER_SERVICE_IDENTIFIER: &str = "android.system.virtmanager";

fn main() -> Result<(), Error> {
    env_logger::init();

    let args: Vec<_> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage:");
        eprintln!("  {} run <vm_config.json>", args[0]);
        exit(1);
    }

    // We need to start the thread pool for Binder to work properly, especially link_to_death.
    ProcessState::start_thread_pool();

    match args[1].as_ref() {
        "run" if args.len() == 3 => command_run(&args[2]),
        command => bail!("Invalid command '{}' or wrong number of arguments", command),
    }
}

/// Run a VM from the given configuration file.
fn command_run(config_filename: &str) -> Result<(), Error> {
    let virt_manager: Strong<dyn IVirtManager> =
        get_interface(VIRT_MANAGER_BINDER_SERVICE_IDENTIFIER)
            .with_context(|| "Failed to find Virt Manager service")?;
    let vm = virt_manager.startVm(config_filename).with_context(|| "Failed to start VM")?;
    let cid = vm.getCid().with_context(|| "Failed to get CID")?;
    println!("Started VM from {} with CID {}.", config_filename, cid);

    // Wait until the VM dies. If we just returned immediately then the IVirtualMachine Binder
    // object would be dropped and the VM would be killed.
    wait_for_death(&mut vm.as_binder())?;
    println!("VM died");
    Ok(())
}

/// Block until the given Binder object dies.
fn wait_for_death(binder: &mut impl IBinder) -> Result<(), Error> {
    let dead = AtomicFlag::default();
    let mut death_recipient = {
        let dead = dead.clone();
        DeathRecipient::new(move || {
            dead.raise();
        })
    };
    binder.link_to_death(&mut death_recipient)?;
    dead.wait();
    Ok(())
}
