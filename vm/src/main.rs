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

mod create_idsig;
mod create_partition;
mod run;

use android_system_virtualizationservice::aidl::android::system::virtualizationservice::{
    IVirtualizationService::IVirtualizationService, PartitionType::PartitionType,
    VirtualMachineAppConfig::DebugLevel::DebugLevel,
};
use anyhow::{Context, Error};
use binder::ProcessState;
use clap::Parser;
use create_idsig::command_create_idsig;
use create_partition::command_create_partition;
use run::{command_run, command_run_app, command_run_microdroid};
use rustutils::system_properties;
use std::path::{Path, PathBuf};

#[derive(Debug)]
struct Idsigs(Vec<PathBuf>);

#[derive(Parser)]
enum Opt {
    /// Run a virtual machine with a config in APK
    RunApp {
        /// Path to VM Payload APK
        apk: PathBuf,

        /// Path to idsig of the APK
        idsig: PathBuf,

        /// Path to the instance image. Created if not exists.
        instance: PathBuf,

        /// Path to VM config JSON within APK (e.g. assets/vm_config.json)
        #[clap(long)]
        config_path: Option<String>,

        /// Path to VM payload binary within APK (e.g. MicrodroidTestNativeLib.so)
        #[clap(long)]
        payload_path: Option<String>,

        /// Name of VM
        #[clap(long)]
        name: Option<String>,

        /// Detach VM from the terminal and run in the background
        #[clap(short, long)]
        daemonize: bool,

        /// Path to the file backing the storage.
        /// Created if the option is used but the path does not exist in the device.
        #[clap(long)]
        storage: Option<PathBuf>,

        /// Size of the storage. Used only if --storage is supplied but path does not exist
        /// Default size is 10*1024*1024
        #[clap(long)]
        storage_size: Option<u64>,

        /// Path to file for VM console output.
        #[clap(long)]
        console: Option<PathBuf>,

        /// Path to file for VM log output.
        #[clap(long)]
        log: Option<PathBuf>,

        /// Path to file where ramdump is recorded on kernel panic
        #[clap(long)]
        ramdump: Option<PathBuf>,

        /// Debug level of the VM. Supported values: "none" (default), "app_only", and "full".
        #[clap(long, default_value = "none", value_parser = parse_debug_level)]
        debug: DebugLevel,

        /// Run VM in protected mode.
        #[clap(short, long)]
        protected: bool,

        /// Memory size (in MiB) of the VM. If unspecified, defaults to the value of `memory_mib`
        /// in the VM config file.
        #[clap(short, long)]
        mem: Option<u32>,

        /// Number of vCPUs in the VM. If unspecified, defaults to 1.
        #[clap(long)]
        cpus: Option<u32>,

        /// Comma separated list of task profile names to apply to the VM
        #[clap(long)]
        task_profiles: Vec<String>,

        /// Paths to extra idsig files.
        #[clap(long = "extra-idsig")]
        extra_idsigs: Vec<PathBuf>,
    },
    /// Run a virtual machine with Microdroid inside
    RunMicrodroid {
        /// Path to the directory where VM-related files (e.g. instance.img, apk.idsig, etc.) will
        /// be stored. If not specified a random directory under /data/local/tmp/microdroid will be
        /// created and used.
        #[clap(long)]
        work_dir: Option<PathBuf>,

        /// Name of VM
        #[clap(long)]
        name: Option<String>,

        /// Detach VM from the terminal and run in the background
        #[clap(short, long)]
        daemonize: bool,

        /// Path to the file backing the storage.
        /// Created if the option is used but the path does not exist in the device.
        #[clap(long)]
        storage: Option<PathBuf>,

        /// Size of the storage. Used only if --storage is supplied but path does not exist
        /// Default size is 10*1024*1024
        #[clap(long)]
        storage_size: Option<u64>,

        /// Path to file for VM console output.
        #[clap(long)]
        console: Option<PathBuf>,

        /// Path to file for VM log output.
        #[clap(long)]
        log: Option<PathBuf>,

        /// Path to file where ramdump is recorded on kernel panic
        #[clap(long)]
        ramdump: Option<PathBuf>,

        /// Debug level of the VM. Supported values: "none" (default), "app_only", and "full".
        #[clap(long, default_value = "full", value_parser = parse_debug_level)]
        debug: DebugLevel,

        /// Run VM in protected mode.
        #[clap(short, long)]
        protected: bool,

        /// Memory size (in MiB) of the VM. If unspecified, defaults to the value of `memory_mib`
        /// in the VM config file.
        #[clap(short, long)]
        mem: Option<u32>,

        /// Number of vCPUs in the VM. If unspecified, defaults to 1.
        #[clap(long)]
        cpus: Option<u32>,

        /// Comma separated list of task profile names to apply to the VM
        #[clap(long)]
        task_profiles: Vec<String>,
    },
    /// Run a virtual machine
    Run {
        /// Path to VM config JSON
        config: PathBuf,

        /// Name of VM
        #[clap(long)]
        name: Option<String>,

        /// Detach VM from the terminal and run in the background
        #[clap(short, long)]
        daemonize: bool,

        /// Number of vCPUs in the VM. If unspecified, defaults to 1.
        #[clap(long)]
        cpus: Option<u32>,

        /// Comma separated list of task profile names to apply to the VM
        #[clap(long)]
        task_profiles: Vec<String>,

        /// Path to file for VM console output.
        #[clap(long)]
        console: Option<PathBuf>,

        /// Path to file for VM log output.
        #[clap(long)]
        log: Option<PathBuf>,
    },
    /// Stop a virtual machine running in the background
    Stop {
        /// CID of the virtual machine
        cid: u32,
    },
    /// List running virtual machines
    List,
    /// Print information about virtual machine support
    Info,
    /// Create a new empty partition to be used as a writable partition for a VM
    CreatePartition {
        /// Path at which to create the image file
        path: PathBuf,

        /// The desired size of the partition, in bytes.
        size: u64,

        /// Type of the partition
        #[clap(short = 't', long = "type", default_value = "raw",
               value_parser = parse_partition_type)]
        partition_type: PartitionType,
    },
    /// Creates or update the idsig file by digesting the input APK file.
    CreateIdsig {
        /// Path to VM Payload APK
        apk: PathBuf,

        /// Path to idsig of the APK
        path: PathBuf,
    },
}

fn parse_debug_level(s: &str) -> Result<DebugLevel, String> {
    match s {
        "none" => Ok(DebugLevel::NONE),
        "app_only" => Ok(DebugLevel::APP_ONLY),
        "full" => Ok(DebugLevel::FULL),
        _ => Err(format!("Invalid debug level {}", s)),
    }
}

fn parse_partition_type(s: &str) -> Result<PartitionType, String> {
    match s {
        "raw" => Ok(PartitionType::RAW),
        "instance" => Ok(PartitionType::ANDROID_VM_INSTANCE),
        _ => Err(format!("Invalid partition type {}", s)),
    }
}

fn main() -> Result<(), Error> {
    env_logger::init();
    let opt = Opt::parse();

    // We need to start the thread pool for Binder to work properly, especially link_to_death.
    ProcessState::start_thread_pool();

    let service = vmclient::connect().context("Failed to find VirtualizationService")?;

    match opt {
        Opt::RunApp {
            name,
            apk,
            idsig,
            instance,
            storage,
            storage_size,
            config_path,
            payload_path,
            daemonize,
            console,
            log,
            ramdump,
            debug,
            protected,
            mem,
            cpus,
            task_profiles,
            extra_idsigs,
        } => command_run_app(
            name,
            service.as_ref(),
            &apk,
            &idsig,
            &instance,
            storage.as_deref(),
            storage_size,
            config_path,
            payload_path,
            daemonize,
            console.as_deref(),
            log.as_deref(),
            ramdump.as_deref(),
            debug,
            protected,
            mem,
            cpus,
            task_profiles,
            &extra_idsigs,
        ),
        Opt::RunMicrodroid {
            name,
            work_dir,
            storage,
            storage_size,
            daemonize,
            console,
            log,
            ramdump,
            debug,
            protected,
            mem,
            cpus,
            task_profiles,
        } => command_run_microdroid(
            name,
            service.as_ref(),
            work_dir,
            storage.as_deref(),
            storage_size,
            daemonize,
            console.as_deref(),
            log.as_deref(),
            ramdump.as_deref(),
            debug,
            protected,
            mem,
            cpus,
            task_profiles,
        ),
        Opt::Run { name, config, daemonize, cpus, task_profiles, console, log } => {
            command_run(
                name,
                service.as_ref(),
                &config,
                daemonize,
                console.as_deref(),
                log.as_deref(),
                /* mem */ None,
                cpus,
                task_profiles,
            )
        }
        Opt::Stop { cid } => command_stop(service.as_ref(), cid),
        Opt::List => command_list(service.as_ref()),
        Opt::Info => command_info(),
        Opt::CreatePartition { path, size, partition_type } => {
            command_create_partition(service.as_ref(), &path, size, partition_type)
        }
        Opt::CreateIdsig { apk, path } => command_create_idsig(service.as_ref(), &apk, &path),
    }
}

/// Retrieve reference to a previously daemonized VM and stop it.
fn command_stop(service: &dyn IVirtualizationService, cid: u32) -> Result<(), Error> {
    service
        .debugDropVmRef(cid as i32)
        .context("Failed to get VM from VirtualizationService")?
        .context("CID does not correspond to a running background VM")?;
    Ok(())
}

/// List the VMs currently running.
fn command_list(service: &dyn IVirtualizationService) -> Result<(), Error> {
    let vms = service.debugListVms().context("Failed to get list of VMs")?;
    println!("Running VMs: {:#?}", vms);
    Ok(())
}

/// Print information about supported VM types.
fn command_info() -> Result<(), Error> {
    let unprotected_vm_supported =
        system_properties::read_bool("ro.boot.hypervisor.vm.supported", false)?;
    let protected_vm_supported =
        system_properties::read_bool("ro.boot.hypervisor.protected_vm.supported", false)?;
    match (unprotected_vm_supported, protected_vm_supported) {
        (false, false) => println!("VMs are not supported."),
        (false, true) => println!("Only protected VMs are supported."),
        (true, false) => println!("Only unprotected VMs are supported."),
        (true, true) => println!("Both protected and unprotected VMs are supported."),
    }

    if let Some(version) = system_properties::read("ro.boot.hypervisor.version")? {
        println!("Hypervisor version: {}", version);
    } else {
        println!("Hypervisor version not set.");
    }

    if Path::new("/dev/kvm").exists() {
        println!("/dev/kvm exists.");
    } else {
        println!("/dev/kvm does not exist.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::IntoApp;

    #[test]
    fn verify_app() {
        Opt::into_app().debug_assert();
    }
}
