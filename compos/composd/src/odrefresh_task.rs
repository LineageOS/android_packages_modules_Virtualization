/*
 * Copyright 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crate::fd_server_helper::FdServerConfig;
use crate::instance_starter::CompOsInstance;
use crate::odrefresh;
use crate::service::open_dir;
use android_system_composd::aidl::android::system::composd::{
    ICompilationTask::ICompilationTask, ICompilationTaskCallback::ICompilationTaskCallback,
};
use android_system_composd::binder::{Interface, Result as BinderResult, Strong};
use anyhow::{bail, Result};
use compos_aidl_interface::aidl::com::android::compos::ICompOsService::ICompOsService;
use log::{error, warn};
use num_traits::FromPrimitive;
use rustutils::system_properties;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Clone)]
pub struct OdrefreshTask {
    running_task: Arc<Mutex<Option<RunningTask>>>,
}

impl Interface for OdrefreshTask {}

impl ICompilationTask for OdrefreshTask {
    fn cancel(&self) -> BinderResult<()> {
        let task = self.take();
        // Drop the VM, which should end compilation - and cause our thread to exit
        drop(task);
        Ok(())
    }
}

impl OdrefreshTask {
    /// Return the current running task, if any, removing it from this CompilationTask.
    /// Once removed, meaning the task has ended or been canceled, further calls will always return
    /// None.
    fn take(&self) -> Option<RunningTask> {
        self.running_task.lock().unwrap().take()
    }

    pub fn start(
        comp_os: Arc<CompOsInstance>,
        output_dir_path: PathBuf,
        callback: &Strong<dyn ICompilationTaskCallback>,
    ) -> Result<OdrefreshTask> {
        let service = comp_os.get_service();
        let task = RunningTask { comp_os, callback: callback.clone() };
        let task = OdrefreshTask { running_task: Arc::new(Mutex::new(Some(task))) };

        task.clone().start_thread(service, output_dir_path);

        Ok(task)
    }

    fn start_thread(self, service: Strong<dyn ICompOsService>, output_dir_path: PathBuf) {
        thread::spawn(move || {
            let exit_code = try_odrefresh(service, &output_dir_path);

            let task = self.take();
            // We don't do the callback if cancel has already happened.
            if let Some(task) = task {
                let result = match exit_code {
                    Ok(odrefresh::ExitCode::CompilationSuccess) => task.callback.onSuccess(),
                    Ok(exit_code) => {
                        error!("Unexpected odrefresh result: {:?}", exit_code);
                        task.callback.onFailure()
                    }
                    Err(e) => {
                        error!("Running odrefresh failed: {:?}", e);
                        task.callback.onFailure()
                    }
                };
                if let Err(e) = result {
                    warn!("Failed to deliver callback: {:?}", e);
                }
            }
        });
    }
}

fn try_odrefresh(
    service: Strong<dyn ICompOsService>,
    output_dir_path: &Path,
) -> Result<odrefresh::ExitCode> {
    let output_dir = open_dir(output_dir_path)?;
    let system_dir = open_dir(Path::new("/system"))?;

    // Spawn a fd_server to serve the FDs.
    let fd_server_config = FdServerConfig {
        ro_dir_fds: vec![system_dir.as_raw_fd()],
        rw_dir_fds: vec![output_dir.as_raw_fd()],
        ..Default::default()
    };
    let fd_server_raii = fd_server_config.into_fd_server()?;

    let zygote_arch = system_properties::read("ro.zygote")?;
    let exit_code =
        service.odrefresh(system_dir.as_raw_fd(), output_dir.as_raw_fd(), &zygote_arch)?.exitCode;

    drop(fd_server_raii);
    if let Some(exit_code) = FromPrimitive::from_i8(exit_code) {
        Ok(exit_code)
    } else {
        bail!("odrefresh exited with {}", exit_code)
    }
}

struct RunningTask {
    callback: Strong<dyn ICompilationTaskCallback>,
    #[allow(dead_code)] // Keeps the CompOS VM alive
    comp_os: Arc<CompOsInstance>,
}
