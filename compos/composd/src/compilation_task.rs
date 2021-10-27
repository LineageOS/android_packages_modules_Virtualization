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

use crate::instance_starter::CompOsInstance;
use crate::odrefresh::{self, Odrefresh};
use android_system_composd::aidl::android::system::composd::{
    ICompilationTask::ICompilationTask, ICompilationTaskCallback::ICompilationTaskCallback,
};
use android_system_composd::binder::{Interface, Result as BinderResult, Strong};
use anyhow::Result;
use log::{error, warn};
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Clone)]
pub struct CompilationTask {
    running_task: Arc<Mutex<Option<RunningTask>>>,
}

impl Interface for CompilationTask {}

impl ICompilationTask for CompilationTask {
    fn cancel(&self) -> BinderResult<()> {
        let task = self.take();
        if let Some(task) = task {
            if let Err(e) = task.odrefresh.kill() {
                warn!("Failed to kill running task: {:?}", e)
            }
        }
        Ok(())
    }
}

impl CompilationTask {
    /// Return the current running task, if any, removing it from this CompilationTask.
    /// Once removed, meaning the task has ended or been canceled, further calls will always return
    /// None.
    fn take(&self) -> Option<RunningTask> {
        self.running_task.lock().unwrap().take()
    }

    pub fn start_test_compile(
        comp_os: Arc<CompOsInstance>,
        callback: &Strong<dyn ICompilationTaskCallback>,
    ) -> Result<CompilationTask> {
        let odrefresh = Odrefresh::spawn_forced_compile("test-artifacts")?;
        let odrefresh = Arc::new(odrefresh);
        let task =
            RunningTask { odrefresh: odrefresh.clone(), comp_os, callback: callback.clone() };
        let task = CompilationTask { running_task: Arc::new(Mutex::new(Some(task))) };

        task.clone().start_waiting_thread(odrefresh);

        Ok(task)
    }

    fn start_waiting_thread(self, odrefresh: Arc<Odrefresh>) {
        thread::spawn(move || {
            let exit_code = odrefresh.wait_for_exit();
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

struct RunningTask {
    odrefresh: Arc<Odrefresh>,
    callback: Strong<dyn ICompilationTaskCallback>,
    #[allow(dead_code)] // Keeps the CompOS VM alive
    comp_os: Arc<CompOsInstance>,
}
