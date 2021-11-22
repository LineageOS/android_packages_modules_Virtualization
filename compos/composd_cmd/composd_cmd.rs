/*
 * Copyright (C) 2021 The Android Open Source Project
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

//! Simple command-line tool to drive composd for testing and debugging.

use android_system_composd::{
    aidl::android::system::composd::{
        ICompilationTaskCallback::{BnCompilationTaskCallback, ICompilationTaskCallback},
        IIsolatedCompilationService::IIsolatedCompilationService,
    },
    binder::{
        wait_for_interface, BinderFeatures, DeathRecipient, IBinder, Interface, ProcessState,
        Result as BinderResult,
    },
};
use anyhow::{bail, Context, Result};
use compos_common::timeouts::timeouts;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

fn main() -> Result<()> {
    let app = clap::App::new("composd_cmd").arg(
        clap::Arg::with_name("command")
            .index(1)
            .takes_value(true)
            .required(true)
            .possible_values(&["forced-compile-test", "forced-odrefresh"]),
    );
    let args = app.get_matches();
    let command = args.value_of("command").unwrap();

    ProcessState::start_thread_pool();

    match command {
        "forced-compile-test" => run_forced_compile_for_test()?,
        "forced-odrefresh" => run_forced_odrefresh_for_test()?,
        _ => panic!("Unexpected command {}", command),
    }

    println!("All Ok!");

    Ok(())
}

struct Callback(Arc<State>);

#[derive(Default)]
struct State {
    mutex: Mutex<Option<Outcome>>,
    completed: Condvar,
}

#[derive(Copy, Clone)]
enum Outcome {
    Succeeded,
    Failed,
}

impl Interface for Callback {}

impl ICompilationTaskCallback for Callback {
    fn onSuccess(&self) -> BinderResult<()> {
        self.0.set_outcome(Outcome::Succeeded);
        Ok(())
    }

    fn onFailure(&self) -> BinderResult<()> {
        self.0.set_outcome(Outcome::Failed);
        Ok(())
    }
}

impl State {
    fn set_outcome(&self, outcome: Outcome) {
        let mut guard = self.mutex.lock().unwrap();
        *guard = Some(outcome);
        drop(guard);
        self.completed.notify_all();
    }

    fn wait(&self, duration: Duration) -> Result<Outcome> {
        let (outcome, result) = self
            .completed
            .wait_timeout_while(self.mutex.lock().unwrap(), duration, |outcome| outcome.is_none())
            .unwrap();
        if result.timed_out() {
            bail!("Timed out waiting for compilation")
        }
        Ok(outcome.unwrap())
    }
}

fn run_forced_compile_for_test() -> Result<()> {
    let service = wait_for_interface::<dyn IIsolatedCompilationService>("android.system.composd")
        .context("Failed to connect to composd service")?;

    let state = Arc::new(State::default());
    let callback = Callback(state.clone());
    let callback = BnCompilationTaskCallback::new_binder(callback, BinderFeatures::default());
    let task = service.startTestCompile(&callback).context("Compilation failed")?;

    // Make sure composd keeps going even if we don't hold a reference to its service.
    drop(service);

    let state_clone = state.clone();
    let mut death_recipient = DeathRecipient::new(move || {
        eprintln!("CompilationTask died");
        state_clone.set_outcome(Outcome::Failed);
    });
    // Note that dropping death_recipient cancels this, so we can't use a temporary here.
    task.as_binder().link_to_death(&mut death_recipient)?;

    println!("Waiting");

    match state.wait(timeouts()?.odrefresh_max_execution_time) {
        Ok(Outcome::Succeeded) => Ok(()),
        Ok(Outcome::Failed) => bail!("Compilation failed"),
        Err(e) => {
            if let Err(e) = task.cancel() {
                eprintln!("Failed to cancel compilation: {:?}", e);
            }
            Err(e)
        }
    }
}

fn run_forced_odrefresh_for_test() -> Result<()> {
    let service = wait_for_interface::<dyn IIsolatedCompilationService>("android.system.composd")
        .context("Failed to connect to composd service")?;
    let compilation_result = service.startTestOdrefresh().context("Compilation failed")?;
    println!("odrefresh exit code: {:?}", compilation_result);
    Ok(())
}
