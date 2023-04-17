// Copyright 2023, The Android Open Source Project
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

//! Wrappers around hypervisor back-ends.

mod common;
mod kvm;

pub use common::Hypervisor;
use kvm::KvmHypervisor;

static HYPERVISOR: HypervisorBackend = HypervisorBackend::Kvm;

enum HypervisorBackend {
    Kvm,
}

impl HypervisorBackend {
    fn get_hypervisor(&self) -> &'static dyn Hypervisor {
        match self {
            Self::Kvm => &KvmHypervisor,
        }
    }
}

/// Gets the hypervisor singleton.
pub fn get_hypervisor() -> &'static dyn Hypervisor {
    HYPERVISOR.get_hypervisor()
}
