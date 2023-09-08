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

//! IRemotelyProvisionedComponent HAL implementation.

use android_hardware_security_rkp::aidl::android::hardware::security::keymint::{
    DeviceInfo::DeviceInfo,
    IRemotelyProvisionedComponent::{
        BnRemotelyProvisionedComponent, IRemotelyProvisionedComponent, STATUS_REMOVED,
    },
    MacedPublicKey::MacedPublicKey,
    ProtectedData::ProtectedData,
    RpcHardwareInfo::{RpcHardwareInfo, CURVE_NONE, MIN_SUPPORTED_NUM_KEYS_IN_CSR},
};
use avflog::LogResult;
use binder::{BinderFeatures, ExceptionCode, Interface, Result as BinderResult, Status, Strong};

/// Constructs a binder object that implements `IRemotelyProvisionedComponent`.
pub(crate) fn new_binder() -> Strong<dyn IRemotelyProvisionedComponent> {
    BnRemotelyProvisionedComponent::new_binder(
        AvfRemotelyProvisionedComponent {},
        BinderFeatures::default(),
    )
}

struct AvfRemotelyProvisionedComponent {}

impl Interface for AvfRemotelyProvisionedComponent {}

#[allow(non_snake_case)]
impl IRemotelyProvisionedComponent for AvfRemotelyProvisionedComponent {
    fn getHardwareInfo(&self) -> BinderResult<RpcHardwareInfo> {
        Ok(RpcHardwareInfo {
            versionNumber: 3,
            rpcAuthorName: String::from("Android Virtualization Framework"),
            supportedEekCurve: CURVE_NONE,
            uniqueId: Some(String::from("Android Virtualization Framework 1")),
            supportedNumKeysInCsr: MIN_SUPPORTED_NUM_KEYS_IN_CSR,
        })
    }

    fn generateEcdsaP256KeyPair(
        &self,
        testMode: bool,
        _macedPublicKey: &mut MacedPublicKey,
    ) -> BinderResult<Vec<u8>> {
        if testMode {
            return Err(Status::new_service_specific_error_str(
                STATUS_REMOVED,
                Some("generateEcdsaP256KeyPair does not support test mode in IRPC v3+ HAL."),
            ))
            .with_log();
        }
        // TODO(b/274881098): Implement this.
        Err(Status::new_exception(ExceptionCode::UNSUPPORTED_OPERATION, None)).with_log()
    }

    fn generateCertificateRequest(
        &self,
        _testMode: bool,
        _keysToSign: &[MacedPublicKey],
        _endpointEncryptionCertChain: &[u8],
        _challenge: &[u8],
        _deviceInfo: &mut DeviceInfo,
        _protectedData: &mut ProtectedData,
    ) -> BinderResult<Vec<u8>> {
        Err(Status::new_service_specific_error_str(
            STATUS_REMOVED,
            Some("This method was deprecated in v3 of the interface."),
        ))
        .with_log()
    }

    fn generateCertificateRequestV2(
        &self,
        _keysToSign: &[MacedPublicKey],
        _challenge: &[u8],
    ) -> BinderResult<Vec<u8>> {
        // TODO(b/274881098): Implement this.
        Err(Status::new_exception(ExceptionCode::UNSUPPORTED_OPERATION, None)).with_log()
    }
}
