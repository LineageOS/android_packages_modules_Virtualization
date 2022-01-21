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
#include <aidl/android/system/keystore2/IKeystoreService.h>
#include <aidl/android/system/virtualmachineservice/IVirtualMachineService.h>
#include <aidl/com/android/microdroid/testservice/BnTestService.h>
#include <android-base/properties.h>
#include <android-base/result.h>
#include <android-base/unique_fd.h>
#include <android/binder_auto_utils.h>
#include <android/binder_manager.h>
#include <fcntl.h>
#include <linux/vm_sockets.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include <binder_rpc_unstable.hpp>
#include <string>

using aidl::android::hardware::security::keymint::Algorithm;
using aidl::android::hardware::security::keymint::Digest;
using aidl::android::hardware::security::keymint::KeyParameter;
using aidl::android::hardware::security::keymint::KeyParameterValue;
using aidl::android::hardware::security::keymint::KeyPurpose;
using aidl::android::hardware::security::keymint::SecurityLevel;
using aidl::android::hardware::security::keymint::Tag;

using aidl::android::system::keystore2::CreateOperationResponse;
using aidl::android::system::keystore2::Domain;
using aidl::android::system::keystore2::IKeystoreSecurityLevel;
using aidl::android::system::keystore2::IKeystoreService;
using aidl::android::system::keystore2::KeyDescriptor;
using aidl::android::system::keystore2::KeyMetadata;

using aidl::android::system::virtualmachineservice::IVirtualMachineService;

using android::base::ErrnoError;
using android::base::Error;
using android::base::Result;
using android::base::unique_fd;

extern void testlib_sub();

namespace {

Result<void> test_keystore() {
    // Connect to Keystore.
    ndk::SpAIBinder binder(
            AServiceManager_waitForService("android.system.keystore2.IKeystoreService/default"));
    auto service = IKeystoreService::fromBinder(binder);
    if (service == nullptr) {
        return Error() << "Failed to find Keystore";
    }
    std::shared_ptr<IKeystoreSecurityLevel> securityLevel;
    auto status = service->getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT, &securityLevel);
    if (!status.isOk()) {
        return Error() << "Failed to get security level";
    }

    // Create a signing key.
    std::vector<KeyParameter> params;

    KeyParameter algo;
    algo.tag = Tag::ALGORITHM;
    algo.value = KeyParameterValue::make<KeyParameterValue::algorithm>(Algorithm::HMAC);
    params.push_back(algo);

    KeyParameter key_size;
    key_size.tag = Tag::KEY_SIZE;
    key_size.value = KeyParameterValue::make<KeyParameterValue::integer>(256);
    params.push_back(key_size);

    KeyParameter min_mac_length;
    min_mac_length.tag = Tag::MIN_MAC_LENGTH;
    min_mac_length.value = KeyParameterValue::make<KeyParameterValue::integer>(256);
    params.push_back(min_mac_length);

    KeyParameter digest;
    digest.tag = Tag::DIGEST;
    digest.value = KeyParameterValue::make<KeyParameterValue::digest>(Digest::SHA_2_256);
    params.push_back(digest);

    KeyParameter purposeSign;
    purposeSign.tag = Tag::PURPOSE;
    purposeSign.value = KeyParameterValue::make<KeyParameterValue::keyPurpose>(KeyPurpose::SIGN);
    params.push_back(purposeSign);

    KeyParameter purposeVerify;
    purposeVerify.tag = Tag::PURPOSE;
    purposeVerify.value =
            KeyParameterValue::make<KeyParameterValue::keyPurpose>(KeyPurpose::VERIFY);
    params.push_back(purposeVerify);

    KeyParameter auth;
    auth.tag = Tag::NO_AUTH_REQUIRED;
    auth.value = KeyParameterValue::make<KeyParameterValue::boolValue>(true);
    params.push_back(auth);

    KeyDescriptor descriptor;
    descriptor.domain = Domain::SELINUX;
    descriptor.alias = "payload-test-key";
    descriptor.nspace = 140; // vm_payload_key

    KeyMetadata metadata;
    status = securityLevel->generateKey(descriptor, {}, params, 0, {}, &metadata);
    if (!status.isOk()) {
        return Error() << "Failed to create new HMAC key";
    }

    // Sign something.
    params.clear();
    params.push_back(algo);
    params.push_back(digest);
    params.push_back(purposeSign);

    KeyParameter mac_length;
    mac_length.tag = Tag::MAC_LENGTH;
    mac_length.value = KeyParameterValue::make<KeyParameterValue::integer>(256);
    params.push_back(mac_length);

    CreateOperationResponse opResponse;
    status = securityLevel->createOperation(descriptor, params, false, &opResponse);
    if (!status.isOk()) {
        return Error() << "Failed to create keystore signing operation: "
                       << status.getServiceSpecificError();
    }
    auto operation = opResponse.iOperation;

    std::string message = "This is the message to sign";
    std::optional<std::vector<uint8_t>> out;
    status = operation->update({message.begin(), message.end()}, &out);
    if (!status.isOk()) {
        return Error() << "Failed to call keystore update operation.";
    }

    std::optional<std::vector<uint8_t>> signature;
    status = operation->finish({}, {}, &signature);
    if (!status.isOk()) {
        return Error() << "Failed to call keystore finish operation.";
    }

    if (!signature.has_value()) {
        return Error() << "Didn't receive a signature from keystore finish operation.";
    }

    // Verify the signature.
    params.clear();
    params.push_back(algo);
    params.push_back(digest);
    params.push_back(purposeVerify);

    status = securityLevel->createOperation(descriptor, params, false, &opResponse);
    if (!status.isOk()) {
        return Error() << "Failed to create keystore verification operation: "
                       << status.getServiceSpecificError();
    }
    operation = opResponse.iOperation;

    status = operation->update({message.begin(), message.end()}, &out);
    if (!status.isOk()) {
        return Error() << "Failed to call keystore update operation.";
    }

    std::optional<std::vector<uint8_t>> out_signature;
    status = operation->finish({}, signature.value(), &out_signature);
    if (!status.isOk()) {
        return Error() << "Failed to call keystore finish operation.";
    }

    return {};
}

template <typename T>
Result<T> report_test(std::string name, Result<T> result) {
    auto property = "debug.microdroid.test." + name;
    std::stringstream outcome;
    if (result.ok()) {
        outcome << "PASS";
    } else {
        outcome << "FAIL: " << result.error();
        // Pollute stdout with the error in case the property is truncated.
        std::cout << "[" << name << "] test failed: " << result.error() << "\n";
    }
    __system_property_set(property.c_str(), outcome.str().c_str());
    return result;
}

Result<void> start_test_service() {
    class TestService : public aidl::com::android::microdroid::testservice::BnTestService {
        ndk::ScopedAStatus addInteger(int32_t a, int32_t b, int32_t* out) override {
            *out = a + b;
            return ndk::ScopedAStatus::ok();
        }

        ndk::ScopedAStatus readProperty(const std::string& prop, std::string* out) override {
            *out = android::base::GetProperty(prop, "");
            if (out->empty()) {
                std::string msg = "cannot find property " + prop;
                return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_SERVICE_SPECIFIC,
                                                                        msg.c_str());
            }

            return ndk::ScopedAStatus::ok();
        }
    };
    auto testService = ndk::SharedRefBase::make<TestService>();

    auto callback = []([[maybe_unused]] void* param) {
        // Tell microdroid_manager that we're ready.
        // Failing to notify is not a fatal error; the payload can continue.
        ndk::SpAIBinder binder(
                RpcClient(VMADDR_CID_HOST, IVirtualMachineService::VM_BINDER_SERVICE_PORT));
        auto virtualMachineService = IVirtualMachineService::fromBinder(binder);
        if (virtualMachineService == nullptr) {
            std::cerr << "failed to connect VirtualMachineService";
            return;
        }
        if (!virtualMachineService->notifyPayloadReady().isOk()) {
            std::cerr << "failed to notify payload ready to virtualizationservice";
        }
    };

    if (!RunRpcServerCallback(testService->asBinder().get(), testService->SERVICE_PORT, callback,
                              nullptr)) {
        return Error() << "RPC Server failed to run";
    }

    return {};
}

} // Anonymous namespace

extern "C" int android_native_main(int argc, char* argv[]) {
    // disable buffering to communicate seamlessly
    setvbuf(stdin, nullptr, _IONBF, 0);
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);

    printf("Hello Microdroid ");
    for (int i = 0; i < argc; i++) {
        printf("%s", argv[i]);
        bool last = i == (argc - 1);
        if (!last) {
            printf(" ");
        }
    }
    testlib_sub();
    printf("\n");

    __system_property_set("debug.microdroid.app.run", "true");
    if (!report_test("keystore", test_keystore()).ok()) return 1;

    if (auto res = start_test_service(); res.ok()) {
        return 0;
    } else {
        std::cerr << "starting service failed: " << res.error();
        return 1;
    }
}
