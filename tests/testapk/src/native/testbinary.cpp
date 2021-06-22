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
#include <android/binder_auto_utils.h>
#include <android/binder_manager.h>
#include <stdio.h>
#include <sys/system_properties.h>

using aidl::android::hardware::security::keymint::SecurityLevel;

using aidl::android::system::keystore2::IKeystoreSecurityLevel;
using aidl::android::system::keystore2::IKeystoreService;

namespace {

bool test_keystore() {
    ndk::SpAIBinder binder(
            AServiceManager_getService("android.system.keystore2.IKeystoreService/default"));
    auto service = IKeystoreService::fromBinder(binder);
    if (service == nullptr) {
        return false;
    }
    std::shared_ptr<IKeystoreSecurityLevel> securityLevel;
    auto status = service->getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT, &securityLevel);
    if (!status.isOk()) {
        return false;
    }
    return true;
}

} // Anonymous namespace

extern "C" int android_native_main(int argc, char* argv[]) {
    printf("Hello Microdroid ");
    for (int i = 0; i < argc; i++) {
        printf("%s", argv[i]);
        bool last = i == (argc - 1);
        if (!last) {
            printf(" ");
        }
    }
    printf("\n");

    __system_property_set("debug.microdroid.app.run", "true");
    __system_property_set("debug.microdroid.test_keystore", test_keystore() ? "PASS" : "FAIL");
    return 0;
}
