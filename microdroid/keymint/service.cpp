/*
 * Copyright 2021, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "android.hardware.security.keymint-service"

#include <AndroidKeyMintDevice.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/result.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <keymaster/android_keymaster_utils.h>
#include <keymaster/mem.h>
#include <keymaster/soft_keymaster_logger.h>
#include <openssl/digest.h>
#include <openssl/hkdf.h>
#include <openssl/is_boringssl.h>
#include <openssl/sha.h>

#include "MicrodroidKeyMintDevice.h"

using aidl::android::hardware::security::keymint::MicrodroidKeyMintDevice;
using aidl::android::hardware::security::keymint::SecurityLevel;

using android::base::Error;
using android::base::GetProperty;
using android::base::Result;

using keymaster::KeymasterBlob;
using keymaster::KeymasterKeyBlob;
using keymaster::memset_s;

namespace {

template <typename T, class... Args>
std::shared_ptr<T> addService(Args&&... args) {
    std::shared_ptr<T> ser = ndk::SharedRefBase::make<T>(std::forward<Args>(args)...);
    auto instanceName = std::string(T::descriptor) + "/default";
    LOG(INFO) << "adding keymint service instance: " << instanceName;
    binder_status_t status =
            AServiceManager_addService(ser->asBinder().get(), instanceName.c_str());
    CHECK(status == STATUS_OK);
    return ser;
}

Result<KeymasterKeyBlob> getRootKey() {
    const std::string prop = "ro.vmsecret.keymint";
    const std::chrono::seconds timeout(15);
    while (!android::base::WaitForPropertyCreation(prop, timeout)) {
        LOG(WARNING) << "waited " << timeout.count() << "seconds for " << prop
                     << ", still waiting...";
    }

    // In a small effort to avoid spreading the secret around too widely in
    // memory, move the secert into a buffer that will wipe itself and clear
    // the original string.
    std::string secretProp = GetProperty(prop, "");
    KeymasterBlob secret(reinterpret_cast<const uint8_t*>(secretProp.data()), secretProp.size());
    memset_s(secretProp.data(), 0, secretProp.size());
    if (secret.size() < 64u) return Error() << "secret is too small";

    // Derive the root key from the secret to avoid getting locked into using
    // the secret directly.
    KeymasterKeyBlob rootKey(SHA512_DIGEST_LENGTH);
    const uint8_t kRootKeyIkm[] = "keymint_root_key";
    const uint8_t* kNoSalt = nullptr;
    const size_t kNoSaltLen = 0;
    if (!HKDF(rootKey.writable_data(), rootKey.size(), EVP_sha512(), (uint8_t*)secret.begin(),
              secret.size(), kNoSalt, kNoSaltLen, kRootKeyIkm, sizeof(kRootKeyIkm))) {
        return Error() << "Failed to derive a key";
    }
    if (rootKey.size() < 64u) return Error() << "root key is too small";

    LOG(INFO) << "root key obtained";
    return rootKey;
}

} // namespace

int main() {
    auto rootKey = getRootKey();
    if (!rootKey.ok()) {
        LOG(FATAL) << "Failed to get root key: " << rootKey.error();
    }

    // Zero threads seems like a useless pool, but below we'll join this thread
    // to it, increasing the pool size to 1.
    ABinderProcess_setThreadPoolMaxThreadCount(0);

    // Add Keymint Service
    std::shared_ptr<MicrodroidKeyMintDevice> keyMint =
            ndk::SharedRefBase::make<MicrodroidKeyMintDevice>(*rootKey);
    auto instanceName = std::string(MicrodroidKeyMintDevice::descriptor) + "/default";
    LOG(INFO) << "adding keymint service instance: " << instanceName;
    binder_status_t status =
            AServiceManager_addService(keyMint->asBinder().get(), instanceName.c_str());
    CHECK(status == STATUS_OK);

    ABinderProcess_joinThreadPool();
    return EXIT_FAILURE; // should not reach
}
