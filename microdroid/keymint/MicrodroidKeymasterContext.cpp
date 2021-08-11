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

#include "MicrodroidKeymasterContext.h"

#include <android-base/logging.h>
#include <keymaster/key.h>
#include <keymaster/key_blob_utils/auth_encrypted_key_blob.h>
#include <keymaster/key_blob_utils/software_keyblobs.h>

using namespace ::keymaster;

// This value is used for the ROOT_OF_TRUST tag which is only used in
// attestation records which aren't supported in this implementation so a
// constant doesn't cause any hard. MicroDroid SoftWare root-of-trust.
static uint8_t SWROT[] = {'M', 'D', 'S', 'W'};
static const KeymasterBlob microdroidSoftwareRootOfTrust(SWROT);

keymaster_error_t MicrodroidKeymasterContext::CreateKeyBlob(const AuthorizationSet& key_description,
                                                            keymaster_key_origin_t origin,
                                                            const KeymasterKeyBlob& key_material,
                                                            KeymasterKeyBlob* blob,
                                                            AuthorizationSet* hw_enforced,
                                                            AuthorizationSet* sw_enforced) const {
    keymaster_error_t error;

    if (key_description.GetTagValue(TAG_ROLLBACK_RESISTANCE)) {
        return KM_ERROR_ROLLBACK_RESISTANCE_UNAVAILABLE;
    }

    error = SetKeyBlobAuthorizations(key_description, origin, os_version_, os_patchlevel_,
                                     hw_enforced, sw_enforced);
    if (error != KM_ERROR_OK) return error;

    AuthorizationSet hidden;
    error = BuildHiddenAuthorizations(key_description, &hidden, microdroidSoftwareRootOfTrust);
    if (error != KM_ERROR_OK) return error;

    CHECK(hw_enforced->empty());

    // Note that the authorizations included in the blob are not encrypted. This
    // doesn't pose a problem for the current applications but may be a
    // candidate for hardening.
    auto encrypted_key = EncryptKey(key_material, AES_GCM_WITH_SW_ENFORCED, *hw_enforced,
                                    *sw_enforced, hidden, SecureDeletionData{}, root_key_, random_);
    if (!encrypted_key) return encrypted_key.error();

    auto serialized = SerializeAuthEncryptedBlob(*encrypted_key, *hw_enforced, *sw_enforced,
                                                 0 /* key_slot */);
    if (!serialized) return serialized.error();
    *blob = *serialized;
    return KM_ERROR_OK;
}

keymaster_error_t MicrodroidKeymasterContext::ParseKeyBlob(
        const KeymasterKeyBlob& blob, const AuthorizationSet& additional_params,
        UniquePtr<Key>* key) const {
    keymaster_error_t error;

    AuthorizationSet hidden;
    error = BuildHiddenAuthorizations(additional_params, &hidden, microdroidSoftwareRootOfTrust);
    if (error != KM_ERROR_OK) return error;

    auto deserialized_key = DeserializeAuthEncryptedBlob(blob);
    if (!deserialized_key) return deserialized_key.error();

    keymaster_algorithm_t algorithm;
    if (!deserialized_key->sw_enforced.GetTagValue(TAG_ALGORITHM, &algorithm)) {
        return KM_ERROR_INVALID_ARGUMENT;
    }

    auto key_material = DecryptKey(*deserialized_key, hidden, SecureDeletionData{}, root_key_);
    if (!key_material) return key_material.error();

    auto factory = GetKeyFactory(algorithm);
    return factory->LoadKey(move(*key_material), additional_params,
                            move(deserialized_key->hw_enforced),
                            move(deserialized_key->sw_enforced), key);
}

static bool UpgradeIntegerTag(keymaster_tag_t tag, uint32_t value, AuthorizationSet* set) {
    int index = set->find(tag);
    if (index == -1) {
        keymaster_key_param_t param;
        param.tag = tag;
        param.integer = value;
        set->push_back(param);
        return true;
    }

    if (set->params[index].integer > value) return false;

    if (set->params[index].integer != value) {
        set->params[index].integer = value;
    }
    return true;
}

keymaster_error_t MicrodroidKeymasterContext::UpgradeKeyBlob(const KeymasterKeyBlob& key_to_upgrade,
                                                             const AuthorizationSet& upgrade_params,
                                                             KeymasterKeyBlob* upgraded_key) const {
    UniquePtr<Key> key;
    keymaster_error_t error = ParseKeyBlob(key_to_upgrade, upgrade_params, &key);
    if (error != KM_ERROR_OK) return error;

    if (os_version_ == 0) {
        // We need to allow "upgrading" OS version to zero, to support upgrading from proper
        // numbered releases to unnumbered development and preview releases.

        int key_os_version_pos = key->sw_enforced().find(TAG_OS_VERSION);
        if (key_os_version_pos != -1) {
            uint32_t key_os_version = key->sw_enforced()[key_os_version_pos].integer;
            if (key_os_version != 0) {
                key->sw_enforced()[key_os_version_pos].integer = os_version_;
            }
        }
    }

    if (!UpgradeIntegerTag(TAG_OS_VERSION, os_version_, &key->sw_enforced()) ||
        !UpgradeIntegerTag(TAG_OS_PATCHLEVEL, os_patchlevel_, &key->sw_enforced()))
        // One of the version fields would have been a downgrade. Not allowed.
        return KM_ERROR_INVALID_ARGUMENT;

    AuthorizationSet hidden;
    error = BuildHiddenAuthorizations(upgrade_params, &hidden, microdroidSoftwareRootOfTrust);
    if (error != KM_ERROR_OK) return error;

    auto encrypted_key =
            EncryptKey(key->key_material(), AES_GCM_WITH_SW_ENFORCED, key->hw_enforced(),
                       key->sw_enforced(), hidden, SecureDeletionData{}, root_key_, random_);
    if (!encrypted_key) return encrypted_key.error();

    auto serialized = SerializeAuthEncryptedBlob(*encrypted_key, key->hw_enforced(),
                                                 key->sw_enforced(), 0 /* key_slot */);
    if (!serialized) return serialized.error();

    *upgraded_key = std::move(*serialized);
    return error;
}
