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

#include <keymaster/contexts/pure_soft_keymaster_context.h>
#include <keymaster/km_openssl/software_random_source.h>

class MicrodroidKeymasterContext : public ::keymaster::PureSoftKeymasterContext {
public:
    explicit MicrodroidKeymasterContext(::keymaster::KmVersion version,
                                        ::keymaster::KeymasterKeyBlob& root_key)
          : PureSoftKeymasterContext(version, KM_SECURITY_LEVEL_SOFTWARE), root_key_(root_key) {}

    keymaster_error_t CreateKeyBlob(const ::keymaster::AuthorizationSet& auths,
                                    keymaster_key_origin_t origin,
                                    const ::keymaster::KeymasterKeyBlob& key_material,
                                    ::keymaster::KeymasterKeyBlob* blob,
                                    ::keymaster::AuthorizationSet* hw_enforced,
                                    ::keymaster::AuthorizationSet* sw_enforced) const override;

    keymaster_error_t ParseKeyBlob(const ::keymaster::KeymasterKeyBlob& blob,
                                   const ::keymaster::AuthorizationSet& additional_params,
                                   ::keymaster::UniquePtr<::keymaster::Key>* key) const override;

    keymaster_error_t UpgradeKeyBlob(const ::keymaster::KeymasterKeyBlob& key_to_upgrade,
                                     const ::keymaster::AuthorizationSet& upgrade_params,
                                     ::keymaster::KeymasterKeyBlob* upgraded_key) const override;

private:
    ::keymaster::SoftwareRandomSource random_;
    ::keymaster::KeymasterKeyBlob root_key_;
};
