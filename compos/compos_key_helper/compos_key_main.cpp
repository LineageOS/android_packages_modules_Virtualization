/*
 * Copyright 2022 The Android Open Source Project
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

#include <android-base/file.h>
#include <android-base/logging.h>
#include <unistd.h>
#include <vm_payload.h>

#include <string_view>

#include "compos_key.h"

using android::base::Error;
using android::base::ReadFdToString;
using android::base::Result;
using android::base::WriteFully;
using namespace std::literals;
using compos_key::Ed25519KeyPair;

namespace {

constexpr const char* kSigningKeySecretIdentifier = "CompOS signing key secret";

Result<Ed25519KeyPair> deriveKeyFromDice() {
    uint8_t secret[32];
    if (!get_vm_instance_secret(kSigningKeySecretIdentifier, strlen(kSigningKeySecretIdentifier),
                                secret, sizeof(secret))) {
        return Error() << "Failed to get signing key secret";
    }
    return compos_key::deriveKeyFromSecret(secret, sizeof(secret));
}

int write_public_key() {
    auto key_pair = deriveKeyFromDice();
    if (!key_pair.ok()) {
        LOG(ERROR) << key_pair.error();
        return 1;
    }
    if (!WriteFully(STDOUT_FILENO, key_pair->public_key.data(), key_pair->public_key.size())) {
        PLOG(ERROR) << "Write failed";
        return 1;
    }
    return 0;
}

int write_bcc() {
    uint8_t bcc[2048];
    size_t bcc_size = get_dice_attestation_chain(bcc, sizeof(bcc));
    if (bcc_size == 0) {
        LOG(ERROR) << "Failed to get attestation chain";
        return 1;
    }

    if (!WriteFully(STDOUT_FILENO, bcc, bcc_size)) {
        PLOG(ERROR) << "Write failed";
        return 1;
    }

    return 0;
}

int sign_input() {
    std::string to_sign;
    if (!ReadFdToString(STDIN_FILENO, &to_sign)) {
        PLOG(ERROR) << "Read failed";
        return 1;
    }

    auto key_pair = deriveKeyFromDice();
    if (!key_pair.ok()) {
        LOG(ERROR) << key_pair.error();
        return 1;
    }

    auto signature =
            compos_key::sign(key_pair->private_key,
                             reinterpret_cast<const uint8_t*>(to_sign.data()), to_sign.size());
    if (!signature.ok()) {
        LOG(ERROR) << signature.error();
        return 1;
    }

    if (!WriteFully(STDOUT_FILENO, signature->data(), signature->size())) {
        PLOG(ERROR) << "Write failed";
        return 1;
    }
    return 0;
}
} // namespace

int main(int argc, char** argv) {
    android::base::InitLogging(argv, android::base::LogdLogger(android::base::SYSTEM));

    if (argc == 2) {
        if (argv[1] == "public_key"sv) {
            return write_public_key();
        } else if (argv[1] == "bcc"sv) {
            return write_bcc();
        } else if (argv[1] == "sign"sv) {
            return sign_input();
        }
    }

    LOG(INFO) << "Usage: compos_key_helper <command>. Available commands are:\n"
                 "public_key   Write current public key to stdout\n"
                 "sign         Consume stdin, sign it and write signature to stdout\n";
    return 1;
}
