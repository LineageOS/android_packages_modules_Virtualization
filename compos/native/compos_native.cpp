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

#include "compos_native.h"

#include <openssl/bn.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <algorithm>
#include <iterator>
#include <vector>

namespace {
KeyResult make_key_error(const char* message) {
    return KeyResult{{}, {}, message};
}

SignResult make_sign_error(const char* message) {
    return SignResult{{}, message};
}
} // namespace

constexpr int KEY_BITS = 2048;

KeyResult generate_key_pair() {
    bssl::UniquePtr<RSA> key_pair(RSA_new());

    // This function specifies that the public exponent is always 65537, which is good because
    // that's  what odsign is expecting.
    if (!RSA_generate_key_fips(key_pair.get(), KEY_BITS, /*callback=*/nullptr)) {
        return make_key_error("Failed to generate key pair");
    }

    KeyResult result;

    uint8_t* out;
    int size;
    bssl::UniquePtr<uint8_t> out_owner;

    // Extract public key as DER.
    out = nullptr;
    size = i2d_RSAPublicKey(key_pair.get(), &out);
    if (size < 0 || !out) {
        return make_key_error("Failed to get RSAPublicKey");
    }
    out_owner.reset(out);

    result.public_key.reserve(size);
    std::copy(out, out + size, std::back_inserter(result.public_key));
    out_owner.reset();

    // And ditto for the private key (which actually includes the public bits).
    out = nullptr;
    size = i2d_RSAPrivateKey(key_pair.get(), &out);
    if (size < 0 || !out) {
        return make_key_error("Failed to get RSAPrivateKey");
    }
    out_owner.reset(out);

    result.private_key.reserve(size);
    std::copy(out, out + size, std::back_inserter(result.private_key));
    out_owner.reset();

    return result;
}

SignResult sign(rust::Slice<const uint8_t> private_key, rust::Slice<const uint8_t> data) {
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), digest);

    const uint8_t* key_in = private_key.data();
    bssl::UniquePtr<RSA> key(d2i_RSAPrivateKey(nullptr, &key_in, private_key.size()));
    if (!key) {
        return make_sign_error("Failed to load RSAPrivateKey");
    }

    // rust::Vec doesn't support resize, so we need our own buffer.
    // The signature is always less than the modulus (public key), so
    // will fit in KEY_BITS.

    uint8_t signature[KEY_BITS / 8];
    if (sizeof(signature) < RSA_size(key.get())) {
        return make_sign_error("Signing key is too large");
    }
    unsigned signature_len = 0;

    if (!RSA_sign(NID_sha256, digest, sizeof(digest), signature, &signature_len, key.get())) {
        return make_sign_error("Failed to sign");
    }

    SignResult result;
    result.signature.reserve(signature_len);
    std::copy(signature, signature + signature_len, std::back_inserter(result.signature));

    return result;
}
