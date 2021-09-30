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

#include "composd_native.h"

#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <algorithm>
#include <iterator>

using rust::Slice;
using rust::String;

namespace {
KeyResult make_error(const char* message) {
    return KeyResult{{}, message};
}
} // namespace

KeyResult extract_rsa_public_key(rust::Slice<const uint8_t> der_certificate) {
    auto data = der_certificate.data();
    bssl::UniquePtr<X509> x509(d2i_X509(nullptr, &data, der_certificate.size()));
    if (!x509) {
        return make_error("Failed to parse certificate");
    }
    if (data != der_certificate.data() + der_certificate.size()) {
        return make_error("Certificate has unexpected trailing data");
    }

    bssl::UniquePtr<EVP_PKEY> pkey(X509_get_pubkey(x509.get()));
    if (EVP_PKEY_base_id(pkey.get()) != EVP_PKEY_RSA) {
        return make_error("Subject key is not RSA");
    }
    RSA* rsa = EVP_PKEY_get0_RSA(pkey.get());
    if (!rsa) {
        return make_error("Failed to extract RSA key");
    }

    uint8_t* out = nullptr;
    int size = i2d_RSAPublicKey(rsa, &out);
    if (size < 0 || !out) {
        return make_error("Failed to convert to RSAPublicKey");
    }
    bssl::UniquePtr<uint8_t> buffer(out);

    KeyResult result;
    result.key.reserve(size);
    std::copy(out, out + size, std::back_inserter(result.key));
    return result;
}
