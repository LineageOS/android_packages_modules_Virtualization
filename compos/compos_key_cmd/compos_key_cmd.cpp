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

#include <aidl/com/android/compos/ICompOsKeyService.h>
#include <android-base/file.h>
#include <android-base/result.h>
#include <android/binder_auto_utils.h>
#include <android/binder_manager.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <iostream>
#include <string>

using android::base::Error;
using android::base::Result;

using aidl::com::android::compos::CompOsKeyData;
using aidl::com::android::compos::ICompOsKeyService;

static bool writeBytesToFile(const std::vector<uint8_t>& bytes, const std::string& path) {
    std::string str(bytes.begin(), bytes.end());
    return android::base::WriteStringToFile(str, path);
}

static Result<std::vector<uint8_t>> readBytesFromFile(const std::string& path) {
    std::string str;
    if (!android::base::ReadFileToString(path, &str)) {
        return Error() << "Failed to read " << path;
    }
    return std::vector<uint8_t>(str.begin(), str.end());
}

static Result<std::vector<uint8_t>> extractRsaPublicKey(
        const std::vector<uint8_t>& der_certificate) {
    auto data = der_certificate.data();
    bssl::UniquePtr<X509> x509(d2i_X509(nullptr, &data, der_certificate.size()));
    if (!x509) {
        return Error() << "Failed to parse certificate";
    }
    if (data != der_certificate.data() + der_certificate.size()) {
        return Error() << "Certificate has unexpected trailing data";
    }

    bssl::UniquePtr<EVP_PKEY> pkey(X509_get_pubkey(x509.get()));
    if (EVP_PKEY_base_id(pkey.get()) != EVP_PKEY_RSA) {
        return Error() << "Subject key is not RSA";
    }
    RSA* rsa = EVP_PKEY_get0_RSA(pkey.get());
    if (!rsa) {
        return Error() << "Failed to extract RSA key";
    }

    uint8_t* out = nullptr;
    int size = i2d_RSAPublicKey(rsa, &out);
    if (size < 0 || !out) {
        return Error() << "Failed to convert to RSAPublicKey";
    }

    bssl::UniquePtr<uint8_t> buffer(out);
    std::vector<uint8_t> result(out, out + size);
    return result;
}

static Result<void> generate(const std::string& blob_file, const std::string& public_key_file) {
    ndk::SpAIBinder binder(AServiceManager_getService("android.system.composkeyservice"));
    auto service = ICompOsKeyService::fromBinder(binder);
    if (!service) {
        return Error() << "No service";
    }

    CompOsKeyData key_data;
    auto status = service->generateSigningKey(&key_data);
    if (!status.isOk()) {
        return Error() << "Failed to generate key: " << status.getDescription();
    }

    auto public_key = extractRsaPublicKey(key_data.certificate);
    if (!public_key.ok()) {
        return Error() << "Failed to extract public key from cert: " << public_key.error();
    }
    if (!writeBytesToFile(key_data.keyBlob, blob_file)) {
        return Error() << "Failed to write keyBlob to " << blob_file;
    }

    if (!writeBytesToFile(public_key.value(), public_key_file)) {
        return Error() << "Failed to write public key to " << public_key_file;
    }

    return {};
}

static Result<bool> verify(const std::string& blob_file, const std::string& public_key_file) {
    ndk::SpAIBinder binder(AServiceManager_getService("android.system.composkeyservice"));
    auto service = ICompOsKeyService::fromBinder(binder);
    if (!service) {
        return Error() << "No service";
    }

    auto blob = readBytesFromFile(blob_file);
    if (!blob.ok()) {
        return blob.error();
    }

    auto public_key = readBytesFromFile(public_key_file);
    if (!public_key.ok()) {
        return public_key.error();
    }

    bool result = false;
    auto status = service->verifySigningKey(blob.value(), public_key.value(), &result);
    if (!status.isOk()) {
        return Error() << "Failed to verify key: " << status.getDescription();
    }

    return result;
}

int main(int argc, char** argv) {
    if (argc == 4 && std::string(argv[1]) == "--generate") {
        auto result = generate(argv[2], argv[3]);
        if (result.ok()) {
            return 0;
        } else {
            std::cerr << result.error() << '\n';
        }
    } else if (argc == 4 && std::string(argv[1]) == "--verify") {
        auto result = verify(argv[2], argv[3]);
        if (result.ok()) {
            if (result.value()) {
                std::cerr << "Key files are valid.\n";
                return 0;
            } else {
                std::cerr << "Key files are not valid.\n";
            }
        } else {
            std::cerr << result.error() << '\n';
        }
    } else {
        std::cerr << "Usage: \n"
                  << "  --generate <blob file> <public key file> Generate new key pair and "
                     "write\n"
                  << "    the private key blob and public key to the specified files.\n "
                  << "  --verify <blob file> <public key file> Verify that the content of the\n"
                  << "    specified private key blob and public key files are valid.\n ";
    }
    return 1;
}
