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
#include <android-base/unique_fd.h>
#include <android/binder_auto_utils.h>
#include <android/binder_manager.h>
#include <asm/byteorder.h>
#include <libfsverity.h>
#include <linux/fsverity.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>

#include "compos_signature.pb.h"

using namespace std::literals;

using aidl::com::android::compos::CompOsKeyData;
using aidl::com::android::compos::ICompOsKeyService;
using android::base::ErrnoError;
using android::base::Error;
using android::base::Result;
using android::base::unique_fd;
using compos::proto::Signature;

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

static Result<void> signFile(ICompOsKeyService* service, const std::vector<uint8_t>& key_blob,
                             const std::string& file) {
    unique_fd fd(TEMP_FAILURE_RETRY(open(file.c_str(), O_RDONLY | O_CLOEXEC)));
    if (!fd.ok()) {
        return ErrnoError() << "Failed to open";
    }

    std::filesystem::path signature_path{file};
    signature_path += ".signature";
    unique_fd out_fd(TEMP_FAILURE_RETRY(open(signature_path.c_str(),
                                             O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC,
                                             S_IRUSR | S_IWUSR | S_IRGRP)));
    if (!out_fd.ok()) {
        return ErrnoError() << "Unable to create signature file";
    }

    struct stat filestat;
    if (fstat(fd, &filestat) != 0) {
        return ErrnoError() << "Failed to fstat";
    }

    struct libfsverity_merkle_tree_params params = {
            .version = 1,
            .hash_algorithm = FS_VERITY_HASH_ALG_SHA256,
            .file_size = static_cast<uint64_t>(filestat.st_size),
            .block_size = 4096,
    };

    auto read_callback = [](void* file, void* buf, size_t count) {
        int* fd = static_cast<int*>(file);
        if (TEMP_FAILURE_RETRY(read(*fd, buf, count)) < 0) return -errno;
        return 0;
    };

    struct libfsverity_digest* digest;
    int ret = libfsverity_compute_digest(&fd, read_callback, &params, &digest);
    if (ret < 0) {
        return Error(-ret) << "Failed to compute fs-verity digest";
    }
    std::unique_ptr<libfsverity_digest, decltype(&std::free)> digestOwner{digest, std::free};

    std::vector<uint8_t> buffer(sizeof(fsverity_formatted_digest) + digest->digest_size);
    auto to_be_signed = new (buffer.data()) fsverity_formatted_digest;
    memcpy(to_be_signed->magic, "FSVerity", sizeof(to_be_signed->magic));
    to_be_signed->digest_algorithm = __cpu_to_le16(digest->digest_algorithm);
    to_be_signed->digest_size = __cpu_to_le16(digest->digest_size);
    memcpy(to_be_signed->digest, digest->digest, digest->digest_size);

    std::vector<uint8_t> signature;
    auto status = service->sign(key_blob, buffer, &signature);
    if (!status.isOk()) {
        return Error() << "Failed to sign: " << status.getDescription();
    }

    Signature compos_signature;
    compos_signature.set_digest(digest->digest, digest->digest_size);
    compos_signature.set_signature(signature.data(), signature.size());
    if (!compos_signature.SerializeToFileDescriptor(out_fd.get())) {
        return Error() << "Failed to write signature";
    }
    if (close(out_fd.release()) != 0) {
        return ErrnoError() << "Failed to close signature file";
    }

    return {};
}

static Result<void> sign(const std::string& blob_file, const std::vector<std::string>& files) {
    ndk::SpAIBinder binder(AServiceManager_getService("android.system.composkeyservice"));
    auto service = ICompOsKeyService::fromBinder(binder);
    if (!service) {
        return Error() << "No service";
    }

    auto blob = readBytesFromFile(blob_file);
    if (!blob.ok()) {
        return blob.error();
    }

    for (auto& file : files) {
        auto result = signFile(service.get(), blob.value(), file);
        if (!result.ok()) {
            return Error() << result.error() << ": " << file;
        }
    }
    return {};
}

int main(int argc, char** argv) {
    if (argc == 4 && argv[1] == "--generate"sv) {
        auto result = generate(argv[2], argv[3]);
        if (result.ok()) {
            return 0;
        } else {
            std::cerr << result.error() << '\n';
        }
    } else if (argc == 4 && argv[1] == "--verify"sv) {
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
    } else if (argc >= 4 && argv[1] == "--sign"sv) {
        const std::vector<std::string> files{&argv[3], &argv[argc]};
        auto result = sign(argv[2], files);
        if (result.ok()) {
            std::cerr << "All signatures generated.\n";
            return 0;
        } else {
            std::cerr << result.error() << '\n';
        }
    } else {
        std::cerr << "Usage: \n"
                  << "  --generate <blob file> <public key file> Generate new key pair and "
                     "write\n"
                  << "    the private key blob and public key to the specified files.\n "
                  << "  --verify <blob file> <public key file> Verify that the content of the\n"
                  << "    specified private key blob and public key files are valid.\n "
                  << "  --sign <blob file> <files to be signed> Generate signatures for one or\n"
                  << "    more files using the supplied private key blob.\n";
    }
    return 1;
}
