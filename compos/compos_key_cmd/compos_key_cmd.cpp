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

#include <aidl/android/system/virtualizationservice/BnVirtualMachineCallback.h>
#include <aidl/android/system/virtualizationservice/IVirtualizationService.h>
#include <aidl/com/android/compos/ICompOsService.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/result.h>
#include <android-base/unique_fd.h>
#include <android/binder_auto_utils.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <asm/byteorder.h>
#include <libfsverity.h>
#include <linux/fsverity.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <unistd.h>

#include <binder_rpc_unstable.hpp>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <iostream>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>

#include "compos_signature.pb.h"

using namespace std::literals;

using aidl::android::system::virtualizationservice::BnVirtualMachineCallback;
using aidl::android::system::virtualizationservice::IVirtualizationService;
using aidl::android::system::virtualizationservice::IVirtualMachine;
using aidl::android::system::virtualizationservice::IVirtualMachineCallback;
using aidl::android::system::virtualizationservice::PartitionType;
using aidl::android::system::virtualizationservice::VirtualMachineAppConfig;
using aidl::android::system::virtualizationservice::VirtualMachineConfig;
using aidl::com::android::compos::CompOsKeyData;
using aidl::com::android::compos::ICompOsService;
using android::base::ErrnoError;
using android::base::Error;
using android::base::Fdopen;
using android::base::Result;
using android::base::unique_fd;
using compos::proto::Signature;
using ndk::ScopedAStatus;
using ndk::ScopedFileDescriptor;
using ndk::SharedRefBase;

constexpr unsigned int kRpcPort = 6432;

constexpr const char* kConfigApkPath =
        "/apex/com.android.compos/app/CompOSPayloadApp/CompOSPayloadApp.apk";
constexpr const char* kConfigApkIdsigPath =
        "/apex/com.android.compos/etc/CompOSPayloadApp.apk.idsig";

// This is a path inside the APK
constexpr const char* kConfigFilePath = "assets/vm_config.json";

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

static std::shared_ptr<ICompOsService> getService(int cid) {
    LOG(INFO) << "Connecting to cid " << cid;
    ndk::SpAIBinder binder(cid == 0 ? AServiceManager_getService("android.system.composkeyservice")
                                    : RpcClient(cid, kRpcPort));
    return ICompOsService::fromBinder(binder);
}

namespace {

void copyToLog(unique_fd&& fd) {
    FILE* source = Fdopen(std::move(fd), "r");
    size_t size = 0;
    char* line = nullptr;

    LOG(INFO) << "Started logging VM output";

    for (;;) {
        ssize_t len = getline(&line, &size, source);
        if (len < 0) {
            LOG(INFO) << "VM logging ended: " << ErrnoError().str();
            break;
        }
        LOG(DEBUG) << "VM: " << std::string_view(line, len);
    }
    free(line);
}

class Callback : public BnVirtualMachineCallback {
public:
    ::ndk::ScopedAStatus onPayloadStarted(int32_t in_cid,
                                          const ::ndk::ScopedFileDescriptor& stream) override {
        LOG(INFO) << "Payload started! cid = " << in_cid;

        unique_fd stream_fd(dup(stream.get()));
        std::thread logger([fd = std::move(stream_fd)]() mutable { copyToLog(std::move(fd)); });
        logger.detach();

        return ScopedAStatus::ok();
    }

    ::ndk::ScopedAStatus onPayloadReady(int32_t in_cid) override {
        LOG(INFO) << "Payload is ready! cid = " << in_cid;
        {
            std::unique_lock lock(mMutex);
            mReady = true;
        }
        mCv.notify_all();
        return ScopedAStatus::ok();
    }

    ::ndk::ScopedAStatus onPayloadFinished(int32_t in_cid, int32_t in_exit_code) override {
        LOG(INFO) << "Payload finished! cid = " << in_cid << ", exit_code = " << in_exit_code;
        return ScopedAStatus::ok();
    }

    ::ndk::ScopedAStatus onDied(int32_t in_cid) override {
        LOG(WARNING) << "VM died! cid = " << in_cid;
        {
            std::unique_lock lock(mMutex);
            mDied = true;
        }
        mCv.notify_all();
        return ScopedAStatus::ok();
    }

    bool waitUntilReady() {
        std::unique_lock lock(mMutex);
        // 10s is long enough on real hardware, but it can take 90s when using nested
        // virtualization.
        // TODO(b/200924405): Reduce timeout/detect nested virtualization
        return mCv.wait_for(lock, std::chrono::seconds(120), [this] { return mReady || mDied; }) &&
                !mDied;
    }

private:
    std::mutex mMutex;
    std::condition_variable mCv;
    bool mReady;
    bool mDied;
};

class TargetVm {
public:
    TargetVm(int cid, const std::string& logFile, const std::string& instanceImageFile)
          : mCid(cid), mLogFile(logFile), mInstanceImageFile(instanceImageFile) {}

    // Returns 0 if we are to connect to a local service, otherwise the CID of
    // either an existing VM or a VM we have started, depending on the command
    // line arguments.
    Result<int> resolveCid() {
        if (mInstanceImageFile.empty()) {
            return mCid;
        }
        if (mCid != 0) {
            return Error() << "Can't specify both cid and image file.";
        }

        // We need a thread pool to receive VM callbacks.
        ABinderProcess_startThreadPool();

        ndk::SpAIBinder binder(
                AServiceManager_waitForService("android.system.virtualizationservice"));
        auto service = IVirtualizationService::fromBinder(binder);
        if (!service) {
            return Error() << "Failed to connect to virtualization service.";
        }

        ScopedFileDescriptor logFd;
        if (mLogFile.empty()) {
            logFd.set(dup(STDOUT_FILENO));
            if (logFd.get() == -1) {
                return ErrnoError() << "dup() failed: ";
            }
        } else {
            logFd.set(TEMP_FAILURE_RETRY(open(mLogFile.c_str(),
                                              O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                                              S_IRUSR | S_IWUSR)));
            if (logFd.get() == -1) {
                return ErrnoError() << "Failed to open " << mLogFile;
            }
        }

        ScopedFileDescriptor apkFd(TEMP_FAILURE_RETRY(open(kConfigApkPath, O_RDONLY | O_CLOEXEC)));
        if (apkFd.get() == -1) {
            return ErrnoError() << "Failed to open config APK";
        }

        ScopedFileDescriptor idsigFd(
                TEMP_FAILURE_RETRY(open(kConfigApkIdsigPath, O_RDONLY | O_CLOEXEC)));
        if (idsigFd.get() == -1) {
            return ErrnoError() << "Failed to open config APK signature";
        }

        ScopedFileDescriptor instanceFd(
                TEMP_FAILURE_RETRY(open(mInstanceImageFile.c_str(), O_RDONLY | O_CLOEXEC)));
        if (instanceFd.get() == -1) {
            return ErrnoError() << "Failed to open instance image file";
        }

        auto config = VirtualMachineConfig::make<VirtualMachineConfig::Tag::appConfig>();
        auto& appConfig = config.get<VirtualMachineConfig::Tag::appConfig>();
        appConfig.apk = std::move(apkFd);
        appConfig.idsig = std::move(idsigFd);
        appConfig.instanceImage = std::move(instanceFd);
        appConfig.configPath = kConfigFilePath;
        appConfig.debugLevel = VirtualMachineAppConfig::DebugLevel::NONE;
        appConfig.memoryMib = 0; // Use default

        LOG(INFO) << "Starting VM";
        auto status = service->createVm(config, logFd, &mVm);
        if (!status.isOk()) {
            return Error() << status.getDescription();
        }

        int32_t cid;
        status = mVm->getCid(&cid);
        if (!status.isOk()) {
            return Error() << status.getDescription();
        }

        LOG(INFO) << "Created VM with CID = " << cid;

        // We need to use this rather than std::make_shared to make sure the
        // embedded weak_ptr is initialised.
        mCallback = SharedRefBase::make<Callback>();

        status = mVm->registerCallback(mCallback);
        if (!status.isOk()) {
            return Error() << status.getDescription();
        }

        status = mVm->start();
        if (!status.isOk()) {
            return Error() << status.getDescription();
        }
        LOG(INFO) << "Started VM";

        if (!mCallback->waitUntilReady()) {
            return Error() << "VM Payload failed to start";
        }

        return cid;
    }

private:
    const int mCid;
    const std::string mLogFile;
    const std::string mInstanceImageFile;
    std::shared_ptr<Callback> mCallback;
    std::shared_ptr<IVirtualMachine> mVm;
};

} // namespace

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

static Result<void> generate(TargetVm& vm, const std::string& blob_file,
                             const std::string& public_key_file) {
    auto cid = vm.resolveCid();
    if (!cid.ok()) {
        return cid.error();
    }
    auto service = getService(*cid);
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

static Result<bool> verify(TargetVm& vm, const std::string& blob_file,
                           const std::string& public_key_file) {
    auto cid = vm.resolveCid();
    if (!cid.ok()) {
        return cid.error();
    }
    auto service = getService(*cid);
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

static Result<void> signFile(ICompOsService* service, const std::string& file) {
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
    auto status = service->sign(buffer, &signature);
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

static Result<void> sign(TargetVm& vm, const std::string& blob_file,
                         const std::vector<std::string>& files) {
    auto cid = vm.resolveCid();
    if (!cid.ok()) {
        return cid.error();
    }
    auto service = getService(*cid);
    if (!service) {
        return Error() << "No service";
    }

    auto blob = readBytesFromFile(blob_file);
    if (!blob.ok()) {
        return blob.error();
    }

    auto status = service->initializeSigningKey(blob.value());
    if (!status.isOk()) {
        return Error() << "Failed to initialize signing key: " << status.getDescription();
    }

    for (auto& file : files) {
        auto result = signFile(service.get(), file);
        if (!result.ok()) {
            return Error() << result.error() << ": " << file;
        }
    }
    return {};
}

static Result<void> initializeKey(TargetVm& vm, const std::string& blob_file) {
    auto cid = vm.resolveCid();
    if (!cid.ok()) {
        return cid.error();
    }
    auto service = getService(*cid);
    if (!service) {
        return Error() << "No service";
    }

    auto blob = readBytesFromFile(blob_file);
    if (!blob.ok()) {
        return blob.error();
    }

    auto status = service->initializeSigningKey(blob.value());
    if (!status.isOk()) {
        return Error() << "Failed to initialize signing key: " << status.getDescription();
    }
    return {};
}

static Result<void> makeInstanceImage(const std::string& image_path) {
    ndk::SpAIBinder binder(AServiceManager_waitForService("android.system.virtualizationservice"));
    auto service = IVirtualizationService::fromBinder(binder);
    if (!service) {
        return Error() << "Failed to connect to virtualization service.";
    }

    ScopedFileDescriptor fd(TEMP_FAILURE_RETRY(
            open(image_path.c_str(), O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC, S_IRUSR | S_IWUSR)));
    if (fd.get() == -1) {
        return ErrnoError() << "Failed to create image file";
    }

    auto status = service->initializeWritablePartition(fd, 10 * 1024 * 1024,
                                                       PartitionType::ANDROID_VM_INSTANCE);
    if (!status.isOk()) {
        return Error() << "Failed to initialize partition: " << status.getDescription();
    }
    return {};
}

int main(int argc, char** argv) {
    // Restrict access to our outputs to the current user.
    umask(077);

    int cid = 0;
    std::string imageFile;
    std::string logFile;

    while (argc >= 3) {
        if (argv[1] == "--cid"sv) {
            cid = atoi(argv[2]);
            if (cid == 0) {
                std::cerr << "Invalid cid\n";
                return 1;
            }
        } else if (argv[1] == "--start"sv) {
            imageFile = argv[2];
        } else if (argv[1] == "--log"sv) {
            logFile = argv[2];
        } else {
            break;
        }
        argc -= 2;
        argv += 2;
    }

    TargetVm vm(cid, logFile, imageFile);

    if (argc == 4 && argv[1] == "generate"sv) {
        auto result = generate(vm, argv[2], argv[3]);
        if (result.ok()) {
            return 0;
        } else {
            std::cerr << result.error() << '\n';
        }
    } else if (argc == 4 && argv[1] == "verify"sv) {
        auto result = verify(vm, argv[2], argv[3]);
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
    } else if (argc >= 4 && argv[1] == "sign"sv) {
        const std::vector<std::string> files{&argv[3], &argv[argc]};
        auto result = sign(vm, argv[2], files);
        if (result.ok()) {
            std::cerr << "All signatures generated.\n";
            return 0;
        } else {
            std::cerr << result.error() << '\n';
        }
    } else if (argc == 3 && argv[1] == "init-key"sv) {
        auto result = initializeKey(vm, argv[2]);
        if (result.ok()) {
            return 0;
        } else {
            std::cerr << result.error() << '\n';
        }
    } else if (argc == 3 && argv[1] == "make-instance"sv) {
        auto result = makeInstanceImage(argv[2]);
        if (result.ok()) {
            return 0;
        } else {
            std::cerr << result.error() << '\n';
        }
    } else {
        std::cerr << "Usage: compos_key_cmd [OPTIONS] generate|verify|sign|make-instance|init-key\n"
                  << "  generate <blob file> <public key file> Generate new key pair and write\n"
                  << "    the private key blob and public key to the specified files.\n "
                  << "  verify <blob file> <public key file> Verify that the content of the\n"
                  << "    specified private key blob and public key files are valid.\n "
                  << "  init-key <blob file> Initialize the service key.\n"
                  << "  sign <blob file> <files to be signed> Generate signatures for one or\n"
                  << "    more files using the supplied private key blob. Signature is stored in\n"
                  << "    <filename>.signature\n"
                  << "  make-instance <image file> Create an empty instance image file for a VM.\n"
                  << "\n"
                  << "OPTIONS: --log <log file> (--cid <cid> | --start <image file>)\n"
                  << "  Specify --log to write VM log to a file rather than stdout.\n"
                  << "  Specify --cid to connect to a VM rather than the host.\n"
                  << "  Specify --start to start a VM from the given instance image file and\n "
                  << "    connect to that.\n";
    }
    return 1;
}
