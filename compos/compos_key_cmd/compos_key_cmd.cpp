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
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>

#include "odsign_info.pb.h"

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
using android::base::Dirname;
using android::base::ErrnoError;
using android::base::Error;
using android::base::Fdopen;
using android::base::Result;
using android::base::unique_fd;
using android::base::WriteFully;
using ndk::ScopedAStatus;
using ndk::ScopedFileDescriptor;
using ndk::SharedRefBase;
using odsign::proto::OdsignInfo;

constexpr unsigned int kRpcPort = 6432;

constexpr const char* kConfigApkPath =
        "/apex/com.android.compos/app/CompOSPayloadApp/CompOSPayloadApp.apk";

// These are paths inside the APK
constexpr const char* kDefaultConfigFilePath = "assets/vm_config.json";
constexpr const char* kPreferStagedConfigFilePath = "assets/vm_config_staged.json";

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
    if (source == nullptr) {
        LOG(INFO) << "Can't log VM output";
        return;
    }
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

    ::ndk::ScopedAStatus onError(int32_t in_cid, int32_t in_error_code,
                                 const std::string& in_message) override {
        LOG(WARNING) << "VM error! cid = " << in_cid << ", error_code = " << in_error_code
                     << ", message = " << in_message;
        {
            std::unique_lock lock(mMutex);
            mDied = true;
        }
        mCv.notify_all();
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
    TargetVm(int cid, const std::string& logFile, const std::string& instanceImageFile,
             bool debuggable, bool preferStaged)
          : mCid(cid),
            mLogFile(logFile),
            mInstanceImageFile(instanceImageFile),
            mDebuggable(debuggable),
            mPreferStaged(preferStaged) {}

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

        // Start a new VM with a given instance.img

        // We need a thread pool to receive VM callbacks.
        ABinderProcess_startThreadPool();

        ndk::SpAIBinder binder(
                AServiceManager_waitForService("android.system.virtualizationservice"));
        auto service = IVirtualizationService::fromBinder(binder);
        if (!service) {
            return Error() << "Failed to connect to virtualization service.";
        }

        // Console output and the system log output from the VM are redirected to this file.
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

        // Prepare an idsig file
        std::string idsigPath = Dirname(mInstanceImageFile) + "/idsig";
        {
            ScopedFileDescriptor idsigFd(TEMP_FAILURE_RETRY(
                    open(idsigPath.c_str(), O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC,
                         S_IRUSR | S_IWUSR | S_IRGRP)));
            if (idsigFd.get() == -1) {
                return ErrnoError() << "Failed to create an idsig file";
            }
            auto status = service->createOrUpdateIdsigFile(apkFd, idsigFd);
            if (!status.isOk()) {
                return Error() << status.getDescription();
            }
        }

        ScopedFileDescriptor idsigFd(
                TEMP_FAILURE_RETRY(open(idsigPath.c_str(), O_RDONLY | O_CLOEXEC)));
        if (idsigFd.get() == -1) {
            return ErrnoError() << "Failed to open an idsig file";
        }

        ScopedFileDescriptor instanceFd(
                TEMP_FAILURE_RETRY(open(mInstanceImageFile.c_str(), O_RDWR | O_CLOEXEC)));
        if (instanceFd.get() == -1) {
            return ErrnoError() << "Failed to open instance image file";
        }

        auto config = VirtualMachineConfig::make<VirtualMachineConfig::Tag::appConfig>();
        auto& appConfig = config.get<VirtualMachineConfig::Tag::appConfig>();
        appConfig.apk = std::move(apkFd);
        appConfig.idsig = std::move(idsigFd);
        appConfig.instanceImage = std::move(instanceFd);
        appConfig.configPath = mPreferStaged ? kPreferStagedConfigFilePath : kDefaultConfigFilePath;
        appConfig.debugLevel = mDebuggable ? VirtualMachineAppConfig::DebugLevel::FULL
                                           : VirtualMachineAppConfig::DebugLevel::NONE;
        appConfig.memoryMib = 0; // Use default

        LOG(INFO) << "Starting VM";
        auto status = service->createVm(config, logFd, logFd, &mVm);
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
    const bool mDebuggable;
    const bool mPreferStaged;
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
    bool debuggable = false;
    bool preferStaged = false;

    for (;;) {
        // Options with no associated value
        if (argc >= 2) {
            if (argv[1] == "--debug"sv) {
                debuggable = true;
                argc -= 1;
                argv += 1;
                continue;
            } else if (argv[1] == "--staged"sv) {
                preferStaged = true;
                argc -= 1;
                argv += 1;
                continue;
            }
        }
        if (argc < 3) break;
        // Options requiring a value
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

    TargetVm vm(cid, logFile, imageFile, debuggable, preferStaged);

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
        std::cerr << "Usage: compos_key_cmd [OPTIONS] COMMAND\n"
                  << "Where COMMAND can be:\n"
                  << "  make-instance <image file> Create an empty instance image file for a VM.\n"
                  << "  generate <blob file> <public key file> Generate new key pair and write\n"
                  << "    the private key blob and public key to the specified files.\n "
                  << "  verify <blob file> <public key file> Verify that the content of the\n"
                  << "    specified private key blob and public key files are valid.\n "
                  << "  init-key <blob file> Initialize the service key.\n"
                  << "\n"
                  << "OPTIONS: --log <log file> --debug --staged\n"
                  << "    (--cid <cid> | --start <image file>)\n"
                  << "  Specify --log to write VM log to a file rather than stdout.\n"
                  << "  Specify --debug with --start to make the VM fully debuggable.\n"
                  << "  Specify --staged with --start to prefer staged APEXes in the VM.\n"
                  << "  Specify --cid to connect to a VM rather than the host.\n"
                  << "  Specify --start to start a VM from the given instance image file and\n "
                  << "    connect to that.\n";
    }
    return 1;
}
