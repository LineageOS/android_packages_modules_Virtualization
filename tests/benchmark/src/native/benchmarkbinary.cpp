/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <aidl/android/system/virtualmachineservice/IVirtualMachineService.h>
#include <aidl/com/android/microdroid/testservice/BnBenchmarkService.h>
#include <android-base/result.h>
#include <android-base/unique_fd.h>
#include <fcntl.h>
#include <linux/vm_sockets.h>
#include <stdio.h>
#include <unistd.h>

#include <binder_rpc_unstable.hpp>
#include <chrono>
#include <random>
#include <string>

#include "android-base/logging.h"

using aidl::android::system::virtualmachineservice::IVirtualMachineService;
using android::base::ErrnoError;
using android::base::Error;
using android::base::Result;
using android::base::unique_fd;

namespace {
constexpr uint64_t kBlockSizeBytes = 4096;

class IOBenchmarkService : public aidl::com::android::microdroid::testservice::BnBenchmarkService {
public:
    ndk::ScopedAStatus readFile(const std::string& filename, int64_t fileSizeBytes, bool isRand,
                                double* out) override {
        if (auto res = read_file(filename, fileSizeBytes, isRand); res.ok()) {
            *out = res.value();
        } else {
            std::stringstream error;
            error << "Failed reading file: " << res.error();
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_ARGUMENT,
                                                                    error.str().c_str());
        }
        return ndk::ScopedAStatus::ok();
    }

private:
    /** Returns the elapsed seconds for reading the file. */
    Result<double> read_file(const std::string& filename, int64_t fileSizeBytes, bool is_rand) {
        const int64_t block_count = fileSizeBytes / kBlockSizeBytes;
        std::vector<uint64_t> offsets;
        if (is_rand) {
            std::mt19937 rd{std::random_device{}()};
            offsets.reserve(block_count);
            for (auto i = 0; i < block_count; ++i) offsets.push_back(i * kBlockSizeBytes);
            std::shuffle(offsets.begin(), offsets.end(), rd);
        }
        char buf[kBlockSizeBytes];

        clock_t start = clock();
        unique_fd fd(open(filename.c_str(), O_RDONLY));
        if (fd.get() == -1) {
            return ErrnoError() << "Read: opening " << filename << " failed";
        }
        for (auto i = 0; i < block_count; ++i) {
            if (is_rand) {
                if (lseek(fd.get(), offsets[i], SEEK_SET) == -1) {
                    return ErrnoError() << "failed to lseek";
                }
            }
            auto bytes = read(fd.get(), buf, kBlockSizeBytes);
            if (bytes == 0) {
                return Error() << "unexpected end of file";
            } else if (bytes == -1) {
                return ErrnoError() << "failed to read";
            }
        }
        return {((double)clock() - start) / CLOCKS_PER_SEC};
    }
};

Result<void> run_io_benchmark_tests() {
    auto test_service = ndk::SharedRefBase::make<IOBenchmarkService>();
    auto callback = []([[maybe_unused]] void* param) {
        // Tell microdroid_manager that we're ready.
        // If we can't, abort in order to fail fast - the host won't proceed without
        // receiving the onReady signal.
        ndk::SpAIBinder binder(
                RpcClient(VMADDR_CID_HOST, IVirtualMachineService::VM_BINDER_SERVICE_PORT));
        auto vm_service = IVirtualMachineService::fromBinder(binder);
        if (vm_service == nullptr) {
            LOG(ERROR) << "failed to connect VirtualMachineService\n";
            abort();
        }
        if (auto status = vm_service->notifyPayloadReady(); !status.isOk()) {
            LOG(ERROR) << "failed to notify payload ready to virtualizationservice: "
                       << status.getDescription();
            abort();
        }
    };

    if (!RunRpcServerCallback(test_service->asBinder().get(), test_service->SERVICE_PORT, callback,
                              nullptr)) {
        return Error() << "RPC Server failed to run";
    }
    return {};
}
} // Anonymous namespace

extern "C" int android_native_main([[maybe_unused]] int argc, char* argv[]) {
    if (strcmp(argv[1], "no_io") == 0) {
        // do nothing for now; just leave it alive. good night.
        for (;;) {
            sleep(1000);
        }
    } else if (strcmp(argv[1], "io") == 0) {
        if (auto res = run_io_benchmark_tests(); res.ok()) {
            return 0;
        } else {
            LOG(ERROR) << "IO benchmark test failed: " << res.error() << "\n";
            return 1;
        }
    }
    return 0;
}
