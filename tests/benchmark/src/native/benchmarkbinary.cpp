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
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/result.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <fcntl.h>
#include <linux/vm_sockets.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <vm_payload.h>

#include <binder_rpc_unstable.hpp>
#include <fstream>
#include <random>
#include <string>

#include "io_vsock.h"

using aidl::android::system::virtualmachineservice::IVirtualMachineService;
using android::base::ErrnoError;
using android::base::Error;
using android::base::Result;
using android::base::unique_fd;

namespace {
constexpr uint64_t kBlockSizeBytes = 4096;
constexpr uint64_t kNumBytesPerMB = 1024 * 1024;

template <typename T>
static ndk::ScopedAStatus resultStatus(const T& result) {
    if (!result.ok()) {
        std::stringstream error;
        error << result.error();
        return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_ARGUMENT,
                                                                error.str().c_str());
    }
    return ndk::ScopedAStatus::ok();
}

class IOBenchmarkService : public aidl::com::android::microdroid::testservice::BnBenchmarkService {
public:
    ndk::ScopedAStatus measureReadRate(const std::string& filename, int64_t fileSizeBytes,
                                       bool isRand, double* out) override {
        auto res = measure_read_rate(filename, fileSizeBytes, isRand);
        if (res.ok()) {
            *out = res.value();
        }
        return resultStatus(res);
    }

    ndk::ScopedAStatus getMemInfoEntry(const std::string& name, int64_t* out) override {
        auto value = read_meminfo_entry(name);
        if (!value.ok()) {
            return resultStatus(value);
        }

        *out = (int64_t)value.value();
        return ndk::ScopedAStatus::ok();
    }

    ndk::ScopedAStatus initVsockServer(int32_t port, int32_t* out) override {
        auto res = io_vsock::init_vsock_server(port);
        if (res.ok()) {
            *out = res.value();
        }
        return resultStatus(res);
    }

    ndk::ScopedAStatus runVsockServerAndReceiveData(int32_t server_fd,
                                                    int32_t num_bytes_to_receive) override {
        auto res = io_vsock::run_vsock_server_and_receive_data(server_fd, num_bytes_to_receive);
        return resultStatus(res);
    }

private:
    /** Measures the read rate for reading the given file. */
    Result<double> measure_read_rate(const std::string& filename, int64_t fileSizeBytes,
                                     bool is_rand) {
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
        unique_fd fd(open(filename.c_str(), O_RDONLY | O_CLOEXEC));
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
        double elapsed_seconds = ((double)clock() - start) / CLOCKS_PER_SEC;
        double read_rate = (double)fileSizeBytes / kNumBytesPerMB / elapsed_seconds;
        return {read_rate};
    }

    Result<size_t> read_meminfo_entry(const std::string& stat) {
        std::ifstream fs("/proc/meminfo");
        if (!fs.is_open()) {
            return Error() << "could not open /proc/meminfo";
        }

        std::string line;
        while (std::getline(fs, line)) {
            auto elems = android::base::Split(line, ":");
            if (elems[0] != stat) continue;

            std::string str = android::base::Trim(elems[1]);
            if (android::base::EndsWith(str, " kB")) {
                str = str.substr(0, str.length() - 3);
            }

            size_t value;
            if (!android::base::ParseUint(str, &value)) {
                return ErrnoError() << "failed to parse \"" << str << "\" as size_t";
            }
            return {value};
        }

        return Error() << "entry \"" << stat << "\" not found";
    }
};

Result<void> run_io_benchmark_tests() {
    auto test_service = ndk::SharedRefBase::make<IOBenchmarkService>();
    auto callback = []([[maybe_unused]] void* param) {
        if (!AVmPayload_notifyPayloadReady()) {
            LOG(ERROR) << "failed to notify payload ready to virtualizationservice";
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

extern "C" int android_native_main(int /* argc */, char* /* argv */[]) {
    if (auto res = run_io_benchmark_tests(); !res.ok()) {
        LOG(ERROR) << "IO benchmark test failed: " << res.error() << "\n";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
