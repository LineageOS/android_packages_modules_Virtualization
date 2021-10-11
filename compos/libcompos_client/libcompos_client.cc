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

#include "libcompos_client.h"

#include <android-base/logging.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <android/binder_auto_utils.h>
#include <android/binder_manager.h>
#include <binder/IInterface.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <binder_rpc_unstable.hpp>
#include <memory>

#include "aidl/android/system/composd/IIsolatedCompilationService.h"
#include "aidl/com/android/compos/FdAnnotation.h"
#include "aidl/com/android/compos/ICompOsService.h"

using aidl::android::system::composd::IIsolatedCompilationService;
using aidl::com::android::compos::FdAnnotation;
using aidl::com::android::compos::ICompOsService;
using android::base::Join;
using android::base::Pipe;
using android::base::unique_fd;

namespace {

constexpr unsigned int kCompsvcRpcPort = 6432;
constexpr const char* kComposdServiceName = "android.system.composd";

void ExecFdServer(const int* ro_fds, size_t ro_fds_num, const int* rw_fds, size_t rw_fds_num,
                  unique_fd ready_fd) {
    // Holder of C Strings, with enough memory reserved to avoid reallocation. Otherwise,
    // `holder.rbegin()->c_str()` may become invalid.
    std::vector<std::string> holder;
    holder.reserve(ro_fds_num + rw_fds_num + 1 /* for --ready-fd */);

    std::vector<char const*> args = {"/apex/com.android.virt/bin/fd_server"};
    for (int i = 0; i < ro_fds_num; ++i) {
        args.emplace_back("--ro-fds");
        holder.emplace_back(std::to_string(*(ro_fds + i)));
        args.emplace_back(holder.rbegin()->c_str());
    }
    for (int i = 0; i < rw_fds_num; ++i) {
        args.emplace_back("--rw-fds");
        holder.emplace_back(std::to_string(*(rw_fds + i)));
        args.emplace_back(holder.rbegin()->c_str());
    }
    args.emplace_back("--ready-fd");
    holder.emplace_back(std::to_string(ready_fd.get()));
    args.emplace_back(holder.rbegin()->c_str());

    LOG(DEBUG) << "Starting fd_server, args: " << Join(args, ' ');
    args.emplace_back(nullptr);
    if (execv(args[0], const_cast<char* const*>(args.data())) < 0) {
        PLOG(ERROR) << "execv failed";
    }
}

class FileSharingSession final {
public:
    static std::unique_ptr<FileSharingSession> Create(const int* ro_fds, size_t ro_fds_num,
                                                      const int* rw_fds, size_t rw_fds_num) {
        // Create pipe for receiving a ready ping from fd_server.
        unique_fd pipe_read, pipe_write;
        if (!Pipe(&pipe_read, &pipe_write, /* flags= */ 0)) {
            PLOG(ERROR) << "Cannot create pipe";
            return nullptr;
        }

        pid_t pid = fork();
        if (pid < 0) {
            PLOG(ERROR) << "fork error";
            return nullptr;
        } else if (pid > 0) {
            pipe_write.reset();

            // When fd_server is ready it closes its end of the pipe. And if it exits, the pipe is
            // also closed. Either way this read will return 0 bytes at that point, and there's no
            // point waiting any longer.
            char c;
            read(pipe_read.get(), &c, sizeof(c));

            std::unique_ptr<FileSharingSession> session(new FileSharingSession(pid));
            return session;
        } else if (pid == 0) {
            pipe_read.reset();
            ExecFdServer(ro_fds, ro_fds_num, rw_fds, rw_fds_num, std::move(pipe_write));
            exit(EXIT_FAILURE);
        }
        return nullptr;
    }

    ~FileSharingSession() {
        if (kill(fd_server_pid_, SIGTERM) < 0) {
            PLOG(ERROR) << "Cannot kill fd_server (pid " << std::to_string(fd_server_pid_)
                        << ") with SIGTERM. Retry with SIGKILL.";
            if (kill(fd_server_pid_, SIGKILL) < 0) {
                PLOG(ERROR) << "Still cannot terminate with SIGKILL. Give up.";
                // TODO: it may be the safest if we turn fd_server into a library to run in a
                // thread.
            }
        }
    }

private:
    explicit FileSharingSession(pid_t pid) : fd_server_pid_(pid) {}

    pid_t fd_server_pid_;
};

int MakeRequestToVM(int cid, const uint8_t* marshaled, size_t size, const int* ro_fds,
                    size_t ro_fds_num, const int* rw_fds, size_t rw_fds_num) {
    ndk::SpAIBinder binder(RpcClient(cid, kCompsvcRpcPort));
    std::shared_ptr<ICompOsService> service = ICompOsService::fromBinder(binder);
    if (!service) {
        LOG(ERROR) << "Cannot connect to the service";
        return -1;
    }

    std::unique_ptr<FileSharingSession> session_raii =
            FileSharingSession::Create(ro_fds, ro_fds_num, rw_fds, rw_fds_num);
    if (!session_raii) {
        LOG(ERROR) << "Cannot start to share FDs";
        return -1;
    }

    // Since the input from the C API are raw pointers, we need to duplicate them into vectors in
    // order to pass to the binder API.
    std::vector<uint8_t> duplicated_buffer(marshaled, marshaled + size);
    FdAnnotation fd_annotation = {
            .input_fds = std::vector<int>(ro_fds, ro_fds + ro_fds_num),
            .output_fds = std::vector<int>(rw_fds, rw_fds + rw_fds_num),
    };
    int8_t exit_code;
    ndk::ScopedAStatus status = service->compile(duplicated_buffer, fd_annotation, &exit_code);
    if (!status.isOk()) {
        LOG(ERROR) << "Compilation failed (exit " << std::to_string(exit_code)
                   << "): " << status.getDescription();
        return -1;
    }
    return 0;
}

int MakeRequestToComposd(const uint8_t* marshaled, size_t size, const int* ro_fds,
                         size_t ro_fds_num, const int* rw_fds, size_t rw_fds_num) {
    ndk::SpAIBinder binder(AServiceManager_getService(kComposdServiceName));
    std::shared_ptr<IIsolatedCompilationService> service =
            IIsolatedCompilationService::fromBinder(binder);
    if (!service) {
        LOG(ERROR) << "Cannot connect to the service";
        return -1;
    }

    auto session_raii = std::unique_ptr<FileSharingSession>(
            FileSharingSession::Create(ro_fds, ro_fds_num, rw_fds, rw_fds_num));
    if (!session_raii) {
        LOG(ERROR) << "Cannot start to share FDs";
        return -1;
    }

    // Since the input from the C API are raw pointers, we need to duplicate them into vectors in
    // order to pass to the binder API.
    std::vector<uint8_t> duplicated_buffer(marshaled, marshaled + size);
    FdAnnotation fd_annotation = {
            .input_fds = std::vector<int>(ro_fds, ro_fds + ro_fds_num),
            .output_fds = std::vector<int>(rw_fds, rw_fds + rw_fds_num),
    };
    int8_t exit_code;
    ndk::ScopedAStatus status = service->compile(duplicated_buffer, fd_annotation, &exit_code);
    if (!status.isOk()) {
        LOG(ERROR) << "Compilation failed (exit " << std::to_string(exit_code)
                   << "): " << status.getDescription();
        return -1;
    }
    return 0;
}

} // namespace

__BEGIN_DECLS

int AComposClient_Request(int cid, const uint8_t* marshaled, size_t size, const int* ro_fds,
                          size_t ro_fds_num, const int* rw_fds, size_t rw_fds_num) {
    if (cid == -1 /* VMADDR_CID_ANY */) {
        return MakeRequestToComposd(marshaled, size, ro_fds, ro_fds_num, rw_fds, rw_fds_num);
    } else {
        return MakeRequestToVM(cid, marshaled, size, ro_fds, ro_fds_num, rw_fds, rw_fds_num);
    }
}

__END_DECLS
