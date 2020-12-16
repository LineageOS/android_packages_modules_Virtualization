/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <sys/socket.h>
#include <unistd.h>

// Needs to be included after sys/socket.h
#include <linux/vm_sockets.h>

#include <iostream>

#include "android-base/file.h"
#include "android-base/logging.h"
#include "android-base/parseint.h"
#include "android-base/unique_fd.h"

using namespace android::base;

int main(int argc, const char *argv[]) {
    unsigned int port;
    if (argc != 2 || !ParseUint(argv[1], &port)) {
        LOG(ERROR) << "Usage: " << argv[0] << " <port>";
        return EXIT_FAILURE;
    }

    unique_fd server_fd(TEMP_FAILURE_RETRY(socket(AF_VSOCK, SOCK_STREAM, 0)));
    if (server_fd < 0) {
        PLOG(ERROR) << "socket";
        return EXIT_FAILURE;
    }

    struct sockaddr_vm server_sa = (struct sockaddr_vm){
            .svm_family = AF_VSOCK,
            .svm_port = port,
            .svm_cid = VMADDR_CID_ANY,
    };

    int ret = TEMP_FAILURE_RETRY(bind(server_fd, (struct sockaddr *)&server_sa, sizeof(server_sa)));
    if (ret != 0) {
        PLOG(ERROR) << "bind";
        return EXIT_FAILURE;
    }

    LOG(INFO) << "Listening on port " << port << "...";
    ret = TEMP_FAILURE_RETRY(listen(server_fd, 1));
    if (ret != 0) {
        PLOG(ERROR) << "listen";
        return EXIT_FAILURE;
    }

    LOG(INFO) << "Accepting connection...";
    struct sockaddr_vm client_sa;
    socklen_t client_sa_len = sizeof(client_sa);
    unique_fd client_fd(
            TEMP_FAILURE_RETRY(accept(server_fd, (struct sockaddr *)&client_sa, &client_sa_len)));
    if (client_fd < 0) {
        PLOG(ERROR) << "accept";
        return EXIT_FAILURE;
    }
    LOG(INFO) << "Connection from CID " << client_sa.svm_cid << " on port " << client_sa.svm_port;

    LOG(INFO) << "Reading message from the client...";
    std::string msg;
    if (!ReadFdToString(client_fd, &msg)) {
        PLOG(ERROR) << "ReadFdToString";
        return EXIT_FAILURE;
    }

    // Print the received message to stdout.
    std::cout << msg << std::endl;

    LOG(INFO) << "Exiting...";
    return EXIT_SUCCESS;
}
