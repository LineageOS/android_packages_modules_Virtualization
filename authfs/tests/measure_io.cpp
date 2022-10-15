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

#include <android-base/unique_fd.h>
#include <err.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <random>

using android::base::unique_fd;

constexpr int kBlockSizeBytes = 4096;
constexpr int kNumBytesPerMB = 1024 * 1024;

int main(int argc, const char *argv[]) {
    if (argc != 4 || !(strcmp(argv[3], "rand") == 0 || strcmp(argv[3], "seq") == 0)) {
        errx(EXIT_FAILURE, "Usage: %s <filename> <file_size_mb> <rand|seq>", argv[0]);
    }
    int file_size_mb = std::stoi(argv[2]);
    bool is_rand = (strcmp(argv[3], "rand") == 0);
    const int block_count = file_size_mb * kNumBytesPerMB / kBlockSizeBytes;
    std::vector<int> offsets(block_count);
    for (auto i = 0; i < block_count; ++i) {
        offsets[i] = i * kBlockSizeBytes;
    }
    if (is_rand) {
        std::mt19937 rd{std::random_device{}()};
        std::shuffle(offsets.begin(), offsets.end(), rd);
    }
    unique_fd fd(open(argv[1], O_RDONLY | O_CLOEXEC));
    if (fd.get() == -1) {
        errx(EXIT_FAILURE, "failed to open file: %s", argv[1]);
    }

    char buf[kBlockSizeBytes];
    clock_t start = clock();
    for (auto i = 0; i < block_count; ++i) {
        auto bytes = pread(fd, buf, kBlockSizeBytes, offsets[i]);
        if (bytes == 0) {
            errx(EXIT_FAILURE, "unexpected end of file");
        } else if (bytes == -1) {
            errx(EXIT_FAILURE, "failed to read");
        }
    }
    double elapsed_seconds = ((double)clock() - start) / CLOCKS_PER_SEC;
    double rate = (double)file_size_mb / elapsed_seconds;
    std::cout << std::setprecision(12) << rate << std::endl;

    return EXIT_SUCCESS;
}
