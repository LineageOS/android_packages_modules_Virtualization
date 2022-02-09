/*
 * Copyright 2022 The Android Open Source Project
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

#include <android-base/file.h>
#include <android-base/logging.h>
#include <unistd.h>

#include <iostream>
#include <string_view>

#include "compos_key.h"

using android::base::ErrnoError;
using android::base::WriteFully;
using namespace std::literals;

int main(int argc, char** argv) {
    android::base::InitLogging(argv, android::base::LogdLogger(android::base::SYSTEM));

    if (argc == 2) {
        if (argv[1] == "public_key"sv) {
            auto key_pair = deriveKeyFromDice();
            if (!key_pair.ok()) {
                LOG(ERROR) << key_pair.error();
                return 1;
            }
            if (!WriteFully(STDOUT_FILENO, key_pair->public_key.data(),
                            key_pair->public_key.size())) {
                PLOG(ERROR) << "Write failed";
                return 1;
            }
            return 0;
        }
    }

    std::cerr << "Usage:\n"
                 "compos_key_helper public_key   Write current public key to stdout\n";
    return 1;
}
