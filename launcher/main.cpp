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

#include <dlfcn.h>

#include <cstdlib>
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage:\n";
        std::cout << "    " << argv[0] << " LIBNAME [ARGS...]\n";
        return EXIT_FAILURE;
    }

    const char* libname = argv[1];
    void* handle = dlopen(libname, RTLD_NOW);
    if (handle == nullptr) {
        std::cerr << "Failed to load " << libname << ": " << dlerror() << "\n";
        return EXIT_FAILURE;
    }

    int (*entry)(int argc, char* argv[]) = nullptr;
    entry = reinterpret_cast<decltype(entry)>(dlsym(handle, "android_native_main"));
    if (entry == nullptr) {
        std::cerr << "Failed to find entrypoint `android_native_main`: " << dlerror() << "\n";
        return EXIT_FAILURE;
    }

    return entry(argc - 1, argv + 1);
}
