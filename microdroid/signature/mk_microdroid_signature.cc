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

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <string>

#include <android-base/file.h>
#include <android-base/result.h>
#include <json/json.h>

#include "microdroid/signature.h"

using android::base::Dirname;
using android::base::ErrnoError;
using android::base::Error;
using android::base::Result;
using android::microdroid::MicrodroidSignature;
using android::microdroid::WriteMicrodroidSignature;

Result<uint32_t> GetFileSize(const std::string& path) {
    struct stat st;
    if (lstat(path.c_str(), &st) == -1) {
        return ErrnoError() << "Can't lstat " << path;
    }
    return static_cast<uint32_t>(st.st_size);
}

// config JSON schema:
// {
//   "apexes": [
//     {
//       "name": string,       // the apex name
//       "path": string,       // the path to the apex file
//                             // absolute or relative to the config file
//       "publicKey": string,  // optional
//       "rootDigest": string, // optional
//     }
//   ]
// }

Result<MicrodroidSignature> LoadConfig(const std::string& config_file) {
    MicrodroidSignature signature;
    signature.set_version(1);

    const std::string dirname = Dirname(config_file);
    std::ifstream in(config_file);
    Json::CharReaderBuilder builder;
    Json::Value root;
    Json::String errs;
    if (!parseFromStream(builder, in, &root, &errs)) {
        return Error() << "bad config: " << errs;
    }

    for (const Json::Value& apex : root["apexes"]) {
        auto apex_signature = signature.add_apexes();

        Json::Value name = apex["name"];
        Json::Value path = apex["path"];
        Json::Value publicKey = apex["publicKey"];
        Json::Value rootDigest = apex["rootDigest"];

        if (name.isString()) {
            apex_signature->set_name(name.asString());
        } else {
            return Error() << "bad config: apexes.name should be a string: " << path;
        }

        if (path.isString()) {
            std::string apex_path = path.asString();

            // resolve path with the config_file's dirname if not absolute
            bool is_absolute = !apex_path.empty() && apex_path[0] == '/';
            if (!is_absolute) {
                apex_path = dirname + "/" + apex_path;
            }

            auto file_size = GetFileSize(apex_path);
            if (!file_size.ok()) {
                return Error() << "I/O error: " << file_size.error();
            }
            apex_signature->set_size(file_size.value());
        } else {
            return Error() << "bad config: apexes.path should be a string: " << path;
        }

        if (publicKey.isString()) {
            apex_signature->set_publickey(publicKey.asString());
        } else if (!publicKey.isNull()) {
            return Error() << "bad config: apexes.publicKey should be a string or null: "
                           << publicKey;
        }

        if (rootDigest.isString()) {
            apex_signature->set_rootdigest(rootDigest.asString());
        } else if (!rootDigest.isNull()) {
            return Error() << "bad config: apexes.rootDigest should be a string or null: "
                           << rootDigest;
        }
    }

    return signature;
}

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <config> <output>\n";
        return 1;
    }

    auto config = LoadConfig(argv[1]);
    if (!config.ok()) {
        std::cerr << config.error() << '\n';
        return 1;
    }

    std::ofstream out(argv[2]);
    auto result = WriteMicrodroidSignature(*config, out);
    if (!result.ok()) {
        std::cerr << result.error() << '\n';
        return 1;
    }
    return 0;
}