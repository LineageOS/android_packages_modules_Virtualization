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
#include <optional>
#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/result.h>
#include <com_android_apex.h>
#include <image_aggregator.h>
#include <json/json.h>

#include "microdroid/signature.h"

using android::base::Dirname;
using android::base::ErrnoError;
using android::base::Error;
using android::base::Result;
using android::microdroid::ApexSignature;
using android::microdroid::MicrodroidSignature;
using android::microdroid::WriteMicrodroidSignature;

using com::android::apex::ApexInfoList;
using com::android::apex::readApexInfoList;

using cuttlefish::CreateCompositeDisk;
using cuttlefish::ImagePartition;
using cuttlefish::kLinuxFilesystem;

Result<uint32_t> GetFileSize(const std::string& path) {
    struct stat st;
    if (lstat(path.c_str(), &st) == -1) {
        return ErrnoError() << "Can't lstat " << path;
    }
    return static_cast<uint32_t>(st.st_size);
}

std::string ToAbsolute(const std::string& path, const std::string& dirname) {
    bool is_absolute = !path.empty() && path[0] == '/';
    if (is_absolute) {
        return path;
    } else {
        return dirname + "/" + path;
    }
}

// Returns `append` is appended to the end of filename preserving the extension.
std::string AppendFileName(const std::string& filename, const std::string& append) {
    size_t pos = filename.find_last_of('.');
    if (pos == std::string::npos) {
        return filename + append;
    } else {
        return filename.substr(0, pos) + append + filename.substr(pos);
    }
}

struct ApexConfig {
    std::string name; // the apex name
    std::string path; // the path to the apex file
                      // absolute or relative to the config file
    std::optional<std::string> public_key;
    std::optional<std::string> root_digest;
};

struct Config {
    std::string dirname; // config file's direname to resolve relative paths in the config

    std::vector<std::string> system_apexes;
    std::vector<ApexConfig> apexes;
};

#define DO(expr) \
    if (auto res = (expr); !res.ok()) return res.error()

Result<void> ParseJson(const Json::Value& value, std::string& s) {
    if (!value.isString()) {
        return Error() << "should be a string: " << value;
    }
    s = value.asString();
    return {};
}

Result<void> ParseJson(const Json::Value& value, std::optional<std::string>& s) {
    if (value.isNull()) {
        s.reset();
        return {};
    }
    s.emplace();
    return ParseJson(value, *s);
}

Result<void> ParseJson(const Json::Value& value, ApexConfig& apex_config) {
    DO(ParseJson(value["name"], apex_config.name));
    DO(ParseJson(value["path"], apex_config.path));
    DO(ParseJson(value["publicKey"], apex_config.public_key));
    DO(ParseJson(value["rootDigest"], apex_config.root_digest));
    return {};
}

template <typename T>
Result<void> ParseJson(const Json::Value& values, std::vector<T>& parsed) {
    for (const Json::Value& value : values) {
        T t;
        DO(ParseJson(value, t));
        parsed.push_back(std::move(t));
    }
    return {};
}

Result<void> ParseJson(const Json::Value& value, Config& config) {
    DO(ParseJson(value["system_apexes"], config.system_apexes));
    DO(ParseJson(value["apexes"], config.apexes));
    return {};
}

Result<Config> LoadConfig(const std::string& config_file) {
    std::ifstream in(config_file);
    Json::CharReaderBuilder builder;
    Json::Value root;
    Json::String errs;
    if (!parseFromStream(builder, in, &root, &errs)) {
        return Error() << "bad config: " << errs;
    }

    Config config;
    config.dirname = Dirname(config_file);
    DO(ParseJson(root, config));
    return config;
}

#undef DO

Result<void> LoadSystemApexes(Config& config) {
    static const char* kApexInfoListFile = "/apex/apex-info-list.xml";
    std::optional<ApexInfoList> apex_info_list = readApexInfoList(kApexInfoListFile);
    if (!apex_info_list.has_value()) {
        return Error() << "Failed to read " << kApexInfoListFile;
    }
    auto get_apex_path = [&](const std::string& apex_name) -> std::optional<std::string> {
        for (const auto& apex_info : apex_info_list->getApexInfo()) {
            if (apex_info.getIsActive() && apex_info.getModuleName() == apex_name) {
                return apex_info.getModulePath();
            }
        }
        return std::nullopt;
    };
    for (const auto& apex_name : config.system_apexes) {
        const auto& apex_path = get_apex_path(apex_name);
        if (!apex_path.has_value()) {
            return Error() << "Can't find the system apex: " << apex_name;
        }
        config.apexes.push_back(ApexConfig{
                .name = apex_name,
                .path = *apex_path,
                .public_key = std::nullopt,
                .root_digest = std::nullopt,
        });
    }
    return {};
}

Result<void> MakeSignature(const Config& config, const std::string& filename) {
    MicrodroidSignature signature;
    signature.set_version(1);

    for (const auto& apex_config : config.apexes) {
        ApexSignature* apex_signature = signature.add_apexes();

        // name
        apex_signature->set_name(apex_config.name);

        // size
        auto file_size = GetFileSize(ToAbsolute(apex_config.path, config.dirname));
        if (!file_size.ok()) {
            return Error() << "I/O error: " << file_size.error();
        }
        apex_signature->set_size(file_size.value());

        // publicKey
        if (apex_config.public_key.has_value()) {
            apex_signature->set_publickey(apex_config.public_key.value());
        }

        // rootDigest
        if (apex_config.root_digest.has_value()) {
            apex_signature->set_rootdigest(apex_config.root_digest.value());
        }
    }

    std::ofstream out(filename);
    return WriteMicrodroidSignature(signature, out);
}

Result<void> MakePayload(const Config& config, const std::string& signature_file,
                         const std::string& output_file) {
    std::vector<ImagePartition> partitions;

    // put signature at the first partition
    partitions.push_back(ImagePartition{
            .label = "signature",
            .image_file_path = signature_file,
            .type = kLinuxFilesystem,
            .read_only = true,
    });

    // put apexes at the subsequent partitions
    for (size_t i = 0; i < config.apexes.size(); i++) {
        const auto& apex_config = config.apexes[i];
        partitions.push_back(ImagePartition{
                .label = "payload_apex_" + std::to_string(i),
                .image_file_path = apex_config.path,
                .type = kLinuxFilesystem,
                .read_only = true,
        });
    }

    const std::string gpt_header = AppendFileName(output_file, "-header");
    const std::string gpt_footer = AppendFileName(output_file, "-footer");
    CreateCompositeDisk(partitions, gpt_header, gpt_footer, output_file);
    return {};
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

    if (const auto res = LoadSystemApexes(*config); !res.ok()) {
        std::cerr << res.error() << '\n';
        return 1;
    }

    const std::string output_file(argv[2]);
    const std::string signature_file = AppendFileName(output_file, "-signature");

    if (const auto res = MakeSignature(*config, signature_file); !res.ok()) {
        std::cerr << res.error() << '\n';
        return 1;
    }
    if (const auto res = MakePayload(*config, signature_file, output_file); !res.ok()) {
        std::cerr << res.error() << '\n';
        return 1;
    }

    return 0;
}