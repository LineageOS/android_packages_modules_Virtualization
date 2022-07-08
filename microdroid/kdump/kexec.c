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

// This program loads kernel and initrd which the system will boot into when
// panic occurs.

#include <errno.h>
#include <fcntl.h>
#include <linux/kexec.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

static int open_checked(const char* path) {
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
        exit(1);
    }
    return fd;
}

int main(int argc, const char* argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <kernel> <initrd> <commandline>\n", argv[0]);
        return 1;
    }

    // TODO(b/238272206): consider harding these
    const char* kernel = argv[1];
    const char* initrd = argv[2];
    const char* cmdline = argv[3];
    unsigned long cmdline_len = strlen(cmdline) + 1; // include null terminator, otherwise EINVAL

    if (syscall(SYS_kexec_file_load, open_checked(kernel), open_checked(initrd), cmdline_len,
                cmdline, KEXEC_FILE_ON_CRASH) == -1) {
        fprintf(stderr, "Failed to load panic kernel: %s\n", strerror(errno));
        return 1;
    }
    return 0;
}
