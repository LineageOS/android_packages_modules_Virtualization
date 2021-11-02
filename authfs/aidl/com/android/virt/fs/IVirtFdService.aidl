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

package com.android.virt.fs;

/**
 * A service that works like a file server, where the files and directories are identified by
 * "remote FD" that may be pre-exchanged or created on request.
 *
 * When a binder error is returned and it is a service specific error, the error code is an errno
 * value which is an int.
 *
 * {@hide}
 */
interface IVirtFdService {
    /** Maximum content size that the service allows the client to request. */
    const int MAX_REQUESTING_DATA = 16384;

    /**
     * Returns the content of the given remote FD, from the offset, for the amount of requested size
     * or until EOF.
     */
    byte[] readFile(int fd, long offset, int size);

    /**
     * Returns the content of fs-verity compatible Merkle tree of the given remote FD, from the
     * offset, for the amount of requested size or until EOF.
     */
    byte[] readFsverityMerkleTree(int fd, long offset, int size);

    /** Returns the fs-verity signature of the given remote FD. */
    byte[] readFsveritySignature(int fd);

    /**
     * Writes the buffer to the given remote FD from the file's offset. Returns the number of bytes
     * written.
     */
    int writeFile(int fd, in byte[] buf, long offset);

    /** Resizes the file backed by the given remote FD to the new size. */
    void resize(int fd, long size);

    /** Returns the file size. */
    long getFileSize(int fd);

    /**
     * Create a file given the remote directory FD.
     *
     * @param basename The file name to create. Must not contain directory separator.
     * @return file A remote FD that represents the new created file.
     */
    int createFileInDirectory(int fd, String basename);

    /**
     * Create a directory inside the given remote directory FD.
     *
     * @param basename The directory name to create. Must not contain directory separator.
     * @return file FD that represents the new created directory.
     */
    int createDirectoryInDirectory(int id, String basename);
}
