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

package com.android.compos;

import com.android.compos.CompOsKeyData;

/** {@hide} */
interface ICompOsService {
    /**
     * What type of compilation to perform.
     */
    @Backing(type="int")
    enum CompilationMode {
        /** Compile artifacts required by the current set of APEXes for use on reboot. */
        NORMAL_COMPILE = 0,
        /** Compile a full set of artifacts for test purposes. */
        TEST_COMPILE = 1,
    }

    /**
     * Initializes the service with the supplied encrypted private key blob. The key cannot be
     * changed once initialized, so once initiailzed, a repeated call will fail with
     * EX_ILLEGAL_STATE.
     *
     * @param keyBlob The encrypted blob containing the private key, as returned by
     *                generateSigningKey().
     */
    void initializeSigningKey(in byte[] keyBlob);

    /**
     * Run odrefresh in the VM context.
     *
     * The execution is based on the VM's APEX mounts, files on Android's /system (by accessing
     * through systemDirFd over AuthFS), and *CLASSPATH derived in the VM, to generate the same
     * odrefresh output artifacts to the output directory (through outputDirFd).
     *
     * @param compilationMode The type of compilation to be performed
     * @param systemDirFd An fd referring to /system
     * @param outputDirFd An fd referring to the output directory, ART_APEX_DATA
     * @param stagingDirFd An fd referring to the staging directory, e.g. ART_APEX_DATA/staging
     * @param targetDirName The sub-directory of the output directory to which artifacts are to be
     *                      written (e.g. dalvik-cache)
     * @param zygoteArch The zygote architecture (ro.zygote)
     * @param systemServerCompilerFilter The compiler filter used to compile system server
     * @return odrefresh exit code
     */
    byte odrefresh(CompilationMode compilation_mode, int systemDirFd, int outputDirFd,
            int stagingDirFd, String targetDirName, String zygoteArch,
            String systemServerCompilerFilter);

    /**
     * Generate a new public/private key pair suitable for signing CompOs output files.
     *
     * @return a certificate for the public key and the encrypted private key
     */
    CompOsKeyData generateSigningKey();

    /**
     * Check that the supplied encrypted private key is valid for signing CompOs output files, and
     * corresponds to the public key.
     *
     * @param keyBlob The encrypted blob containing the private key, as returned by
     *                generateSigningKey().
     * @param publicKey The public key, as a DER encoded RSAPublicKey (RFC 3447 Appendix-A.1.1).
     * @return whether the inputs are valid and correspond to each other.
     */
    boolean verifySigningKey(in byte[] keyBlob, in byte[] publicKey);
}
