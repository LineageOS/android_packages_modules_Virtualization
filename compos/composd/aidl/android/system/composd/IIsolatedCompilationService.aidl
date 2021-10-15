/*
 * Copyright 2021 The Android Open Source Project
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
package android.system.composd;

import com.android.compos.CompilationResult;
import com.android.compos.FdAnnotation;

interface IIsolatedCompilationService {
    /**
     * Run "odrefresh --dalvik-cache=pending-test --force-compile" in a test instance of CompOS.
     * This compiles BCP extensions and system server, even if the system artifacts are up to date,
     * and writes the results to a test directory to avoid disrupting any real artifacts in
     * existence.
     */
    void runForcedCompileForTest();

    /**
     * Run dex2oat in the currently running instance of the CompOS VM. This is a simple proxy
     * to ICompOsService#compile_cmd.
     *
     * This method can only be called from odrefresh. If there is no currently running instance
     * an error is returned.
     */
    CompilationResult compile_cmd(in String[] args, in FdAnnotation fd_annotation);

    /**
     * Run dex2oat in the currently running instance of the CompOS VM. This is a simple proxy
     * to ICompOsService#compile.
     *
     * This method can only be called from libcompos_client. If there is no currently running
     * instance an error is returned.
     */
    byte compile(in byte[] marshaledArguments, in FdAnnotation fd_annotation);
}
