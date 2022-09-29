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

package android.system.virtualizationservice;

parcelable VirtualMachinePayloadConfig {
    /**
     * Path to the payload executable code in an APK. The code is in the form of a .so with a
     * defined entry point; inside the VM this file is loaded and the entry function invoked.
     */
    @utf8InCpp String payloadPath;

    /**
     * Whether to export tombstones (VM crash details) from the VM to the host.
     */
    boolean exportTombstones;

    /**
     * Command-line style arguments to be passed to the payload when it is executed.
     * TODO(b/249064104): Remove this
     */
    @utf8InCpp String[] args;
}
