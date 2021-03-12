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
package android.system.virtmanager;

/** Information about a running VM, for debug purposes only. */
parcelable VirtualMachineDebugInfo {
    /** The CID assigned to the VM. */
    int cid;

    /**
     * The filename of the config file used to start the VM. This may have changed since it was
     * read so it shouldn't be trusted; it is only stored for debugging purposes.
     */
    String configPath;
}
