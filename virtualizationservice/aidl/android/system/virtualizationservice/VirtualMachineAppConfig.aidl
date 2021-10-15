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
package android.system.virtualizationservice;

/** Configuration for running an App in a VM */
parcelable VirtualMachineAppConfig {
    /** Main APK */
    ParcelFileDescriptor apk;

    /** idsig for an APK */
    ParcelFileDescriptor idsig;

    /** instance.img that has per-instance data */
    ParcelFileDescriptor instanceImage;

    /** Path to a configuration in an APK. This is the actual configuration for a VM. */
    @utf8InCpp String configPath;

    enum DebugLevel {
        /** Not debuggable at all */
        NONE,
        /** Only the logs from app is shown */
        APP_ONLY,
        /**
         * Fully debuggable. All logs are shown, kernel messages are shown, and adb shell is
         * supported
         */
        FULL,
    }

    /** Debug level of the VM */
    DebugLevel debugLevel;

    /**
     * The amount of RAM to give the VM, in MiB. If this is 0 or negative then it will default to
     * the value in microdroid.json, if any, or the crosvm default.
     */
    int memoryMib;
}
