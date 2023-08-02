/*
 * Copyright 2023 The Android Open Source Project
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
package android.system.virtualizationservice_internal;

import android.system.virtualizationservice.AssignableDevice;
import android.system.virtualizationservice.VirtualMachineDebugInfo;
import android.system.virtualizationservice_internal.AtomVmBooted;
import android.system.virtualizationservice_internal.AtomVmCreationRequested;
import android.system.virtualizationservice_internal.AtomVmExited;
import android.system.virtualizationservice_internal.IGlobalVmContext;

/** VFIO related methods which should be done as root. */
interface IVfioHandler {
    /**
     * Bind given devices to vfio driver.
     *
     * @param devices paths of sysfs nodes of devices to assign.
     * @return a file descriptor containing DTBO for VM.
     */
    ParcelFileDescriptor bindDevicesToVfioDriver(in String[] devices);
}
