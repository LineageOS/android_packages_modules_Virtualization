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

import android.system.virtualizationservice.IVirtualMachineCallback;

interface IVirtualMachine {
    /** Get the CID allocated to the VM. */
    int getCid();

    /** Returns true if the VM is still running, or false if it has exited for any reason. */
    boolean isRunning();

    /**
     * Register a Binder object to get callbacks when the state of the VM changes, such as if it
     * dies.
     *
     * TODO(jiyong): this should be registered when IVirtualizationService.run is called. Otherwise,
     * we might miss some events that happen before the registration is done.
     */
    void registerCallback(IVirtualMachineCallback callback);

    /** Open a vsock connection to the CID of the VM on the given port. */
    ParcelFileDescriptor connectVsock(int port);
}
