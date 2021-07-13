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

import android.system.virtualizationservice.IVirtualMachine;

/**
 * An object which a client may register with the VirtualizationService to get callbacks about the
 * state of a particular VM.
 */
oneway interface IVirtualMachineCallback {
    /**
     * Called when the payload starts in the VM. `stdout` is the stdout of the payload.
     *
     * <p>Note: when the virtual machine object is shared to multiple processes and they register
     * this callback to the same virtual machine object, the processes will compete to read from the
     * same payload stdout. As a result, each process might get only a part of the entire output
     * stream. To avoid such a case, keep only one process to read from the stdout.
     */
    void onPayloadStarted(int cid, in ParcelFileDescriptor stdout);

    /**
     * Called when the VM dies.
     *
     * Note that this will not be called if the VirtualizationService itself dies, so you should
     * also use `link_to_death` to handle that.
     */
    void onDied(int cid);
}
