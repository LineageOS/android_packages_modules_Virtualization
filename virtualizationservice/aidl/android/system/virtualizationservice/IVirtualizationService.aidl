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
import android.system.virtualizationservice.VirtualMachineConfig;
import android.system.virtualizationservice.VirtualMachineDebugInfo;

interface IVirtualizationService {
    /**
     * Start the VM with the given config file, and return a handle to it. If `logFd` is provided
     * then console logs from the VM will be sent to it.
     */
    IVirtualMachine startVm(
            in VirtualMachineConfig config, in @nullable ParcelFileDescriptor logFd);

    /**
     * Initialise an empty partition image of the given size to be used as a writable partition.
     *
     * The file must be open with both read and write permissions, and should be a new empty file.
     */
    void initializeWritablePartition(in ParcelFileDescriptor imageFd, long size);

    /**
     * Create or update an idsig file that digests the given APK file. The idsig file follows the
     * idsig format that is defined by the APK Signature Scheme V4. The idsig file is not updated
     * when it is up to date with the input file, which is checked by comparing the
     * signing_info.apk_digest field in the idsig file with the signer.signed_data.digests.digest
     * field in the input APK file.
     */
    void createOrUpdateIdsigFile(in ParcelFileDescriptor inputFd, in ParcelFileDescriptor idsigFd);

    /**
     * Get a list of all currently running VMs. This method is only intended for debug purposes,
     * and as such is only permitted from the shell user.
     */
    VirtualMachineDebugInfo[] debugListVms();

    /**
     * Hold a strong reference to a VM in VirtualizationService. This method is only intended for
     * debug purposes, and as such is only permitted from the shell user.
     */
    void debugHoldVmRef(IVirtualMachine vm);

    /**
     * Drop reference to a VM that is being held by VirtualizationService. Returns the reference if
     * VM was found and null otherwise. This method is only intended for debug purposes, and as such
     * is only permitted from the shell user.
     */
    @nullable IVirtualMachine debugDropVmRef(int cid);
}
