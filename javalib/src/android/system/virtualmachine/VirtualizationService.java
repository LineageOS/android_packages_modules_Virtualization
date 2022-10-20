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

package android.system.virtualmachine;

import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.system.virtualizationservice.IVirtualizationService;

/** A running instance of virtmgr that is hosting a VirtualizationService AIDL service. */
class VirtualizationService {
    static {
        System.loadLibrary("virtualizationservice_jni");
    }

    /*
     * Client FD for UDS connection to virtmgr's RpcBinder server. Closing it
     * will make virtmgr shut down.
     */
    private ParcelFileDescriptor mClientFd;

    private static native int nativeSpawn();

    private native IBinder nativeConnect(int clientFd);

    /*
     * Spawns a new virtmgr subprocess that will host a VirtualizationService
     * AIDL service.
     */
    public VirtualizationService() throws VirtualMachineException {
        int clientFd = nativeSpawn();
        if (clientFd < 0) {
            throw new VirtualMachineException("Could not spawn VirtualizationService");
        }
        mClientFd = ParcelFileDescriptor.adoptFd(clientFd);
    }

    /* Connects to the VirtualizationService AIDL service. */
    public IVirtualizationService connect() throws VirtualMachineException {
        IBinder binder = nativeConnect(mClientFd.getFd());
        if (binder == null) {
            throw new VirtualMachineException("Could not connect to VirtualizationService");
        }
        return IVirtualizationService.Stub.asInterface(binder);
    }
}
