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

import android.annotation.IntDef;
import android.annotation.NonNull;
import android.annotation.Nullable;
import android.os.ParcelFileDescriptor;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * Callback interface to get notified with the events from the virtual machine. The methods are
 * executed on a binder thread. Implementations can make blocking calls in the methods.
 *
 * @hide
 */
public interface VirtualMachineCallback {
    /** @hide */
    @Retention(RetentionPolicy.SOURCE)
    @IntDef({ERROR_UNKNOWN, ERROR_PAYLOAD_VERIFICATION_FAILED, ERROR_PAYLOAD_CHANGED})
    @interface ErrorCode {}

    /** Error code for all other errors not listed below. */
    int ERROR_UNKNOWN = 0;

    /**
     * Error code indicating that the payload can't be verified due to various reasons (e.g invalid
     * merkle tree, invalid formats, etc).
     */
    int ERROR_PAYLOAD_VERIFICATION_FAILED = 1;

    /** Error code indicating that the payload is verified, but has changed since the last boot. */
    int ERROR_PAYLOAD_CHANGED = 2;

    /** Called when the payload starts in the VM. */
    void onPayloadStarted(@NonNull VirtualMachine vm, @Nullable ParcelFileDescriptor stream);

    /** Called when the payload in the VM is ready to serve. */
    void onPayloadReady(@NonNull VirtualMachine vm);

    /** Called when the payload has finished in the VM. */
    void onPayloadFinished(@NonNull VirtualMachine vm, int exitCode);

    /** Called when an error occurs in the VM. */
    void onError(@NonNull VirtualMachine vm, @ErrorCode int errorCode, @NonNull String message);

    /** Called when the VM died. */
    void onDied(@NonNull VirtualMachine vm);
}
