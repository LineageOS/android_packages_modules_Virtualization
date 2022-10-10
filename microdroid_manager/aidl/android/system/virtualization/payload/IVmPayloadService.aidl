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

package android.system.virtualization.payload;

/**
 * This interface regroups the tasks that payloads delegate to
 * Microdroid Manager for execution.
 */
interface IVmPayloadService {
    /** Name of the service IVmPayloadService. */
    const String VM_PAYLOAD_SERVICE_NAME = "virtual_machine_payload_service";

    /** Notifies that the payload is ready to serve. */
    void notifyPayloadReady();

    /**
     * Gets the DICE attestation chain for the VM.
     *
     * STOPSHIP:
     * TODO: don't expose this to untrusted payloads as it contains privacy breaking identifiers.
     */
    byte[] getDiceAttestationChain();

    /**
     * Gets the DICE attestation CDI for the VM.
     *
     * STOPSHIP:
     * TODO: A better API would handle key derivation on behalf of the payload so they can't forget
     * to do it themselves. It also means the payload doesn't get the raw CDI so there's less chance
     * of it leaking.
     */
    byte[] getDiceAttestationCdi();

    /**
     * Gets the DICE sealing CDI for the VM.
     *
     * TODO: A better API would handle key derivation on behalf of the payload so they can't forget
     * to do it themselves. It also means the payload doesn't get the raw CDI so there's less chance
     * of it leaking.
     */
    byte[] getDiceSealingCdi();
}
