/*
 * Copyright 2024 The Android Open Source Project
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

package com.android.virt.vm_attestation.testservice;

/** {@hide} */
interface IAttestationService {
    const int PORT = 5679;

    /**
     * The result of signing a message with the attested key.
     */
    parcelable SigningResult {
        /** The DER-encoded ECDSA signature of the message. */
        byte[] signature;

        /** The DER-encoded attestation X509 certificate chain. */
        byte[] certificateChain;
    }

    /**
     * Requests attestation with {@link AVmPayload_requestAttestation} API and signs the
     * given message with the attested key.
     *
     * @param message the message to sign.
     * @return the result of signing the message with the attested key.
     */
    SigningResult signWithAttestationKey(in byte[] message);
}
