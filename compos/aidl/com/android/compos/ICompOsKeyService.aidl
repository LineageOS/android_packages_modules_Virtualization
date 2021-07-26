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

package com.android.compos;

import com.android.compos.CompOsKeyData;
import com.android.compos.ICompService;

/** {@hide} */
interface ICompOsKeyService {
    /**
     * Generate a new public/private key pair suitable for signing CompOs output files.
     *
     * @return a certificate for the public key and the encrypted private key
     */
    CompOsKeyData generateSigningKey();

    /**
     * Check that the supplied encrypted private key is valid for signing CompOs output files, and
     * corresponds to the public key.
     *
     * @param keyBlob The encrypted blob containing the private key, as returned by
     *                generateSigningKey().
     * @param publicKey The public key, as a DER encoded RSAPublicKey (RFC 3447 Appendix-A.1.1).
     * @return whether the inputs are valid and correspond to each other.
     */
    boolean verifySigningKey(in byte[] keyBlob, in byte[] publicKey);

    /**
     * Use the supplied encrypted private key to sign some data.
     *
     * @param keyBlob The encrypted blob containing the private key, as returned by
     *                generateSigningKey().
     * @param data The data to be signed. (Large data sizes may cause failure.)
     * @return the signature.
     */
    // STOPSHIP(b/193241041): We must not expose this from the PVM.
    byte[] sign(in byte[] keyBlob, in byte[] data);

    /**
     * Return an instance of ICompService that will sign output files with a given encrypted
     * private key.
     *
     * @param keyBlob The encrypted blob containing the private key, as returned by
     *                generateSigningKey().
     */
    ICompService getCompService(in byte[] keyBlob);
}
