/*
 * Copyright (C) 2022 The Android Open Source Project
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

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "vm_main.h"

#ifdef __cplusplus
extern "C" {
#endif

struct AIBinder;
typedef struct AIBinder AIBinder;

/**
 * Notifies the host that the payload is ready.
 *
 * \return true if the notification succeeds else false.
 */
bool AVmPayload_notifyPayloadReady(void);

/**
 * Runs a binder RPC server, serving the supplied binder service implementation on the given vsock
 * port.
 *
 * If and when the server is ready for connections (it is listening on the port), `on_ready` is
 * called to allow appropriate action to be taken - e.g. to notify clients that they may now
 * attempt to connect with `AVmPayload_notifyPayloadReady`.
 *
 * The current thread is joined to the binder thread pool to handle incoming messages.
 *
 * \param service the service to bind to the given port.
 * \param port vsock port.
 * \param on_ready the callback to execute once the server is ready for connections. The callback
 *                 will be called at most once.
 * \param param param for the `on_ready` callback.
 *
 * \return true if the server has shutdown normally, false if it failed in some way.
 */
bool AVmPayload_runVsockRpcServer(AIBinder *service, unsigned int port,
                                  void (*on_ready)(void *param), void *param);

/**
 * Get a secret that is uniquely bound to this VM instance. The secrets are 32-byte values and the
 * value associated with an identifier will not change over the lifetime of the VM instance.
 *
 * \param identifier identifier of the secret to return.
 * \param identifier_size size of the secret identifier.
 * \param secret pointer to size bytes where the secret is written.
 * \param size number of bytes of the secret to get, up to the secret size.
 *
 * \return true on success and false on failure.
 */
bool AVmPayload_getVmInstanceSecret(const void *identifier, size_t identifier_size, void *secret,
                                    size_t size);

/**
 * Get the VM's DICE attestation chain.
 *
 * This function will fail if the use of restricted APIs is not permitted.
 *
 * \param data pointer to size bytes where the chain is written.
 * \param size number of bytes that can be written to data.
 * \param total outputs the total size of the chain if the function succeeds
 *
 * \return true on success and false on failure.
 */
bool AVmPayload_getDiceAttestationChain(void *data, size_t size, size_t *total);

/**
 * Get the VM's DICE attestation CDI.
 *
 * This function will fail if the use of restricted APIs is not permitted.
 *
 * \param data pointer to size bytes where the CDI is written.
 * \param size number of bytes that can be written to data.
 * \param total outputs the total size of the CDI if the function succeeds
 *
 * \return true on success and false on failure.
 */
bool AVmPayload_getDiceAttestationCdi(void *data, size_t size, size_t *total);

#ifdef __cplusplus
} // extern "C"
#endif
