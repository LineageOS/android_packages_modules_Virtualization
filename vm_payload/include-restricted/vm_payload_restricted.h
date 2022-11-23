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
#include <sys/cdefs.h>

#include "vm_payload.h"

// The functions declared here are restricted to VMs created with a config file;
// they will fail if called in other VMs. The ability to create such VMs
// requires the android.permission.USE_CUSTOM_VIRTUAL_MACHINE permission, and is
// therefore not available to privileged or third party apps.

// These functions can be used by tests, if the permission is granted via shell.

__BEGIN_DECLS

/**
 * Get the VM's DICE attestation chain.
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
 * \param data pointer to size bytes where the CDI is written.
 * \param size number of bytes that can be written to data.
 * \param total outputs the total size of the CDI if the function succeeds
 *
 * \return true on success and false on failure.
 */
bool AVmPayload_getDiceAttestationCdi(void *data, size_t size, size_t *total);

__END_DECLS
