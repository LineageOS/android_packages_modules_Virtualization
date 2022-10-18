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

import static java.util.Objects.requireNonNull;

import android.annotation.IntDef;
import android.annotation.NonNull;
import android.annotation.Nullable;
import android.annotation.RequiresPermission;
import android.annotation.SuppressLint;
import android.content.Context;
import android.sysprop.HypervisorProperties;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.ref.WeakReference;
import java.util.Map;
import java.util.WeakHashMap;

/**
 * Manages {@link VirtualMachine} objects created for an application.
 *
 * @hide
 */
public class VirtualMachineManager {
    @NonNull private final Context mContext;

    private VirtualMachineManager(@NonNull Context context) {
        mContext = context;
    }

    private static final Map<Context, WeakReference<VirtualMachineManager>> sInstances =
            new WeakHashMap<>();

    /**
     * Capabilities of the virtual machine implementation.
     *
     * @hide
     */
    @Retention(RetentionPolicy.SOURCE)
    @IntDef(prefix = "CAPABILITY_", flag = true, value = {
            CAPABILITY_PROTECTED_VM,
            CAPABILITY_NON_PROTECTED_VM
    })
    public @interface Capability {}

    /* The implementation supports creating protected VMs, whose memory is inaccessible to the
     * host OS.
     */
    public static final int CAPABILITY_PROTECTED_VM = 1;

    /* The implementation supports creating non-protected VMs, whose memory is accessible to the
     * host OS.
     */
    public static final int CAPABILITY_NON_PROTECTED_VM = 2;

    /**
     * Returns the per-context instance.
     *
     * @hide
     */
    @NonNull
    @SuppressLint("ManagerLookup") // Optional API
    public static VirtualMachineManager getInstance(@NonNull Context context) {
        requireNonNull(context, "context must not be null");
        synchronized (sInstances) {
            VirtualMachineManager vmm =
                    sInstances.containsKey(context) ? sInstances.get(context).get() : null;
            if (vmm == null) {
                vmm = new VirtualMachineManager(context);
                sInstances.put(context, new WeakReference<>(vmm));
            }
            return vmm;
        }
    }

    /** A lock used to synchronize the creation of virtual machines */
    private static final Object sCreateLock = new Object();

    /**
     * Returns a set of flags indicating what this implementation of virtualization is capable of.
     *
     * @see #CAPABILITY_PROTECTED_VM
     * @see #CAPABILITY_NON_PROTECTED_VM
     * @hide
     */
    @Capability
    public int getCapabilities() {
        @Capability int result = 0;
        if (HypervisorProperties.hypervisor_protected_vm_supported().orElse(false)) {
            result |= CAPABILITY_PROTECTED_VM;
        }
        if (HypervisorProperties.hypervisor_vm_supported().orElse(false)) {
            result |= CAPABILITY_NON_PROTECTED_VM;
        }
        return result;
    }

    /**
     * Creates a new {@link VirtualMachine} with the given name and config. Creating a virtual
     * machine with the same name as an existing virtual machine is an error. The existing virtual
     * machine has to be deleted before its name can be reused.
     *
     * Each successful call to this method creates a new (and different) virtual machine even if the
     * name and the config are the same as a deleted one. The new virtual machine will initially
     * be stopped.
     *
     * @throws VirtualMachineException If there is an existing virtual machine with the given name
     * @hide
     */
    @NonNull
    @RequiresPermission(VirtualMachine.MANAGE_VIRTUAL_MACHINE_PERMISSION)
    public VirtualMachine create(
            @NonNull String name, @NonNull VirtualMachineConfig config)
            throws VirtualMachineException {
        synchronized (sCreateLock) {
            return VirtualMachine.create(mContext, name, config);
        }
    }

    /**
     * Returns an existing {@link VirtualMachine} with the given name. Returns null if there is no
     * such virtual machine.
     *
     * @hide
     */
    @Nullable
    public VirtualMachine get(@NonNull String name) throws VirtualMachineException {
        return VirtualMachine.load(mContext, name);
    }

    /**
     * Returns an existing {@link VirtualMachine} if it exists, or create a new one. The config
     * parameter is used only when a new virtual machine is created.
     *
     * @hide
     */
    @NonNull
    public VirtualMachine getOrCreate(
            @NonNull String name, @NonNull VirtualMachineConfig config)
            throws VirtualMachineException {
        VirtualMachine vm;
        synchronized (sCreateLock) {
            vm = get(name);
            if (vm == null) {
                vm = create(name, config);
            }
        }
        return vm;
    }
}
