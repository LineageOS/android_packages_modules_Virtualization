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

import com.android.internal.annotations.GuardedBy;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.ref.WeakReference;
import java.util.Map;
import java.util.WeakHashMap;

/**
 * Manages {@link VirtualMachine virtual machine} instances created by an app. Each instance is
 * created from a {@link VirtualMachineConfig configuration} that defines the shape of the VM
 * (RAM, CPUs), the code to execute within it, etc.
 * <p>
 * Each virtual machine instance is named; the configuration and related state of each is
 * persisted in the app's private data directory and an instance can be retrieved given the name.
 * <p>
 * The app can then start, stop and otherwise interact with the VM.
 *
 * @hide
 */
public class VirtualMachineManager {
    @NonNull private final Context mContext;

    private VirtualMachineManager(@NonNull Context context) {
        mContext = context;
    }

    @GuardedBy("sInstances")
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
     * @throws VirtualMachineException if the VM cannot be created, or there is an existing VM with
     *         the given name.
     * @hide
     */
    @NonNull
    @RequiresPermission(VirtualMachine.MANAGE_VIRTUAL_MACHINE_PERMISSION)
    public VirtualMachine create(
            @NonNull String name, @NonNull VirtualMachineConfig config)
            throws VirtualMachineException {
        synchronized (VirtualMachine.sCreateLock) {
            return VirtualMachine.create(mContext, name, config);
        }
    }

    /**
     * Imports a virtual machine from an {@link VirtualMachineDescriptor} object and associates it
     * with the given name.
     *
     * <p>The new virtual machine will be in the same state as the descriptor indicates.
     *
     * @throws VirtualMachineException if the VM cannot be imported.
     * @hide
     */
    @NonNull
    public VirtualMachine importFromDescriptor(
            @NonNull String name, @NonNull VirtualMachineDescriptor vmDescriptor)
            throws VirtualMachineException {
        synchronized (VirtualMachine.sCreateLock) {
            return VirtualMachine.fromDescriptor(mContext, name, vmDescriptor);
        }
    }

    /**
     * Returns an existing {@link VirtualMachine} with the given name. Returns null if there is no
     * such virtual machine.
     *
     * @throws VirtualMachineException if the virtual machine exists but could not be successfully
     *                                 retrieved.
     * @hide
     */
    @Nullable
    public VirtualMachine get(@NonNull String name) throws VirtualMachineException {
        synchronized (VirtualMachine.sCreateLock) {
            return VirtualMachine.load(mContext, name);
        }
    }

    /**
     * Returns an existing {@link VirtualMachine} if it exists, or create a new one. The config
     * parameter is used only when a new virtual machine is created.
     *
     * @throws VirtualMachineException if the virtual machine could not be created or retrieved.
     * @hide
     */
    @NonNull
    public VirtualMachine getOrCreate(
            @NonNull String name, @NonNull VirtualMachineConfig config)
            throws VirtualMachineException {
        VirtualMachine vm;
        synchronized (VirtualMachine.sCreateLock) {
            vm = get(name);
            if (vm == null) {
                vm = create(name, config);
            }
        }
        return vm;
    }

    /**
     * Deletes an existing {@link VirtualMachine}. Deleting a virtual machine means deleting any
     * persisted data associated with it including the per-VM secret. This is an irreversible
     * action. A virtual machine once deleted can never be restored. A new virtual machine created
     * with the same name is different from an already deleted virtual machine even if it has the
     * same config.
     *
     * @throws VirtualMachineException if the virtual machine does not exist, is not stopped,
     *                                 or cannot be deleted.
     * @hide
     */
    public void delete(@NonNull String name) throws VirtualMachineException {
        requireNonNull(name);
        synchronized (VirtualMachine.sCreateLock) {
            VirtualMachine.delete(mContext, name);
        }
    }
}
