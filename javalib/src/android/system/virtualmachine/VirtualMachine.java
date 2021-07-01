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

import android.content.Context;
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.system.virtualizationservice.IVirtualMachine;
import android.system.virtualizationservice.IVirtualizationService;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.Optional;

/**
 * A handle to the virtual machine. The virtual machine is local to the app which created the
 * virtual machine.
 *
 * @hide
 */
public class VirtualMachine {
    /** Name of the directory under the files directory where all VMs created for the app exist. */
    private static final String VM_DIR = "vm";

    /** Name of the persisted config file for a VM. */
    private static final String CONFIG_FILE = "config.xml";

    /** Name of the instance image file for a VM. (Not implemented) */
    private static final String INSTANCE_IMAGE_FILE = "instance.img";

    /** Name of the virtualization service. */
    private static final String SERVICE_NAME = "android.system.virtualizationservice";

    /** Status of a virtual machine */
    public enum Status {
        /** The virtual machine has just been created, or {@link #stop()} was called on it. */
        STOPPED,
        /** The virtual machine is running. */
        RUNNING,
        /**
         * The virtual machine is deleted. This is a irreversable state. Once a virtual machine is
         * deleted, it can never be undone, which means all its secrets are permanently lost.
         */
        DELETED,
    }

    /** The package which owns this VM. */
    private final String mPackageName;

    /** Name of this VM within the package. The name should be unique in the package. */
    private final String mName;

    /**
     * Path to the config file for this VM. The config file is where the configuration is persisted.
     */
    private final File mConfigFilePath;

    /** Path to the instance image file for this VM. (Not implemented) */
    private final File mInstanceFilePath;

    /** The configuration that is currently associated with this VM. */
    private VirtualMachineConfig mConfig;

    /** Handle to the "running" VM. */
    private IVirtualMachine mVirtualMachine;

    private ParcelFileDescriptor mConsoleReader;
    private ParcelFileDescriptor mConsoleWriter;

    private VirtualMachine(Context context, String name, VirtualMachineConfig config) {
        mPackageName = context.getPackageName();
        mName = name;
        mConfig = config;

        final File vmRoot = new File(context.getFilesDir(), VM_DIR);
        final File thisVmDir = new File(vmRoot, mName);
        mConfigFilePath = new File(thisVmDir, CONFIG_FILE);
        mInstanceFilePath = new File(thisVmDir, INSTANCE_IMAGE_FILE);
    }

    /**
     * Creates a virtual machine with the given name and config. Once a virtual machine is created
     * it is persisted until it is deleted by calling {@link #delete()}. The created virtual machine
     * is in {@link #STOPPED} state. To run the VM, call {@link #run()}.
     */
    /* package */ static VirtualMachine create(
            Context context, String name, VirtualMachineConfig config)
            throws VirtualMachineException {
        // TODO(jiyong): trigger an error if the VM having 'name' already exists.
        VirtualMachine vm = new VirtualMachine(context, name, config);

        try {
            final File vmRoot = vm.mConfigFilePath.getParentFile();
            Files.createDirectories(vmRoot.toPath());

            FileOutputStream output = new FileOutputStream(vm.mConfigFilePath);
            vm.mConfig.serialize(output);
            output.close();
        } catch (IOException e) {
            throw new VirtualMachineException(e);
        }

        // TODO(jiyong): create the instance image file
        return vm;
    }

    /** Loads a virtual machine that is already created before. */
    /* package */ static VirtualMachine load(Context context, String name)
            throws VirtualMachineException {
        // TODO(jiyong): return null if the VM having the 'name' doesn't exist.
        VirtualMachine vm = new VirtualMachine(context, name, /* config */ null);

        try {
            FileInputStream input = new FileInputStream(vm.mConfigFilePath);
            VirtualMachineConfig config = VirtualMachineConfig.from(input);
            input.close();
            vm.mConfig = config;
        } catch (IOException e) {
            throw new VirtualMachineException(e);
        }

        return vm;
    }

    /**
     * Returns the name of this virtual machine. The name is unique in the package and can't be
     * changed.
     */
    public String getName() {
        return mName;
    }

    /**
     * Returns the currently selected config of this virtual machine. There can be multiple virtual
     * machines sharing the same config. Even in that case, the virtual machines are completely
     * isolated from each other; one cannot share its secret to another virtual machine even if they
     * share the same config. It is also possible that a virtual machine can switch its config,
     * which can be done by calling {@link #setConfig(VirtualMachineCOnfig)}.
     */
    public VirtualMachineConfig getConfig() {
        return mConfig;
    }

    /** Returns the current status of this virtual machine. */
    public Status getStatus() throws VirtualMachineException {
        try {
            if (mVirtualMachine != null && mVirtualMachine.isRunning()) {
                return Status.RUNNING;
            }
        } catch (RemoteException e) {
            throw new VirtualMachineException(e);
        }
        if (!mConfigFilePath.exists()) {
            return Status.DELETED;
        }
        return Status.STOPPED;
    }

    /**
     * Runs this virtual machine. The returning of this method however doesn't mean that the VM has
     * actually started running or the OS has booted there. Such events can be notified by
     * registering a callback object (not implemented currently).
     */
    public void run() throws VirtualMachineException {
        if (getStatus() != Status.STOPPED) {
            throw new VirtualMachineException(this + " is not in stopped state");
        }
        IVirtualizationService service =
                IVirtualizationService.Stub.asInterface(ServiceManager.getService(SERVICE_NAME));

        try {
            if (mConsoleReader == null && mConsoleWriter == null) {
                ParcelFileDescriptor[] pipe = ParcelFileDescriptor.createPipe();
                mConsoleReader = pipe[0];
                mConsoleWriter = pipe[1];
            }
            mVirtualMachine =
                    service.startVm(
                            android.system.virtualizationservice.VirtualMachineConfig.appConfig(
                                    getConfig().toParcel()),
                            mConsoleWriter);
        } catch (IOException e) {
            throw new VirtualMachineException(e);
        } catch (RemoteException e) {
            throw new VirtualMachineException(e);
        }
    }

    /** Returns the stream object representing the console output from the virtual machine. */
    public InputStream getConsoleOutputStream() throws VirtualMachineException {
        if (mConsoleReader == null) {
            throw new VirtualMachineException("Console output not available");
        }
        return new FileInputStream(mConsoleReader.getFileDescriptor());
    }

    /**
     * Stops this virtual machine. Stopping a virtual machine is like pulling the plug on a real
     * computer; the machine halts immediately. Software running on the virtual machine is not
     * notified with the event. A stopped virtual machine can be re-started by calling {@link
     * #run()}.
     */
    public void stop() throws VirtualMachineException {
        // Dropping the IVirtualMachine handle stops the VM
        mVirtualMachine = null;
    }

    /**
     * Deletes this virtual machine. Deleting a virtual machine means deleting any persisted data
     * associated with it including the per-VM secret. This is an irreversable action. A virtual
     * machine once deleted can never be restored. A new virtual machine created with the same name
     * and the same config is different from an already deleted virtual machine.
     */
    public void delete() throws VirtualMachineException {
        if (getStatus() != Status.STOPPED) {
            throw new VirtualMachineException("Virtual machine is not stopped");
        }
        final File vmRootDir = mConfigFilePath.getParentFile();
        mConfigFilePath.delete();
        mInstanceFilePath.delete();
        vmRootDir.delete();
    }

    /** Returns the CID of this virtual machine, if it is running. */
    public Optional<Integer> getCid() throws VirtualMachineException {
        if (getStatus() != Status.RUNNING) {
            return Optional.empty();
        }
        try {
            return Optional.of(mVirtualMachine.getCid());
        } catch (RemoteException e) {
            throw new VirtualMachineException(e);
        }
    }

    /**
     * Changes the config of this virtual machine to a new one. This can be used to adjust things
     * like the number of CPU and size of the RAM, depending on the situation (e.g. the size of the
     * application to run on the virtual machine, etc.) However, changing a config might make the
     * virtual machine un-bootable if the new config is not compatible with the existing one. For
     * example, if the signer of the app payload in the new config is different from that of the old
     * config, the virtual machine won't boot. To prevent such cases, this method returns exception
     * when an incompatible config is attempted.
     *
     * @return the old config
     */
    public VirtualMachineConfig setConfig(VirtualMachineConfig newConfig)
            throws VirtualMachineException {
        // TODO(jiyong): implement this
        throw new VirtualMachineException("Not implemented");
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("VirtualMachine(");
        sb.append("name:" + getName() + ", ");
        sb.append("config:" + getConfig().getPayloadConfigPath() + ", ");
        sb.append("package: " + mPackageName);
        sb.append(")");
        return sb.toString();
    }
}
