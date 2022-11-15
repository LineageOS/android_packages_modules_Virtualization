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

import static android.os.ParcelFileDescriptor.MODE_READ_ONLY;
import static android.os.ParcelFileDescriptor.MODE_READ_WRITE;
import static android.system.virtualmachine.VirtualMachineCallback.ERROR_PAYLOAD_CHANGED;
import static android.system.virtualmachine.VirtualMachineCallback.ERROR_PAYLOAD_INVALID_CONFIG;
import static android.system.virtualmachine.VirtualMachineCallback.ERROR_PAYLOAD_VERIFICATION_FAILED;
import static android.system.virtualmachine.VirtualMachineCallback.ERROR_UNKNOWN;
import static android.system.virtualmachine.VirtualMachineCallback.STOP_REASON_BOOTLOADER_INSTANCE_IMAGE_CHANGED;
import static android.system.virtualmachine.VirtualMachineCallback.STOP_REASON_BOOTLOADER_PUBLIC_KEY_MISMATCH;
import static android.system.virtualmachine.VirtualMachineCallback.STOP_REASON_CRASH;
import static android.system.virtualmachine.VirtualMachineCallback.STOP_REASON_ERROR;
import static android.system.virtualmachine.VirtualMachineCallback.STOP_REASON_HANGUP;
import static android.system.virtualmachine.VirtualMachineCallback.STOP_REASON_INFRASTRUCTURE_ERROR;
import static android.system.virtualmachine.VirtualMachineCallback.STOP_REASON_KILLED;
import static android.system.virtualmachine.VirtualMachineCallback.STOP_REASON_MICRODROID_FAILED_TO_CONNECT_TO_VIRTUALIZATION_SERVICE;
import static android.system.virtualmachine.VirtualMachineCallback.STOP_REASON_MICRODROID_INVALID_PAYLOAD_CONFIG;
import static android.system.virtualmachine.VirtualMachineCallback.STOP_REASON_MICRODROID_PAYLOAD_HAS_CHANGED;
import static android.system.virtualmachine.VirtualMachineCallback.STOP_REASON_MICRODROID_PAYLOAD_VERIFICATION_FAILED;
import static android.system.virtualmachine.VirtualMachineCallback.STOP_REASON_MICRODROID_UNKNOWN_RUNTIME_ERROR;
import static android.system.virtualmachine.VirtualMachineCallback.STOP_REASON_PVM_FIRMWARE_INSTANCE_IMAGE_CHANGED;
import static android.system.virtualmachine.VirtualMachineCallback.STOP_REASON_PVM_FIRMWARE_PUBLIC_KEY_MISMATCH;
import static android.system.virtualmachine.VirtualMachineCallback.STOP_REASON_REBOOT;
import static android.system.virtualmachine.VirtualMachineCallback.STOP_REASON_SHUTDOWN;
import static android.system.virtualmachine.VirtualMachineCallback.STOP_REASON_UNKNOWN;

import static java.util.Objects.requireNonNull;

import android.annotation.CallbackExecutor;
import android.annotation.IntDef;
import android.annotation.NonNull;
import android.annotation.Nullable;
import android.annotation.RequiresPermission;
import android.content.Context;
import android.os.Binder;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.ServiceSpecificException;
import android.system.virtualizationcommon.ErrorCode;
import android.system.virtualizationservice.DeathReason;
import android.system.virtualizationservice.IVirtualMachine;
import android.system.virtualizationservice.IVirtualMachineCallback;
import android.system.virtualizationservice.IVirtualizationService;
import android.system.virtualizationservice.PartitionType;
import android.system.virtualizationservice.VirtualMachineAppConfig;
import android.system.virtualizationservice.VirtualMachineState;
import android.util.JsonReader;

import com.android.internal.annotations.GuardedBy;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.ref.WeakReference;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.zip.ZipFile;

/**
 * Represents an VM instance, with its own configuration and state. Instances are persistent and are
 * created or retrieved via {@link VirtualMachineManager}.
 * <p>
 * The {@link #run} method actually starts up the VM and allows the payload code to execute. It
 * will continue until it exits or {@link #stop} is called. Updates on the state of the VM can
 * be received using {@link #setCallback}. The app can communicate with the VM using
 * {@link #connectToVsockServer} or {@link #connectVsock}.
 *
 * @hide
 */
public class VirtualMachine implements AutoCloseable {
    /** Map from context to a map of all that context's VMs by name. */
    @GuardedBy("sCreateLock")
    private static final Map<Context, Map<String, WeakReference<VirtualMachine>>> sInstances =
            new WeakHashMap<>();

    /** Name of the directory under the files directory where all VMs created for the app exist. */
    private static final String VM_DIR = "vm";

    /** Name of the persisted config file for a VM. */
    private static final String CONFIG_FILE = "config.xml";

    /** Name of the instance image file for a VM. (Not implemented) */
    private static final String INSTANCE_IMAGE_FILE = "instance.img";

    /** Name of the idsig file for a VM */
    private static final String IDSIG_FILE = "idsig";

    /** Name of the idsig files for extra APKs. */
    private static final String EXTRA_IDSIG_FILE_PREFIX = "extra_idsig_";

    /** Name of the virtualization service. */
    private static final String SERVICE_NAME = "android.system.virtualizationservice";

    /** The permission needed to create or run a virtual machine. */
    public static final String MANAGE_VIRTUAL_MACHINE_PERMISSION =
            "android.permission.MANAGE_VIRTUAL_MACHINE";

    /**
     * The permission needed to create a virtual machine with more advanced configuration options.
     */
    public static final String USE_CUSTOM_VIRTUAL_MACHINE_PERMISSION =
            "android.permission.USE_CUSTOM_VIRTUAL_MACHINE";

    /**
     * Status of a virtual machine
     *
     * @hide
     */
    @Retention(RetentionPolicy.SOURCE)
    @IntDef(prefix = "STATUS_", value = {
            STATUS_STOPPED,
            STATUS_RUNNING,
            STATUS_DELETED
    })
    public @interface Status {}

     /** The virtual machine has just been created, or {@link #stop()} was called on it. */
    public static final int STATUS_STOPPED = 0;

    /** The virtual machine is running. */
    public static final int STATUS_RUNNING = 1;

    /**
     * The virtual machine has been deleted. This is an irreversible state. Once a virtual machine
     * is deleted all its secrets are permanently lost, and it cannot be run. A new virtual machine
     * with the same name and config may be created, with new and different secrets.
     */
    public static final int STATUS_DELETED = 2;

    /** The package which owns this VM. */
    @NonNull private final String mPackageName;

    /** Name of this VM within the package. The name should be unique in the package. */
    @NonNull private final String mName;

    /**
     * Path to the directory containing all the files related to this VM.
     */
    @NonNull private final File mVmRootPath;

    /**
     * Path to the config file for this VM. The config file is where the configuration is persisted.
     */
    @NonNull private final File mConfigFilePath;

    /** Path to the instance image file for this VM. */
    @NonNull private final File mInstanceFilePath;

    /** Path to the idsig file for this VM. */
    @NonNull private final File mIdsigFilePath;

    private static class ExtraApkSpec {
        public final File apk;
        public final File idsig;

        ExtraApkSpec(File apk, File idsig) {
            this.apk = apk;
            this.idsig = idsig;
        }
    }

    /**
     * Unmodifiable list of extra apks. Apks are specified by the vm config, and corresponding
     * idsigs are to be generated.
     */
    @NonNull private final List<ExtraApkSpec> mExtraApks;

    /** Size of the instance image. 10 MB. */
    private static final long INSTANCE_FILE_SIZE = 10 * 1024 * 1024;

    // A note on lock ordering:
    // You can take mLock while holding sCreateLock, but not vice versa.
    // We never take any other lock while holding mCallbackLock; therefore you can
    // take mCallbackLock while holding any other lock.

    /**
     * A lock used to synchronize the creation of virtual machines. It protects
     * {@link #sInstances}, but is also held throughout VM creation / retrieval / deletion, to
     * prevent these actions racing with each other.
     */
    static final Object sCreateLock = new Object();

    /** Lock protecting our mutable state (other than callbacks). */
    private final Object mLock = new Object();

    /** Lock protecting callbacks. */
    private final Object mCallbackLock = new Object();


    /** The configuration that is currently associated with this VM. */
    @GuardedBy("mLock")
    @NonNull
    private VirtualMachineConfig mConfig;

    /** Handle to the "running" VM. */
    @GuardedBy("mLock")
    @Nullable
    private IVirtualMachine mVirtualMachine;

    @GuardedBy("mLock")
    @Nullable
    private ParcelFileDescriptor mConsoleReader;

    @GuardedBy("mLock")
    @Nullable
    private ParcelFileDescriptor mConsoleWriter;

    @GuardedBy("mLock")
    @Nullable
    private ParcelFileDescriptor mLogReader;

    @GuardedBy("mLock")
    @Nullable
    private ParcelFileDescriptor mLogWriter;

    /** The registered callback */
    @GuardedBy("mCallbackLock")
    @Nullable
    private VirtualMachineCallback mCallback;

    /** The executor on which the callback will be executed */
    @GuardedBy("mCallbackLock")
    @Nullable
    private Executor mCallbackExecutor;

    static {
        System.loadLibrary("virtualmachine_jni");
    }

    private VirtualMachine(
            @NonNull Context context, @NonNull String name, @NonNull VirtualMachineConfig config)
            throws VirtualMachineException {
        mPackageName = context.getPackageName();
        mName = requireNonNull(name, "Name must not be null");
        mConfig = requireNonNull(config, "Config must not be null");

        File thisVmDir = getVmDir(context, mName);
        mVmRootPath = thisVmDir;
        mConfigFilePath = new File(thisVmDir, CONFIG_FILE);
        mInstanceFilePath = new File(thisVmDir, INSTANCE_IMAGE_FILE);
        mIdsigFilePath = new File(thisVmDir, IDSIG_FILE);
        mExtraApks = setupExtraApks(context, config, thisVmDir);
    }

    @GuardedBy("sCreateLock")
    @NonNull
    private static Map<String, WeakReference<VirtualMachine>> getInstancesMap(Context context) {
        return sInstances.computeIfAbsent(context, unused -> new HashMap<>());
    }

    @NonNull
    private static File getVmDir(Context context, String name) {
        File vmRoot = new File(context.getDataDir(), VM_DIR);
        return new File(vmRoot, name);
    }

    /**
     * Creates a virtual machine with the given name and config. Once a virtual machine is created
     * it is persisted until it is deleted by calling {@link #delete}. The created virtual machine
     * is in {@link #STATUS_STOPPED} state. To run the VM, call {@link #run}.
     */
    @GuardedBy("sCreateLock")
    @NonNull
    static VirtualMachine create(
            @NonNull Context context, @NonNull String name, @NonNull VirtualMachineConfig config)
            throws VirtualMachineException {
        File vmDir = getVmDir(context, name);

        try {
            // We don't need to undo this even if VM creation fails.
            Files.createDirectories(vmDir.getParentFile().toPath());

            // The checking of the existence of this directory and the creation of it is done
            // atomically. If the directory already exists (i.e. the VM with the same name was
            // already created), FileAlreadyExistsException is thrown.
            Files.createDirectory(vmDir.toPath());
        } catch (FileAlreadyExistsException e) {
            throw new VirtualMachineException("virtual machine already exists", e);
        } catch (IOException e) {
            throw new VirtualMachineException("failed to create directory for VM", e);
        }

        try {
            VirtualMachine vm = new VirtualMachine(context, name, config);

            try (FileOutputStream output = new FileOutputStream(vm.mConfigFilePath)) {
                config.serialize(output);
            } catch (IOException e) {
                throw new VirtualMachineException("failed to write VM config", e);
            }

            try {
                vm.mInstanceFilePath.createNewFile();
            } catch (IOException e) {
                throw new VirtualMachineException("failed to create instance image", e);
            }

            IVirtualizationService service =
                    IVirtualizationService.Stub.asInterface(
                            ServiceManager.waitForService(SERVICE_NAME));

            try {
                service.initializeWritablePartition(
                        ParcelFileDescriptor.open(vm.mInstanceFilePath, MODE_READ_WRITE),
                        INSTANCE_FILE_SIZE,
                        PartitionType.ANDROID_VM_INSTANCE);
            } catch (FileNotFoundException e) {
                throw new VirtualMachineException("instance image missing", e);
            } catch (RemoteException e) {
                throw e.rethrowAsRuntimeException();
            } catch (ServiceSpecificException | IllegalArgumentException e) {
                throw new VirtualMachineException("failed to create instance partition", e);
            }

            getInstancesMap(context).put(name, new WeakReference<>(vm));

            return vm;
        } catch (VirtualMachineException | RuntimeException e) {
            // If anything goes wrong, delete any files created so far and the VM's directory
            try {
                deleteRecursively(vmDir);
            } catch (IOException innerException) {
                e.addSuppressed(innerException);
            }
            throw e;
        }
    }

    /** Loads a virtual machine that is already created before. */
    @GuardedBy("sCreateLock")
    @Nullable
    static VirtualMachine load(
            @NonNull Context context, @NonNull String name) throws VirtualMachineException {
        File thisVmDir = getVmDir(context, name);
        if (!thisVmDir.exists()) {
            // The VM doesn't exist.
            return null;
        }
        File configFilePath = new File(thisVmDir, CONFIG_FILE);
        VirtualMachineConfig config;
        try (FileInputStream input = new FileInputStream(configFilePath)) {
            config = VirtualMachineConfig.from(input);
        } catch (IOException e) {
            throw new VirtualMachineException("Failed to read config file", e);
        }

        Map<String, WeakReference<VirtualMachine>> instancesMap = getInstancesMap(context);

        VirtualMachine vm = null;
        if (instancesMap.containsKey(name)) {
            vm = instancesMap.get(name).get();
        }
        if (vm == null) {
            vm = new VirtualMachine(context, name, config);
        }

        if (!vm.mInstanceFilePath.exists()) {
            throw new VirtualMachineException("instance image missing");
        }

        instancesMap.put(name, new WeakReference<>(vm));

        return vm;
    }

    @GuardedBy("sCreateLock")
    static void delete(Context context, String name) throws VirtualMachineException {
        Map<String, WeakReference<VirtualMachine>> instancesMap = sInstances.get(context);
        VirtualMachine vm;
        if (instancesMap != null && instancesMap.containsKey(name)) {
            vm = instancesMap.get(name).get();
        } else {
            vm = null;
        }

        if (vm != null) {
            synchronized (vm.mLock) {
                vm.checkStopped();
            }
        }

        try {
            deleteRecursively(getVmDir(context, name));
        } catch (IOException e) {
            throw new VirtualMachineException(e);
        }

        if (instancesMap != null) instancesMap.remove(name);
    }

    /**
     * Returns the name of this virtual machine. The name is unique in the package and can't be
     * changed.
     *
     * @hide
     */
    @NonNull
    public String getName() {
        return mName;
    }

    /**
     * Returns the currently selected config of this virtual machine. There can be multiple virtual
     * machines sharing the same config. Even in that case, the virtual machines are completely
     * isolated from each other; one cannot share its secret to another virtual machine even if they
     * share the same config. It is also possible that a virtual machine can switch its config,
     * which can be done by calling {@link #setConfig(VirtualMachineConfig)}.
     *
     * @hide
     */
    @NonNull
    public VirtualMachineConfig getConfig() {
        synchronized (mLock) {
            return mConfig;
        }
    }

    /**
     * Returns the current status of this virtual machine.
     *
     * @hide
     */
    @Status
    public int getStatus() {
        IVirtualMachine virtualMachine;
        synchronized (mLock) {
            virtualMachine = mVirtualMachine;
        }
        if (virtualMachine == null) {
            return mVmRootPath.exists() ? STATUS_STOPPED : STATUS_DELETED;
        } else {
            try {
                return stateToStatus(virtualMachine.getState());
            } catch (RemoteException e) {
                throw e.rethrowAsRuntimeException();
            }
        }
    }

    private int stateToStatus(@VirtualMachineState int state) {
        switch (state) {
            case VirtualMachineState.STARTING:
            case VirtualMachineState.STARTED:
            case VirtualMachineState.READY:
            case VirtualMachineState.FINISHED:
                return STATUS_RUNNING;
            case VirtualMachineState.NOT_STARTED:
            case VirtualMachineState.DEAD:
            default:
                return STATUS_STOPPED;
        }
    }

    // Throw an appropriate exception if we have a running VM, or the VM has been deleted.
    @GuardedBy("mLock")
    private void checkStopped() throws VirtualMachineException {
        if (!mVmRootPath.exists()) {
            throw new VirtualMachineException("VM has been deleted");
        }
        if (mVirtualMachine == null) {
            return;
        }
        try {
            if (stateToStatus(mVirtualMachine.getState()) != STATUS_STOPPED) {
                throw new VirtualMachineException("VM is not in stopped state");
            }
        } catch (RemoteException e) {
            throw e.rethrowAsRuntimeException();
        }
    }

    // If we have an IVirtualMachine in the running state return it, otherwise throw.
    @GuardedBy("mLock")
    private IVirtualMachine getRunningVm() throws VirtualMachineException {
        try {
            if (mVirtualMachine != null
                    && stateToStatus(mVirtualMachine.getState()) == STATUS_RUNNING) {
                return mVirtualMachine;
            } else {
                if (!mVmRootPath.exists()) {
                    throw new VirtualMachineException("VM has been deleted");
                } else {
                    throw new VirtualMachineException("VM is not in running state");
                }
            }
        } catch (RemoteException e) {
            throw e.rethrowAsRuntimeException();
        }
    }

    /**
     * Registers the callback object to get events from the virtual machine. If a callback was
     * already registered, it is replaced with the new one.
     *
     * @hide
     */
    public void setCallback(@NonNull @CallbackExecutor Executor executor,
            @NonNull VirtualMachineCallback callback) {
        synchronized (mCallbackLock) {
            mCallback = callback;
            mCallbackExecutor = executor;
        }
    }

    /**
     * Clears the currently registered callback.
     *
     * @hide
     */
    public void clearCallback() {
        synchronized (mCallbackLock) {
            mCallback = null;
            mCallbackExecutor = null;
        }
    }

    /** Executes a callback on the callback executor. */
    private void executeCallback(Consumer<VirtualMachineCallback> fn) {
        final VirtualMachineCallback callback;
        final Executor executor;
        synchronized (mCallbackLock) {
            callback = mCallback;
            executor = mCallbackExecutor;
        }
        if (callback == null || executor == null) {
            return;
        }
        final long restoreToken = Binder.clearCallingIdentity();
        try {
            executor.execute(() -> fn.accept(callback));
        } finally {
            Binder.restoreCallingIdentity(restoreToken);
        }
    }

    /**
     * Runs this virtual machine. The returning of this method however doesn't mean that the VM has
     * actually started running or the OS has booted there. Such events can be notified by
     * registering a callback using {@link #setCallback(Executor, VirtualMachineCallback)} before
     * calling {@code run()}.
     *
     * @throws VirtualMachineException if the virtual machine is not stopped or could not be
     *         started.
     * @hide
     */
    @RequiresPermission(MANAGE_VIRTUAL_MACHINE_PERMISSION)
    public void run() throws VirtualMachineException {
        synchronized (mLock) {
            checkStopped();

            try {
                mIdsigFilePath.createNewFile();
                for (ExtraApkSpec extraApk : mExtraApks) {
                    extraApk.idsig.createNewFile();
                }
            } catch (IOException e) {
                // If the file already exists, exception is not thrown.
                throw new VirtualMachineException("failed to create idsig file", e);
            }

            IVirtualizationService service =
                    IVirtualizationService.Stub.asInterface(
                            ServiceManager.waitForService(SERVICE_NAME));

            try {
                createVmPipes();

                VirtualMachineAppConfig appConfig = getConfig().toVsConfig();
                appConfig.name = mName;

                // Fill the idsig file by hashing the apk
                service.createOrUpdateIdsigFile(
                        appConfig.apk, ParcelFileDescriptor.open(mIdsigFilePath, MODE_READ_WRITE));

                for (ExtraApkSpec extraApk : mExtraApks) {
                    service.createOrUpdateIdsigFile(
                            ParcelFileDescriptor.open(extraApk.apk, MODE_READ_ONLY),
                            ParcelFileDescriptor.open(extraApk.idsig, MODE_READ_WRITE));
                }

                // Re-open idsig file in read-only mode
                appConfig.idsig = ParcelFileDescriptor.open(mIdsigFilePath, MODE_READ_ONLY);
                appConfig.instanceImage = ParcelFileDescriptor.open(mInstanceFilePath,
                        MODE_READ_WRITE);
                List<ParcelFileDescriptor> extraIdsigs = new ArrayList<>();
                for (ExtraApkSpec extraApk : mExtraApks) {
                    extraIdsigs.add(ParcelFileDescriptor.open(extraApk.idsig, MODE_READ_ONLY));
                }
                appConfig.extraIdsigs = extraIdsigs;

                android.system.virtualizationservice.VirtualMachineConfig vmConfigParcel =
                        android.system.virtualizationservice.VirtualMachineConfig.appConfig(
                                appConfig);

                // The VM should only be observed to die once
                AtomicBoolean onDiedCalled = new AtomicBoolean(false);

                IBinder.DeathRecipient deathRecipient = () -> {
                    if (onDiedCalled.compareAndSet(false, true)) {
                        executeCallback((cb) -> cb.onStopped(VirtualMachine.this,
                                VirtualMachineCallback.STOP_REASON_VIRTUALIZATION_SERVICE_DIED));
                    }
                };

                mVirtualMachine = service.createVm(vmConfigParcel, mConsoleWriter, mLogWriter);
                mVirtualMachine.registerCallback(
                        new IVirtualMachineCallback.Stub() {
                            @Override
                            public void onPayloadStarted(int cid) {
                                executeCallback((cb) -> cb.onPayloadStarted(VirtualMachine.this));
                            }

                            @Override
                            public void onPayloadStdio(int cid, ParcelFileDescriptor stream) {
                                executeCallback(
                                        (cb) -> cb.onPayloadStdio(VirtualMachine.this, stream));
                            }

                            @Override
                            public void onPayloadReady(int cid) {
                                executeCallback((cb) -> cb.onPayloadReady(VirtualMachine.this));
                            }

                            @Override
                            public void onPayloadFinished(int cid, int exitCode) {
                                executeCallback(
                                        (cb) ->
                                                cb.onPayloadFinished(
                                                        VirtualMachine.this, exitCode));
                            }

                            @Override
                            public void onError(int cid, int errorCode, String message) {
                                int translatedError = getTranslatedError(errorCode);
                                executeCallback(
                                        (cb) ->
                                                cb.onError(
                                                        VirtualMachine.this,
                                                        translatedError,
                                                        message));
                            }

                            @Override
                            public void onDied(int cid, int reason) {
                                service.asBinder().unlinkToDeath(deathRecipient, 0);
                                int translatedReason = getTranslatedReason(reason);
                                if (onDiedCalled.compareAndSet(false, true)) {
                                    executeCallback(
                                            (cb) ->
                                                    cb.onStopped(
                                                            VirtualMachine.this, translatedReason));
                                }
                            }

                            @Override
                            public void onRamdump(int cid, ParcelFileDescriptor ramdump) {
                                executeCallback((cb) -> cb.onRamdump(VirtualMachine.this, ramdump));
                            }
                        });
                service.asBinder().linkToDeath(deathRecipient, 0);
                mVirtualMachine.start();
            } catch (IOException | IllegalStateException | ServiceSpecificException e) {
                throw new VirtualMachineException(e);
            } catch (RemoteException e) {
                throw e.rethrowAsRuntimeException();
            }
        }
    }

    @GuardedBy("mLock")
    private void createVmPipes() throws VirtualMachineException {
        try {
            if (mConsoleReader == null || mConsoleWriter == null) {
                ParcelFileDescriptor[] pipe = ParcelFileDescriptor.createPipe();
                mConsoleReader = pipe[0];
                mConsoleWriter = pipe[1];
            }

            if (mLogReader == null || mLogWriter == null) {
                ParcelFileDescriptor[] pipe = ParcelFileDescriptor.createPipe();
                mLogReader = pipe[0];
                mLogWriter = pipe[1];
            }
        } catch (IOException e) {
            throw new VirtualMachineException("Failed to create stream for VM", e);
        }
    }

    /**
     * Returns the stream object representing the console output from the virtual machine.
     *
     * @throws VirtualMachineException if the stream could not be created.
     * @hide
     */
    @NonNull
    public InputStream getConsoleOutput() throws VirtualMachineException {
        synchronized (mLock) {
            createVmPipes();
            return new FileInputStream(mConsoleReader.getFileDescriptor());
        }
    }

    /**
     * Returns the stream object representing the log output from the virtual machine.
     *
     * @throws VirtualMachineException if the stream could not be created.
     * @hide
     */
    @NonNull
    public InputStream getLogOutput() throws VirtualMachineException {
        synchronized (mLock) {
            createVmPipes();
            return new FileInputStream(mLogReader.getFileDescriptor());
        }
    }

    /**
     * Stops this virtual machine. Stopping a virtual machine is like pulling the plug on a real
     * computer; the machine halts immediately. Software running on the virtual machine is not
     * notified of the event. A stopped virtual machine can be re-started by calling {@link
     * #run()}.
     *
     * @throws VirtualMachineException if the virtual machine could not be stopped.
     * @hide
     */
    public void stop() throws VirtualMachineException {
        synchronized (mLock) {
            if (mVirtualMachine == null) {
                throw new VirtualMachineException("VM is not running");
            }
            try {
                mVirtualMachine.stop();
                mVirtualMachine = null;
            } catch (RemoteException e) {
                throw e.rethrowAsRuntimeException();
            } catch (ServiceSpecificException e) {
                throw new VirtualMachineException(e);
            }
        }
    }

    /**
     * Stops this virtual machine. See {@link #stop()}.
     *
     * @throws VirtualMachineException if the virtual machine could not be stopped.
     * @hide
     */
    @Override
    public void close() throws VirtualMachineException {
        stop();
    }

    private static void deleteRecursively(File dir) throws IOException {
        // Note: This doesn't follow symlinks, which is important. Instead they are just deleted
        // (and Files.delete deletes the link not the target).
        Files.walkFileTree(dir.toPath(), new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs)
                    throws IOException {
                Files.delete(file);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path dir, IOException e) throws IOException {
                // Directory is deleted after we've visited (deleted) all its contents, so it
                // should be empty by now.
                Files.delete(dir);
                return FileVisitResult.CONTINUE;
            }
        });
    }

    /**
     * Returns the CID of this virtual machine, if it is running.
     *
     * @throws VirtualMachineException if the virtual machine is not running.
     * @hide
     */
    public int getCid() throws VirtualMachineException {
        synchronized (mLock) {
            try {
                return getRunningVm().getCid();
            } catch (RemoteException e) {
                throw e.rethrowAsRuntimeException();
            }
        }
    }

    /**
     * Changes the config of this virtual machine to a new one. This can be used to adjust things
     * like the number of CPU and size of the RAM, depending on the situation (e.g. the size of the
     * application to run on the virtual machine, etc.)
     *
     * The new config must be {@link VirtualMachineConfig#isCompatibleWith compatible with} the
     * existing config.
     *
     * @return the old config
     * @throws VirtualMachineException if the virtual machine is not stopped, or the new config is
     *         incompatible.
     * @hide
     */
    @NonNull
    public VirtualMachineConfig setConfig(@NonNull VirtualMachineConfig newConfig)
            throws VirtualMachineException {
        synchronized (mLock) {
            VirtualMachineConfig oldConfig = mConfig;
            if (!oldConfig.isCompatibleWith(newConfig)) {
                throw new VirtualMachineException("incompatible config");
            }
            checkStopped();

            try {
                FileOutputStream output = new FileOutputStream(mConfigFilePath);
                newConfig.serialize(output);
                output.close();
            } catch (IOException e) {
                throw new VirtualMachineException("Failed to persist config", e);
            }
            mConfig = newConfig;
            return oldConfig;
        }
    }

    @Nullable
    private static native IBinder nativeConnectToVsockServer(IBinder vmBinder, int port);

    /**
     * Connect to a VM's binder service via vsock and return the root IBinder object. Guest VMs are
     * expected to set up vsock servers in their payload. After the host app receives the {@link
     * VirtualMachineCallback#onPayloadReady(VirtualMachine)}, it can use this method to
     * establish a connection to the guest VM.
     *
     * @throws VirtualMachineException if the virtual machine is not running or the connection
     *         failed.
     * @hide
     */
    @NonNull
    public IBinder connectToVsockServer(int port) throws VirtualMachineException {
        synchronized (mLock) {
            IBinder iBinder = nativeConnectToVsockServer(getRunningVm().asBinder(), port);
            if (iBinder == null) {
                throw new VirtualMachineException("Failed to connect to vsock server");
            }
            return iBinder;
        }
    }

    /**
     * Opens a vsock connection to the VM on the given port.
     *
     * @throws VirtualMachineException if connecting fails.
     * @hide
     */
    @NonNull
    public ParcelFileDescriptor connectVsock(int port) throws VirtualMachineException {
        synchronized (mLock) {
            try {
                return getRunningVm().connectVsock(port);
            } catch (RemoteException e) {
                throw e.rethrowAsRuntimeException();
            } catch (ServiceSpecificException e) {
                throw new VirtualMachineException(e);
            }
        }
    }

    /**
     * Captures the current state of the VM in a {@link VirtualMachineDescriptor} instance. The VM
     * needs to be stopped to avoid inconsistency in its state representation.
     *
     * @return a {@link VirtualMachineDescriptor} instance that represents the VM's state.
     * @throws VirtualMachineException if the virtual machine is not stopped, or the state could not
     *     be captured.
     */
    @NonNull
    public VirtualMachineDescriptor toDescriptor() throws VirtualMachineException {
        synchronized (mLock) {
            checkStopped();
        }
        try {
            return new VirtualMachineDescriptor(
                    ParcelFileDescriptor.open(mConfigFilePath, MODE_READ_ONLY),
                    ParcelFileDescriptor.open(mInstanceFilePath, MODE_READ_ONLY));
        } catch (IOException e) {
            throw new VirtualMachineException(e);
        }
    }

    @VirtualMachineCallback.ErrorCode
    private int getTranslatedError(int reason) {
        switch (reason) {
            case ErrorCode.PAYLOAD_VERIFICATION_FAILED:
                return ERROR_PAYLOAD_VERIFICATION_FAILED;
            case ErrorCode.PAYLOAD_CHANGED:
                return ERROR_PAYLOAD_CHANGED;
            case ErrorCode.PAYLOAD_CONFIG_INVALID:
                return ERROR_PAYLOAD_INVALID_CONFIG;
            default:
                return ERROR_UNKNOWN;
        }
    }

    @VirtualMachineCallback.StopReason
    private int getTranslatedReason(int reason) {
        switch (reason) {
            case DeathReason.INFRASTRUCTURE_ERROR:
                return STOP_REASON_INFRASTRUCTURE_ERROR;
            case DeathReason.KILLED:
                return STOP_REASON_KILLED;
            case DeathReason.SHUTDOWN:
                return STOP_REASON_SHUTDOWN;
            case DeathReason.ERROR:
                return STOP_REASON_ERROR;
            case DeathReason.REBOOT:
                return STOP_REASON_REBOOT;
            case DeathReason.CRASH:
                return STOP_REASON_CRASH;
            case DeathReason.PVM_FIRMWARE_PUBLIC_KEY_MISMATCH:
                return STOP_REASON_PVM_FIRMWARE_PUBLIC_KEY_MISMATCH;
            case DeathReason.PVM_FIRMWARE_INSTANCE_IMAGE_CHANGED:
                return STOP_REASON_PVM_FIRMWARE_INSTANCE_IMAGE_CHANGED;
            case DeathReason.BOOTLOADER_PUBLIC_KEY_MISMATCH:
                return STOP_REASON_BOOTLOADER_PUBLIC_KEY_MISMATCH;
            case DeathReason.BOOTLOADER_INSTANCE_IMAGE_CHANGED:
                return STOP_REASON_BOOTLOADER_INSTANCE_IMAGE_CHANGED;
            case DeathReason.MICRODROID_FAILED_TO_CONNECT_TO_VIRTUALIZATION_SERVICE:
                return STOP_REASON_MICRODROID_FAILED_TO_CONNECT_TO_VIRTUALIZATION_SERVICE;
            case DeathReason.MICRODROID_PAYLOAD_HAS_CHANGED:
                return STOP_REASON_MICRODROID_PAYLOAD_HAS_CHANGED;
            case DeathReason.MICRODROID_PAYLOAD_VERIFICATION_FAILED:
                return STOP_REASON_MICRODROID_PAYLOAD_VERIFICATION_FAILED;
            case DeathReason.MICRODROID_INVALID_PAYLOAD_CONFIG:
                return STOP_REASON_MICRODROID_INVALID_PAYLOAD_CONFIG;
            case DeathReason.MICRODROID_UNKNOWN_RUNTIME_ERROR:
                return STOP_REASON_MICRODROID_UNKNOWN_RUNTIME_ERROR;
            case DeathReason.HANGUP:
                return STOP_REASON_HANGUP;
            default:
                return STOP_REASON_UNKNOWN;
        }
    }

    @Override
    public String toString() {
        VirtualMachineConfig config = getConfig();
        String payloadConfigPath = config.getPayloadConfigPath();
        String payloadBinaryPath = config.getPayloadBinaryPath();

        StringBuilder result = new StringBuilder();
        result.append("VirtualMachine(")
                .append("name:")
                .append(getName())
                .append(", ");
        if (payloadBinaryPath != null) {
            result.append("payload:")
                    .append(payloadBinaryPath)
                    .append(", ");
        }
        if (payloadConfigPath != null) {
            result.append("config:")
                    .append(payloadConfigPath)
                    .append(", ");
        }
        result.append("package: ")
                .append(mPackageName)
                .append(")");
        return result.toString();
    }

    private static List<String> parseExtraApkListFromPayloadConfig(JsonReader reader)
            throws VirtualMachineException {
        /*
         * JSON schema from packages/modules/Virtualization/microdroid/payload/config/src/lib.rs:
         *
         * <p>{ "extra_apks": [ { "path": "/system/app/foo.apk", }, ... ], ... }
         */
        try {
            List<String> apks = new ArrayList<>();

            reader.beginObject();
            while (reader.hasNext()) {
                if (reader.nextName().equals("extra_apks")) {
                    reader.beginArray();
                    while (reader.hasNext()) {
                        reader.beginObject();
                        String name = reader.nextName();
                        if (name.equals("path")) {
                            apks.add(reader.nextString());
                        } else {
                            reader.skipValue();
                        }
                        reader.endObject();
                    }
                    reader.endArray();
                } else {
                    reader.skipValue();
                }
            }
            reader.endObject();
            return apks;
        } catch (IOException e) {
            throw new VirtualMachineException(e);
        }
    }

    /**
     * Reads the payload config inside the application, parses extra APK information, and then
     * creates corresponding idsig file paths.
     */
    private static List<ExtraApkSpec> setupExtraApks(
            @NonNull Context context, @NonNull VirtualMachineConfig config, @NonNull File vmDir)
            throws VirtualMachineException {
        String configPath = config.getPayloadConfigPath();
        if (configPath == null) {
            return Collections.emptyList();
        }
        try {
            ZipFile zipFile = new ZipFile(context.getPackageCodePath());
            InputStream inputStream =
                    zipFile.getInputStream(zipFile.getEntry(configPath));
            List<String> apkList =
                    parseExtraApkListFromPayloadConfig(
                            new JsonReader(new InputStreamReader(inputStream)));

            List<ExtraApkSpec> extraApks = new ArrayList<>();
            for (int i = 0; i < apkList.size(); ++i) {
                extraApks.add(
                        new ExtraApkSpec(
                                new File(apkList.get(i)),
                                new File(vmDir, EXTRA_IDSIG_FILE_PREFIX + i)));
            }

            return Collections.unmodifiableList(extraApks);
        } catch (IOException e) {
            throw new VirtualMachineException("Couldn't parse extra apks from the vm config", e);
        }
    }
}
