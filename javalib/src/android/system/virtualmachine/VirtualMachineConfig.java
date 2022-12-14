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

import static android.os.ParcelFileDescriptor.AutoCloseInputStream;
import static android.os.ParcelFileDescriptor.MODE_READ_ONLY;

import static java.util.Objects.requireNonNull;

import android.annotation.IntDef;
import android.annotation.IntRange;
import android.annotation.NonNull;
import android.annotation.Nullable;
import android.annotation.RequiresPermission;
import android.annotation.SystemApi;
import android.annotation.TestApi;
import android.content.Context;
import android.os.ParcelFileDescriptor;
import android.os.PersistableBundle;
import android.sysprop.HypervisorProperties;
import android.system.virtualizationservice.VirtualMachineAppConfig;
import android.system.virtualizationservice.VirtualMachinePayloadConfig;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.Objects;

/**
 * Represents a configuration of a virtual machine. A configuration consists of hardware
 * configurations like the number of CPUs and the size of RAM, and software configurations like the
 * payload to run on the virtual machine.
 *
 * @hide
 */
@SystemApi
public final class VirtualMachineConfig {
    private static final String[] EMPTY_STRING_ARRAY = {};

    // These define the schema of the config file persisted on disk.
    private static final int VERSION = 2;
    private static final String KEY_VERSION = "version";
    private static final String KEY_APKPATH = "apkPath";
    private static final String KEY_PAYLOADCONFIGPATH = "payloadConfigPath";
    private static final String KEY_PAYLOADBINARYPATH = "payloadBinaryPath";
    private static final String KEY_DEBUGLEVEL = "debugLevel";
    private static final String KEY_PROTECTED_VM = "protectedVm";
    private static final String KEY_MEMORY_MIB = "memoryMib";
    private static final String KEY_NUM_CPUS = "numCpus";
    private static final String KEY_ENCRYPTED_STORAGE_KIB = "encryptedStorageKib";

    /** @hide */
    @Retention(RetentionPolicy.SOURCE)
    @IntDef(prefix = "DEBUG_LEVEL_", value = {
            DEBUG_LEVEL_NONE,
            DEBUG_LEVEL_FULL
    })
    public @interface DebugLevel {}

    /**
     * Not debuggable at all. No log is exported from the VM. Debugger can't be attached to the app
     * process running in the VM. This is the default level.
     *
     * @hide
     */
    @SystemApi public static final int DEBUG_LEVEL_NONE = 0;

    /**
     * Fully debuggable. All logs (both logcat and kernel message) are exported. All processes
     * running in the VM can be attached to the debugger. Rooting is possible.
     *
     * @hide
     */
    @SystemApi public static final int DEBUG_LEVEL_FULL = 1;

    /** Absolute path to the APK file containing the VM payload. */
    @NonNull private final String mApkPath;

    @DebugLevel private final int mDebugLevel;

    /**
     * Whether to run the VM in protected mode, so the host can't access its memory.
     */
    private final boolean mProtectedVm;

    /**
     * The amount of RAM to give the VM, in MiB. If this is 0 or negative the default will be used.
     */
    private final int mMemoryMib;

    /**
     * Number of vCPUs in the VM. Defaults to 1 when not specified.
     */
    private final int mNumCpus;

    /**
     * Path within the APK to the payload config file that defines software aspects of the VM.
     */
    @Nullable private final String mPayloadConfigPath;

    /**
     * Path within the APK to the payload binary file that will be executed within the VM.
     */
    @Nullable private final String mPayloadBinaryPath;

    /** The size of storage in KB. 0 indicates that encryptedStorage is not required */
    private final long mEncryptedStorageKib;

    private VirtualMachineConfig(
            @NonNull String apkPath,
            @Nullable String payloadConfigPath,
            @Nullable String payloadBinaryPath,
            @DebugLevel int debugLevel,
            boolean protectedVm,
            int memoryMib,
            int numCpus,
            long encryptedStorageKib) {
        // This is only called from Builder.build(); the builder handles parameter validation.
        mApkPath = apkPath;
        mPayloadConfigPath = payloadConfigPath;
        mPayloadBinaryPath = payloadBinaryPath;
        mDebugLevel = debugLevel;
        mProtectedVm = protectedVm;
        mMemoryMib = memoryMib;
        mNumCpus = numCpus;
        mEncryptedStorageKib = encryptedStorageKib;
    }

    /** Loads a config from a file. */
    @NonNull
    static VirtualMachineConfig from(@NonNull File file) throws VirtualMachineException {
        try (FileInputStream input = new FileInputStream(file)) {
            return fromInputStream(input);
        } catch (IOException e) {
            throw new VirtualMachineException("Failed to read VM config from file", e);
        }
    }

    /** Loads a config from a {@link ParcelFileDescriptor}. */
    @NonNull
    static VirtualMachineConfig from(@NonNull ParcelFileDescriptor fd)
            throws VirtualMachineException {
        try (AutoCloseInputStream input = new AutoCloseInputStream(fd)) {
            return fromInputStream(input);
        } catch (IOException e) {
            throw new VirtualMachineException("failed to read VM config from file descriptor", e);
        }
    }

    /** Loads a config from a stream, for example a file. */
    @NonNull
    private static VirtualMachineConfig fromInputStream(@NonNull InputStream input)
            throws IOException, VirtualMachineException {
        PersistableBundle b = PersistableBundle.readFromStream(input);
        try {
            return fromPersistableBundle(b);
        } catch (NullPointerException | IllegalArgumentException | IllegalStateException e) {
            throw new VirtualMachineException("Persisted VM config is invalid", e);
        }
    }

    @NonNull
    private static VirtualMachineConfig fromPersistableBundle(PersistableBundle b) {
        int version = b.getInt(KEY_VERSION);
        if (version > VERSION) {
            throw new IllegalArgumentException(
                    "Version " + version + " too high; current is " + VERSION);
        }

        Builder builder = new Builder();
        builder.setApkPath(b.getString(KEY_APKPATH));

        String payloadConfigPath = b.getString(KEY_PAYLOADCONFIGPATH);
        if (payloadConfigPath == null) {
            builder.setPayloadBinaryPath(b.getString(KEY_PAYLOADBINARYPATH));
        } else {
            builder.setPayloadConfigPath(payloadConfigPath);
        }

        @DebugLevel int debugLevel = b.getInt(KEY_DEBUGLEVEL);
        if (debugLevel != DEBUG_LEVEL_NONE && debugLevel != DEBUG_LEVEL_FULL) {
            throw new IllegalArgumentException("Invalid debugLevel: " + debugLevel);
        }
        builder.setDebugLevel(debugLevel);
        builder.setProtectedVm(b.getBoolean(KEY_PROTECTED_VM));
        int memoryMib = b.getInt(KEY_MEMORY_MIB);
        if (memoryMib != 0) {
            builder.setMemoryMib(memoryMib);
        }
        builder.setNumCpus(b.getInt(KEY_NUM_CPUS));
        long encryptedStorageKib = b.getLong(KEY_ENCRYPTED_STORAGE_KIB);
        if (encryptedStorageKib != 0) {
            builder.setEncryptedStorageKib(encryptedStorageKib);
        }

        return builder.build();
    }

    /** Persists this config to a file. */
    void serialize(@NonNull File file) throws VirtualMachineException {
        try (FileOutputStream output = new FileOutputStream(file)) {
            serializeOutputStream(output);
        } catch (IOException e) {
            throw new VirtualMachineException("failed to write VM config", e);
        }
    }

    /** Persists this config to a stream, for example a file. */
    private void serializeOutputStream(@NonNull OutputStream output) throws IOException {
        PersistableBundle b = new PersistableBundle();
        b.putInt(KEY_VERSION, VERSION);
        b.putString(KEY_APKPATH, mApkPath);
        b.putString(KEY_PAYLOADCONFIGPATH, mPayloadConfigPath);
        b.putString(KEY_PAYLOADBINARYPATH, mPayloadBinaryPath);
        b.putInt(KEY_DEBUGLEVEL, mDebugLevel);
        b.putBoolean(KEY_PROTECTED_VM, mProtectedVm);
        b.putInt(KEY_NUM_CPUS, mNumCpus);
        if (mMemoryMib > 0) {
            b.putInt(KEY_MEMORY_MIB, mMemoryMib);
        }
        if (mEncryptedStorageKib > 0) {
            b.putLong(KEY_ENCRYPTED_STORAGE_KIB, mEncryptedStorageKib);
        }
        b.writeToStream(output);
    }

    /**
     * Returns the absolute path of the APK which should contain the binary payload that will
     * execute within the VM.
     *
     * @hide
     */
    @SystemApi
    @NonNull
    public String getApkPath() {
        return mApkPath;
    }

    /**
     * Returns the path within the APK to the payload config file that defines software aspects of
     * the VM.
     *
     * @hide
     */
    @TestApi
    @Nullable
    public String getPayloadConfigPath() {
        return mPayloadConfigPath;
    }

    /**
     * Returns the path within the {@code lib/<ABI>} directory of the APK to the payload binary file
     * that will be executed within the VM.
     *
     * @hide
     */
    @SystemApi
    @Nullable
    public String getPayloadBinaryPath() {
        return mPayloadBinaryPath;
    }

    /**
     * Returns the debug level for the VM.
     *
     * @hide
     */
    @SystemApi
    @NonNull
    @DebugLevel
    public int getDebugLevel() {
        return mDebugLevel;
    }

    /**
     * Returns whether the VM's memory will be protected from the host.
     *
     * @hide
     */
    @SystemApi
    public boolean isProtectedVm() {
        return mProtectedVm;
    }

    /**
     * Returns the amount of RAM that will be made available to the VM, or 0 if the default size
     * will be used.
     *
     * @hide
     */
    @SystemApi
    @IntRange(from = 0)
    public int getMemoryMib() {
        return mMemoryMib;
    }

    /**
     * Returns the number of vCPUs that the VM will have.
     *
     * @hide
     */
    @SystemApi
    @IntRange(from = 1)
    public int getNumCpus() {
        return mNumCpus;
    }

    /**
     * Returns whether encrypted storage is enabled or not.
     *
     * @hide
     */
    @SystemApi
    public boolean isEncryptedStorageEnabled() {
        return mEncryptedStorageKib > 0;
    }

    /**
     * Returns the size of encrypted storage (in KB) available in the VM, or 0 if encrypted storage
     * is not enabled
     *
     * @hide
     */
    @SystemApi
    @IntRange(from = 0)
    public long getEncryptedStorageKib() {
        return mEncryptedStorageKib;
    }

    /**
     * Tests if this config is compatible with other config. Being compatible means that the configs
     * can be interchangeably used for the same virtual machine. Compatible changes includes the
     * number of CPUs and the size of the RAM. All other changes (e.g. using a different payload,
     * change of the debug mode, etc.) are considered as incompatible.
     *
     * @hide
     */
    @SystemApi
    public boolean isCompatibleWith(@NonNull VirtualMachineConfig other) {
        return this.mDebugLevel == other.mDebugLevel
                && this.mProtectedVm == other.mProtectedVm
                && this.mEncryptedStorageKib == other.mEncryptedStorageKib
                && Objects.equals(this.mPayloadConfigPath, other.mPayloadConfigPath)
                && Objects.equals(this.mPayloadBinaryPath, other.mPayloadBinaryPath)
                && this.mApkPath.equals(other.mApkPath);
    }

    /**
     * Converts this config object into the parcelable type used when creating a VM via the
     * virtualization service. Notice that the files are not passed as paths, but as file
     * descriptors because the service doesn't accept paths as it might not have permission to open
     * app-owned files and that could be abused to run a VM with software that the calling
     * application doesn't own.
     */
    VirtualMachineAppConfig toVsConfig() throws FileNotFoundException {
        VirtualMachineAppConfig vsConfig = new VirtualMachineAppConfig();
        vsConfig.apk = ParcelFileDescriptor.open(new File(mApkPath), MODE_READ_ONLY);
        if (mPayloadBinaryPath != null) {
            VirtualMachinePayloadConfig payloadConfig = new VirtualMachinePayloadConfig();
            payloadConfig.payloadPath = mPayloadBinaryPath;
            vsConfig.payload =
                    VirtualMachineAppConfig.Payload.payloadConfig(payloadConfig);
        } else {
            vsConfig.payload =
                    VirtualMachineAppConfig.Payload.configPath(mPayloadConfigPath);
        }
        switch (mDebugLevel) {
            case DEBUG_LEVEL_FULL:
                vsConfig.debugLevel = VirtualMachineAppConfig.DebugLevel.FULL;
                break;
            default:
                vsConfig.debugLevel = VirtualMachineAppConfig.DebugLevel.NONE;
                break;
        }
        vsConfig.protectedVm = mProtectedVm;
        vsConfig.memoryMib = mMemoryMib;
        vsConfig.numCpus = mNumCpus;
        // Don't allow apps to set task profiles ... at least for now.
        vsConfig.taskProfiles = EMPTY_STRING_ARRAY;
        return vsConfig;
    }

    /**
     * A builder used to create a {@link VirtualMachineConfig}.
     *
     * @hide
     */
    @SystemApi
    public static final class Builder {
        @Nullable private final Context mContext;
        @Nullable private String mApkPath;
        @Nullable private String mPayloadConfigPath;
        @Nullable private String mPayloadBinaryPath;
        @DebugLevel private int mDebugLevel = DEBUG_LEVEL_NONE;
        private boolean mProtectedVm;
        private boolean mProtectedVmSet;
        private int mMemoryMib;
        private int mNumCpus = 1;
        private long mEncryptedStorageKib;

        /**
         * Creates a builder for the given context.
         *
         * @hide
         */
        @SystemApi
        public Builder(@NonNull Context context) {
            mContext = requireNonNull(context, "context must not be null");
        }

        /**
         * Creates a builder with no associated context; {@link #setApkPath} must be called to
         * specify which APK contains the payload.
         */
        private Builder() {
            mContext = null;
        }

        /**
         * Builds an immutable {@link VirtualMachineConfig}
         *
         * @hide
         */
        @SystemApi
        @NonNull
        public VirtualMachineConfig build() {
            String apkPath;
            if (mApkPath == null) {
                if (mContext == null) {
                    throw new IllegalStateException("apkPath must be specified");
                }
                apkPath = mContext.getPackageCodePath();
            } else {
                apkPath = mApkPath;
            }

            if (mPayloadBinaryPath == null) {
                if (mPayloadConfigPath == null) {
                    throw new IllegalStateException("setPayloadBinaryPath must be called");
                }
            } else {
                if (mPayloadConfigPath != null) {
                    throw new IllegalStateException(
                            "setPayloadBinaryPath and setPayloadConfigPath may not both be called");
                }
            }

            if (!mProtectedVmSet) {
                throw new IllegalStateException("setProtectedVm must be called explicitly");
            }

            return new VirtualMachineConfig(
                    apkPath,
                    mPayloadConfigPath,
                    mPayloadBinaryPath,
                    mDebugLevel,
                    mProtectedVm,
                    mMemoryMib,
                    mNumCpus,
                    mEncryptedStorageKib);
        }

        /**
         * Sets the absolute path of the APK containing the binary payload that will execute within
         * the VM. If not set explicitly, defaults to the primary APK of the context.
         *
         * @hide
         */
        @SystemApi
        @NonNull
        public Builder setApkPath(@NonNull String apkPath) {
            requireNonNull(apkPath, "apkPath must not be null");
            if (!apkPath.startsWith("/")) {
                throw new IllegalArgumentException("APK path must be an absolute path");
            }
            mApkPath = apkPath;
            return this;
        }

        /**
         * Sets the path within the APK to the payload config file that defines software aspects of
         * the VM. The file is a JSON file; see
         * packages/modules/Virtualization/microdroid/payload/config/src/lib.rs for the format.
         *
         * @hide
         */
        @RequiresPermission(VirtualMachine.USE_CUSTOM_VIRTUAL_MACHINE_PERMISSION)
        @TestApi
        @NonNull
        public Builder setPayloadConfigPath(@NonNull String payloadConfigPath) {
            mPayloadConfigPath =
                    requireNonNull(payloadConfigPath, "payloadConfigPath must not be null");
            return this;
        }

        /**
         * Sets the path within the {@code lib/<ABI>} directory of the APK to the payload binary
         * file that will be executed within the VM.
         *
         * @hide
         */
        @SystemApi
        @NonNull
        public Builder setPayloadBinaryPath(@NonNull String payloadBinaryPath) {
            mPayloadBinaryPath =
                    requireNonNull(payloadBinaryPath, "payloadBinaryPath must not be null");
            return this;
        }

        /**
         * Sets the debug level. Defaults to {@link #DEBUG_LEVEL_NONE}.
         *
         * @hide
         */
        @SystemApi
        @NonNull
        public Builder setDebugLevel(@DebugLevel int debugLevel) {
            if (debugLevel != DEBUG_LEVEL_NONE && debugLevel != DEBUG_LEVEL_FULL) {
                throw new IllegalArgumentException("Invalid debugLevel: " + debugLevel);
            }
            mDebugLevel = debugLevel;
            return this;
        }

        /**
         * Sets whether to protect the VM memory from the host. No default is provided, this must be
         * set explicitly.
         *
         * @see VirtualMachineManager#getCapabilities
         * @hide
         */
        @SystemApi
        @NonNull
        public Builder setProtectedVm(boolean protectedVm) {
            if (protectedVm) {
                if (!HypervisorProperties.hypervisor_protected_vm_supported().orElse(false)) {
                    throw new UnsupportedOperationException(
                            "Protected VMs are not supported on this device.");
                }
            } else {
                if (!HypervisorProperties.hypervisor_vm_supported().orElse(false)) {
                    throw new UnsupportedOperationException(
                            "Unprotected VMs are not supported on this device.");
                }
            }
            mProtectedVm = protectedVm;
            mProtectedVmSet = true;
            return this;
        }

        /**
         * Sets the amount of RAM to give the VM, in mebibytes. If not explicitly set then a default
         * size will be used.
         *
         * @hide
         */
        @SystemApi
        @NonNull
        public Builder setMemoryMib(@IntRange(from = 1) int memoryMib) {
            if (memoryMib <= 0) {
                throw new IllegalArgumentException("Memory size must be positive");
            }
            mMemoryMib = memoryMib;
            return this;
        }

        /**
         * Sets the number of vCPUs in the VM. Defaults to 1. Cannot be more than the number of real
         * CPUs (as returned by {@link Runtime#availableProcessors()}).
         *
         * @hide
         */
        @SystemApi
        @NonNull
        public Builder setNumCpus(@IntRange(from = 1) int numCpus) {
            int availableCpus = Runtime.getRuntime().availableProcessors();
            if (numCpus < 1 || numCpus > availableCpus) {
                throw new IllegalArgumentException(
                        "Number of vCPUs ("
                                + numCpus
                                + ") is out of "
                                + "range [1, "
                                + availableCpus
                                + "]");
            }
            mNumCpus = numCpus;
            return this;
        }

        /**
         * Sets the size (in KB) of encrypted storage available to the VM. If not set, no encrypted
         * storage is provided.
         *
         * <p>The storage is encrypted with a key deterministically derived from the VM identity
         *
         * <p>The encrypted storage is persistent across VM reboots as well as device reboots. The
         * backing file (containing encrypted data) is stored in the app's private data directory.
         *
         * <p>Note - There is no integrity guarantee or rollback protection on the storage in case
         * the encrypted data is modified.
         *
         * <p>Deleting the VM will delete the encrypted data - there is no way to recover that data.
         *
         * @hide
         */
        @SystemApi
        @NonNull
        public Builder setEncryptedStorageKib(@IntRange(from = 1) long encryptedStorageKib) {
            if (encryptedStorageKib <= 0) {
                throw new IllegalArgumentException("Encrypted Storage size must be positive");
            }
            mEncryptedStorageKib = encryptedStorageKib;
            return this;
        }
    }
}
