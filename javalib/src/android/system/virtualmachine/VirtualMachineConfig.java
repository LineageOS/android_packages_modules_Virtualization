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

import android.content.Context;
import android.os.ParcelFileDescriptor;
import android.os.PersistableBundle;
import android.system.virtualizationservice.VirtualMachineAppConfig;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Represents a configuration of a virtual machine. A configuration consists of hardware
 * configurations like the number of CPUs and the size of RAM, and software configurations like the
 * OS and application to run on the virtual machine.
 *
 * @hide
 */
public final class VirtualMachineConfig {
    // These defines the schema of the config file persisted on disk.
    private static final int VERSION = 1;
    private static final String KEY_VERSION = "version";
    private static final String KEY_APKPATH = "apkPath";
    private static final String KEY_IDSIGPATH = "idsigPath";
    private static final String KEY_PAYLOADCONFIGPATH = "payloadConfigPath";
    private static final String KEY_DEBUGMODE = "debugMode";

    // Paths to the APK and its idsig file of this application.
    private final String mApkPath;
    private final String mIdsigPath;
    private final boolean mDebugMode;

    /**
     * Path within the APK to the payload config file that defines software aspects of this config.
     */
    private final String mPayloadConfigPath;

    // TODO(jiyong): add more items like # of cpu, size of ram, debuggability, etc.

    private VirtualMachineConfig(
            String apkPath, String idsigPath, String payloadConfigPath, boolean debugMode) {
        mApkPath = apkPath;
        mIdsigPath = idsigPath;
        mPayloadConfigPath = payloadConfigPath;
        mDebugMode = debugMode;
    }

    /** Loads a config from a stream, for example a file. */
    /* package */ static VirtualMachineConfig from(InputStream input)
            throws IOException, VirtualMachineException {
        PersistableBundle b = PersistableBundle.readFromStream(input);
        final int version = b.getInt(KEY_VERSION);
        if (version > VERSION) {
            throw new VirtualMachineException("Version too high");
        }
        final String apkPath = b.getString(KEY_APKPATH);
        if (apkPath == null) {
            throw new VirtualMachineException("No apkPath");
        }
        final String idsigPath = b.getString(KEY_IDSIGPATH);
        if (idsigPath == null) {
            throw new VirtualMachineException("No idsigPath");
        }
        final String payloadConfigPath = b.getString(KEY_PAYLOADCONFIGPATH);
        if (payloadConfigPath == null) {
            throw new VirtualMachineException("No payloadConfigPath");
        }
        final boolean debugMode = b.getBoolean(KEY_DEBUGMODE);
        return new VirtualMachineConfig(apkPath, idsigPath, payloadConfigPath, debugMode);
    }

    /** Persists this config to a stream, for example a file. */
    /* package */ void serialize(OutputStream output) throws IOException {
        PersistableBundle b = new PersistableBundle();
        b.putInt(KEY_VERSION, VERSION);
        b.putString(KEY_APKPATH, mApkPath);
        b.putString(KEY_IDSIGPATH, mIdsigPath);
        b.putString(KEY_PAYLOADCONFIGPATH, mPayloadConfigPath);
        b.putBoolean(KEY_DEBUGMODE, mDebugMode);
        b.writeToStream(output);
    }

    /** Returns the path to the payload config within the owning application. */
    public String getPayloadConfigPath() {
        return mPayloadConfigPath;
    }

    /**
     * Converts this config object into a parcel. Used when creating a VM via the virtualization
     * service. Notice that the files are not passed as paths, but as file descriptors because the
     * service doesn't accept paths as it might not have permission to open app-owned files and that
     * could be abused to run a VM with software that the calling application doesn't own.
     */
    /* package */ VirtualMachineAppConfig toParcel() throws FileNotFoundException {
        VirtualMachineAppConfig parcel = new VirtualMachineAppConfig();
        parcel.apk = ParcelFileDescriptor.open(new File(mApkPath), MODE_READ_ONLY);
        parcel.idsig = ParcelFileDescriptor.open(new File(mIdsigPath), MODE_READ_ONLY);
        parcel.configPath = mPayloadConfigPath;
        parcel.debug = mDebugMode;
        return parcel;
    }

    /** A builder used to create a {@link VirtualMachineConfig}. */
    public static class Builder {
        private Context mContext;
        private String mPayloadConfigPath;
        private boolean mDebugMode;
        private String mIdsigPath; // TODO(jiyong): remove this
        // TODO(jiyong): add more items like # of cpu, size of ram, debuggability, etc.

        /** Creates a builder for the given context (APK), and the payload config file in APK. */
        public Builder(Context context, String payloadConfigPath) {
            mContext = context;
            mPayloadConfigPath = payloadConfigPath;
            mDebugMode = false;
        }

        /** Enables or disables the debug mode */
        public Builder debugMode(boolean enableOrDisable) {
            mDebugMode = enableOrDisable;
            return this;
        }

        // TODO(jiyong): remove this. Apps shouldn't need to set the path to the idsig file. It
        // should be automatically found or created on demand.
        /** Set the path to the idsig file for the current application. */
        public Builder idsigPath(String idsigPath) {
            mIdsigPath = idsigPath;
            return this;
        }

        /** Builds an immutable {@link VirtualMachineConfig} */
        public VirtualMachineConfig build() {
            final String apkPath = mContext.getPackageCodePath();
            return new VirtualMachineConfig(apkPath, mIdsigPath, mPayloadConfigPath, mDebugMode);
        }
    }
}