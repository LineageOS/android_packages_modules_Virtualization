/*
 * Copyright 2021 The Android Open Source Project
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

package com.android.server.compos;

import android.annotation.NonNull;
import android.app.job.JobScheduler;
import android.content.Context;
import android.content.pm.ApexStagedEvent;
import android.content.pm.IPackageManagerNative;
import android.content.pm.IStagedApexObserver;
import android.content.pm.StagedApexInfo;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.provider.DeviceConfig;
import android.util.Log;

import com.android.server.SystemService;

import java.io.File;

/**
 * A system service responsible for performing Isolated Compilation (compiling boot & system server
 * classpath JARs in a protected VM) when appropriate.
 *
 * @hide
 */
public class IsolatedCompilationService extends SystemService {
    private static final String TAG = IsolatedCompilationService.class.getName();

    public IsolatedCompilationService(@NonNull Context context) {
        super(context);
    }

    @Override
    public void onStart() {
        // Note that our binder service is exposed directly from native code in composd, so
        // we don't need to do anything here.
    }

    @Override
    public void onBootPhase(/* @BootPhase */ int phase) {
        if (phase != PHASE_BOOT_COMPLETED) return;

        if (!isIsolatedCompilationSupported()) {
            Log.i(TAG, "Isolated compilation not supported, not scheduling job");
            return;
        }


        JobScheduler scheduler = getContext().getSystemService(JobScheduler.class);
        if (scheduler == null) {
            Log.e(TAG, "No scheduler");
            return;
        }

        IsolatedCompilationJobService.scheduleDailyJob(scheduler);
        StagedApexObserver.registerForStagedApexUpdates(scheduler);
    }

    private static boolean isIsolatedCompilationSupported() {
        // Check that the relevant experiment is enabled on this device
        // TODO - Remove this once we are ready for wider use.
        if (!DeviceConfig.getBoolean(
                "virtualization_framework_native", "isolated_compilation_enabled", false)) {
            return false;
        }

        // Check that KVM is enabled on the device
        if (!new File("/dev/kvm").exists()) {
            return false;
        }

        return true;
    }

    private static class StagedApexObserver extends IStagedApexObserver.Stub {
        private final JobScheduler mScheduler;
        private final IPackageManagerNative mPackageNative;

        static void registerForStagedApexUpdates(JobScheduler scheduler) {
            final IPackageManagerNative packageNative = IPackageManagerNative.Stub.asInterface(
                    ServiceManager.getService("package_native"));
            if (packageNative == null) {
                Log.e(TAG, "No IPackageManagerNative");
                return;
            }

            StagedApexObserver observer = new StagedApexObserver(scheduler, packageNative);
            try {
                packageNative.registerStagedApexObserver(observer);
                // In the unlikely event that an APEX has been staged before we get here, we may
                // have to schedule compilation immediately.
                observer.checkModules(packageNative.getStagedApexModuleNames());
            } catch (RemoteException e) {
                Log.e(TAG, "Failed to initialize observer", e);
            }
        }

        private StagedApexObserver(JobScheduler scheduler,
                IPackageManagerNative packageNative) {
            mScheduler = scheduler;
            mPackageNative = packageNative;
        }

        @Override
        public void onApexStaged(ApexStagedEvent event) {
            Log.d(TAG, "onApexStaged");
            checkModules(event.stagedApexModuleNames);
        }

        void checkModules(String[] moduleNames) {
            if (IsolatedCompilationJobService.isStagedApexJobScheduled(mScheduler)) {
                Log.d(TAG, "Job already scheduled");
                // We're going to run anyway, we don't need to check this update
                return;
            }
            boolean needCompilation = false;
            for (String moduleName : moduleNames) {
                try {
                    StagedApexInfo apexInfo = mPackageNative.getStagedApexInfo(moduleName);
                    if (apexInfo != null && apexInfo.hasClassPathJars) {
                        Log.i(TAG, "Classpath affecting module updated: " + moduleName);
                        needCompilation = true;
                        break;
                    }
                } catch (RemoteException e) {
                    Log.w(TAG, "Failed to get getStagedApexInfo for " + moduleName);
                }
            }
            if (needCompilation) {
                IsolatedCompilationJobService.scheduleStagedApexJob(mScheduler);
            }
        }
    }
}
