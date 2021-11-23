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
import android.app.job.JobInfo;
import android.app.job.JobScheduler;
import android.content.ComponentName;
import android.content.Context;
import android.provider.DeviceConfig;
import android.util.Log;

import com.android.server.SystemService;

import java.io.File;
import java.util.concurrent.TimeUnit;

/**
 * A system service responsible for performing Isolated Compilation (compiling boot & system server
 * classpath JARs in a protected VM) when appropriate.
 *
 * @hide
 */
public class IsolatedCompilationService extends SystemService {
    private static final String TAG = IsolatedCompilationService.class.getName();
    private static final int JOB_ID = 5132250;
    private static final long JOB_PERIOD_MILLIS = TimeUnit.DAYS.toMillis(1);

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

        ComponentName serviceName =
                new ComponentName("android", IsolatedCompilationJobService.class.getName());

        JobScheduler scheduler = getContext().getSystemService(JobScheduler.class);
        if (scheduler == null) {
            Log.e(TAG, "No scheduler");
            return;
        }
        int result =
                scheduler.schedule(
                        new JobInfo.Builder(JOB_ID, serviceName)
                                .setRequiresDeviceIdle(true)
                                .setRequiresCharging(true)
                                .setPeriodic(JOB_PERIOD_MILLIS)
                                .build());
        if (result != JobScheduler.RESULT_SUCCESS) {
            Log.e(TAG, "Failed to schedule job");
        }
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
}
