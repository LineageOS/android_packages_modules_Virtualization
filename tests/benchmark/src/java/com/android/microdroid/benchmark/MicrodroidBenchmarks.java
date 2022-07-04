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
package com.android.microdroid.benchmark;

import static androidx.test.platform.app.InstrumentationRegistry.getInstrumentation;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.TruthJUnit.assume;

import static org.junit.Assume.assumeNoException;

import android.app.Instrumentation;
import android.content.Context;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.os.SystemProperties;
import android.sysprop.HypervisorProperties;
import android.system.virtualizationservice.DeathReason;
import android.system.virtualmachine.VirtualMachine;
import android.system.virtualmachine.VirtualMachineCallback;
import android.system.virtualmachine.VirtualMachineConfig;
import android.system.virtualmachine.VirtualMachineConfig.DebugLevel;
import android.system.virtualmachine.VirtualMachineException;
import android.system.virtualmachine.VirtualMachineManager;
import android.util.Log;

import androidx.annotation.CallSuper;
import androidx.test.core.app.ApplicationProvider;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.Timeout;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

@RunWith(Parameterized.class)
public class MicrodroidBenchmarks {
    private static final String TAG = "MicrodroidBenchmarks";

    @Rule public Timeout globalTimeout = Timeout.seconds(300);

    private static final String KERNEL_VERSION = SystemProperties.get("ro.kernel.version");

    private boolean isCuttlefish() {
        String productName = SystemProperties.get("ro.product.name");
        return (null != productName)
                && (productName.startsWith("aosp_cf_x86")
                        || productName.startsWith("aosp_cf_arm")
                        || productName.startsWith("cf_x86")
                        || productName.startsWith("cf_arm"));
    }

    /** Copy output from the VM to logcat. This is helpful when things go wrong. */
    private static void logVmOutput(InputStream vmOutputStream, String name) {
        new Thread(
                () -> {
                    try {
                        BufferedReader reader =
                                new BufferedReader(new InputStreamReader(vmOutputStream));
                        String line;
                        while ((line = reader.readLine()) != null
                                && !Thread.interrupted()) {
                            Log.i(TAG, name + ": " + line);
                        }
                    } catch (Exception e) {
                        Log.w(TAG, name, e);
                    }
                }).start();
    }

    private static class Inner {
        public boolean mProtectedVm;
        public Context mContext;
        public VirtualMachineManager mVmm;
        public VirtualMachine mVm;

        Inner(boolean protectedVm) {
            mProtectedVm = protectedVm;
        }

        /** Create a new VirtualMachineConfig.Builder with the parameterized protection mode. */
        public VirtualMachineConfig.Builder newVmConfigBuilder(String payloadConfigPath) {
            return new VirtualMachineConfig.Builder(mContext, payloadConfigPath)
                    .protectedVm(mProtectedVm);
        }
    }

    @Parameterized.Parameters(name = "protectedVm={0}")
    public static Object[] protectedVmConfigs() {
        return new Object[] {false, true};
    }

    @Parameterized.Parameter public boolean mProtectedVm;

    private boolean mPkvmSupported = false;
    private Inner mInner;

    private Instrumentation mInstrumentation;

    @Before
    public void setup() {
        // In case when the virt APEX doesn't exist on the device, classes in the
        // android.system.virtualmachine package can't be loaded. Therefore, before using the
        // classes, check the existence of a class in the package and skip this test if not exist.
        try {
            Class.forName("android.system.virtualmachine.VirtualMachineManager");
            mPkvmSupported = true;
        } catch (ClassNotFoundException e) {
            assumeNoException(e);
            return;
        }
        if (mProtectedVm) {
            assume().withMessage("Skip where protected VMs aren't support")
                    .that(HypervisorProperties.hypervisor_protected_vm_supported().orElse(false))
                    .isTrue();
        } else {
            assume().withMessage("Skip where VMs aren't support")
                    .that(HypervisorProperties.hypervisor_vm_supported().orElse(false))
                    .isTrue();
        }
        mInner = new Inner(mProtectedVm);
        mInner.mContext = ApplicationProvider.getApplicationContext();
        mInner.mVmm = VirtualMachineManager.getInstance(mInner.mContext);
        mInstrumentation = getInstrumentation();
    }

    @After
    public void cleanup() throws VirtualMachineException {
        if (!mPkvmSupported) {
            return;
        }
        if (mInner == null) {
            return;
        }
        if (mInner.mVm == null) {
            return;
        }
        mInner.mVm.stop();
        mInner.mVm.delete();
    }

    private abstract static class VmEventListener implements VirtualMachineCallback {
        private ExecutorService mExecutorService = Executors.newSingleThreadExecutor();

        void runToFinish(VirtualMachine vm) throws VirtualMachineException, InterruptedException {
            vm.setCallback(mExecutorService, this);
            vm.run();
            logVmOutput(vm.getConsoleOutputStream(), "Console");
            logVmOutput(vm.getLogOutputStream(), "Log");
            mExecutorService.awaitTermination(300, TimeUnit.SECONDS);
        }

        void forceStop(VirtualMachine vm) {
            try {
                vm.clearCallback();
                vm.stop();
                mExecutorService.shutdown();
            } catch (VirtualMachineException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public void onPayloadStarted(VirtualMachine vm, ParcelFileDescriptor stream) {}

        @Override
        public void onPayloadReady(VirtualMachine vm) {}

        @Override
        public void onPayloadFinished(VirtualMachine vm, int exitCode) {}

        @Override
        public void onError(VirtualMachine vm, int errorCode, String message) {}

        @Override
        @CallSuper
        public void onDied(VirtualMachine vm, @DeathReason int reason) {
            mExecutorService.shutdown();
        }
    }

    private static class BootResult {
        public final boolean payloadStarted;
        public final int deathReason;

        BootResult(boolean payloadStarted, int deathReason) {
            this.payloadStarted = payloadStarted;
            this.deathReason = deathReason;
        }
    }

    private BootResult tryBootVm(String vmName)
            throws VirtualMachineException, InterruptedException {
        mInner.mVm = mInner.mVmm.get(vmName); // re-load the vm before running tests
        final CompletableFuture<Boolean> payloadStarted = new CompletableFuture<>();
        final CompletableFuture<Integer> deathReason = new CompletableFuture<>();
        VmEventListener listener =
                new VmEventListener() {
                    @Override
                    public void onPayloadStarted(VirtualMachine vm, ParcelFileDescriptor stream) {
                        payloadStarted.complete(true);
                        forceStop(vm);
                    }

                    @Override
                    public void onDied(VirtualMachine vm, int reason) {
                        deathReason.complete(reason);
                        super.onDied(vm, reason);
                    }
                };
        listener.runToFinish(mInner.mVm);
        return new BootResult(
                payloadStarted.getNow(false), deathReason.getNow(DeathReason.INFRASTRUCTURE_ERROR));
    }

    private boolean canBootMicrodroidWithMemory(int mem)
            throws VirtualMachineException, InterruptedException, IOException {
        final int trialCount = 5;

        // returns true if succeeded at least once.
        for (int i = 0; i < trialCount; i++) {
            VirtualMachine existingVm = mInner.mVmm.get("test_vm_minimum_memory");
            if (existingVm != null) {
                existingVm.delete();
            }

            VirtualMachineConfig.Builder builder =
                    mInner.newVmConfigBuilder("assets/vm_config.json");
            VirtualMachineConfig normalConfig =
                    builder.debugLevel(DebugLevel.FULL).memoryMib(mem).build();
            mInner.mVmm.create("test_vm_minimum_memory", normalConfig);

            if (tryBootVm("test_vm_minimum_memory").payloadStarted) return true;
        }

        return false;
    }

    @Test
    public void testMinimumRequiredRAM()
            throws VirtualMachineException, InterruptedException, IOException {
        assume().withMessage("Skip on CF; too slow").that(isCuttlefish()).isFalse();

        int lo = 16, hi = 512, minimum = 0;
        boolean found = false;

        while (lo <= hi) {
            int mid = (lo + hi) / 2;
            if (canBootMicrodroidWithMemory(mid)) {
                found = true;
                minimum = mid;
                hi = mid - 1;
            } else {
                lo = mid + 1;
            }
        }

        assertThat(found).isTrue();

        Bundle bundle = new Bundle();
        bundle.putInt("avf_perf/microdroid/minimum_required_memory", minimum);
        mInstrumentation.sendStatus(0, bundle);
    }
}
