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
package com.android.microdroid.test;

import static com.google.common.truth.TruthJUnit.assume;

import static org.junit.Assume.assumeNoException;

import android.content.Context;
import android.os.ParcelFileDescriptor;
import android.os.SystemProperties;
import android.sysprop.HypervisorProperties;
import android.system.virtualizationservice.DeathReason;
import android.system.virtualmachine.VirtualMachine;
import android.system.virtualmachine.VirtualMachineCallback;
import android.system.virtualmachine.VirtualMachineConfig;
import android.system.virtualmachine.VirtualMachineException;
import android.system.virtualmachine.VirtualMachineManager;
import android.util.Log;

import androidx.annotation.CallSuper;
import androidx.test.core.app.ApplicationProvider;

import com.android.virt.VirtualizationTestHelper;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public abstract class MicrodroidDeviceTestBase {
    /** Copy output from the VM to logcat. This is helpful when things go wrong. */
    protected static void logVmOutput(String tag, InputStream vmOutputStream, String name) {
        new Thread(
                () -> {
                    try {
                        BufferedReader reader =
                                new BufferedReader(new InputStreamReader(vmOutputStream));
                        String line;
                        while ((line = reader.readLine()) != null
                                && !Thread.interrupted()) {
                            Log.i(tag, name + ": " + line);
                        }
                    } catch (Exception e) {
                        Log.w(tag, name, e);
                    }
                }).start();
    }

    public static boolean isCuttlefish() {
        return VirtualizationTestHelper.isCuttlefish(SystemProperties.get("ro.product.name"));
    }

    // TODO(b/220920264): remove Inner class; this is a hack to hide virt APEX types
    protected static class Inner {
        private final boolean mProtectedVm;
        private final Context mContext;
        private final VirtualMachineManager mVmm;

        public Inner(Context context, boolean protectedVm, VirtualMachineManager vmm) {
            mProtectedVm = protectedVm;
            mVmm = vmm;
            mContext = context;
        }

        public VirtualMachineManager getVirtualMachineManager() {
            return mVmm;
        }

        public Context getContext() {
            return mContext;
        }

        /** Create a new VirtualMachineConfig.Builder with the parameterized protection mode. */
        public VirtualMachineConfig.Builder newVmConfigBuilder(String payloadConfigPath) {
            return new VirtualMachineConfig.Builder(mContext, payloadConfigPath)
                        .protectedVm(mProtectedVm);
        }

        /**
         * Creates a new virtual machine, potentially removing an existing virtual machine with
         * given name.
         */
        public VirtualMachine forceCreateNewVirtualMachine(String name, VirtualMachineConfig config)
                throws VirtualMachineException {
            VirtualMachine existingVm = mVmm.get(name);
            if (existingVm != null) {
                existingVm.delete();
            }
            return mVmm.create(name, config);
        }
    }

    protected Inner mInner;

    protected Context getContext() {
        return mInner.getContext();
    }

    public void prepareTestSetup(boolean protectedVm) {
        // In case when the virt APEX doesn't exist on the device, classes in the
        // android.system.virtualmachine package can't be loaded. Therefore, before using the
        // classes, check the existence of a class in the package and skip this test if not exist.
        try {
            Class.forName("android.system.virtualmachine.VirtualMachineManager");
        } catch (ClassNotFoundException e) {
            assumeNoException(e);
            return;
        }
        if (protectedVm) {
            assume().withMessage("Skip where protected VMs aren't support")
                    .that(HypervisorProperties.hypervisor_protected_vm_supported().orElse(false))
                    .isTrue();
        } else {
            assume().withMessage("Skip where VMs aren't support")
                    .that(HypervisorProperties.hypervisor_vm_supported().orElse(false))
                    .isTrue();
        }
        Context context = ApplicationProvider.getApplicationContext();
        mInner = new Inner(context, protectedVm, VirtualMachineManager.getInstance(context));
    }

    protected abstract static class VmEventListener implements VirtualMachineCallback {
        private ExecutorService mExecutorService = Executors.newSingleThreadExecutor();

        void runToFinish(String logTag, VirtualMachine vm)
                throws VirtualMachineException, InterruptedException {
            vm.setCallback(mExecutorService, this);
            vm.run();
            logVmOutput(logTag, vm.getConsoleOutputStream(), "Console");
            logVmOutput(logTag, vm.getLogOutputStream(), "Log");
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

        @Override
        public void onRamdump(VirtualMachine vm, ParcelFileDescriptor ramdump) {}
    }

    public static class BootResult {
        public final boolean payloadStarted;
        public final int deathReason;
        public final long elapsedNanoTime;

        BootResult(boolean payloadStarted, int deathReason, long elapsedNanoTime) {
            this.payloadStarted = payloadStarted;
            this.deathReason = deathReason;
            this.elapsedNanoTime = elapsedNanoTime;
        }
    }

    public BootResult tryBootVm(String logTag, String vmName)
            throws VirtualMachineException, InterruptedException {
        VirtualMachine vm = mInner.getVirtualMachineManager().get(vmName);
        final CompletableFuture<Boolean> payloadStarted = new CompletableFuture<>();
        final CompletableFuture<Integer> deathReason = new CompletableFuture<>();
        final CompletableFuture<Long> endTime = new CompletableFuture<>();
        VmEventListener listener =
                new VmEventListener() {
                    @Override
                    public void onPayloadStarted(VirtualMachine vm, ParcelFileDescriptor stream) {
                        endTime.complete(System.nanoTime());
                        payloadStarted.complete(true);
                        forceStop(vm);
                    }

                    @Override
                    public void onDied(VirtualMachine vm, int reason) {
                        deathReason.complete(reason);
                        super.onDied(vm, reason);
                    }
                };
        long beginTime = System.nanoTime();
        listener.runToFinish(logTag, vm);
        return new BootResult(
                payloadStarted.getNow(false),
                deathReason.getNow(DeathReason.INFRASTRUCTURE_ERROR),
                endTime.getNow(beginTime) - beginTime);
    }
}
