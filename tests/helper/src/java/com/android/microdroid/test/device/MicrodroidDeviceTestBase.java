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
package com.android.microdroid.test.device;

import static com.google.common.truth.TruthJUnit.assume;

import static org.junit.Assume.assumeNoException;

import android.app.Instrumentation;
import android.app.UiAutomation;
import android.content.Context;
import android.os.ParcelFileDescriptor;
import android.os.SystemProperties;
import android.system.virtualmachine.VirtualMachine;
import android.system.virtualmachine.VirtualMachineCallback;
import android.system.virtualmachine.VirtualMachineConfig;
import android.system.virtualmachine.VirtualMachineException;
import android.system.virtualmachine.VirtualMachineManager;
import android.util.Log;

import androidx.annotation.CallSuper;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.platform.app.InstrumentationRegistry;

import com.android.microdroid.test.common.MetricsProcessor;
import com.android.virt.VirtualizationTestHelper;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.OptionalLong;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public abstract class MicrodroidDeviceTestBase {
    public static boolean isCuttlefish() {
        return VirtualizationTestHelper.isCuttlefish(
                SystemProperties.get("ro.product.vendor.device"));
    }

    public static String getMetricPrefix() {
        return MetricsProcessor.getMetricPrefix(
                SystemProperties.get("debug.hypervisor.metrics_tag"));
    }

    protected final void grantPermission(String permission) {
        Instrumentation instrumentation = InstrumentationRegistry.getInstrumentation();
        UiAutomation uiAutomation = instrumentation.getUiAutomation();
        uiAutomation.grantRuntimePermission(instrumentation.getContext().getPackageName(),
                permission);
    }

    protected final void revokePermission(String permission) {
        Instrumentation instrumentation = InstrumentationRegistry.getInstrumentation();
        UiAutomation uiAutomation = instrumentation.getUiAutomation();
        uiAutomation.revokeRuntimePermission(instrumentation.getContext().getPackageName(),
                permission);
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

        public VirtualMachineConfig.Builder newVmConfigBuilder() {
            return new VirtualMachineConfig.Builder(mContext).setProtectedVm(mProtectedVm);
        }

        /**
         * Creates a new virtual machine, potentially removing an existing virtual machine with
         * given name.
         */
        public VirtualMachine forceCreateNewVirtualMachine(String name, VirtualMachineConfig config)
                throws VirtualMachineException {
            VirtualMachine existingVm = mVmm.get(name);
            if (existingVm != null) {
                mVmm.delete(name);
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
        Context context = ApplicationProvider.getApplicationContext();
        mInner = new Inner(context, protectedVm, VirtualMachineManager.getInstance(context));

        int capabilities = mInner.getVirtualMachineManager().getCapabilities();
        if (protectedVm) {
            assume().withMessage("Skip where protected VMs aren't supported")
                    .that(capabilities & VirtualMachineManager.CAPABILITY_PROTECTED_VM)
                    .isNotEqualTo(0);
        } else {
            assume().withMessage("Skip where VMs aren't supported")
                    .that(capabilities & VirtualMachineManager.CAPABILITY_NON_PROTECTED_VM)
                    .isNotEqualTo(0);
        }
    }

    public abstract static class VmEventListener implements VirtualMachineCallback {
        private ExecutorService mExecutorService = Executors.newSingleThreadExecutor();
        private OptionalLong mVcpuStartedNanoTime = OptionalLong.empty();
        private OptionalLong mKernelStartedNanoTime = OptionalLong.empty();
        private OptionalLong mInitStartedNanoTime = OptionalLong.empty();
        private OptionalLong mPayloadStartedNanoTime = OptionalLong.empty();

        private void processBootEvents(String log) {
            if (!mVcpuStartedNanoTime.isPresent()) {
                mVcpuStartedNanoTime = OptionalLong.of(System.nanoTime());
            }
            if (log.contains("Starting payload...") && !mKernelStartedNanoTime.isPresent()) {
                mKernelStartedNanoTime = OptionalLong.of(System.nanoTime());
            }
            if (log.contains("Run /init as init process") && !mInitStartedNanoTime.isPresent()) {
                mInitStartedNanoTime = OptionalLong.of(System.nanoTime());
            }
            if (log.contains("microdroid_manager") && log.contains("executing main task")
                    && !mPayloadStartedNanoTime.isPresent()) {
                mPayloadStartedNanoTime = OptionalLong.of(System.nanoTime());
            }
        }

        private void logVmOutputAndMonitorBootEvents(String tag,
                InputStream vmOutputStream,
                String name,
                boolean monitorEvents) {
            new Thread(
                    () -> {
                        try {
                            BufferedReader reader =
                                    new BufferedReader(new InputStreamReader(vmOutputStream));
                            String line;
                            while ((line = reader.readLine()) != null
                                    && !Thread.interrupted()) {
                                if (monitorEvents) processBootEvents(line);
                                Log.i(tag, name + ": " + line);
                            }
                        } catch (Exception e) {
                            Log.w(tag, name, e);
                        }
                    }).start();
        }

        private void logVmOutputAndMonitorBootEvents(String tag,
                InputStream vmOutputStream,
                String name) {
            logVmOutputAndMonitorBootEvents(tag, vmOutputStream, name, true);
        }

        /** Copy output from the VM to logcat. This is helpful when things go wrong. */
        protected void logVmOutput(String tag, InputStream vmOutputStream, String name) {
            logVmOutputAndMonitorBootEvents(tag, vmOutputStream, name, false);
        }

        public void runToFinish(String logTag, VirtualMachine vm)
                throws VirtualMachineException, InterruptedException {
            vm.setCallback(mExecutorService, this);
            vm.run();
            logVmOutputAndMonitorBootEvents(logTag, vm.getConsoleOutput(), "Console");
            logVmOutput(logTag, vm.getLogOutput(), "Log");
            mExecutorService.awaitTermination(300, TimeUnit.SECONDS);
        }

        public OptionalLong getVcpuStartedNanoTime() {
            return mVcpuStartedNanoTime;
        }

        public OptionalLong getKernelStartedNanoTime() {
            return mKernelStartedNanoTime;
        }

        public OptionalLong getInitStartedNanoTime() {
            return mInitStartedNanoTime;
        }

        public OptionalLong getPayloadStartedNanoTime() {
            return mPayloadStartedNanoTime;
        }

        protected void forceStop(VirtualMachine vm) {
            try {
                vm.stop();
            } catch (VirtualMachineException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public void onPayloadStarted(VirtualMachine vm) {}

        @Override
        public void onPayloadStdio(VirtualMachine vm, ParcelFileDescriptor stream) {}

        @Override
        public void onPayloadReady(VirtualMachine vm) {}

        @Override
        public void onPayloadFinished(VirtualMachine vm, int exitCode) {}

        @Override
        public void onError(VirtualMachine vm, int errorCode, String message) {}

        @Override
        @CallSuper
        public void onStopped(VirtualMachine vm, int reason) {
            vm.clearCallback();
            mExecutorService.shutdown();
        }

        @Override
        public void onRamdump(VirtualMachine vm, ParcelFileDescriptor ramdump) {}
    }

    public static class BootResult {
        public final boolean payloadStarted;
        public final int deathReason;
        public final long apiCallNanoTime;
        public final long endToEndNanoTime;

        public final OptionalLong vcpuStartedNanoTime;
        public final OptionalLong kernelStartedNanoTime;
        public final OptionalLong initStartedNanoTime;
        public final OptionalLong payloadStartedNanoTime;

        BootResult(boolean payloadStarted,
                int deathReason,
                long apiCallNanoTime,
                long endToEndNanoTime,
                OptionalLong vcpuStartedNanoTime,
                OptionalLong kernelStartedNanoTime,
                OptionalLong initStartedNanoTime,
                OptionalLong payloadStartedNanoTime) {
            this.apiCallNanoTime = apiCallNanoTime;
            this.payloadStarted = payloadStarted;
            this.deathReason = deathReason;
            this.endToEndNanoTime = endToEndNanoTime;
            this.vcpuStartedNanoTime = vcpuStartedNanoTime;
            this.kernelStartedNanoTime = kernelStartedNanoTime;
            this.initStartedNanoTime = initStartedNanoTime;
            this.payloadStartedNanoTime = payloadStartedNanoTime;
        }

        private long getVcpuStartedNanoTime() {
            return vcpuStartedNanoTime.getAsLong();
        }

        private long getKernelStartedNanoTime() {
            // pvmfw emits log at the end which is used to estimate the kernelStart time.
            // In case of no pvmfw run(non-protected mode), use vCPU started time instead.
            return kernelStartedNanoTime.orElse(vcpuStartedNanoTime.getAsLong());
        }

        private long getInitStartedNanoTime() {
            return initStartedNanoTime.getAsLong();
        }

        private long getPayloadStartedNanoTime() {
            return payloadStartedNanoTime.getAsLong();
        }

        public long getVMStartingElapsedNanoTime() {
            return getVcpuStartedNanoTime() - apiCallNanoTime;
        }

        public long getBootloaderElapsedNanoTime() {
            return getKernelStartedNanoTime() - getVcpuStartedNanoTime();
        }

        public long getKernelElapsedNanoTime() {
            return getInitStartedNanoTime() - getKernelStartedNanoTime();
        }

        public long getUserspaceElapsedNanoTime() {
            return getPayloadStartedNanoTime() - getInitStartedNanoTime();
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
                    public void onPayloadStarted(VirtualMachine vm) {
                        endTime.complete(System.nanoTime());
                        payloadStarted.complete(true);
                        forceStop(vm);
                    }

                    @Override
                    public void onStopped(VirtualMachine vm, int reason) {
                        deathReason.complete(reason);
                        super.onStopped(vm, reason);
                    }
                };
        long apiCallNanoTime = System.nanoTime();
        listener.runToFinish(logTag, vm);
        return new BootResult(
                payloadStarted.getNow(false),
                deathReason.getNow(VmEventListener.STOP_REASON_INFRASTRUCTURE_ERROR),
                apiCallNanoTime,
                endTime.getNow(apiCallNanoTime) - apiCallNanoTime,
                listener.getVcpuStartedNanoTime(),
                listener.getKernelStartedNanoTime(),
                listener.getInitStartedNanoTime(),
                listener.getPayloadStartedNanoTime());
    }

    /** Execute a command. Returns stdout. */
    protected String runInShell(String tag, UiAutomation uiAutomation, String command) {
        try (InputStream is =
                        new ParcelFileDescriptor.AutoCloseInputStream(
                                uiAutomation.executeShellCommand(command));
                ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            is.transferTo(out);
            String stdout = out.toString("UTF-8");
            Log.i(tag, "Got stdout : " + stdout);
            return stdout;
        } catch (IOException e) {
            Log.e(tag, "Error executing: " + command, e);
            throw new RuntimeException("Failed to run the command.");
        }
    }
}
