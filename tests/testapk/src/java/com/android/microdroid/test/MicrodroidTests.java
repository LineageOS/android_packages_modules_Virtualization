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
package com.android.microdroid.test;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.TruthJUnit.assume;

import static org.junit.Assume.assumeNoException;

import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;

import android.content.Context;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.os.SystemProperties;
import android.sysprop.HypervisorProperties;
import android.system.virtualmachine.VirtualMachine;
import android.system.virtualmachine.VirtualMachineCallback;
import android.system.virtualmachine.VirtualMachineConfig;
import android.system.virtualmachine.VirtualMachineConfig.DebugLevel;
import android.system.virtualmachine.VirtualMachineException;
import android.system.virtualmachine.VirtualMachineManager;

import androidx.annotation.CallSuper;
import androidx.test.core.app.ApplicationProvider;

import com.android.microdroid.testservice.ITestService;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.Timeout;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

@RunWith(Parameterized.class)
public class MicrodroidTests {
    @Rule public Timeout globalTimeout = Timeout.seconds(300);

    private static final String KERNEL_VERSION = SystemProperties.get("ro.kernel.version");

    private static class Inner {
        public Context mContext;
        public VirtualMachineManager mVmm;
        public VirtualMachine mVm;
    }

    @Parameterized.Parameters(name = "protectedVm={0}")
    public static Object[] protectedVmConfigs() {
        return new Object[] { false, true };
    }

    @Parameterized.Parameter
    public boolean mProtectedVm;

    private boolean mPkvmSupported = false;
    private Inner mInner;

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
            assume()
                .withMessage("Skip where protected VMs aren't support")
                .that(HypervisorProperties.hypervisor_protected_vm_supported().orElse(false))
                .isTrue();
        } else {
            assume()
                .withMessage("Skip where VMs aren't support")
                .that(HypervisorProperties.hypervisor_vm_supported().orElse(false))
                .isTrue();
        }
        mInner = new Inner();
        mInner.mContext = ApplicationProvider.getApplicationContext();
        mInner.mVmm = VirtualMachineManager.getInstance(mInner.mContext);
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
            mExecutorService.awaitTermination(300, TimeUnit.SECONDS);
        }

        void forceStop(VirtualMachine vm) {
            this.onDied(vm, VirtualMachineCallback.DEATH_REASON_KILLED);
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
            try {
                vm.stop();
                mExecutorService.shutdown();
            } catch (VirtualMachineException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private static final int MIN_MEM_ARM64 = 145;
    private static final int MIN_MEM_X86_64 = 196;

    @Test
    public void connectToVmService() throws VirtualMachineException, InterruptedException {
        assume()
            .withMessage("SKip on 5.4 kernel. b/218303240")
            .that(KERNEL_VERSION)
            .isNotEqualTo("5.4");

        VirtualMachineConfig.Builder builder =
                new VirtualMachineConfig.Builder(mInner.mContext, "assets/vm_config_extra_apk.json")
                        .protectedVm(mProtectedVm);
        if (Build.SUPPORTED_ABIS.length > 0) {
            String primaryAbi = Build.SUPPORTED_ABIS[0];
            switch(primaryAbi) {
                case "x86_64":
                    builder.memoryMib(MIN_MEM_X86_64);
                    break;
                case "arm64-v8a":
                    builder.memoryMib(MIN_MEM_ARM64);
                    break;
            }
        }
        VirtualMachineConfig config = builder.build();

        mInner.mVm = mInner.mVmm.getOrCreate("test_vm_extra_apk", config);

        class TestResults {
            Exception mException;
            Integer mAddInteger;
            String mAppRunProp;
            String mSublibRunProp;
            String mExtraApkTestProp;
        }
        final CompletableFuture<Boolean> payloadStarted = new CompletableFuture<>();
        final CompletableFuture<Boolean> payloadReady = new CompletableFuture<>();
        final TestResults testResults = new TestResults();
        VmEventListener listener =
                new VmEventListener() {
                    private void testVMService(VirtualMachine vm) {
                        try {
                            ITestService testService = ITestService.Stub.asInterface(
                                    vm.connectToVsockServer(ITestService.SERVICE_PORT).get());
                            testResults.mAddInteger = testService.addInteger(123, 456);
                            testResults.mAppRunProp =
                                    testService.readProperty("debug.microdroid.app.run");
                            testResults.mSublibRunProp =
                                    testService.readProperty("debug.microdroid.app.sublib.run");
                            testResults.mExtraApkTestProp =
                                    testService.readProperty("debug.microdroid.test.extra_apk");
                        } catch (Exception e) {
                            testResults.mException = e;
                        }
                    }

                    @Override
                    public void onPayloadReady(VirtualMachine vm) {
                        payloadReady.complete(true);
                        testVMService(vm);
                        forceStop(vm);
                    }

                    @Override
                    public void onPayloadStarted(VirtualMachine vm, ParcelFileDescriptor stream) {
                        payloadStarted.complete(true);
                    }
                };
        listener.runToFinish(mInner.mVm);
        assertThat(payloadStarted.getNow(false)).isTrue();
        assertThat(payloadReady.getNow(false)).isTrue();
        assertThat(testResults.mException).isNull();
        assertThat(testResults.mAddInteger).isEqualTo(123 + 456);
        assertThat(testResults.mAppRunProp).isEqualTo("true");
        assertThat(testResults.mSublibRunProp).isEqualTo("true");
        assertThat(testResults.mExtraApkTestProp).isEqualTo("PASS");
    }

    @Test
    public void changingDebugLevelInvalidatesVmIdentity()
            throws VirtualMachineException, InterruptedException, IOException {
        assume()
            .withMessage("Skip on Cuttlefish. b/195765441")
            .that(android.os.Build.DEVICE)
            .isNotEqualTo("vsoc_x86_64");

        assume()
            .withMessage("SKip on 5.4 kernel. b/218303240")
            .that(KERNEL_VERSION)
            .isNotEqualTo("5.4");

        VirtualMachineConfig.Builder builder =
                new VirtualMachineConfig.Builder(mInner.mContext, "assets/vm_config.json")
                        .protectedVm(mProtectedVm);
        VirtualMachineConfig normalConfig = builder.debugLevel(DebugLevel.NONE).build();
        mInner.mVm = mInner.mVmm.getOrCreate("test_vm", normalConfig);
        VmEventListener listener =
                new VmEventListener() {
                    @Override
                    public void onPayloadReady(VirtualMachine vm) {
                        forceStop(vm);
                    }
                };
        listener.runToFinish(mInner.mVm);

        // Launch the same VM with different debug level. The Java API prohibits this (thankfully).
        // For testing, we do that by creating another VM with debug level, and copy the config file
        // from the new VM directory to the old VM directory.
        VirtualMachineConfig debugConfig = builder.debugLevel(DebugLevel.FULL).build();
        VirtualMachine newVm  = mInner.mVmm.getOrCreate("test_debug_vm", debugConfig);
        File vmRoot = new File(mInner.mContext.getFilesDir(), "vm");
        File newVmConfig = new File(new File(vmRoot, "test_debug_vm"), "config.xml");
        File oldVmConfig = new File(new File(vmRoot, "test_vm"), "config.xml");
        Files.copy(newVmConfig.toPath(), oldVmConfig.toPath(), REPLACE_EXISTING);
        newVm.delete();
        mInner.mVm = mInner.mVmm.get("test_vm"); // re-load with the copied-in config file.
        final CompletableFuture<Boolean> payloadStarted = new CompletableFuture<>();
        listener =
                new VmEventListener() {
                    @Override
                    public void onPayloadStarted(VirtualMachine vm, ParcelFileDescriptor stream) {
                        payloadStarted.complete(true);
                        forceStop(vm);
                    }
                };
        listener.runToFinish(mInner.mVm);
        assertThat(payloadStarted.getNow(false)).isFalse();
    }

    private byte[] launchVmAndGetSecret(String instanceName)
            throws VirtualMachineException, InterruptedException {
        VirtualMachineConfig.Builder builder =
                new VirtualMachineConfig.Builder(mInner.mContext, "assets/vm_config.json")
                        .protectedVm(mProtectedVm);
        VirtualMachineConfig normalConfig = builder.debugLevel(DebugLevel.NONE).build();
        mInner.mVm = mInner.mVmm.getOrCreate(instanceName, normalConfig);
        final CompletableFuture<byte[]> secret = new CompletableFuture<>();
        final CompletableFuture<Exception> exception = new CompletableFuture<>();
        VmEventListener listener =
                new VmEventListener() {
                    @Override
                    public void onPayloadReady(VirtualMachine vm) {
                        try {
                            ITestService testService = ITestService.Stub.asInterface(
                                    vm.connectToVsockServer(ITestService.SERVICE_PORT).get());
                            secret.complete(testService.insecurelyExposeSecret());
                            forceStop(vm);
                        } catch (Exception e) {
                            exception.complete(e);
                        }
                    }
                };
        listener.runToFinish(mInner.mVm);
        assertThat(exception.getNow(null)).isNull();
        return secret.getNow(null);
    }

    @Test
    public void instancesOfSameVmHaveDifferentSecrets()
            throws VirtualMachineException, InterruptedException {
        assume()
            .withMessage("Skip on Cuttlefish. b/195765441")
            .that(android.os.Build.DEVICE)
            .isNotEqualTo("vsoc_x86_64");

        assume()
            .withMessage("SKip on 5.4 kernel. b/218303240")
            .that(KERNEL_VERSION)
            .isNotEqualTo("5.4");

        byte[] vm_a_secret = launchVmAndGetSecret("test_vm_a");
        byte[] vm_b_secret = launchVmAndGetSecret("test_vm_b");
        assertThat(vm_a_secret).isNotNull();
        assertThat(vm_b_secret).isNotNull();
        assertThat(vm_a_secret).isNotEqualTo(vm_b_secret);
    }

    @Test
    public void sameInstanceKeepsSameSecrets()
            throws VirtualMachineException, InterruptedException {
        assume()
            .withMessage("Skip on Cuttlefish. b/195765441")
            .that(android.os.Build.DEVICE)
            .isNotEqualTo("vsoc_x86_64");

        assume()
            .withMessage("SKip on 5.4 kernel. b/218303240")
            .that(KERNEL_VERSION)
            .isNotEqualTo("5.4");

        byte[] vm_secret_first_boot = launchVmAndGetSecret("test_vm");
        byte[] vm_secret_second_boot = launchVmAndGetSecret("test_vm");
        assertThat(vm_secret_first_boot).isNotNull();
        assertThat(vm_secret_second_boot).isNotNull();
        assertThat(vm_secret_first_boot).isEqualTo(vm_secret_second_boot);
    }

    @Test
    public void bootFailsWhenInstanceDiskIsCompromised()
            throws VirtualMachineException, InterruptedException, IOException {
        assume().withMessage("Skip on Cuttlefish. b/195765441")
                .that(android.os.Build.DEVICE)
                .isNotEqualTo("vsoc_x86_64");

        VirtualMachineConfig config =
                new VirtualMachineConfig.Builder(mInner.mContext, "assets/vm_config.json")
                        .protectedVm(mProtectedVm)
                        .debugLevel(DebugLevel.NONE)
                        .build();

        // Remove any existing VM so we can start from scratch
        VirtualMachine oldVm = mInner.mVmm.getOrCreate("test_vm_integrity", config);
        oldVm.delete();

        mInner.mVm = mInner.mVmm.getOrCreate("test_vm_integrity", config);

        final CompletableFuture<Boolean> payloadReady = new CompletableFuture<>();
        VmEventListener listener =
                new VmEventListener() {
                    @Override
                    public void onPayloadReady(VirtualMachine vm) {
                        payloadReady.complete(true);
                        forceStop(vm);
                    }
                };
        listener.runToFinish(mInner.mVm);
        assertThat(payloadReady.getNow(false)).isTrue();

        // Launch the same VM after flipping a bit of the instance image.
        // Flip actual data, as flipping trivial bits like the magic string isn't interesting.
        File vmRoot = new File(mInner.mContext.getFilesDir(), "vm");
        File vmDir = new File(vmRoot, "test_vm_integrity");
        File instanceImgPath = new File(vmDir, "instance.img");
        RandomAccessFile instanceFile = new RandomAccessFile(instanceImgPath, "rw");

        // microdroid data partition starts at 0x60200, actual data at 0x60400, based on experiment
        // TODO: parse image file (QEMU qcow2) correctly?
        long headerOffset = 0x60400;
        instanceFile.seek(headerOffset);
        int b = instanceFile.readByte();
        instanceFile.seek(headerOffset);
        instanceFile.writeByte(b ^ 1);
        instanceFile.close();

        mInner.mVm = mInner.mVmm.get("test_vm_integrity"); // re-load the vm with new instance disk
        final CompletableFuture<Boolean> payloadStarted = new CompletableFuture<>();
        listener =
                new VmEventListener() {
                    @Override
                    public void onPayloadStarted(VirtualMachine vm, ParcelFileDescriptor stream) {
                        payloadStarted.complete(true);
                        forceStop(vm);
                    }
                };
        listener.runToFinish(mInner.mVm);
        assertThat(payloadStarted.getNow(false)).isFalse();
    }
}
