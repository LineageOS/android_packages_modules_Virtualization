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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeNoException;

import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;

import android.content.Context;
import android.os.Build;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.system.virtualmachine.VirtualMachine;
import android.system.virtualmachine.VirtualMachineCallback;
import android.system.virtualmachine.VirtualMachineConfig;
import android.system.virtualmachine.VirtualMachineConfig.DebugLevel;
import android.system.virtualmachine.VirtualMachineException;
import android.system.virtualmachine.VirtualMachineManager;

import androidx.test.core.app.ApplicationProvider;

import com.android.microdroid.testservice.ITestService;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.Timeout;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

@RunWith(JUnit4.class)
public class MicrodroidTests {
    @Rule public Timeout globalTimeout = Timeout.seconds(300);

    private static class Inner {
        public Context mContext;
        public VirtualMachineManager mVmm;
        public VirtualMachine mVm;
    }

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
        mInner = new Inner();
        mInner.mContext = ApplicationProvider.getApplicationContext();
        mInner.mVmm = VirtualMachineManager.getInstance(mInner.mContext);
    }

    @After
    public void cleanup() throws VirtualMachineException {
        if (!mPkvmSupported) {
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
            try {
                vm.stop();
                this.onDied(vm, VirtualMachineCallback.DEATH_REASON_KILLED);
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
        public void onDied(VirtualMachine vm, @DeathReason int reason) {}
    }

    private static final int MIN_MEM_ARM64 = 135;
    private static final int MIN_MEM_X86_64 = 196;

    @Test
    public void connectToVmService() throws VirtualMachineException, InterruptedException {
        VirtualMachineConfig.Builder builder =
                new VirtualMachineConfig.Builder(mInner.mContext,
                        "assets/vm_config_extra_apk.json");
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
        VmEventListener listener =
                new VmEventListener() {
                    private boolean mPayloadReadyCalled = false;
                    private boolean mPayloadStartedCalled = false;

                    private void testVMService(Future<IBinder> service) {
                        try {
                            IBinder binder = service.get();

                            ITestService testService = ITestService.Stub.asInterface(binder);
                            assertEquals(
                                    testService.addInteger(123, 456),
                                    123 + 456);
                            assertEquals(
                                    testService.readProperty("debug.microdroid.app.run"),
                                    "true");
                            assertEquals(
                                    testService.readProperty("debug.microdroid.app.sublib.run"),
                                    "true");
                            assertEquals(
                                    testService.readProperty("debug.microdroid.test.extra_apk"),
                                    "PASS");
                        } catch (Exception e) {
                            fail("Exception while testing service: " + e.toString());
                        }
                    }

                    @Override
                    public void onPayloadReady(VirtualMachine vm) {
                        mPayloadReadyCalled = true;
                        try {
                            testVMService(vm.connectToVsockServer(ITestService.SERVICE_PORT));
                        } catch (Exception e) {
                            fail("Exception while connecting to service: " + e.toString());
                        }

                        forceStop(vm);
                    }

                    @Override
                    public void onPayloadStarted(VirtualMachine vm, ParcelFileDescriptor stream) {
                        mPayloadStartedCalled = true;
                    }

                    @Override
                    public void onDied(VirtualMachine vm, @DeathReason int reason) {
                        assertTrue(mPayloadReadyCalled);
                        assertTrue(mPayloadStartedCalled);
                    }
                };
        listener.runToFinish(mInner.mVm);
    }

    @Test
    public void changingDebugLevelInvalidatesVmIdentity()
            throws VirtualMachineException, InterruptedException, IOException {
        assume()
            .withMessage("Skip on Cuttlefish. b/195765441")
            .that(android.os.Build.DEVICE)
            .isNotEqualTo("vsoc_x86_64");

        VirtualMachineConfig.Builder builder =
                new VirtualMachineConfig.Builder(mInner.mContext, "assets/vm_config.json");
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
        listener =
                new VmEventListener() {
                    private boolean mPayloadStarted = false;
                    private boolean mErrorOccurred = false;

                    @Override
                    public void onPayloadStarted(VirtualMachine vm, ParcelFileDescriptor stream) {
                        mPayloadStarted = true;
                        forceStop(vm);
                    }

                    @Override
                    public void onError(VirtualMachine vm, int errorCode, String message) {
                        mErrorOccurred = true;
                        forceStop(vm);
                    }

                    @Override
                    public void onDied(VirtualMachine vm, @DeathReason int reason) {
                        assertFalse(mPayloadStarted);
                        assertTrue(mErrorOccurred);
                    }
                };
        listener.runToFinish(mInner.mVm);
    }

    private byte[] launchVmAndGetSecret(String instanceName)
            throws VirtualMachineException, InterruptedException {
        VirtualMachineConfig.Builder builder =
                new VirtualMachineConfig.Builder(mInner.mContext, "assets/vm_config.json");
        VirtualMachineConfig normalConfig = builder.debugLevel(DebugLevel.NONE).build();
        mInner.mVm = mInner.mVmm.getOrCreate(instanceName, normalConfig);
        final CompletableFuture<byte[]> secret = new CompletableFuture<>();
        VmEventListener listener =
                new VmEventListener() {
                    @Override
                    public void onPayloadReady(VirtualMachine vm) {
                        try {
                            ITestService testService = ITestService.Stub.asInterface(
                                    vm.connectToVsockServer(ITestService.SERVICE_PORT).get());
                            secret.complete(testService.insecurelyExposeSecret());
                        } catch (Exception e) {
                            fail("Exception while connecting to service: " + e.toString());
                        }
                        forceStop(vm);
                    }
                };
        listener.runToFinish(mInner.mVm);
        return secret.getNow(null);
    }

    @Test
    public void instancesOfSameVmHaveDifferentSecrets()
            throws VirtualMachineException, InterruptedException {
        assume()
            .withMessage("Skip on Cuttlefish. b/195765441")
            .that(android.os.Build.DEVICE)
            .isNotEqualTo("vsoc_x86_64");

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

        byte[] vm_secret_first_boot = launchVmAndGetSecret("test_vm");
        byte[] vm_secret_second_boot = launchVmAndGetSecret("test_vm");
        assertThat(vm_secret_first_boot).isNotNull();
        assertThat(vm_secret_second_boot).isNotNull();
        assertThat(vm_secret_first_boot).isEqualTo(vm_secret_second_boot);
    }
}
