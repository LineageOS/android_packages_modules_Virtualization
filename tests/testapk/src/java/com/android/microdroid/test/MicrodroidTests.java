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

import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;

import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.os.SystemProperties;
import android.system.virtualmachine.VirtualMachine;
import android.system.virtualmachine.VirtualMachineCallback;
import android.system.virtualmachine.VirtualMachineConfig;
import android.system.virtualmachine.VirtualMachineConfig.DebugLevel;
import android.system.virtualmachine.VirtualMachineException;
import android.util.Log;

import com.android.compatibility.common.util.CddTest;
import com.android.microdroid.test.device.MicrodroidDeviceTestBase;
import com.android.microdroid.testservice.ITestService;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.Timeout;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.util.List;
import java.util.OptionalLong;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.MajorType;

@RunWith(Parameterized.class)
public class MicrodroidTests extends MicrodroidDeviceTestBase {
    private static final String TAG = "MicrodroidTests";

    @Rule public Timeout globalTimeout = Timeout.seconds(300);

    private static final String KERNEL_VERSION = SystemProperties.get("ro.kernel.version");

    @Parameterized.Parameters(name = "protectedVm={0}")
    public static Object[] protectedVmConfigs() {
        return new Object[] { false, true };
    }

    @Parameterized.Parameter public boolean mProtectedVm;

    @Before
    public void setup() {
        prepareTestSetup(mProtectedVm);
    }

    private static final int MIN_MEM_ARM64 = 150;
    private static final int MIN_MEM_X86_64 = 196;

    @Test
    @CddTest(requirements = {
            "9.17/C-1-1",
            "9.17/C-2-1"
    })
    public void connectToVmService() throws VirtualMachineException, InterruptedException {
        assume()
            .withMessage("SKip on 5.4 kernel. b/218303240")
            .that(KERNEL_VERSION)
            .isNotEqualTo("5.4");

        VirtualMachineConfig.Builder builder =
                mInner.newVmConfigBuilder("assets/vm_config_extra_apk.json");
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
        VirtualMachine vm = mInner.forceCreateNewVirtualMachine("test_vm_extra_apk", config);

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
                        Log.i(TAG, "onPayloadReady");
                        payloadReady.complete(true);
                        testVMService(vm);
                        forceStop(vm);
                    }

                    @Override
                    public void onPayloadStarted(VirtualMachine vm, ParcelFileDescriptor stream) {
                        Log.i(TAG, "onPayloadStarted");
                        payloadStarted.complete(true);
                        logVmOutput(TAG, new FileInputStream(stream.getFileDescriptor()),
                                "Payload");
                    }
                };
        listener.runToFinish(TAG, vm);
        assertThat(payloadStarted.getNow(false)).isTrue();
        assertThat(payloadReady.getNow(false)).isTrue();
        assertThat(testResults.mException).isNull();
        assertThat(testResults.mAddInteger).isEqualTo(123 + 456);
        assertThat(testResults.mAppRunProp).isEqualTo("true");
        assertThat(testResults.mSublibRunProp).isEqualTo("true");
        assertThat(testResults.mExtraApkTestProp).isEqualTo("PASS");
    }

    @Test
    public void bootFailsWhenLowMem() throws VirtualMachineException, InterruptedException {
        for (int memMib : new int[]{ 10, 20, 40 }) {
            VirtualMachineConfig lowMemConfig = mInner.newVmConfigBuilder("assets/vm_config.json")
                    .memoryMib(memMib)
                    .debugLevel(DebugLevel.NONE)
                    .build();
            VirtualMachine vm = mInner.forceCreateNewVirtualMachine("low_mem", lowMemConfig);
            final CompletableFuture<Integer> exception = new CompletableFuture<>();
            VmEventListener listener =
                    new VmEventListener() {
                        @Override
                        public void onDied(VirtualMachine vm,  int reason) {
                            exception.complete(reason);
                            super.onDied(vm, reason);
                        }
                    };
            listener.runToFinish(TAG, vm);
            assertThat(exception.getNow(0)).isAnyOf(VirtualMachineCallback.DEATH_REASON_REBOOT,
                    VirtualMachineCallback.DEATH_REASON_HANGUP,
                    VirtualMachineCallback.DEATH_REASON_CRASH);
        }
    }

    @Test
    @CddTest(requirements = {
            "9.17/C-1-1",
            "9.17/C-2-7"
    })
    public void changingDebugLevelInvalidatesVmIdentity()
            throws VirtualMachineException, InterruptedException, IOException {
        assume()
            .withMessage("SKip on 5.4 kernel. b/218303240")
            .that(KERNEL_VERSION)
            .isNotEqualTo("5.4");

        VirtualMachineConfig.Builder builder = mInner.newVmConfigBuilder("assets/vm_config.json");
        VirtualMachineConfig normalConfig = builder.debugLevel(DebugLevel.NONE).build();
        VirtualMachine vm = mInner.forceCreateNewVirtualMachine("test_vm", normalConfig);
        VmEventListener listener =
                new VmEventListener() {
                    @Override
                    public void onPayloadReady(VirtualMachine vm) {
                        forceStop(vm);
                    }
                };
        listener.runToFinish(TAG, vm);

        // Launch the same VM with different debug level. The Java API prohibits this (thankfully).
        // For testing, we do that by creating another VM with debug level, and copy the config file
        // from the new VM directory to the old VM directory.
        VirtualMachineConfig debugConfig = builder.debugLevel(DebugLevel.FULL).build();
        VirtualMachine newVm = mInner.forceCreateNewVirtualMachine("test_debug_vm", debugConfig);
        File vmRoot = new File(getContext().getFilesDir(), "vm");
        File newVmConfig = new File(new File(vmRoot, "test_debug_vm"), "config.xml");
        File oldVmConfig = new File(new File(vmRoot, "test_vm"), "config.xml");
        Files.copy(newVmConfig.toPath(), oldVmConfig.toPath(), REPLACE_EXISTING);
        newVm.delete();
        // re-load with the copied-in config file.
        vm = mInner.getVirtualMachineManager().get("test_vm");
        final CompletableFuture<Boolean> payloadStarted = new CompletableFuture<>();
        listener =
                new VmEventListener() {
                    @Override
                    public void onPayloadStarted(VirtualMachine vm, ParcelFileDescriptor stream) {
                        payloadStarted.complete(true);
                        forceStop(vm);
                    }
                };
        listener.runToFinish(TAG, vm);
        assertThat(payloadStarted.getNow(false)).isFalse();
    }

    private class VmCdis {
        public byte[] cdiAttest;
        public byte[] cdiSeal;
    }

    private VmCdis launchVmAndGetCdis(String instanceName)
            throws VirtualMachineException, InterruptedException {
        VirtualMachine vm = mInner.getVirtualMachineManager().get(instanceName);
        final VmCdis vmCdis = new VmCdis();
        final CompletableFuture<Exception> exception = new CompletableFuture<>();
        VmEventListener listener =
                new VmEventListener() {
                    @Override
                    public void onPayloadReady(VirtualMachine vm) {
                        try {
                            ITestService testService = ITestService.Stub.asInterface(
                                    vm.connectToVsockServer(ITestService.SERVICE_PORT).get());
                            vmCdis.cdiAttest = testService.insecurelyExposeAttestationCdi();
                            vmCdis.cdiSeal = testService.insecurelyExposeSealingCdi();
                            forceStop(vm);
                        } catch (Exception e) {
                            exception.complete(e);
                        }
                    }
                };
        listener.runToFinish(TAG, vm);
        assertThat(exception.getNow(null)).isNull();
        return vmCdis;
    }

    @Test
    @CddTest(requirements = {
            "9.17/C-1-1",
            "9.17/C-2-7"
    })
    public void instancesOfSameVmHaveDifferentCdis()
            throws VirtualMachineException, InterruptedException {
        assume()
            .withMessage("SKip on 5.4 kernel. b/218303240")
            .that(KERNEL_VERSION)
            .isNotEqualTo("5.4");

        VirtualMachineConfig normalConfig = mInner.newVmConfigBuilder("assets/vm_config.json")
                .debugLevel(DebugLevel.FULL)
                .build();
        mInner.forceCreateNewVirtualMachine("test_vm_a", normalConfig);
        mInner.forceCreateNewVirtualMachine("test_vm_b", normalConfig);
        VmCdis vm_a_cdis = launchVmAndGetCdis("test_vm_a");
        VmCdis vm_b_cdis = launchVmAndGetCdis("test_vm_b");
        assertThat(vm_a_cdis.cdiAttest).isNotNull();
        assertThat(vm_b_cdis.cdiAttest).isNotNull();
        assertThat(vm_a_cdis.cdiAttest).isNotEqualTo(vm_b_cdis.cdiAttest);
        assertThat(vm_a_cdis.cdiSeal).isNotNull();
        assertThat(vm_b_cdis.cdiSeal).isNotNull();
        assertThat(vm_a_cdis.cdiSeal).isNotEqualTo(vm_b_cdis.cdiSeal);
        assertThat(vm_a_cdis.cdiAttest).isNotEqualTo(vm_b_cdis.cdiSeal);
    }

    @Test
    @CddTest(requirements = {
            "9.17/C-1-1",
            "9.17/C-2-7"
    })
    public void sameInstanceKeepsSameCdis()
            throws VirtualMachineException, InterruptedException {
        assume()
            .withMessage("SKip on 5.4 kernel. b/218303240")
            .that(KERNEL_VERSION)
            .isNotEqualTo("5.4");

        VirtualMachineConfig normalConfig = mInner.newVmConfigBuilder("assets/vm_config.json")
                .debugLevel(DebugLevel.FULL)
                .build();
        mInner.forceCreateNewVirtualMachine("test_vm", normalConfig);

        VmCdis first_boot_cdis = launchVmAndGetCdis("test_vm");
        VmCdis second_boot_cdis = launchVmAndGetCdis("test_vm");
        // The attestation CDI isn't specified to be stable, though it might be
        assertThat(first_boot_cdis.cdiSeal).isNotNull();
        assertThat(second_boot_cdis.cdiSeal).isNotNull();
        assertThat(first_boot_cdis.cdiSeal).isEqualTo(second_boot_cdis.cdiSeal);
    }

    @Test
    @CddTest(requirements = {
            "9.17/C-1-1",
            "9.17/C-2-7"
    })
    public void bccIsSuperficiallyWellFormed()
            throws VirtualMachineException, InterruptedException, CborException {
        assume()
            .withMessage("SKip on 5.4 kernel. b/218303240")
            .that(KERNEL_VERSION)
            .isNotEqualTo("5.4");

        VirtualMachineConfig normalConfig = mInner.newVmConfigBuilder("assets/vm_config.json")
                .debugLevel(DebugLevel.FULL)
                .build();
        VirtualMachine vm = mInner.forceCreateNewVirtualMachine("bcc_vm", normalConfig);
        final VmCdis vmCdis = new VmCdis();
        final CompletableFuture<byte[]> bcc = new CompletableFuture<>();
        final CompletableFuture<Exception> exception = new CompletableFuture<>();
        VmEventListener listener =
                new VmEventListener() {
                    @Override
                    public void onPayloadReady(VirtualMachine vm) {
                        try {
                            ITestService testService = ITestService.Stub.asInterface(
                                    vm.connectToVsockServer(ITestService.SERVICE_PORT).get());
                            bcc.complete(testService.getBcc());
                            forceStop(vm);
                        } catch (Exception e) {
                            exception.complete(e);
                        }
                    }
                };
        listener.runToFinish(TAG, vm);
        byte[] bccBytes = bcc.getNow(null);
        assertThat(exception.getNow(null)).isNull();
        assertThat(bccBytes).isNotNull();

        ByteArrayInputStream bais = new ByteArrayInputStream(bccBytes);
        List<DataItem> dataItems = new CborDecoder(bais).decode();
        assertThat(dataItems.size()).isEqualTo(1);
        assertThat(dataItems.get(0).getMajorType()).isEqualTo(MajorType.ARRAY);
        List<DataItem> rootArrayItems = ((Array) dataItems.get(0)).getDataItems();
        assertThat(rootArrayItems.size()).isAtLeast(2); // Public key and one certificate
        if (mProtectedVm) {
            // When a true DICE chain is created, microdroid expects entries for: u-boot,
            // u-boot-env, microdroid, app payload and the service process.
            assertThat(rootArrayItems.size()).isAtLeast(5);
        }
    }

    private static final UUID MICRODROID_PARTITION_UUID =
            UUID.fromString("cf9afe9a-0662-11ec-a329-c32663a09d75");
    private static final UUID U_BOOT_AVB_PARTITION_UUID =
            UUID.fromString("7e8221e7-03e6-4969-948b-73a4c809a4f2");
    private static final UUID U_BOOT_ENV_PARTITION_UUID =
            UUID.fromString("0ab72d30-86ae-4d05-81b2-c1760be2b1f9");
    private static final UUID PVM_FW_PARTITION_UUID =
            UUID.fromString("90d2174a-038a-4bc6-adf3-824848fc5825");
    private static final long BLOCK_SIZE = 512;

    // Find the starting offset which holds the data of a partition having UUID.
    // This is a kind of hack; rather than parsing QCOW2 we exploit the fact that the cluster size
    // is normally greater than 512. It implies that the partition data should exist at a block
    // which follows the header block
    private OptionalLong findPartitionDataOffset(RandomAccessFile file, UUID uuid)
            throws IOException {
        // For each 512-byte block in file, check header
        long fileSize = file.length();

        for (long idx = 0; idx + BLOCK_SIZE < fileSize; idx += BLOCK_SIZE) {
            file.seek(idx);
            long high = file.readLong();
            long low = file.readLong();
            if (uuid.equals(new UUID(high, low))) return OptionalLong.of(idx + BLOCK_SIZE);
        }
        return OptionalLong.empty();
    }

    private void flipBit(RandomAccessFile file, long offset) throws IOException {
        file.seek(offset);
        int b = file.readByte();
        file.seek(offset);
        file.writeByte(b ^ 1);
    }

    private RandomAccessFile prepareInstanceImage(String vmName)
            throws VirtualMachineException, InterruptedException, IOException {
        VirtualMachineConfig config = mInner.newVmConfigBuilder("assets/vm_config.json")
                .debugLevel(DebugLevel.FULL)
                .build();

        mInner.forceCreateNewVirtualMachine(vmName, config);
        assertThat(tryBootVm(TAG, vmName).payloadStarted).isTrue();

        File vmRoot = new File(getContext().getFilesDir(), "vm");
        File vmDir = new File(vmRoot, vmName);
        File instanceImgPath = new File(vmDir, "instance.img");
        return new RandomAccessFile(instanceImgPath, "rw");
    }

    private void assertThatPartitionIsMissing(UUID partitionUuid)
            throws VirtualMachineException, InterruptedException, IOException {
        RandomAccessFile instanceFile = prepareInstanceImage("test_vm_integrity");
        assertThat(findPartitionDataOffset(instanceFile, partitionUuid).isPresent())
                .isFalse();
    }

    // Flips a bit of given partition, and then see if boot fails.
    private void assertThatBootFailsAfterCompromisingPartition(UUID partitionUuid)
            throws VirtualMachineException, InterruptedException, IOException {
        RandomAccessFile instanceFile = prepareInstanceImage("test_vm_integrity");
        OptionalLong offset = findPartitionDataOffset(instanceFile, partitionUuid);
        assertThat(offset.isPresent()).isTrue();

        flipBit(instanceFile, offset.getAsLong());

        BootResult result = tryBootVm(TAG, "test_vm_integrity");
        assertThat(result.payloadStarted).isFalse();

        // This failure should shut the VM down immediately and shouldn't trigger a hangup.
        assertThat(result.deathReason).isNotEqualTo(VirtualMachineCallback.DEATH_REASON_HANGUP);
    }

    @Test
    @CddTest(requirements = {
            "9.17/C-1-1",
            "9.17/C-2-7"
    })
    public void bootFailsWhenMicrodroidDataIsCompromised()
            throws VirtualMachineException, InterruptedException, IOException {
        assertThatBootFailsAfterCompromisingPartition(MICRODROID_PARTITION_UUID);
    }

    @Test
    @CddTest(requirements = {
            "9.17/C-1-1",
            "9.17/C-2-7"
    })
    public void bootFailsWhenUBootAvbDataIsCompromised()
            throws VirtualMachineException, InterruptedException, IOException {
        if (mProtectedVm) {
            assertThatBootFailsAfterCompromisingPartition(U_BOOT_AVB_PARTITION_UUID);
        } else {
            // non-protected VM shouldn't have u-boot avb data
            assertThatPartitionIsMissing(U_BOOT_AVB_PARTITION_UUID);
        }
    }

    @Test
    @CddTest(requirements = {
            "9.17/C-1-1",
            "9.17/C-2-7"
    })
    public void bootFailsWhenUBootEnvDataIsCompromised()
            throws VirtualMachineException, InterruptedException, IOException {
        if (mProtectedVm) {
            assertThatBootFailsAfterCompromisingPartition(U_BOOT_ENV_PARTITION_UUID);
        } else {
            // non-protected VM shouldn't have u-boot env data
            assertThatPartitionIsMissing(U_BOOT_ENV_PARTITION_UUID);
        }
    }

    @Test
    @CddTest(requirements = {
            "9.17/C-1-1",
            "9.17/C-2-7"
    })
    public void bootFailsWhenPvmFwDataIsCompromised()
            throws VirtualMachineException, InterruptedException, IOException {
        if (mProtectedVm) {
            assertThatBootFailsAfterCompromisingPartition(PVM_FW_PARTITION_UUID);
        } else {
            // non-protected VM shouldn't have pvmfw data
            assertThatPartitionIsMissing(PVM_FW_PARTITION_UUID);
        }
    }

    @Test
    public void bootFailsWhenConfigIsInvalid()
            throws VirtualMachineException, InterruptedException, IOException {
        VirtualMachineConfig.Builder builder =
                mInner.newVmConfigBuilder("assets/vm_config_no_task.json");
        VirtualMachineConfig normalConfig = builder.debugLevel(DebugLevel.FULL).build();
        mInner.forceCreateNewVirtualMachine("test_vm_invalid_config", normalConfig);

        BootResult bootResult = tryBootVm(TAG, "test_vm_invalid_config");
        assertThat(bootResult.payloadStarted).isFalse();
        assertThat(bootResult.deathReason).isEqualTo(
                VirtualMachineCallback.DEATH_REASON_MICRODROID_INVALID_PAYLOAD_CONFIG);
    }
}
