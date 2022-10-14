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

import static android.system.virtualmachine.VirtualMachineConfig.DEBUG_LEVEL_FULL;
import static android.system.virtualmachine.VirtualMachineConfig.DEBUG_LEVEL_NONE;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.TruthJUnit.assume;

import static org.junit.Assert.assertThrows;

import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;

import android.content.Context;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.os.ServiceSpecificException;
import android.os.SystemProperties;
import android.system.virtualmachine.ParcelVirtualMachine;
import android.system.virtualmachine.VirtualMachine;
import android.system.virtualmachine.VirtualMachineCallback;
import android.system.virtualmachine.VirtualMachineConfig;
import android.system.virtualmachine.VirtualMachineException;
import android.system.virtualmachine.VirtualMachineManager;
import android.util.Log;

import androidx.test.core.app.ApplicationProvider;

import com.android.compatibility.common.util.CddTest;
import com.android.microdroid.test.device.MicrodroidDeviceTestBase;
import com.android.microdroid.testservice.ITestService;

import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
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
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.OptionalLong;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import co.nstant.in.cbor.CborDecoder;
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
        grantPermission(VirtualMachine.MANAGE_VIRTUAL_MACHINE_PERMISSION);
        prepareTestSetup(mProtectedVm);
    }

    @After
    public void tearDown() {
        revokePermission(VirtualMachine.MANAGE_VIRTUAL_MACHINE_PERMISSION);
        revokePermission(VirtualMachine.USE_CUSTOM_VIRTUAL_MACHINE_PERMISSION);
    }

    private static final int MIN_MEM_ARM64 = 150;
    private static final int MIN_MEM_X86_64 = 196;

    @Test
    @CddTest(requirements = {
            "9.17/C-1-1",
            "9.17/C-2-1"
    })
    public void connectToVmService() throws Exception {
        assumeSupportedKernel();

        VirtualMachineConfig config = mInner.newVmConfigBuilder()
                .setPayloadBinaryPath("MicrodroidTestNativeLib.so")
                .setMemoryMib(minMemoryRequired())
                .build();
        VirtualMachine vm = mInner.forceCreateNewVirtualMachine("test_vm", config);

        TestResults testResults = runVmTestService(vm);
        assertThat(testResults.mException).isNull();
        assertThat(testResults.mAddInteger).isEqualTo(123 + 456);
        assertThat(testResults.mAppRunProp).isEqualTo("true");
        assertThat(testResults.mSublibRunProp).isEqualTo("true");
        assertThat(testResults.mApkContentsPath).isEqualTo("/mnt/apk");
    }

    @Test
    @CddTest(requirements = {
            "9.17/C-1-1",
            "9.17/C-1-2",
            "9.17/C-1-4",
    })
    public void createVmRequiresPermission() throws Exception {
        assumeSupportedKernel();

        revokePermission(VirtualMachine.MANAGE_VIRTUAL_MACHINE_PERMISSION);

        VirtualMachineConfig config = mInner.newVmConfigBuilder()
                .setPayloadBinaryPath("MicrodroidTestNativeLib.so")
                .setMemoryMib(minMemoryRequired())
                .build();

        SecurityException e = assertThrows(SecurityException.class,
                () -> mInner.forceCreateNewVirtualMachine("test_vm_requires_permission", config));
        assertThat(e).hasMessageThat()
                .contains("android.permission.MANAGE_VIRTUAL_MACHINE permission");
    }

    @Test
    @CddTest(requirements = {
            "9.17/C-1-1",
            "9.17/C-1-2",
            "9.17/C-1-4",
    })
    public void createVmWithConfigRequiresPermission() throws Exception {
        assumeSupportedKernel();

        VirtualMachineConfig config = mInner.newVmConfigBuilder()
                .setPayloadConfigPath("assets/vm_config.json")
                .setMemoryMib(minMemoryRequired())
                .build();

        VirtualMachine vm = mInner.forceCreateNewVirtualMachine(
                "test_vm_config_requires_permission", config);

        SecurityException e = assertThrows(SecurityException.class, () -> runVmTestService(vm));
        assertThat(e).hasMessageThat()
                .contains("android.permission.USE_CUSTOM_VIRTUAL_MACHINE permission");
    }

    @Test
    @CddTest(requirements = {
            "9.17/C-1-1",
    })
    public void deleteVm() throws Exception {
        assumeSupportedKernel();

        VirtualMachineConfig config = mInner.newVmConfigBuilder()
                .setPayloadBinaryPath("MicrodroidTestNativeLib.so")
                .setMemoryMib(minMemoryRequired())
                .build();

        VirtualMachine vm = mInner.forceCreateNewVirtualMachine("test_vm_delete",
                config);
        VirtualMachineManager vmm = mInner.getVirtualMachineManager();
        vmm.delete("test_vm_delete");

        // VM should no longer exist
        assertThat(vmm.get("test_vm_delete")).isNull();

        // Can't start the VM even with an existing reference
        assertThrows(VirtualMachineException.class, vm::run);

        // Can't delete the VM since it no longer exists
        assertThrows(VirtualMachineException.class, () -> vmm.delete("test_vm_delete"));
    }

    @Test
    @CddTest(requirements = {
            "9.17/C-1-1",
    })
    public void validApkPathIsAccepted() throws Exception {
        assumeSupportedKernel();

        VirtualMachineConfig config = mInner.newVmConfigBuilder()
                .setPayloadBinaryPath("MicrodroidTestNativeLib.so")
                .setApkPath(getContext().getPackageCodePath())
                .setMemoryMib(minMemoryRequired())
                .build();

        VirtualMachine vm = mInner.forceCreateNewVirtualMachine(
                "test_vm_explicit_apk_path", config);

        TestResults testResults = runVmTestService(vm);
        assertThat(testResults.mException).isNull();
    }

    @Test
    @CddTest(requirements = {
            "9.17/C-1-1",
    })
    public void invalidApkPathIsRejected() {
        assumeSupportedKernel();

        VirtualMachineConfig.Builder builder = mInner.newVmConfigBuilder()
                .setPayloadBinaryPath("MicrodroidTestNativeLib.so")
                .setApkPath("relative/path/to.apk")
                .setMemoryMib(minMemoryRequired());
        assertThrows(IllegalArgumentException.class, () -> builder.build());
    }

    @Test
    @CddTest(requirements = {
            "9.17/C-1-1",
            "9.17/C-2-1"
    })
    public void extraApk() throws Exception {
        assumeSupportedKernel();

        grantPermission(VirtualMachine.USE_CUSTOM_VIRTUAL_MACHINE_PERMISSION);
        VirtualMachineConfig config = mInner.newVmConfigBuilder()
                .setPayloadConfigPath("assets/vm_config_extra_apk.json")
                .setMemoryMib(minMemoryRequired())
                .build();
        VirtualMachine vm = mInner.forceCreateNewVirtualMachine("test_vm_extra_apk", config);

        TestResults testResults = runVmTestService(vm);
        assertThat(testResults.mExtraApkTestProp).isEqualTo("PASS");
    }

    @Test
    public void bootFailsWhenLowMem() throws Exception {
        for (int memMib : new int[]{ 10, 20, 40 }) {
            VirtualMachineConfig lowMemConfig = mInner.newVmConfigBuilder()
                    .setPayloadBinaryPath("MicrodroidTestNativeLib.so")
                    .setMemoryMib(memMib)
                    .setDebugLevel(DEBUG_LEVEL_NONE)
                    .build();
            VirtualMachine vm = mInner.forceCreateNewVirtualMachine("low_mem", lowMemConfig);
            final CompletableFuture<Boolean> onPayloadReadyExecuted = new CompletableFuture<>();
            final CompletableFuture<Boolean> onStoppedExecuted = new CompletableFuture<>();
            VmEventListener listener =
                    new VmEventListener() {
                        @Override
                        public void onPayloadReady(VirtualMachine vm) {
                            onPayloadReadyExecuted.complete(true);
                            super.onPayloadReady(vm);
                        }
                        @Override
                        public void onStopped(VirtualMachine vm,  int reason) {
                            onStoppedExecuted.complete(true);
                            super.onStopped(vm, reason);
                        }
                    };
            listener.runToFinish(TAG, vm);
            // Assert that onStopped() was executed but onPayloadReady() was never run
            assertThat(onStoppedExecuted.getNow(false)).isTrue();
            assertThat(onPayloadReadyExecuted.getNow(false)).isFalse();
        }
    }

    @Test
    @CddTest(requirements = {
            "9.17/C-1-1",
            "9.17/C-2-7"
    })
    public void changingDebugLevelInvalidatesVmIdentity() throws Exception {
        assumeSupportedKernel();

        VirtualMachineConfig.Builder builder = mInner.newVmConfigBuilder()
                .setPayloadBinaryPath("MicrodroidTestNativeLib.so")
                .setDebugLevel(DEBUG_LEVEL_NONE);
        VirtualMachineConfig normalConfig = builder.build();
        mInner.forceCreateNewVirtualMachine("test_vm", normalConfig);
        assertThat(tryBootVm(TAG, "test_vm").payloadStarted).isTrue();

        // Try to run the VM again with the previous instance.img
        // We need to make sure that no changes on config don't invalidate the identity, to compare
        // the result with the below "different debug level" test.
        File vmInstance = getVmFile("test_vm", "instance.img");
        File vmInstanceBackup = File.createTempFile("instance", ".img");
        Files.copy(vmInstance.toPath(), vmInstanceBackup.toPath(), REPLACE_EXISTING);
        mInner.forceCreateNewVirtualMachine("test_vm", normalConfig);
        Files.copy(vmInstanceBackup.toPath(), vmInstance.toPath(), REPLACE_EXISTING);
        assertThat(tryBootVm(TAG, "test_vm").payloadStarted).isTrue();

        // Launch the same VM with different debug level. The Java API prohibits this (thankfully).
        // For testing, we do that by creating a new VM with debug level, and copy the old instance
        // image to the new VM instance image.
        VirtualMachineConfig debugConfig = builder.setDebugLevel(DEBUG_LEVEL_FULL).build();
        mInner.forceCreateNewVirtualMachine("test_vm", debugConfig);
        Files.copy(vmInstanceBackup.toPath(), vmInstance.toPath(), REPLACE_EXISTING);
        assertThat(tryBootVm(TAG, "test_vm").payloadStarted).isFalse();
    }

    private static class VmCdis {
        public byte[] cdiAttest;
        public byte[] instanceSecret;
    }

    private VmCdis launchVmAndGetCdis(String instanceName) throws Exception {
        VirtualMachine vm = mInner.getVirtualMachineManager().get(instanceName);
        final VmCdis vmCdis = new VmCdis();
        final CompletableFuture<Exception> exception = new CompletableFuture<>();
        VmEventListener listener =
                new VmEventListener() {
                    @Override
                    public void onPayloadReady(VirtualMachine vm) {
                        try {
                            ITestService testService = ITestService.Stub.asInterface(
                                    vm.connectToVsockServer(ITestService.SERVICE_PORT));
                            vmCdis.cdiAttest = testService.insecurelyExposeAttestationCdi();
                            vmCdis.instanceSecret = testService.insecurelyExposeVmInstanceSecret();
                        } catch (Exception e) {
                            exception.complete(e);
                        } finally {
                            forceStop(vm);
                        }
                    }
                };
        listener.runToFinish(TAG, vm);
        Exception e = exception.getNow(null);
        if (e != null) {
            throw e;
        }
        return vmCdis;
    }

    @Test
    @CddTest(requirements = {
            "9.17/C-1-1",
            "9.17/C-2-7"
    })
    public void instancesOfSameVmHaveDifferentCdis() throws Exception {
        assumeSupportedKernel();

        grantPermission(VirtualMachine.USE_CUSTOM_VIRTUAL_MACHINE_PERMISSION);
        VirtualMachineConfig normalConfig = mInner.newVmConfigBuilder()
                .setPayloadConfigPath("assets/vm_config.json")
                .setDebugLevel(DEBUG_LEVEL_FULL)
                .build();
        mInner.forceCreateNewVirtualMachine("test_vm_a", normalConfig);
        mInner.forceCreateNewVirtualMachine("test_vm_b", normalConfig);
        VmCdis vm_a_cdis = launchVmAndGetCdis("test_vm_a");
        VmCdis vm_b_cdis = launchVmAndGetCdis("test_vm_b");
        assertThat(vm_a_cdis.cdiAttest).isNotNull();
        assertThat(vm_b_cdis.cdiAttest).isNotNull();
        assertThat(vm_a_cdis.cdiAttest).isNotEqualTo(vm_b_cdis.cdiAttest);
        assertThat(vm_a_cdis.instanceSecret).isNotNull();
        assertThat(vm_b_cdis.instanceSecret).isNotNull();
        assertThat(vm_a_cdis.instanceSecret).isNotEqualTo(vm_b_cdis.instanceSecret);
    }

    @Test
    @CddTest(requirements = {
            "9.17/C-1-1",
            "9.17/C-2-7"
    })
    public void sameInstanceKeepsSameCdis() throws Exception {
        assumeSupportedKernel();

        grantPermission(VirtualMachine.USE_CUSTOM_VIRTUAL_MACHINE_PERMISSION);
        VirtualMachineConfig normalConfig = mInner.newVmConfigBuilder()
                .setPayloadConfigPath("assets/vm_config.json")
                .setDebugLevel(DEBUG_LEVEL_FULL)
                .build();
        mInner.forceCreateNewVirtualMachine("test_vm", normalConfig);

        VmCdis first_boot_cdis = launchVmAndGetCdis("test_vm");
        VmCdis second_boot_cdis = launchVmAndGetCdis("test_vm");
        // The attestation CDI isn't specified to be stable, though it might be
        assertThat(first_boot_cdis.instanceSecret).isNotNull();
        assertThat(second_boot_cdis.instanceSecret).isNotNull();
        assertThat(first_boot_cdis.instanceSecret).isEqualTo(second_boot_cdis.instanceSecret);
    }

    @Test
    @CddTest(requirements = {
            "9.17/C-1-1",
            "9.17/C-2-7"
    })
    public void bccIsSuperficiallyWellFormed() throws Exception {
        assumeSupportedKernel();

        grantPermission(VirtualMachine.USE_CUSTOM_VIRTUAL_MACHINE_PERMISSION);
        VirtualMachineConfig normalConfig = mInner.newVmConfigBuilder()
                .setPayloadConfigPath("assets/vm_config.json")
                .setDebugLevel(DEBUG_LEVEL_FULL)
                .build();
        VirtualMachine vm = mInner.forceCreateNewVirtualMachine("bcc_vm", normalConfig);
        final CompletableFuture<byte[]> bcc = new CompletableFuture<>();
        final CompletableFuture<Exception> exception = new CompletableFuture<>();
        VmEventListener listener =
                new VmEventListener() {
                    @Override
                    public void onPayloadReady(VirtualMachine vm) {
                        try {
                            ITestService testService = ITestService.Stub.asInterface(
                                    vm.connectToVsockServer(ITestService.SERVICE_PORT));
                            bcc.complete(testService.getBcc());
                        } catch (Exception e) {
                            exception.complete(e);
                        } finally {
                            forceStop(vm);
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

    @Test
    @CddTest(requirements = {
            "9.17/C-1-1",
            "9.17/C-1-2"
    })
    public void accessToCdisIsRestricted() throws Exception {
        assumeSupportedKernel();

        VirtualMachineConfig config = mInner.newVmConfigBuilder()
                .setPayloadBinaryPath("MicrodroidTestNativeLib.so")
                .setDebugLevel(DEBUG_LEVEL_FULL)
                .build();
        mInner.forceCreateNewVirtualMachine("test_vm", config);

        assertThrows(ServiceSpecificException.class, () -> launchVmAndGetCdis("test_vm"));
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

    private RandomAccessFile prepareInstanceImage(String vmName) throws Exception {
        VirtualMachineConfig config = mInner.newVmConfigBuilder()
                .setPayloadBinaryPath("MicrodroidTestNativeLib.so")
                .setDebugLevel(DEBUG_LEVEL_FULL)
                .build();

        mInner.forceCreateNewVirtualMachine(vmName, config);
        assertThat(tryBootVm(TAG, vmName).payloadStarted).isTrue();
        File instanceImgPath = getVmFile(vmName, "instance.img");
        return new RandomAccessFile(instanceImgPath, "rw");
    }

    private void assertThatPartitionIsMissing(UUID partitionUuid) throws Exception {
        RandomAccessFile instanceFile = prepareInstanceImage("test_vm_integrity");
        assertThat(findPartitionDataOffset(instanceFile, partitionUuid).isPresent())
                .isFalse();
    }

    // Flips a bit of given partition, and then see if boot fails.
    private void assertThatBootFailsAfterCompromisingPartition(UUID partitionUuid)
            throws Exception {
        RandomAccessFile instanceFile = prepareInstanceImage("test_vm_integrity");
        OptionalLong offset = findPartitionDataOffset(instanceFile, partitionUuid);
        assertThat(offset.isPresent()).isTrue();

        flipBit(instanceFile, offset.getAsLong());

        BootResult result = tryBootVm(TAG, "test_vm_integrity");
        assertThat(result.payloadStarted).isFalse();

        // This failure should shut the VM down immediately and shouldn't trigger a hangup.
        assertThat(result.deathReason).isNotEqualTo(VirtualMachineCallback.STOP_REASON_HANGUP);
    }

    @Test
    @CddTest(requirements = {
            "9.17/C-1-1",
            "9.17/C-2-7"
    })
    public void bootFailsWhenMicrodroidDataIsCompromised() throws Exception {
        assertThatBootFailsAfterCompromisingPartition(MICRODROID_PARTITION_UUID);
    }

    @Test
    @Ignore("b/249723852")
    @CddTest(requirements = {
            "9.17/C-1-1",
            "9.17/C-2-7"
    })
    public void bootFailsWhenPvmFwDataIsCompromised() throws Exception {
        if (mProtectedVm) {
            assertThatBootFailsAfterCompromisingPartition(PVM_FW_PARTITION_UUID);
        } else {
            // non-protected VM shouldn't have pvmfw data
            assertThatPartitionIsMissing(PVM_FW_PARTITION_UUID);
        }
    }

    @Test
    public void bootFailsWhenConfigIsInvalid() throws Exception {
        grantPermission(VirtualMachine.USE_CUSTOM_VIRTUAL_MACHINE_PERMISSION);
        VirtualMachineConfig normalConfig = mInner.newVmConfigBuilder()
                .setPayloadConfigPath("assets/vm_config_no_task.json")
                .setDebugLevel(DEBUG_LEVEL_FULL)
                .build();
        mInner.forceCreateNewVirtualMachine("test_vm_invalid_config", normalConfig);

        BootResult bootResult = tryBootVm(TAG, "test_vm_invalid_config");
        assertThat(bootResult.payloadStarted).isFalse();
        assertThat(bootResult.deathReason).isEqualTo(
                VirtualMachineCallback.STOP_REASON_MICRODROID_INVALID_PAYLOAD_CONFIG);
    }

    @Test
    public void bootFailsWhenBinaryPathIsInvalid() throws Exception {
        VirtualMachineConfig.Builder builder = mInner.newVmConfigBuilder()
                .setPayloadBinaryPath("DoesNotExist.so");
        VirtualMachineConfig normalConfig = builder.setDebugLevel(DEBUG_LEVEL_FULL).build();
        mInner.forceCreateNewVirtualMachine("test_vm_invalid_binary_path", normalConfig);

        BootResult bootResult = tryBootVm(TAG, "test_vm_invalid_binary_path");
        assertThat(bootResult.payloadStarted).isFalse();
        assertThat(bootResult.deathReason).isEqualTo(
                VirtualMachineCallback.STOP_REASON_MICRODROID_UNKNOWN_RUNTIME_ERROR);
    }

    @Test
    public void sameInstancesShareTheSameVmObject() throws Exception {
        VirtualMachineConfig config = mInner.newVmConfigBuilder()
                .setPayloadBinaryPath("MicrodroidTestNativeLib.so")
                .setDebugLevel(DEBUG_LEVEL_NONE)
                .build();

        VirtualMachine vm = mInner.forceCreateNewVirtualMachine("test_vm", config);
        VirtualMachine vm2 = mInner.getVirtualMachineManager().get("test_vm");
        assertThat(vm).isEqualTo(vm2);

        VirtualMachine newVm = mInner.forceCreateNewVirtualMachine("test_vm", config);
        VirtualMachine newVm2 = mInner.getVirtualMachineManager().get("test_vm");
        assertThat(newVm).isEqualTo(newVm2);

        assertThat(vm).isNotEqualTo(newVm);
    }

    @Test
    public void vmConvertsToValidParcelVm() throws Exception {
        // Arrange
        VirtualMachineConfig config =
                mInner.newVmConfigBuilder()
                        .setPayloadBinaryPath("MicrodroidTestNativeLib.so")
                        .setDebugLevel(DEBUG_LEVEL_NONE)
                        .build();
        String vmName = "test_vm";
        VirtualMachine vm = mInner.forceCreateNewVirtualMachine(vmName, config);

        // Action
        ParcelVirtualMachine parcelVm = vm.toParcelVirtualMachine();

        // Asserts
        assertFileContentsAreEqual(parcelVm.getConfigFd(), vmName, "config.xml");
        assertFileContentsAreEqual(parcelVm.getInstanceImgFd(), vmName, "instance.img");
    }

    private void assertFileContentsAreEqual(
            ParcelFileDescriptor parcelFd, String vmName, String fileName) throws IOException {
        File file = getVmFile(vmName, fileName);
        // Use try-with-resources to close the files automatically after assert.
        try (FileInputStream input1 = new FileInputStream(parcelFd.getFileDescriptor());
                FileInputStream input2 = new FileInputStream(file)) {
            assertThat(input1.readAllBytes()).isEqualTo(input2.readAllBytes());
        }
    }

    private File getVmFile(String vmName, String fileName) {
        Context context = ApplicationProvider.getApplicationContext();
        Path filePath = Paths.get(context.getDataDir().getPath(), "vm", vmName, fileName);
        return filePath.toFile();
    }

    private int minMemoryRequired() {
        if (Build.SUPPORTED_ABIS.length > 0) {
            String primaryAbi = Build.SUPPORTED_ABIS[0];
            switch (primaryAbi) {
                case "x86_64":
                    return MIN_MEM_X86_64;
                case "arm64-v8a":
                    return MIN_MEM_ARM64;
            }
        }
        return 0;
    }

    private void assumeSupportedKernel() {
        assume()
                .withMessage("Skip on 5.4 kernel. b/218303240")
                .that(KERNEL_VERSION)
                .isNotEqualTo("5.4");
    }

    static class TestResults {
        Exception mException;
        Integer mAddInteger;
        String mAppRunProp;
        String mSublibRunProp;
        String mExtraApkTestProp;
        String mApkContentsPath;
    }

    private TestResults runVmTestService(VirtualMachine vm) throws Exception {
        CompletableFuture<Boolean> payloadStarted = new CompletableFuture<>();
        CompletableFuture<Boolean> payloadReady = new CompletableFuture<>();
        TestResults testResults = new TestResults();
        VmEventListener listener =
                new VmEventListener() {
                    private void testVMService(VirtualMachine vm) {
                        try {
                            ITestService testService =
                                    ITestService.Stub.asInterface(
                                            vm.connectToVsockServer(ITestService.SERVICE_PORT));
                            testResults.mAddInteger = testService.addInteger(123, 456);
                            testResults.mAppRunProp =
                                    testService.readProperty("debug.microdroid.app.run");
                            testResults.mSublibRunProp =
                                    testService.readProperty("debug.microdroid.app.sublib.run");
                            testResults.mExtraApkTestProp =
                                    testService.readProperty("debug.microdroid.test.extra_apk");
                            testResults.mApkContentsPath = testService.getApkContentsPath();
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
                    public void onPayloadStarted(VirtualMachine vm) {
                        Log.i(TAG, "onPayloadStarted");
                        payloadStarted.complete(true);
                    }

                    @Override
                    public void onPayloadStdio(VirtualMachine vm, ParcelFileDescriptor stream) {
                        Log.i(TAG, "onPayloadStdio");
                        logVmOutput(
                                TAG, new FileInputStream(stream.getFileDescriptor()), "Payload");
                    }
                };
        listener.runToFinish(TAG, vm);
        assertThat(payloadStarted.getNow(false)).isTrue();
        assertThat(payloadReady.getNow(false)).isTrue();
        return testResults;
    }
}
