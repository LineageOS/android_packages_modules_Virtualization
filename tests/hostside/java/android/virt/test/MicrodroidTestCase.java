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

package android.virt.test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

import com.android.tradefed.device.DeviceNotAvailableException;
import com.android.tradefed.result.TestDescription;
import com.android.tradefed.result.TestResult;
import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
import com.android.tradefed.testtype.junit4.DeviceTestRunOptions;
import com.android.tradefed.util.CommandResult;
import com.android.tradefed.util.CommandStatus;
import com.android.tradefed.util.FileUtil;
import com.android.tradefed.util.RunUtil;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@RunWith(DeviceJUnit4ClassRunner.class)
public class MicrodroidTestCase extends VirtualizationTestCaseBase {
    private static final String APK_NAME = "MicrodroidTestApp.apk";
    private static final String PACKAGE_NAME = "com.android.microdroid.test";

    private static final int MIN_MEM_ARM64 = 145;
    private static final int MIN_MEM_X86_64 = 196;

    // Number of vCPUs and their affinity to host CPUs for testing purpose
    private static final int NUM_VCPUS = 3;
    private static final String CPU_AFFINITY = "0,1,2";

    // TODO(b/176805428): remove this
    private boolean isCuttlefish() throws Exception {
        String productName = getDevice().getProperty("ro.product.name");
        return (null != productName)
                && (productName.startsWith("aosp_cf_x86")
                        || productName.startsWith("aosp_cf_arm")
                        || productName.startsWith("cf_x86")
                        || productName.startsWith("cf_arm"));
    }

    private int minMemorySize() throws DeviceNotAvailableException {
        CommandRunner android = new CommandRunner(getDevice());
        String abi = android.run("getprop", "ro.product.cpu.abi");
        assertTrue(abi != null && !abi.isEmpty());
        if (abi.startsWith("arm64")) {
            return MIN_MEM_ARM64;
        } else if (abi.startsWith("x86_64")) {
            return MIN_MEM_X86_64;
        }
        fail("Unsupported ABI: " + abi);
        return 0;
    }

    private boolean isProtectedVmSupported() throws DeviceNotAvailableException {
        return getDevice().getBooleanProperty("ro.boot.hypervisor.protected_vm.supported",
                false);
    }

    @Test
    public void testCreateVmRequiresPermission() throws Exception {
        // Revoke the MANAGE_VIRTUAL_MACHINE permission for the test app
        CommandRunner android = new CommandRunner(getDevice());
        android.run("pm", "revoke", PACKAGE_NAME, "android.permission.MANAGE_VIRTUAL_MACHINE");

        // Run MicrodroidTests#connectToVmService test, which should fail
        final DeviceTestRunOptions options = new DeviceTestRunOptions(PACKAGE_NAME)
                .setTestClassName(PACKAGE_NAME + ".MicrodroidTests")
                .setTestMethodName("connectToVmService[protectedVm=false]")
                .setCheckResults(false);
        assertFalse(runDeviceTests(options));

        Map<TestDescription, TestResult> results = getLastDeviceRunResults().getTestResults();
        assertThat(results.size(), is(1));
        TestResult result = results.values().toArray(new TestResult[0])[0];
        assertTrue("The test should fail with a permission error",
                result.getStackTrace()
                .contains("android.permission.MANAGE_VIRTUAL_MACHINE permission"));
    }

    // Helper classes for (de)serialization of VM raw configs
    static class VmRawConfig {
        String bootloader;
        List<Disk> disks;
        int memory_mib;
        @SerializedName("protected")
        boolean isProtected;
        String platform_version;
    }

    static class Disk {
        List<Partition> partitions;
        boolean writable;
        public void addPartition(String label, String path) {
            if (partitions == null) {
                partitions = new ArrayList<Partition>();
            }
            Partition partition = new Partition();
            partition.label = label;
            partition.path = path;
            partitions.add(partition);
        }
    }

    static class Partition {
        String label;
        String path;
        boolean writable;
    }

    private void resignVirtApex(File virtApexDir, File signingKey, Map<String, File> keyOverrides) {
        File signVirtApex = findTestFile("sign_virt_apex");

        RunUtil runUtil = new RunUtil();
        // Set the parent dir on the PATH (e.g. <workdir>/bin)
        String separator = System.getProperty("path.separator");
        String path = signVirtApex.getParentFile().getPath() + separator + System.getenv("PATH");
        runUtil.setEnvVariable("PATH", path);

        List<String> command = new ArrayList<String>();
        command.add("sign_virt_apex");
        for (Map.Entry<String, File> entry : keyOverrides.entrySet()) {
            String filename = entry.getKey();
            File overridingKey = entry.getValue();
            command.add("--key_override " + filename + "=" + overridingKey.getPath());
        }
        command.add(signingKey.getPath());
        command.add(virtApexDir.getPath());

        CommandResult result = runUtil.runTimedCmd(
                                    20 * 1000,
                                    "/bin/bash",
                                    "-c",
                                    String.join(" ", command));
        String out = result.getStdout();
        String err = result.getStderr();
        assertEquals(
                "resigning the Virt APEX failed:\n\tout: " + out + "\n\terr: " + err + "\n",
                CommandStatus.SUCCESS, result.getStatus());
    }

    private static <T> void assertThatEventually(long timeoutMillis, Callable<T> callable,
            org.hamcrest.Matcher<T> matcher) throws Exception {
        long start = System.currentTimeMillis();
        while (true) {
            try {
                assertThat(callable.call(), matcher);
                return;
            } catch (Throwable e) {
                if (System.currentTimeMillis() - start < timeoutMillis) {
                    Thread.sleep(500);
                } else {
                    throw e;
                }
            }
        }
    }

    private String runMicrodroidWithResignedImages(File key, Map<String, File> keyOverrides,
            boolean isProtected, boolean daemonize, String consolePath)
            throws DeviceNotAvailableException, IOException {
        CommandRunner android = new CommandRunner(getDevice());

        File virtApexDir = FileUtil.createTempDir("virt_apex");

        // Pull the virt apex's etc/ directory (which contains images and microdroid.json)
        File virtApexEtcDir = new File(virtApexDir, "etc");
        // We need only etc/ directory for images
        assertTrue(virtApexEtcDir.mkdirs());
        assertTrue(getDevice().pullDir(VIRT_APEX + "etc", virtApexEtcDir));

        resignVirtApex(virtApexDir, key, keyOverrides);

        // Push back re-signed virt APEX contents and updated microdroid.json
        getDevice().pushDir(virtApexDir, TEST_ROOT);

        // Create the idsig file for the APK
        final String apkPath = getPathForPackage(PACKAGE_NAME);
        final String idSigPath = TEST_ROOT + "idsig";
        android.run(VIRT_APEX + "bin/vm", "create-idsig", apkPath, idSigPath);

        // Create the instance image for the VM
        final String instanceImgPath = TEST_ROOT + "instance.img";
        android.run(VIRT_APEX + "bin/vm", "create-partition", "--type instance",
                instanceImgPath, Integer.toString(10 * 1024 * 1024));

        // payload-metadata is prepared on host with the two APEXes and APK
        final String payloadMetadataPath = TEST_ROOT + "payload-metadata.img";
        getDevice().pushFile(findTestFile("test-payload-metadata.img"), payloadMetadataPath);

        // push APEXes required for the VM.
        final String statsdApexPath = TEST_ROOT + "com.android.os.statsd.apex";
        final String adbdApexPath = TEST_ROOT + "com.android.adbd.apex";
        getDevice().pushFile(findTestFile("com.android.os.statsd.apex"), statsdApexPath);
        getDevice().pushFile(findTestFile("com.android.adbd.apex"), adbdApexPath);

        // Since Java APP can't start a VM with a custom image, here, we start a VM using `vm run`
        // command with a VM Raw config which is equiv. to what virtualizationservice creates with
        // a VM App config.
        //
        // 1. use etc/microdroid.json as base
        // 2. add partitions: bootconfig, vbmeta, instance image
        // 3. add a payload image disk with
        //   - payload-metadata
        //   - apexes
        //   - test apk
        //   - its idsig

        // Load etc/microdroid.json
        Gson gson = new Gson();
        File microdroidConfigFile = new File(virtApexEtcDir, "microdroid.json");
        VmRawConfig config = gson.fromJson(new FileReader(microdroidConfigFile),
                VmRawConfig.class);

        // Replace paths so that the config uses re-signed images from TEST_ROOT
        config.bootloader = config.bootloader.replace(VIRT_APEX, TEST_ROOT);
        for (Disk disk : config.disks) {
            for (Partition part : disk.partitions) {
                part.path = part.path.replace(VIRT_APEX, TEST_ROOT);
            }
        }

        // Add partitions to the second disk
        Disk secondDisk = config.disks.get(1);
        secondDisk.addPartition("vbmeta",
                TEST_ROOT + "etc/fs/microdroid_vbmeta_bootconfig.img");
        secondDisk.addPartition("bootconfig",
                TEST_ROOT + "etc/microdroid_bootconfig.full_debuggable");
        secondDisk.addPartition("vm-instance", instanceImgPath);

        // Add payload image disk with partitions:
        // - payload-metadata
        // - apexes: com.android.os.statsd, com.android.adbd
        // - apk and idsig
        Disk payloadDisk = new Disk();
        payloadDisk.addPartition("payload-metadata", payloadMetadataPath);
        payloadDisk.addPartition("microdroid-apex-0", statsdApexPath);
        payloadDisk.addPartition("microdroid-apex-1", adbdApexPath);
        payloadDisk.addPartition("microdroid-apk", apkPath);
        payloadDisk.addPartition("microdroid-apk-idsig", idSigPath);
        config.disks.add(payloadDisk);

        config.isProtected = isProtected;

        // Write updated raw config
        final String configPath = TEST_ROOT + "raw_config.json";
        getDevice().pushString(gson.toJson(config), configPath);

        final String logPath = TEST_ROOT + "log";
        final String ret = android.runWithTimeout(
                60 * 1000,
                VIRT_APEX + "bin/vm run",
                daemonize ? "--daemonize" : "",
                (consolePath != null) ? "--console " + consolePath : "",
                "--log " + logPath,
                configPath);
        Pattern pattern = Pattern.compile("with CID (\\d+)");
        Matcher matcher = pattern.matcher(ret);
        assertTrue(matcher.find());
        return matcher.group(1);
    }

    @Test
    public void testBootFailsWhenProtectedVmStartsWithImagesSignedWithDifferentKey()
            throws Exception {
        assumeTrue(isProtectedVmSupported());

        File key = findTestFile("test.com.android.virt.pem");
        Map<String, File> keyOverrides = Map.of();
        boolean isProtected = true;
        boolean daemonize = false;  // VM should shut down due to boot failure.
        String consolePath = TEST_ROOT + "console";
        runMicrodroidWithResignedImages(key, keyOverrides, isProtected, daemonize, consolePath);
        assertThat(getDevice().pullFileContents(consolePath),
                containsString("pvmfw boot failed"));
    }

    @Test
    public void testBootSucceedsWhenNonProtectedVmStartsWithImagesSignedWithDifferentKey()
            throws Exception {
        File key = findTestFile("test.com.android.virt.pem");
        Map<String, File> keyOverrides = Map.of();
        boolean isProtected = false;
        boolean daemonize = true;
        String consolePath = TEST_ROOT + "console";
        String cid = runMicrodroidWithResignedImages(key, keyOverrides, isProtected, daemonize,
                consolePath);
        // Adb connection to the microdroid means that boot succeeded.
        adbConnectToMicrodroid(getDevice(), cid);
        shutdownMicrodroid(getDevice(), cid);
    }

    @Test
    public void testBootFailsWhenBootloaderAndVbMetaAreSignedWithDifferentKeys()
            throws Exception {
        // Sign everything with key1 except vbmeta
        File key = findTestFile("test.com.android.virt.pem");
        File key2 = findTestFile("test2.com.android.virt.pem");
        Map<String, File> keyOverrides = Map.of(
                "microdroid_vbmeta.img", key2);
        boolean isProtected = false;  // Not interested in pvwfw
        boolean daemonize = true;  // Bootloader fails and enters prompts.
                                   // To be able to stop it, it should be a daemon.
        String consolePath = TEST_ROOT + "console";
        String cid = runMicrodroidWithResignedImages(key, keyOverrides, isProtected, daemonize,
                consolePath);
        // Wail for a while so that bootloader prints errors to console
        assertThatEventually(10000, () -> getDevice().pullFileContents(consolePath),
                containsString("Public key was rejected"));
        shutdownMicrodroid(getDevice(), cid);
    }

    @Test
    public void testBootSucceedsWhenBootloaderAndVbmetaHaveSameSigningKeys()
            throws Exception {
        // Sign everything with key1 except bootloader and vbmeta
        File key = findTestFile("test.com.android.virt.pem");
        File key2 = findTestFile("test2.com.android.virt.pem");
        Map<String, File> keyOverrides = Map.of(
                "microdroid_bootloader", key2,
                "microdroid_vbmeta.img", key2,
                "microdroid_vbmeta_bootconfig.img", key2);
        boolean isProtected = false;  // Not interested in pvwfw
        boolean daemonize = true;  // Bootloader should succeed.
                                   // To be able to stop it, it should be a daemon.
        String consolePath = TEST_ROOT + "console";
        String cid = runMicrodroidWithResignedImages(key, keyOverrides, isProtected, daemonize,
                consolePath);
        // Adb connection to the microdroid means that boot succeeded.
        adbConnectToMicrodroid(getDevice(), cid);
        shutdownMicrodroid(getDevice(), cid);
    }

    @Test
    public void testMicrodroidBoots() throws Exception {
        final String configPath = "assets/vm_config.json"; // path inside the APK
        final String cid =
                startMicrodroid(
                        getDevice(),
                        getBuild(),
                        APK_NAME,
                        PACKAGE_NAME,
                        configPath,
                        /* debug */ true,
                        minMemorySize(),
                        Optional.of(NUM_VCPUS),
                        Optional.of(CPU_AFFINITY));
        adbConnectToMicrodroid(getDevice(), cid);

        // Wait until logd-init starts. The service is one of the last services that are started in
        // the microdroid boot procedure. Therefore, waiting for the service means that we wait for
        // the boot to complete. TODO: we need a better marker eventually.
        tryRunOnMicrodroid("watch -e \"getprop init.svc.logd-reinit | grep '^$'\"");

        // Test writing to /data partition
        runOnMicrodroid("echo MicrodroidTest > /data/local/tmp/test.txt");
        assertThat(runOnMicrodroid("cat /data/local/tmp/test.txt"), is("MicrodroidTest"));

        // Check if the APK & its idsig partitions exist
        final String apkPartition = "/dev/block/by-name/microdroid-apk";
        assertThat(runOnMicrodroid("ls", apkPartition), is(apkPartition));
        final String apkIdsigPartition = "/dev/block/by-name/microdroid-apk-idsig";
        assertThat(runOnMicrodroid("ls", apkIdsigPartition), is(apkIdsigPartition));
        // Check the vm-instance partition as well
        final String vmInstancePartition = "/dev/block/by-name/vm-instance";
        assertThat(runOnMicrodroid("ls", vmInstancePartition), is(vmInstancePartition));

        // Check if the native library in the APK is has correct filesystem info
        final String[] abis = runOnMicrodroid("getprop", "ro.product.cpu.abilist").split(",");
        assertThat(abis.length, is(1));
        final String testLib = "/mnt/apk/lib/" + abis[0] + "/MicrodroidTestNativeLib.so";
        final String label = "u:object_r:system_file:s0";
        assertThat(runOnMicrodroid("ls", "-Z", testLib), is(label + " " + testLib));

        // Check that no denials have happened so far
        assertThat(runOnMicrodroid("logcat -d -e 'avc:[[:space:]]{1,2}denied'"), is(""));

        assertThat(runOnMicrodroid("cat /proc/cpuinfo | grep processor | wc -l"),
                is(Integer.toString(NUM_VCPUS)));

        // Check that selinux is enabled
        assertThat(runOnMicrodroid("getenforce"), is("Enforcing"));

        // TODO(b/176805428): adb is broken for nested VM
        if (!isCuttlefish()) {
            // Check neverallow rules on microdroid
            File policyFile = FileUtil.createTempFile("microdroid_sepolicy", "");
            pullMicrodroidFile("/sys/fs/selinux/policy", policyFile);

            File generalPolicyConfFile = findTestFile("microdroid_general_sepolicy.conf");
            File sepolicyAnalyzeBin = findTestFile("sepolicy-analyze");

            CommandResult result =
                    RunUtil.getDefault()
                            .runTimedCmd(
                                    10000,
                                    sepolicyAnalyzeBin.getPath(),
                                    policyFile.getPath(),
                                    "neverallow",
                                    "-w",
                                    "-f",
                                    generalPolicyConfFile.getPath());
            assertEquals(
                    "neverallow check failed: " + result.getStderr().trim(),
                    result.getStatus(),
                    CommandStatus.SUCCESS);
        }

        shutdownMicrodroid(getDevice(), cid);
    }

    @Before
    public void setUp() throws Exception {
        testIfDeviceIsCapable(getDevice());

        prepareVirtualizationTestSetup(getDevice());

        getDevice().installPackage(findTestFile(APK_NAME), /* reinstall */ false);

        // clear the log
        getDevice().executeShellV2Command("logcat -c");
    }

    @After
    public void shutdown() throws Exception {
        cleanUpVirtualizationTestSetup(getDevice());

        getDevice().uninstallPackage(PACKAGE_NAME);
    }
}
