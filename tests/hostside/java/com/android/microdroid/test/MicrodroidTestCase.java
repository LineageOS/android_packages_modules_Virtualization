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

import static com.android.microdroid.test.CommandResultSubject.command_results;
import static com.android.tradefed.testtype.DeviceJUnit4ClassRunner.TestLogData;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth.assertWithMessage;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

import com.android.compatibility.common.util.CddTest;
import com.android.tradefed.device.DeviceNotAvailableException;
import com.android.tradefed.result.TestDescription;
import com.android.tradefed.result.TestResult;
import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
import com.android.tradefed.testtype.junit4.DeviceTestRunOptions;
import com.android.tradefed.util.CommandResult;
import com.android.tradefed.util.FileUtil;
import com.android.tradefed.util.RunUtil;
import com.android.tradefed.util.xml.AbstractXmlParser;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.junit.runner.RunWith;
import org.xml.sax.Attributes;
import org.xml.sax.helpers.DefaultHandler;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@RunWith(DeviceJUnit4ClassRunner.class)
public class MicrodroidTestCase extends MicrodroidHostTestCaseBase {
    private static final String APK_NAME = "MicrodroidTestApp.apk";
    private static final String PACKAGE_NAME = "com.android.microdroid.test";
    private static final String SHELL_PACKAGE_NAME = "com.android.shell";

    private static final int MIN_MEM_ARM64 = 145;
    private static final int MIN_MEM_X86_64 = 196;

    // Number of vCPUs and their affinity to host CPUs for testing purpose
    private static final int NUM_VCPUS = 3;
    private static final String CPU_AFFINITY = "0,1,2";

    @Rule public TestLogData mTestLogs = new TestLogData();
    @Rule public TestName mTestName = new TestName();

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
        return getDevice().getBooleanProperty("ro.boot.hypervisor.protected_vm.supported", false);
    }

    private void waitForBootComplete() {
        runOnMicrodroidForResult("watch -e \"getprop dev.bootcomplete | grep '^0$'\"");
    }

    @Test
    @CddTest(requirements = {"9.17/C-1-1", "9.17/C-1-2", "9.17/C-1-4"})
    public void testCreateVmRequiresPermission() throws Exception {
        // Revoke the MANAGE_VIRTUAL_MACHINE permission for the test app
        CommandRunner android = new CommandRunner(getDevice());
        android.run("pm", "revoke", PACKAGE_NAME, "android.permission.MANAGE_VIRTUAL_MACHINE");

        // Run MicrodroidTests#connectToVmService test, which should fail
        final DeviceTestRunOptions options =
                new DeviceTestRunOptions(PACKAGE_NAME)
                        .setTestClassName(PACKAGE_NAME + ".MicrodroidTests")
                        .setTestMethodName("connectToVmService[protectedVm=false]")
                        .setCheckResults(false);
        assertFalse(runDeviceTests(options));

        Map<TestDescription, TestResult> results = getLastDeviceRunResults().getTestResults();
        assertThat(results).hasSize(1);
        TestResult result = results.values().toArray(new TestResult[0])[0];
        assertTrue(
                "The test should fail with a permission error",
                result.getStackTrace()
                        .contains("android.permission.MANAGE_VIRTUAL_MACHINE permission"));
    }

    private static JSONObject newPartition(String label, String path) {
        return new JSONObject(Map.of("label", label, "path", path));
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

        CommandResult result =
                runUtil.runTimedCmd(
                        // sign_virt_apex is so slow on CI server that this often times
                        // out. Until we can make it fast, use 50s for timeout
                        50 * 1000, "/bin/bash", "-c", String.join(" ", command));
        String out = result.getStdout();
        String err = result.getStderr();
        assertWithMessage(
                        "resigning the Virt APEX failed:\n\tout: " + out + "\n\terr: " + err + "\n")
                .about(command_results())
                .that(result)
                .isSuccess();
    }

    private static <T> void assertThatEventually(
            long timeoutMillis, Callable<T> callable, org.hamcrest.Matcher<T> matcher)
            throws Exception {
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

    static class ActiveApexInfo {
        public String name;
        public String path;

        ActiveApexInfo(String name, String path) {
            this.name = name;
            this.path = path;
        }
    }

    static class ActiveApexInfoList {
        private List<ActiveApexInfo> mList;

        ActiveApexInfoList(List<ActiveApexInfo> list) {
            this.mList = list;
        }

        ActiveApexInfo get(String apexName) {
            for (ActiveApexInfo info : mList) {
                if (info.name.equals(apexName)) {
                    return info;
                }
            }
            return null;
        }
    }

    private ActiveApexInfoList getActiveApexInfoList() throws Exception {
        String apexInfoListXml = getDevice().pullFileContents("/apex/apex-info-list.xml");
        List<ActiveApexInfo> list = new ArrayList<>();
        new AbstractXmlParser() {
            @Override
            protected DefaultHandler createXmlHandler() {
                return new DefaultHandler() {
                    @Override
                    public void startElement(
                            String uri, String localName, String qName, Attributes attributes) {
                        if (localName.equals("apex-info")
                                && attributes.getValue("isActive").equals("true")) {
                            list.add(
                                    new ActiveApexInfo(
                                            attributes.getValue("moduleName"),
                                            attributes.getValue("modulePath")));
                        }
                    }
                };
            }
        }.parse(new ByteArrayInputStream(apexInfoListXml.getBytes()));
        return new ActiveApexInfoList(list);
    }

    private String runMicrodroidWithResignedImages(
            File key,
            Map<String, File> keyOverrides,
            boolean isProtected,
            boolean daemonize,
            String consolePath)
            throws Exception {
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
        android.run(
                VIRT_APEX + "bin/vm",
                "create-partition",
                "--type instance",
                instanceImgPath,
                Integer.toString(10 * 1024 * 1024));

        // payload-metadata is prepared on host with the two APEXes and APK
        final String payloadMetadataPath = TEST_ROOT + "payload-metadata.img";
        getDevice().pushFile(findTestFile("test-payload-metadata.img"), payloadMetadataPath);

        // get paths to the two APEXes required for the VM.
        ActiveApexInfoList list = getActiveApexInfoList();
        final String statsdApexPath = list.get("com.android.os.statsd").path;
        final String adbdApexPath = list.get("com.android.adbd").path;

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
        File microdroidConfigFile = new File(virtApexEtcDir, "microdroid.json");
        JSONObject config = new JSONObject(FileUtil.readStringFromFile(microdroidConfigFile));

        // Replace paths so that the config uses re-signed images from TEST_ROOT
        config.put("bootloader", config.getString("bootloader").replace(VIRT_APEX, TEST_ROOT));
        JSONArray disks = config.getJSONArray("disks");
        for (int diskIndex = 0; diskIndex < disks.length(); diskIndex++) {
            JSONObject disk = disks.getJSONObject(diskIndex);
            JSONArray partitions = disk.getJSONArray("partitions");
            for (int partIndex = 0; partIndex < partitions.length(); partIndex++) {
                JSONObject part = partitions.getJSONObject(partIndex);
                part.put("path", part.getString("path").replace(VIRT_APEX, TEST_ROOT));
            }
        }

        // Add partitions to the second disk
        final String vbmetaPath = TEST_ROOT + "etc/fs/microdroid_vbmeta_bootconfig.img";
        final String bootconfigPath = TEST_ROOT + "etc/fs/microdroid_bootconfig.full_debuggable";
        disks.getJSONObject(1)
                .getJSONArray("partitions")
                .put(newPartition("vbmeta", vbmetaPath))
                .put(newPartition("bootconfig", bootconfigPath))
                .put(newPartition("vm-instance", instanceImgPath));

        // Add payload image disk with partitions:
        // - payload-metadata
        // - apexes: com.android.os.statsd, com.android.adbd
        // - apk and idsig
        disks.put(
                new JSONObject()
                        .put("writable", false)
                        .put(
                                "partitions",
                                new JSONArray()
                                        .put(newPartition("payload-metadata", payloadMetadataPath))
                                        .put(newPartition("com.android.os.statsd", statsdApexPath))
                                        .put(newPartition("com.android.adbd", adbdApexPath))
                                        .put(newPartition("microdroid-apk", apkPath))
                                        .put(newPartition("microdroid-apk-idsig", idSigPath))));

        config.put("protected", isProtected);

        // Write updated raw config
        final String configPath = TEST_ROOT + "raw_config.json";
        getDevice().pushString(config.toString(), configPath);

        final String logPath = LOG_PATH;
        final String ret =
                android.runWithTimeout(
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
    @CddTest(requirements = {"9.17/C-2-1", "9.17/C-2-2", "9.17/C-2-6"})
    public void testBootFailsWhenProtectedVmStartsWithImagesSignedWithDifferentKey()
            throws Exception {
        assumeTrue(isProtectedVmSupported());

        File key = findTestFile("test.com.android.virt.pem");
        Map<String, File> keyOverrides = Map.of();
        boolean isProtected = true;
        boolean daemonize = false; // VM should shut down due to boot failure.
        String consolePath = TEST_ROOT + "console";
        runMicrodroidWithResignedImages(key, keyOverrides, isProtected, daemonize, consolePath);
        assertThat(getDevice().pullFileContents(consolePath), containsString("pvmfw boot failed"));
    }

    @Test
    @CddTest(requirements = {"9.17/C-2-2", "9.17/C-2-6"})
    public void testBootSucceedsWhenNonProtectedVmStartsWithImagesSignedWithDifferentKey()
            throws Exception {
        File key = findTestFile("test.com.android.virt.pem");
        Map<String, File> keyOverrides = Map.of();
        boolean isProtected = false;
        boolean daemonize = true;
        String consolePath = TEST_ROOT + "console";
        String cid =
                runMicrodroidWithResignedImages(
                        key, keyOverrides, isProtected, daemonize, consolePath);
        // Adb connection to the microdroid means that boot succeeded.
        adbConnectToMicrodroid(getDevice(), cid);
        shutdownMicrodroid(getDevice(), cid);
    }

    @Test
    @CddTest(requirements = {"9.17/C-2-2", "9.17/C-2-6"})
    public void testBootFailsWhenBootloaderAndVbMetaAreSignedWithDifferentKeys() throws Exception {
        // Sign everything with key1 except vbmeta
        File key = findTestFile("test.com.android.virt.pem");
        File key2 = findTestFile("test2.com.android.virt.pem");
        Map<String, File> keyOverrides = Map.of("microdroid_vbmeta.img", key2);
        boolean isProtected = false; // Not interested in pvwfw
        boolean daemonize = true; // Bootloader fails and enters prompts.
        // To be able to stop it, it should be a daemon.
        String consolePath = TEST_ROOT + "console";
        String cid =
                runMicrodroidWithResignedImages(
                        key, keyOverrides, isProtected, daemonize, consolePath);
        // Wail for a while so that bootloader prints errors to console
        assertThatEventually(
                10000,
                () -> getDevice().pullFileContents(consolePath),
                containsString("Public key was rejected"));
        shutdownMicrodroid(getDevice(), cid);
    }

    @Test
    @CddTest(requirements = {"9.17/C-2-2", "9.17/C-2-6"})
    public void testBootSucceedsWhenBootloaderAndVbmetaHaveSameSigningKeys() throws Exception {
        // Sign everything with key1 except bootloader and vbmeta
        File key = findTestFile("test.com.android.virt.pem");
        File key2 = findTestFile("test2.com.android.virt.pem");
        Map<String, File> keyOverrides =
                Map.of(
                        "microdroid_bootloader", key2,
                        "microdroid_vbmeta.img", key2,
                        "microdroid_vbmeta_bootconfig.img", key2);
        boolean isProtected = false; // Not interested in pvwfw
        boolean daemonize = true; // Bootloader should succeed.
        // To be able to stop it, it should be a daemon.
        String consolePath = TEST_ROOT + "console";
        String cid =
                runMicrodroidWithResignedImages(
                        key, keyOverrides, isProtected, daemonize, consolePath);
        // Adb connection to the microdroid means that boot succeeded.
        adbConnectToMicrodroid(getDevice(), cid);
        shutdownMicrodroid(getDevice(), cid);
    }

    private boolean isTombstoneGeneratedWithConfig(String configPath) throws Exception {
        // Note this test relies on logcat values being printed by tombstone_transmit on
        // and the reeceiver on host (virtualization_service)
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
        // check until microdroid is shut down
        CommandRunner android = new CommandRunner(getDevice());
        android.runWithTimeout(15000, "logcat", "-m", "1", "-e", "'crosvm has exited normally'");
        // Check that tombstone is received (from host logcat)
        String result =
                runOnHost(
                        "adb",
                        "-s",
                        getDevice().getSerialNumber(),
                        "logcat",
                        "-d",
                        "-e",
                        "Received [0-9]+ bytes from guest & wrote to tombstone file");
        return !result.trim().isEmpty();
    }

    @Test
    public void testTombstonesAreGeneratedUponCrash() throws Exception {
        assertTrue(isTombstoneGeneratedWithConfig("assets/vm_config_crash.json"));
    }

    @Test
    public void testTombstonesAreNotGeneratedIfNotExported() throws Exception {
        assertFalse(isTombstoneGeneratedWithConfig("assets/vm_config_crash_no_tombstone.json"));
    }

    @Test
    @CddTest(requirements = {"9.17/C-1-1", "9.17/C-1-2", "9.17/C/1-3"})
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
        waitForBootComplete();
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
        CommandRunner android = new CommandRunner(getDevice());
        assertThat(
                android.tryRun("egrep", "'avc:[[:space:]]{1,2}denied'", LOG_PATH), is(nullValue()));

        assertThat(
                runOnMicrodroid("cat /proc/cpuinfo | grep processor | wc -l"),
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
            assertWithMessage("neverallow check failed: " + result.getStderr().trim())
                    .about(command_results())
                    .that(result)
                    .isSuccess();
        }

        shutdownMicrodroid(getDevice(), cid);
    }

    @Test
    public void testCustomVirtualMachinePermission()
            throws DeviceNotAvailableException, IOException, JSONException {
        assumeTrue(isProtectedVmSupported());
        CommandRunner android = new CommandRunner(getDevice());

        // Pull etc/microdroid.json
        File virtApexDir = FileUtil.createTempDir("virt_apex");
        File microdroidConfigFile = new File(virtApexDir, "microdroid.json");
        assertTrue(getDevice().pullFile(VIRT_APEX + "etc/microdroid.json", microdroidConfigFile));
        JSONObject config = new JSONObject(FileUtil.readStringFromFile(microdroidConfigFile));

        // USE_CUSTOM_VIRTUAL_MACHINE is enforced only on protected mode
        config.put("protected", true);

        // Write updated config
        final String configPath = TEST_ROOT + "raw_config.json";
        getDevice().pushString(config.toString(), configPath);

        // temporarily revoke the permission
        android.run(
                "pm",
                "revoke",
                SHELL_PACKAGE_NAME,
                "android.permission.USE_CUSTOM_VIRTUAL_MACHINE");
        final String ret =
                android.runForResult(VIRT_APEX + "bin/vm run", configPath).getStderr().trim();

        assertThat(ret)
                .contains(
                        "does not have the android.permission.USE_CUSTOM_VIRTUAL_MACHINE"
                                + " permission");
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

        archiveLogThenDelete(
                mTestLogs, getDevice(), LOG_PATH, "vm.log-" + mTestName.getMethodName());

        getDevice().uninstallPackage(PACKAGE_NAME);

        // testCustomVirtualMachinePermission revokes this permission. Grant it again as cleanup
        new CommandRunner(getDevice())
                .tryRun(
                        "pm",
                        "grant",
                        SHELL_PACKAGE_NAME,
                        "android.permission.USE_CUSTOM_VIRTUAL_MACHINE");
    }
}
