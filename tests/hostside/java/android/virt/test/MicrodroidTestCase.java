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
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeThat;

import com.android.compatibility.common.tradefed.build.CompatibilityBuildHelper;
import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
import com.android.tradefed.util.CommandResult;
import com.android.tradefed.util.CommandStatus;
import com.android.tradefed.util.RunUtil;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

@RunWith(DeviceJUnit4ClassRunner.class)
public class MicrodroidTestCase extends BaseHostJUnit4Test {
    private static final String TEST_ROOT = "/data/local/tmp/virt/";
    private static final String VIRT_APEX = "/apex/com.android.virt/";
    private static final int TEST_VM_CID = 10;
    private static final int TEST_VM_ADB_PORT = 8000;
    private static final String MICRODROID_SERIAL = "localhost:" + TEST_VM_ADB_PORT;

    // This is really slow on GCE (2m 40s) but fast on localhost or actual Android phones (< 10s)
    // Set the maximum timeout value big enough.
    private static final long MICRODROID_BOOT_TIMEOUT_MINUTES = 5;

    @Test
    public void testMicrodroidBoots() throws Exception {
        startMicrodroid("MicrodroidTestApp.apk", "com.android.microdroid.test");
        waitForMicrodroidBoot(MICRODROID_BOOT_TIMEOUT_MINUTES);
        adbConnectToMicrodroid();

        // Check if it actually booted by reading a sysprop.
        assertThat(runOnMicrodroid("getprop", "ro.hardware"), is("microdroid"));

        // Test writing to /data partition
        runOnMicrodroid("echo MicrodroidTest > /data/local/tmp/test.txt");
        assertThat(runOnMicrodroid("cat /data/local/tmp/test.txt"), is("MicrodroidTest"));

        // Check if the APK partition exists
        final String apkPartition = "/dev/block/by-name/microdroid-apk";
        assertThat(runOnMicrodroid("ls", apkPartition), is(apkPartition));

        // Check if the APK is mounted using zipfuse
        final String mountEntry = "zipfuse on /mnt/apk type fuse.zipfuse";
        assertThat(runOnMicrodroid("mount"), containsString(mountEntry));

        // Check if the native library in the APK is has correct filesystem info
        final String[] abis = runOnMicrodroid("getprop", "ro.product.cpu.abilist").split(",");
        assertThat(abis.length, is(1));
        final String testLib = "/mnt/apk/lib/" + abis[0] + "/MicrodroidTestNativeLib.so";
        final String label = "u:object_r:system_file:s0";
        assertThat(runOnMicrodroid("ls", "-Z", testLib), is(label + " " + testLib));

        // Execute the library and check the result
        final String microdroidLauncher = "system/bin/microdroid_launcher";
        assertThat(
                runOnMicrodroid(microdroidLauncher, testLib, "arg1", "arg2"),
                is("Hello Microdroid " + testLib + " arg1 arg2"));

        // Shutdown microdroid
        runOnMicrodroid("reboot");
    }

    // Run an arbitrary command in the host side and returns the result
    private String runOnHost(String... cmd) {
        final long timeout = 10000;
        CommandResult result = RunUtil.getDefault().runTimedCmd(timeout, cmd);
        assertThat(result.getStatus(), is(CommandStatus.SUCCESS));
        return result.getStdout().trim();
    }

    // Same as runOnHost, but failure is not an error
    private String tryRunOnHost(String... cmd) {
        final long timeout = 10000;
        CommandResult result = RunUtil.getDefault().runTimedCmd(timeout, cmd);
        return result.getStdout().trim();
    }

    // Run a shell command on Android
    private String runOnAndroid(String... cmd) throws Exception {
        CommandResult result = getDevice().executeShellV2Command(join(cmd));
        assertThat(result.getStatus(), is(CommandStatus.SUCCESS));
        return result.getStdout().trim();
    }

    // Same as runOnAndroid, but failutre is not an error
    private String tryRunOnAndroid(String... cmd) throws Exception {
        CommandResult result = getDevice().executeShellV2Command(join(cmd));
        return result.getStdout().trim();
    }

    // Run a shell command on Microdroid
    private String runOnMicrodroid(String... cmd) {
        final long timeout = 3000; // 3 sec. Microdroid is extremely slow on GCE-on-CF.
        CommandResult result =
                RunUtil.getDefault()
                        .runTimedCmd(timeout, "adb", "-s", MICRODROID_SERIAL, "shell", join(cmd));
        assertThat(result.getStatus(), is(CommandStatus.SUCCESS));
        return result.getStdout().trim();
    }

    private String join(String... strs) {
        return String.join(" ", Arrays.asList(strs));
    }

    private void startMicrodroid(String apkFile, String packageName) throws Exception {
        // Tools and executables
        final String mkCdisk = VIRT_APEX + "bin/mk_cdisk";
        final String mkPayload = VIRT_APEX + "bin/mk_payload";
        final String crosvm = VIRT_APEX + "bin/crosvm";

        // Input files
        final String cdiskJson = VIRT_APEX + "etc/microdroid_cdisk.json";
        final String cdiskEnvJson = VIRT_APEX + "etc/microdroid_cdisk_env.json";
        final String payloadJsonOrig = VIRT_APEX + "etc/microdroid_payload.json";
        final String bootloader = VIRT_APEX + "etc/microdroid_bootloader";

        // Generated files
        final String payloadJson = TEST_ROOT + "payload.json";
        final String testApkIdsig = TEST_ROOT + apkFile + ".idsig";

        // Image files created
        final String miscImg = TEST_ROOT + "misc.img";
        final String osImg = TEST_ROOT + "os_composite.img";
        final String envImg = TEST_ROOT + "env_composite.img";
        final String payloadImg = TEST_ROOT + "payload.img";

        // Create misc.img
        // TODO(jiyong) remove this step
        runOnAndroid("dd", "if=/dev/zero", "of=" + miscImg, "bs=4k", "count=256");

        // Create os_composite.img, env_composite.img
        runOnAndroid(mkCdisk, cdiskJson, osImg);
        runOnAndroid(mkCdisk, cdiskEnvJson, envImg);

        // Push the idsig file to the device
        // TODO(b/190343842): pass this file to mk_payload
        File idsigOnHost =
                (new CompatibilityBuildHelper(getBuild())).getTestFile(apkFile + ".idsig");
        getDevice().pushFile(idsigOnHost, testApkIdsig);

        // Create payload.img from microdroid_payload.json. APK_PATH marker in the file is
        // replaced with the actual path to the test APK.

        // Get the path to the installed apk. Note that
        // getDevice().getAppPackageInfo(...).getCodePath() doesn't work due to the incorrect
        // parsing of the "=" character. (b/190975227). So we use the `pm path` command directly.
        String testApk = runOnAndroid("pm", "path", packageName);
        assertTrue(testApk.startsWith("package:"));
        testApk = testApk.substring("package:".length());
        testApk = testApk.replace("/", "\\\\/"); // escape slash
        runOnAndroid("sed", "s/APK_PATH/" + testApk + "/", payloadJsonOrig, ">", payloadJson);
        runOnAndroid(mkPayload, payloadJson, payloadImg);

        // Make sure that the images are actually created
        assertThat(runOnAndroid("du", "-b", osImg, envImg, payloadImg), is(not("")));

        // Start microdroid using crosvm
        ExecutorService executor = Executors.newFixedThreadPool(1);
        executor.execute(
                () -> {
                    try {
                        runOnAndroid(
                                crosvm,
                                "run",
                                "--cid=" + TEST_VM_CID,
                                "--disable-sandbox",
                                "--bios=" + bootloader,
                                "--serial=type=syslog",
                                "--disk=" + osImg,
                                "--disk=" + envImg,
                                "--disk=" + payloadImg,
                                "&");
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                });
    }

    private void waitForMicrodroidBoot(long timeoutMinutes) throws Exception {
        // Wait for a specific log from logd
        // TODO(jiyong): use a more reasonable marker
        final String pattern = "logd.auditd: start";
        getDevice()
                .executeShellV2Command(
                        "logcat --regex=\"" + pattern + "\" -m 1",
                        timeoutMinutes,
                        TimeUnit.MINUTES);
    }

    // Establish an adb connection to microdroid by letting Android forward the connection to
    // microdroid.
    private void adbConnectToMicrodroid() {
        final String serial = getDevice().getSerialNumber();
        final String from = "tcp:" + TEST_VM_ADB_PORT;
        final String to = "vsock:" + TEST_VM_CID + ":5555";
        runOnHost("adb", "-s", serial, "forward", from, to);
        runOnHost("adb", "connect", MICRODROID_SERIAL);
    }

    private void skipIfFail(String command) throws Exception {
        CommandResult result = getDevice().executeShellV2Command(command);
        assumeThat(result.getStatus(), is(CommandStatus.SUCCESS));
    }

    @Before
    public void testIfDeviceIsCapable() throws Exception {
        // Checks the preconditions to run microdroid. If the condition is not satisfied
        // don't run the test (instead of failing)
        skipIfFail("ls /dev/kvm");
        skipIfFail("ls /dev/vhost-vsock");
        skipIfFail("ls /apex/com.android.virt/bin/crosvm");
    }

    @Before
    public void setUp() throws Exception {
        // kill stale crosvm processes
        tryRunOnAndroid("killall", "crosvm");

        // Prepare the test root
        tryRunOnAndroid("rm", "-rf", TEST_ROOT);
        tryRunOnAndroid("mkdir", "-p", TEST_ROOT);

        // disconnect from microdroid
        tryRunOnHost("adb", "disconnect", MICRODROID_SERIAL);

        // clear the log
        tryRunOnAndroid("logcat", "-c");
    }

    @After
    public void shutdown() throws Exception {
        // disconnect from microdroid
        tryRunOnHost("adb", "disconnect", MICRODROID_SERIAL);

        // kill stale crosvm processes
        tryRunOnAndroid("killall", "crosvm");
    }
}
