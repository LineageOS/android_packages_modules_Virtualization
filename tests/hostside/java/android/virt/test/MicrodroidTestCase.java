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
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeThat;

import com.android.compatibility.common.tradefed.build.CompatibilityBuildHelper;
import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
import com.android.tradefed.util.CommandResult;
import com.android.tradefed.util.CommandStatus;
import com.android.tradefed.util.RunUtil;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.zip.ZipFile;

@RunWith(DeviceJUnit4ClassRunner.class)
public class MicrodroidTestCase extends BaseHostJUnit4Test {
    private static final String TEST_ROOT = "/data/local/tmp/virt/";
    private static final String VIRT_APEX = "/apex/com.android.virt/";
    private static final int TEST_VM_ADB_PORT = 8000;
    private static final String MICRODROID_SERIAL = "localhost:" + TEST_VM_ADB_PORT;

    // This is really slow on GCE (2m 40s) but fast on localhost or actual Android phones (< 10s)
    // Set the maximum timeout value big enough.
    private static final long MICRODROID_BOOT_TIMEOUT_MINUTES = 5;

    @Test
    public void testMicrodroidBoots() throws Exception {
        final String apkName = "MicrodroidTestApp.apk";
        final String packageName = "com.android.microdroid.test";
        final String configPath = "assets/vm_config.json"; // path inside the APK
        final String cid = startMicrodroid(apkName, packageName, configPath);
        adbConnectToMicrodroid(cid, MICRODROID_BOOT_TIMEOUT_MINUTES);

        // Check if it actually booted by reading a sysprop.
        assertThat(runOnMicrodroid("getprop", "ro.hardware"), is("microdroid"));

        // Test writing to /data partition
        runOnMicrodroid("echo MicrodroidTest > /data/local/tmp/test.txt");
        assertThat(runOnMicrodroid("cat /data/local/tmp/test.txt"), is("MicrodroidTest"));

        // Check if the APK & its idsig partitions exist
        final String apkPartition = "/dev/block/by-name/microdroid-apk";
        assertThat(runOnMicrodroid("ls", apkPartition), is(apkPartition));
        final String apkIdsigPartition = "/dev/block/by-name/microdroid-apk-idsig";
        assertThat(runOnMicrodroid("ls", apkIdsigPartition), is(apkIdsigPartition));

        // Check if the APK is mounted using zipfuse
        final String mountEntry = "zipfuse on /mnt/apk type fuse.zipfuse";
        assertThat(runOnMicrodroid("mount"), containsString(mountEntry));

        // Check if the native library in the APK is has correct filesystem info
        final String[] abis = runOnMicrodroid("getprop", "ro.product.cpu.abilist").split(",");
        assertThat(abis.length, is(1));
        final String testLib = "/mnt/apk/lib/" + abis[0] + "/MicrodroidTestNativeLib.so";
        final String label = "u:object_r:system_file:s0";
        assertThat(runOnMicrodroid("ls", "-Z", testLib), is(label + " " + testLib));

        // Check if the command in vm_config.json was executed by examining the side effect of the
        // command
        assertThat(runOnMicrodroid("getprop", "debug.microdroid.app.run"), is("true"));

        // Manually execute the library and check the output
        final String microdroidLauncher = "system/bin/microdroid_launcher";
        assertThat(
                runOnMicrodroid(microdroidLauncher, testLib, "arg1", "arg2"),
                is("Hello Microdroid " + testLib + " arg1 arg2"));

        // Check that keystore was found by the payload
        assertThat(runOnMicrodroid("getprop", "debug.microdroid.test.keystore"), is("PASS"));

        // Shutdown microdroid
        runOnAndroid(VIRT_APEX + "bin/vm", "stop", cid);
    }

    // Run an arbitrary command in the host side and returns the result
    private String runOnHost(String... cmd) {
        return runOnHostWithTimeout(10000, cmd);
    }

    // Same as runOnHost, but failure is not an error
    private String tryRunOnHost(String... cmd) {
        final long timeout = 10000;
        CommandResult result = RunUtil.getDefault().runTimedCmd(timeout, cmd);
        return result.getStdout().trim();
    }

    // Same as runOnHost, but with custom timeout
    private String runOnHostWithTimeout(long timeoutMillis, String... cmd) {
        assertTrue(timeoutMillis >= 0);
        CommandResult result = RunUtil.getDefault().runTimedCmd(timeoutMillis, cmd);
        assertThat(result.getStatus(), is(CommandStatus.SUCCESS));
        return result.getStdout().trim();
    }

    // Run a shell command on Android
    private String runOnAndroid(String... cmd) throws Exception {
        CommandResult result = getDevice().executeShellV2Command(join(cmd));
        if (result.getStatus() != CommandStatus.SUCCESS) {
            fail(join(cmd) + " has failed: " + result);
        }
        return result.getStdout().trim();
    }

    // Same as runOnAndroid, but failutre is not an error
    private String tryRunOnAndroid(String... cmd) throws Exception {
        CommandResult result = getDevice().executeShellV2Command(join(cmd));
        return result.getStdout().trim();
    }

    // Run a shell command on Microdroid
    private String runOnMicrodroid(String... cmd) {
        final long timeout = 30000; // 30 sec. Microdroid is extremely slow on GCE-on-CF.
        CommandResult result =
                RunUtil.getDefault()
                        .runTimedCmd(timeout, "adb", "-s", MICRODROID_SERIAL, "shell", join(cmd));
        if (result.getStatus() != CommandStatus.SUCCESS) {
            fail(join(cmd) + " has failed: " + result);
        }
        return result.getStdout().trim();
    }

    private String join(String... strs) {
        return String.join(" ", Arrays.asList(strs));
    }

    private String createPayloadImage(String apkName, String packageName, String configPath)
            throws Exception {
        File apkFile = findTestFile(apkName);
        getDevice().installPackage(apkFile, /* reinstall */ true);

        // Read the config file from the apk and parse it to know the list of APEXes needed
        ZipFile apkAsZip = new ZipFile(apkFile);
        InputStream is = apkAsZip.getInputStream(apkAsZip.getEntry(configPath));
        String configString =
                new BufferedReader(new InputStreamReader(is))
                        .lines()
                        .collect(Collectors.joining("\n"));
        JSONObject configObject = new JSONObject(configString);
        JSONArray apexes = configObject.getJSONArray("apexes");
        List<String> apexNames = new ArrayList<>();
        for (int i = 0; i < apexes.length(); i++) {
            JSONObject anApex = apexes.getJSONObject(i);
            apexNames.add(anApex.getString("name"));
        }

        // Get the path to the installed apk. Note that
        // getDevice().getAppPackageInfo(...).getCodePath() doesn't work due to the incorrect
        // parsing of the "=" character. (b/190975227). So we use the `pm path` command directly.
        String apkPath = runOnAndroid("pm", "path", packageName);
        assertTrue(apkPath.startsWith("package:"));
        apkPath = apkPath.substring("package:".length());

        // Push the idsig file to the device
        File idsigOnHost = findTestFile(apkName + ".idsig");
        final String apkIdsigPath = TEST_ROOT + apkName + ".idsig";
        getDevice().pushFile(idsigOnHost, apkIdsigPath);

        // Create payload.json from the gathered data
        JSONObject payloadObject = new JSONObject();
        payloadObject.put("system_apexes", new JSONArray(apexNames));
        payloadObject.put("payload_config_path", "/mnt/apk/" + configPath);
        JSONObject apkObject = new JSONObject();
        apkObject.put("name", packageName);
        apkObject.put("path", apkPath);
        apkObject.put("idsig_path", apkIdsigPath);
        payloadObject.put("apk", apkObject);

        // Copy the json file to Android
        File payloadJsonOnHost = File.createTempFile("payload", "json");
        FileWriter writer = new FileWriter(payloadJsonOnHost);
        writer.write(payloadObject.toString());
        writer.close();
        final String payloadJson = TEST_ROOT + "payload.json";
        getDevice().pushFile(payloadJsonOnHost, payloadJson);

        // Finally run mk_payload to create payload.img
        final String mkPayload = VIRT_APEX + "bin/mk_payload";
        final String payloadImg = TEST_ROOT + "payload.img";
        runOnAndroid(mkPayload, payloadJson, payloadImg);
        assertThat(runOnAndroid("du", "-b", payloadImg), is(not("")));

        // The generated files are owned by root. Allow the virtualizationservice to read them.
        runOnAndroid("chmod", "go+r", TEST_ROOT + "payload*");

        return payloadImg;
    }

    private File findTestFile(String name) throws Exception {
        return (new CompatibilityBuildHelper(getBuild())).getTestFile(name);
    }

    private String startMicrodroid(String apkName, String packageName, String configPath)
            throws Exception {
        // Create payload.img
        createPayloadImage(apkName, packageName, configPath);

        // Run the VM
        runOnAndroid("start", "virtualizationservice");
        String ret =
                runOnAndroid(
                        VIRT_APEX + "bin/vm",
                        "run",
                        "--daemonize",
                        VIRT_APEX + "etc/microdroid.json");

        // Retrieve the CID from the vm tool output
        Pattern pattern = Pattern.compile("with CID (\\d+)");
        Matcher matcher = pattern.matcher(ret);
        assertTrue(matcher.find());
        return matcher.group(1);
    }

    // Establish an adb connection to microdroid by letting Android forward the connection to
    // microdroid. Wait until the connection is established and microdroid is booted.
    private void adbConnectToMicrodroid(String cid, long timeoutMinutes) throws Exception {
        long start = System.currentTimeMillis();
        long timeoutMillis = timeoutMinutes * 60 * 1000;
        long elapsed = 0;

        final String serial = getDevice().getSerialNumber();
        final String from = "tcp:" + TEST_VM_ADB_PORT;
        final String to = "vsock:" + cid + ":5555";
        runOnHost("adb", "-s", serial, "forward", from, to);

        boolean disconnected = true;
        while (disconnected) {
            elapsed = System.currentTimeMillis() - start;
            timeoutMillis -= elapsed;
            start = System.currentTimeMillis();
            String ret = runOnHostWithTimeout(timeoutMillis, "adb", "connect", MICRODROID_SERIAL);
            disconnected = ret.equals("failed to connect to " + MICRODROID_SERIAL);
            if (disconnected) {
                // adb demands us to disconnect if the prior connection was a failure.
                runOnHost("adb", "disconnect", MICRODROID_SERIAL);
            }
        }

        elapsed = System.currentTimeMillis() - start;
        timeoutMillis -= elapsed;
        runOnHostWithTimeout(timeoutMillis, "adb", "-s", MICRODROID_SERIAL, "wait-for-device");

        boolean dataAvailable = false;
        while (!dataAvailable && timeoutMillis >= 0) {
            elapsed = System.currentTimeMillis() - start;
            timeoutMillis -= elapsed;
            start = System.currentTimeMillis();
            final String checkCmd = "if [ -d /data/local/tmp ]; then echo 1; fi";
            dataAvailable = runOnMicrodroid(checkCmd).equals("1");
        }
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

        // kill stale VMs and directories
        tryRunOnAndroid("killall", "crosvm");
        tryRunOnAndroid("rm", "-rf", "/data/misc/virtualizationservice/*");
        tryRunOnAndroid("stop", "virtualizationservice");
    }
}
