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

package com.android.microdroid.test.host;

import static com.android.microdroid.test.host.CommandResultSubject.assertThat;
import static com.android.microdroid.test.host.CommandResultSubject.command_results;
import static com.android.tradefed.testtype.DeviceJUnit4ClassRunner.TestLogData;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth.assertWithMessage;

import static org.junit.Assume.assumeTrue;

import com.android.compatibility.common.tradefed.build.CompatibilityBuildHelper;
import com.android.microdroid.test.common.MetricsProcessor;
import com.android.tradefed.build.IBuildInfo;
import com.android.tradefed.device.DeviceNotAvailableException;
import com.android.tradefed.device.ITestDevice;
import com.android.tradefed.device.TestDevice;
import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
import com.android.tradefed.util.CommandResult;
import com.android.tradefed.util.RunUtil;
import com.android.virt.VirtualizationTestHelper;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public abstract class MicrodroidHostTestCaseBase extends BaseHostJUnit4Test {
    protected static final String TEST_ROOT = "/data/local/tmp/virt/";
    protected static final String VIRT_APEX = "/apex/com.android.virt/";
    protected static final String LOG_PATH = TEST_ROOT + "log.txt";
    protected static final String CONSOLE_PATH = TEST_ROOT + "console.txt";
    private static final int TEST_VM_ADB_PORT = 8000;
    private static final String MICRODROID_SERIAL = "localhost:" + TEST_VM_ADB_PORT;
    private static final String INSTANCE_IMG = "instance.img";

    // This is really slow on GCE (2m 40s) but fast on localhost or actual Android phones (< 10s).
    // Then there is time to run the actual task. Set the maximum timeout value big enough.
    private static final long MICRODROID_MAX_LIFETIME_MINUTES = 20;

    private static final long MICRODROID_ADB_CONNECT_TIMEOUT_MINUTES = 5;
    protected static final long MICRODROID_COMMAND_TIMEOUT_MILLIS = 30000;
    private static final long MICRODROID_COMMAND_RETRY_INTERVAL_MILLIS = 500;
    protected static final int MICRODROID_ADB_CONNECT_MAX_ATTEMPTS =
            (int) (MICRODROID_ADB_CONNECT_TIMEOUT_MINUTES * 60 * 1000
                / MICRODROID_COMMAND_RETRY_INTERVAL_MILLIS);

    public static void prepareVirtualizationTestSetup(ITestDevice androidDevice)
            throws DeviceNotAvailableException {
        CommandRunner android = new CommandRunner(androidDevice);

        // kill stale crosvm processes
        android.tryRun("killall", "crosvm");

        // disconnect from microdroid
        tryRunOnHost("adb", "disconnect", MICRODROID_SERIAL);

        // remove any leftover files under test root
        android.tryRun("rm", "-rf", TEST_ROOT + "*");
    }

    public static void cleanUpVirtualizationTestSetup(ITestDevice androidDevice)
            throws DeviceNotAvailableException {
        CommandRunner android = new CommandRunner(androidDevice);

        // disconnect from microdroid
        tryRunOnHost("adb", "disconnect", MICRODROID_SERIAL);

        // kill stale VMs and directories
        android.tryRun("killall", "crosvm");
        android.tryRun("stop", "virtualizationservice");
        android.tryRun("rm", "-rf", "/data/misc/virtualizationservice/*");
    }

    protected boolean isCuttlefish() throws Exception {
        return VirtualizationTestHelper.isCuttlefish(
            getDevice().getProperty("ro.product.vendor.device"));
    }

    protected String getMetricPrefix() throws Exception {
        return MetricsProcessor.getMetricPrefix(
                getDevice().getProperty("debug.hypervisor.metrics_tag"));
    }

    public static void testIfDeviceIsCapable(ITestDevice androidDevice) throws Exception {
        assumeTrue("Need an actual TestDevice", androidDevice instanceof TestDevice);
        TestDevice testDevice = (TestDevice) androidDevice;
        assumeTrue("Requires VM support", testDevice.supportsMicrodroid());
    }

    public static void archiveLogThenDelete(TestLogData logs, ITestDevice device, String remotePath,
            String localName) throws DeviceNotAvailableException {
        LogArchiver.archiveLogThenDelete(logs, device, remotePath, localName);
    }

    // Run an arbitrary command in the host side and returns the result
    public static String runOnHost(String... cmd) {
        return runOnHostWithTimeout(10000, cmd);
    }

    // Same as runOnHost, but failure is not an error
    private static String tryRunOnHost(String... cmd) {
        final long timeout = 10000;
        CommandResult result = RunUtil.getDefault().runTimedCmd(timeout, cmd);
        return result.getStdout().trim();
    }

    // Same as runOnHost, but with custom timeout
    private static String runOnHostWithTimeout(long timeoutMillis, String... cmd) {
        assertThat(timeoutMillis).isAtLeast(0);
        CommandResult result = RunUtil.getDefault().runTimedCmd(timeoutMillis, cmd);
        assertThat(result).isSuccess();
        return result.getStdout().trim();
    }

    // Run a shell command on Microdroid
    public static String runOnMicrodroid(String... cmd) {
        CommandResult result = runOnMicrodroidForResult(cmd);
        assertWithMessage("microdroid shell cmd `" + join(cmd) + "`")
                .about(command_results())
                .that(result)
                .isSuccess();
        return result.getStdout().trim();
    }

    // Same as runOnHost, but keeps retrying on error for maximum attempts times
    // Each attempt with timeoutMs
    public static String runOnHostRetryingOnFailure(long timeoutMs, int attempts, String... cmd) {
        CommandResult result = RunUtil.getDefault()
                .runTimedCmdRetry(timeoutMs,
                        MICRODROID_COMMAND_RETRY_INTERVAL_MILLIS, attempts, cmd);
        assertWithMessage("Command `" + Arrays.toString(cmd) + "` has failed")
                .about(command_results())
                .that(result)
                .isSuccess();
        return result.getStdout().trim();
    }

    // Same as runOnMicrodroid, but keeps retrying on error for maximum attempts times
    // Each attempt with timeoutMs
    public static String runOnMicrodroidRetryingOnFailure(
            long timeoutMs, int attempts, String... cmd) {
        CommandResult result = RunUtil.getDefault()
                .runTimedCmdRetry(timeoutMs, MICRODROID_COMMAND_RETRY_INTERVAL_MILLIS, attempts,
                        "adb", "-s", MICRODROID_SERIAL, "shell", join(cmd));
        assertWithMessage("Command `" + Arrays.toString(cmd) + "` has failed")
                .about(command_results())
                .that(result)
                .isSuccess();
        return result.getStdout().trim();
    }

    public static CommandResult runOnMicrodroidForResult(String... cmd) {
        final long timeoutMs = 30000; // 30 sec. Microdroid is extremely slow on GCE-on-CF.
        return RunUtil.getDefault()
                .runTimedCmd(timeoutMs, "adb", "-s", MICRODROID_SERIAL, "shell", join(cmd));
    }

    public static void pullMicrodroidFile(String path, File target) {
        final long timeoutMs = 30000; // 30 sec. Microdroid is extremely slow on GCE-on-CF.
        CommandResult result =
                RunUtil.getDefault()
                        .runTimedCmd(
                                timeoutMs,
                                "adb",
                                "-s",
                                MICRODROID_SERIAL,
                                "pull",
                                path,
                                target.getPath());
        assertWithMessage("pulling " + path + " from microdroid")
                .about(command_results())
                .that(result)
                .isSuccess();
    }

    // Asserts the command will fail on Microdroid.
    public static void assertFailedOnMicrodroid(String... cmd) {
        assertThat(runOnMicrodroidForResult(cmd)).isFailed();
    }

    private static String join(String... strs) {
        return String.join(" ", Arrays.asList(strs));
    }

    public File findTestFile(String name) {
        return findTestFile(getBuild(), name);
    }

    private static File findTestFile(IBuildInfo buildInfo, String name) {
        try {
            return (new CompatibilityBuildHelper(buildInfo)).getTestFile(name);
        } catch (FileNotFoundException e) {
            throw new AssertionError("Missing test file: " + name, e);
        }
    }

    public String getPathForPackage(String packageName)
            throws DeviceNotAvailableException {
        return getPathForPackage(getDevice(), packageName);
    }

    // Get the path to the installed apk. Note that
    // getDevice().getAppPackageInfo(...).getCodePath() doesn't work due to the incorrect
    // parsing of the "=" character. (b/190975227). So we use the `pm path` command directly.
    private static String getPathForPackage(ITestDevice device, String packageName)
            throws DeviceNotAvailableException {
        CommandRunner android = new CommandRunner(device);
        String pathLine = android.run("pm", "path", packageName);
        assertWithMessage("Package " + packageName + " not found")
                .that(pathLine).startsWith("package:");
        return pathLine.substring("package:".length());
    }

    public static String startMicrodroid(
            ITestDevice androidDevice,
            IBuildInfo buildInfo,
            String apkName,
            String packageName,
            String configPath,
            boolean debug,
            int memoryMib,
            Optional<Integer> numCpus)
            throws DeviceNotAvailableException {
        return startMicrodroid(androidDevice, buildInfo, apkName, packageName, null, configPath,
                debug, memoryMib, numCpus);
    }

    public static String startMicrodroid(
            ITestDevice androidDevice,
            IBuildInfo buildInfo,
            String apkName,
            String packageName,
            String[] extraIdsigPaths,
            String configPath,
            boolean debug,
            int memoryMib,
            Optional<Integer> numCpus)
            throws DeviceNotAvailableException {
        return startMicrodroid(androidDevice, buildInfo, apkName, null, packageName,
                extraIdsigPaths, configPath, debug,
                memoryMib, numCpus);
    }

    private static void forwardFileToLog(CommandRunner android, String path, String tag)
            throws DeviceNotAvailableException {
        android.runWithTimeout(
                MICRODROID_MAX_LIFETIME_MINUTES * 60 * 1000,
                "logwrapper",
                "sh",
                "-c",
                "\"$'tail -f -n +0 " + path
                        + " | sed \\'s/^/" + tag + ": /g\\''\""); // add tags in front of lines
    }

    public static String startMicrodroid(
            ITestDevice androidDevice,
            IBuildInfo buildInfo,
            String apkName,
            String apkPath,
            String packageName,
            String[] extraIdsigPaths,
            String configPath,
            boolean debug,
            int memoryMib,
            Optional<Integer> numCpus)
            throws DeviceNotAvailableException {
        CommandRunner android = new CommandRunner(androidDevice);

        // Install APK if necessary
        if (apkName != null) {
            File apkFile = findTestFile(buildInfo, apkName);
            androidDevice.installPackage(apkFile, /* reinstall */ true);
        }

        if (apkPath == null) {
            apkPath = getPathForPackage(androidDevice, packageName);
        }

        android.run("mkdir", "-p", TEST_ROOT);

        // This file is not what we provide. It will be created by the vm tool.
        final String outApkIdsigPath = TEST_ROOT + apkName + ".idsig";

        final String instanceImg = TEST_ROOT + INSTANCE_IMG;
        final String logPath = LOG_PATH;
        final String consolePath = CONSOLE_PATH;
        final String debugFlag = debug ? "--debug full" : "";

        // Run the VM
        ArrayList<String> args = new ArrayList<>(Arrays.asList(
                VIRT_APEX + "bin/vm",
                "run-app",
                "--daemonize",
                "--log " + logPath,
                "--console " + consolePath,
                "--mem " + memoryMib,
                numCpus.isPresent() ? "--cpus " + numCpus.get() : "",
                debugFlag,
                apkPath,
                outApkIdsigPath,
                instanceImg,
                configPath));
        if (extraIdsigPaths != null) {
            for (String path : extraIdsigPaths) {
                args.add("--extra-idsig");
                args.add(path);
            }
        }
        String ret = android.run(args.toArray(new String[0]));

        // Redirect log.txt and console.txt to logd using logwrapper
        // Keep redirecting as long as the expecting maximum test time. When an adb
        // command times out, it may trigger the device recovery process, which
        // disconnect adb, which terminates any live adb commands. See an example at
        // b/194974010#comment25.
        ExecutorService executor = Executors.newFixedThreadPool(2);
        executor.execute(
                () -> {
                    try {
                        forwardFileToLog(android, logPath, "MicrodroidLog");
                    } catch (Exception e) {
                        // Consume
                    }
                });

        executor.execute(
                () -> {
                    try {
                        forwardFileToLog(android, consolePath, "MicrodroidConsole");
                    } catch (Exception e) {
                        // Consume
                    }
                });

        // Retrieve the CID from the vm tool output
        Pattern pattern = Pattern.compile("with CID (\\d+)");
        Matcher matcher = pattern.matcher(ret);
        assertWithMessage("Failed to find CID").that(matcher.find()).isTrue();
        return matcher.group(1);
    }

    public static void shutdownMicrodroid(ITestDevice androidDevice, String cid)
            throws DeviceNotAvailableException {
        CommandRunner android = new CommandRunner(androidDevice);

        // Shutdown the VM
        android.run(VIRT_APEX + "bin/vm", "stop", cid);
    }

    public static void rootMicrodroid() throws InterruptedException {
        runOnHostRetryingOnFailure(MICRODROID_COMMAND_TIMEOUT_MILLIS,
                MICRODROID_ADB_CONNECT_MAX_ATTEMPTS, "adb", "-s", MICRODROID_SERIAL, "root");
        // adbd reboots after root. Some commands (including wait-for-device) following this fails
        // with error: closed. Hence, we disconnect and re-connect to the device before returning.
        runOnHostRetryingOnFailure(MICRODROID_COMMAND_TIMEOUT_MILLIS,
                MICRODROID_ADB_CONNECT_MAX_ATTEMPTS, "adb", "disconnect", MICRODROID_SERIAL);
        runOnHostRetryingOnFailure(MICRODROID_COMMAND_TIMEOUT_MILLIS,
                MICRODROID_ADB_CONNECT_MAX_ATTEMPTS, "adb", "connect", MICRODROID_SERIAL);
    }

    // Establish an adb connection to microdroid by letting Android forward the connection to
    // microdroid. Wait until the connection is established and microdroid is booted.
    public static void adbConnectToMicrodroid(ITestDevice androidDevice, String cid) {
        long start = System.currentTimeMillis();
        long timeoutMillis = MICRODROID_ADB_CONNECT_TIMEOUT_MINUTES * 60 * 1000;
        long elapsed = 0;

        // In case there is a stale connection...
        tryRunOnHost("adb", "disconnect", MICRODROID_SERIAL);

        final String serial = androidDevice.getSerialNumber();
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
                // b/194375443: this somtimes fails, thus 'try*'.
                tryRunOnHost("adb", "disconnect", MICRODROID_SERIAL);
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

        // Check if it actually booted by reading a sysprop.
        assertThat(runOnMicrodroidForResult("getprop", "ro.hardware"))
                .stdoutTrimmed()
                .isEqualTo("microdroid");
    }

    public boolean isProtectedVmSupported() throws DeviceNotAvailableException {
        return getDevice().getBooleanProperty("ro.boot.hypervisor.protected_vm.supported", false);
    }
}
