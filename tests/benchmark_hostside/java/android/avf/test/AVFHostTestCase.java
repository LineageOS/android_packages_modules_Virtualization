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

package android.avf.test;

import static com.android.tradefed.testtype.DeviceJUnit4ClassRunner.TestMetrics;

import static com.google.common.truth.Truth.assertWithMessage;
import static com.google.common.truth.TruthJUnit.assume;

import static org.junit.Assume.assumeTrue;

import android.platform.test.annotations.RootPermissionTest;

import com.android.microdroid.test.common.MetricsProcessor;
import com.android.microdroid.test.host.CommandRunner;
import com.android.microdroid.test.host.MicrodroidHostTestCaseBase;
import com.android.tradefed.log.LogUtil.CLog;
import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
import com.android.tradefed.util.CommandResult;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@RootPermissionTest
@RunWith(DeviceJUnit4ClassRunner.class)
public final class AVFHostTestCase extends MicrodroidHostTestCaseBase {

    private static final String COMPOSD_CMD_BIN = "/apex/com.android.compos/bin/composd_cmd";

    // Files that define the "test" instance of CompOS
    private static final String COMPOS_TEST_ROOT = "/data/misc/apexdata/com.android.compos/test/";

    private static final String SYSTEM_SERVER_COMPILER_FILTER_PROP_NAME =
            "dalvik.vm.systemservercompilerfilter";

    /** Boot time test related variables */
    private static final int REINSTALL_APEX_RETRY_INTERVAL_MS = 5 * 1000;
    private static final int REINSTALL_APEX_TIMEOUT_SEC = 15;
    private static final int COMPILE_STAGED_APEX_RETRY_INTERVAL_MS = 10 * 1000;
    private static final int COMPILE_STAGED_APEX_TIMEOUT_SEC = 540;
    private static final int BOOT_COMPLETE_TIMEOUT_MS = 10 * 60 * 1000;
    private static final double NANOS_IN_SEC = 1_000_000_000.0;
    private static final int ROUND_COUNT = 5;
    private static final String METRIC_PREFIX = "avf_perf/hostside/";

    private final MetricsProcessor mMetricsProcessor = new MetricsProcessor(METRIC_PREFIX);

    @Before
    public void setUp() throws Exception {
        testIfDeviceIsCapable(getDevice());
    }

    @After
    public void tearDown() throws Exception {
        // Set PKVM enable and reboot to prevent previous staged session.
        setPKVMStatusWithRebootToBootloader(true);
        rebootFromBootloaderAndWaitBootCompleted();

        CommandRunner android = new CommandRunner(getDevice());

        // Clear up any CompOS instance files we created.
        android.tryRun("rm", "-rf", COMPOS_TEST_ROOT);
    }

    @Test
    public void testBootEnableAndDisablePKVM() throws Exception {
        testPKVMStatusSwitchSupported();

        List<Double> bootWithPKVMEnableTime = new ArrayList<>(ROUND_COUNT);
        List<Double> bootWithoutPKVMEnableTime = new ArrayList<>(ROUND_COUNT);

        for (int round = 0; round < ROUND_COUNT; ++round) {

            setPKVMStatusWithRebootToBootloader(true);
            long start = System.nanoTime();
            rebootFromBootloaderAndWaitBootCompleted();
            long elapsedWithPKVMEnable = System.nanoTime() - start;
            double elapsedSec = elapsedWithPKVMEnable / NANOS_IN_SEC;
            bootWithPKVMEnableTime.add(elapsedSec);
            CLog.i("Boot time with PKVM enable took " + elapsedSec + "s");

            setPKVMStatusWithRebootToBootloader(false);
            start = System.nanoTime();
            rebootFromBootloaderAndWaitBootCompleted();
            long elapsedWithoutPKVMEnable = System.nanoTime() - start;
            elapsedSec = elapsedWithoutPKVMEnable / NANOS_IN_SEC;
            bootWithoutPKVMEnableTime.add(elapsedSec);
            CLog.i("Boot time with PKVM disable took " + elapsedSec + "s");
        }

        reportMetric(bootWithPKVMEnableTime, "boot_time_with_pkvm_enable", "s");
        reportMetric(bootWithoutPKVMEnableTime, "boot_time_with_pkvm_disable", "s");
    }

    @Test
    public void testBootWithAndWithoutCompOS() throws Exception {
        assume().withMessage("Skip on CF; too slow").that(isCuttlefish()).isFalse();

        List<Double> bootWithCompOsTime = new ArrayList<>(ROUND_COUNT);
        List<Double> bootWithoutCompOsTime = new ArrayList<>(ROUND_COUNT);

        for (int round = 0; round < ROUND_COUNT; ++round) {

            // Boot time with compilation OS test.
            reInstallApex(REINSTALL_APEX_TIMEOUT_SEC);
            compileStagedApex(COMPILE_STAGED_APEX_TIMEOUT_SEC);
            getDevice().nonBlockingReboot();
            long start = System.nanoTime();
            waitForBootCompleted();
            long elapsedWithCompOS = System.nanoTime() - start;
            double elapsedSec = elapsedWithCompOS / NANOS_IN_SEC;
            bootWithCompOsTime.add(elapsedSec);
            CLog.i("Boot time with compilation OS took " + elapsedSec + "s");

            // Boot time without compilation OS test.
            reInstallApex(REINSTALL_APEX_TIMEOUT_SEC);
            getDevice().nonBlockingReboot();
            start = System.nanoTime();
            waitForBootCompleted();
            long elapsedWithoutCompOS = System.nanoTime() - start;
            elapsedSec = elapsedWithoutCompOS / NANOS_IN_SEC;
            bootWithoutCompOsTime.add(elapsedSec);
            CLog.i("Boot time without compilation OS took " + elapsedSec + "s");
        }

        reportMetric(bootWithCompOsTime, "boot_time_with_compos", "s");
        reportMetric(bootWithoutCompOsTime, "boot_time_without_compos", "s");
    }

    private void testPKVMStatusSwitchSupported() throws Exception {
        if (!getDevice().isStateBootloaderOrFastbootd()) {
            getDevice().rebootIntoBootloader();
        }
        getDevice().waitForDeviceBootloader();

        CommandResult result;
        result = getDevice().executeFastbootCommand("oem", "pkvm", "status");
        rebootFromBootloaderAndWaitBootCompleted();
        assumeTrue(!result.getStderr().contains("Invalid oem command"));
    }

    private void reportMetric(List<Double> data, String name, String unit) {
        Map<String, Double> stats = mMetricsProcessor.computeStats(data, name, unit);
        TestMetrics metrics = new TestMetrics();
        for (Map.Entry<String, Double> entry : stats.entrySet()) {
            metrics.addTestMetric(entry.getKey(), Double.toString(entry.getValue()));
        }
    }

    private void setPKVMStatusWithRebootToBootloader(boolean isEnable) throws Exception {

        if (!getDevice().isStateBootloaderOrFastbootd()) {
            getDevice().rebootIntoBootloader();
        }
        getDevice().waitForDeviceBootloader();

        CommandResult result;
        if (isEnable) {
            result = getDevice().executeFastbootCommand("oem", "pkvm", "enable");
        } else {
            result = getDevice().executeFastbootCommand("oem", "pkvm", "disable");
        }

        result = getDevice().executeFastbootCommand("oem", "pkvm", "status");
        CLog.i("Gets PKVM status : " + result);

        String expectedOutput = "";

        if (isEnable) {
            expectedOutput = "pkvm is enabled";
        } else {
            expectedOutput = "pkvm is disabled";
        }
        assertWithMessage("Failed to set PKVM status. Reason: " + result)
            .that(result.toString()).ignoringCase().contains(expectedOutput);

        // Skip the test if running on a build with pkvm_enabler. Disabling
        // pKVM for such build results in a bootloop.
        assertWithMessage("Expected build with PKVM status misc=auto. Reason: " + result)
            .that(result.toString()).ignoringCase().contains("misc=auto");
    }

    private void rebootFromBootloaderAndWaitBootCompleted() throws Exception {
        getDevice().executeFastbootCommand("reboot");
        getDevice().waitForDeviceOnline(BOOT_COMPLETE_TIMEOUT_MS);
        getDevice().waitForBootComplete(BOOT_COMPLETE_TIMEOUT_MS);
        getDevice().enableAdbRoot();
    }

    private void waitForBootCompleted() throws Exception {
        getDevice().waitForDeviceOnline(BOOT_COMPLETE_TIMEOUT_MS);
        getDevice().waitForBootComplete(BOOT_COMPLETE_TIMEOUT_MS);
        getDevice().enableAdbRoot();
    }

    private void compileStagedApex(int timeoutSec) throws Exception {

        long timeStart = System.currentTimeMillis();
        long timeEnd = timeStart + timeoutSec * 1000;

        while (true) {

            try {
                CommandRunner android = new CommandRunner(getDevice());

                String result = android.run(
                        COMPOSD_CMD_BIN + " staged-apex-compile");
                assertWithMessage("Failed to compile staged APEX. Reason: " + result)
                    .that(result).ignoringCase().contains("all ok");

                CLog.i("Success to compile staged APEX. Result: " + result);

                break;
            } catch (AssertionError e) {
                CLog.i("Gets AssertionError when compile staged APEX. Detail: " + e);
            }

            if (System.currentTimeMillis() > timeEnd) {
                CLog.e("Try to compile staged APEX several times but all fail.");
                throw new AssertionError("Failed to compile staged APEX.");
            }

            Thread.sleep(COMPILE_STAGED_APEX_RETRY_INTERVAL_MS);
        }
    }

    private void reInstallApex(int timeoutSec) throws Exception {

        long timeStart = System.currentTimeMillis();
        long timeEnd = timeStart + timeoutSec * 1000;

        while (true) {

            try {
                CommandRunner android = new CommandRunner(getDevice());

                String packagesOutput =
                        android.run("pm list packages -f --apex-only");

                Pattern p = Pattern.compile(
                        "package:(.*)=(com(?:\\.google)?\\.android\\.art)$", Pattern.MULTILINE);
                Matcher m = p.matcher(packagesOutput);
                assertWithMessage("ART module not found. Packages are:\n" + packagesOutput)
                    .that(m.find())
                    .isTrue();

                String artApexPath = m.group(1);

                CommandResult result = android.runForResult(
                        "pm install --apex " + artApexPath);
                assertWithMessage("Failed to install APEX. Reason: " + result)
                    .that(result.getExitCode()).isEqualTo(0);

                CLog.i("Success to install APEX. Result: " + result);

                break;
            } catch (AssertionError e) {
                CLog.i("Gets AssertionError when reinstall art APEX. Detail: " + e);
            }

            if (System.currentTimeMillis() > timeEnd) {
                CLog.e("Try to reinstall art APEX several times but all fail.");
                throw new AssertionError("Failed to reinstall art APEX.");
            }

            Thread.sleep(REINSTALL_APEX_RETRY_INTERVAL_MS);
        }
    }
}
