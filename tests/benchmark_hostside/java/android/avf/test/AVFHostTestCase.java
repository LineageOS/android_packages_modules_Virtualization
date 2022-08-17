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

import android.platform.test.annotations.RootPermissionTest;

import static com.android.tradefed.testtype.DeviceJUnit4ClassRunner.TestMetrics;

import static com.google.common.truth.Truth.assertWithMessage;

import com.android.microdroid.test.CommandRunner;
import com.android.microdroid.test.MicrodroidHostTestCaseBase;
import com.android.tradefed.log.LogUtil.CLog;
import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
import com.android.tradefed.util.CommandResult;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

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
    private String mBackupSystemServerCompilerFilter;

    /** Boot time test related variables */
    private static final int BOOT_COMPLETE_TIMEOUT_MS = 10 * 60 * 1000;
    private static final int DEVICE_AVAILABLE_WAIT_TIMEOUT_MS = 3 * 60 * 1000;
    private static final double NANOS_IN_SEC = 1_000_000_000.0;
    private static final int ROUND_COUNT = 3;
    private static final String METRIC_PREFIX = "avf_perf/compos/";

    @Before
    public void setUp() throws Exception {
        testIfDeviceIsCapable(getDevice());

        String value = getDevice().getProperty(SYSTEM_SERVER_COMPILER_FILTER_PROP_NAME);
        if (value == null) {
            mBackupSystemServerCompilerFilter = "";
        } else {
            mBackupSystemServerCompilerFilter = value;
        }

        getDevice().setProperty(SYSTEM_SERVER_COMPILER_FILTER_PROP_NAME, "speed");
    }

    @After
    public void tearDown() throws Exception {
        CommandRunner android = new CommandRunner(getDevice());

        // Clear up any CompOS instance files we created
        android.tryRun("rm", "-rf", COMPOS_TEST_ROOT);

        if (mBackupSystemServerCompilerFilter != null) {
            CLog.d("Restore dalvik.vm.systemservercompilerfilter to "
                    + mBackupSystemServerCompilerFilter);
            getDevice().setProperty(SYSTEM_SERVER_COMPILER_FILTER_PROP_NAME,
                    mBackupSystemServerCompilerFilter);
        }
    }

    @Test
    public void testBootWithAndWithoutCompOS() throws Exception {

        double[] bootWithCompOsTime = new double[ROUND_COUNT];
        double[] bootWithoutCompOsTime = new double[ROUND_COUNT];

        for (int round = 0; round < ROUND_COUNT; ++round) {

            // Boot time with compilation OS test.
            getDevice().waitForDeviceAvailable(DEVICE_AVAILABLE_WAIT_TIMEOUT_MS);
            reInstallApex();
            compileStagedApex();
            long start = System.nanoTime();
            rebootAndWaitBootCompleted();
            long elapsedWithCompOS = System.nanoTime() - start;
            double elapsedSec = elapsedWithCompOS / NANOS_IN_SEC;
            bootWithCompOsTime[round] = elapsedSec;
            CLog.i("Boot time with compilation OS took " + elapsedSec + "s");

            // Boot time without compilation OS test.
            getDevice().waitForDeviceAvailable(DEVICE_AVAILABLE_WAIT_TIMEOUT_MS);
            reInstallApex();
            start = System.nanoTime();
            rebootAndWaitBootCompleted();
            long elapsedWithoutCompOS = System.nanoTime() - start;
            elapsedSec = elapsedWithoutCompOS / NANOS_IN_SEC;
            bootWithoutCompOsTime[round] = elapsedSec;
            CLog.i("Boot time without compilation OS took " + elapsedSec + "s");

            assertWithMessage("Boot time with compilation OS is higher than without")
                .that(elapsedWithCompOS).isLessThan(elapsedWithoutCompOS);
        }

        reportMetric("boot_time_with_compos", "s", bootWithCompOsTime);
        reportMetric("boot_time_without_compos", "s", bootWithoutCompOsTime);
    }

    private void reportMetric(String name, String unit, double[] values) {
        double sum = 0;
        double min = Double.MAX_VALUE;
        double max = Double.MIN_VALUE;

        for (double val : values) {
            sum += val;
            min = val < min ? val : min;
            max = val > max ? val : max;
        }

        double average = sum / values.length;

        double variance = 0;
        for (double val : values) {
            final double tmp = val - average;
            variance += tmp * tmp;
        }
        double stdev = Math.sqrt(variance / (double) (values.length - 1));

        TestMetrics metrics = new TestMetrics();
        metrics.addTestMetric(METRIC_PREFIX + name + "_average_" + unit, Double.toString(average));
        metrics.addTestMetric(METRIC_PREFIX + name + "_min_" + unit, Double.toString(min));
        metrics.addTestMetric(METRIC_PREFIX + name + "_max_" + unit, Double.toString(max));
        metrics.addTestMetric(METRIC_PREFIX + name + "_stdev_" + unit, Double.toString(stdev));
    }

    private void rebootAndWaitBootCompleted() throws Exception {
        getDevice().nonBlockingReboot();
        getDevice().waitForDeviceOnline();
        getDevice().waitForBootComplete(BOOT_COMPLETE_TIMEOUT_MS);
    }

    private void compileStagedApex() throws Exception {
        CommandRunner android = new CommandRunner(getDevice());

        String result = android.run(
                COMPOSD_CMD_BIN + " staged-apex-compile");
        assertWithMessage("Failed to compile staged apex. Reason: " + result)
            .that(result).ignoringCase().contains("all ok");
    }

    private void reInstallApex() throws Exception {
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
        assertWithMessage("Failed to install APEX. Reason: " + result.toString())
             .that(result.getExitCode()).isEqualTo(0);
    }
}
