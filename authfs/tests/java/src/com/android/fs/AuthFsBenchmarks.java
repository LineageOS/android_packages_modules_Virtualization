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

package com.android.virt.fs;

import static com.android.tradefed.testtype.DeviceJUnit4ClassRunner.TestMetrics;

import android.platform.test.annotations.RootPermissionTest;

import com.android.microdroid.test.common.MetricsProcessor;
import com.android.tradefed.device.DeviceNotAvailableException;
import com.android.tradefed.invoker.TestInformation;
import com.android.tradefed.metrics.proto.MetricMeasurement.DataType;
import com.android.tradefed.metrics.proto.MetricMeasurement.Measurements;
import com.android.tradefed.metrics.proto.MetricMeasurement.Metric;
import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
import com.android.tradefed.testtype.junit4.AfterClassWithInfo;
import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
import com.android.tradefed.testtype.junit4.BeforeClassWithInfo;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@RootPermissionTest
@RunWith(DeviceJUnit4ClassRunner.class)
public class AuthFsBenchmarks extends BaseHostJUnit4Test {
    private static final int TRIAL_COUNT = 5;
    private static final double NANO_SECS_PER_SEC = 1_000_000_000.;
    private static final double INPUT_SIZE_IN_MB = 4.;

    /** fs-verity digest (sha256) of testdata/input.4m */
    private static final String DIGEST_4M =
            "sha256-f18a268d565348fb4bbf11f10480b198f98f2922eb711de149857b3cecf98a8d";

    @Rule public final AuthFsTestRule mAuthFsTestRule = new AuthFsTestRule();
    @Rule public final TestMetrics mTestMetrics = new TestMetrics();
    private MetricsProcessor mMetricsProcessor;

    @BeforeClassWithInfo
    public static void beforeClassWithDevice(TestInformation testInfo) throws Exception {
        AuthFsTestRule.setUpClass(testInfo);
    }

    @Before
    public void setUp() throws Exception {
        String metricsPrefix =
                MetricsProcessor.getMetricPrefix(
                        getDevice().getProperty("debug.hypervisor.metrics_tag"));
        mMetricsProcessor = new MetricsProcessor(metricsPrefix + "authfs/");
    }

    @AfterClassWithInfo
    public static void afterClassWithDevice(TestInformation testInfo)
            throws DeviceNotAvailableException {
        AuthFsTestRule.tearDownClass(testInfo);
    }

    @Test
    public void seqReadRemoteFile() throws Exception {
        List<Double> transferRates = new ArrayList<>(TRIAL_COUNT);
        // Cache the file in memory for the host.
        String cmd = "cat " + mAuthFsTestRule.TEST_DIR + "/input.4m > /dev/null";
        mAuthFsTestRule.getAndroid().run(cmd);
        for (int i = 0; i < TRIAL_COUNT + 1; ++i) {
            mAuthFsTestRule.runFdServerOnAndroid(
                    "--open-ro 3:input.4m --open-ro 4:input.4m.fsv_meta", "--ro-fds 3:4");
            mAuthFsTestRule.runAuthFsOnMicrodroid("--remote-ro-file 3:" + DIGEST_4M);
            double elapsedSeconds = measureSeqReadOnMicrodroid("3");
            transferRates.add(INPUT_SIZE_IN_MB / elapsedSeconds);
        }
        reportMetrics(transferRates, "seq_read", "mb_per_sec");
    }

    private double measureSeqReadOnMicrodroid(String filename) throws DeviceNotAvailableException {
        String cmd = "cat " + mAuthFsTestRule.MOUNT_DIR + "/" + filename + " > /dev/null";
        // Ideally, we should measure the time in the VM to avoid the adb and host tests latency.
        double startTime = System.nanoTime();
        mAuthFsTestRule.getMicrodroid().run(cmd);
        double elapsedSeconds = (System.nanoTime() - startTime) / NANO_SECS_PER_SEC;
        return elapsedSeconds;
    }

    private void reportMetrics(List<Double> metrics, String name, String unit) {
        Map<String, Double> stats = mMetricsProcessor.computeStats(metrics, name, unit);
        for (Map.Entry<String, Double> entry : stats.entrySet()) {
            Metric metric =
                    Metric.newBuilder()
                            .setType(DataType.RAW)
                            .setMeasurements(
                                    Measurements.newBuilder().setSingleDouble(entry.getValue()))
                            .build();
            mTestMetrics.addTestMetric(entry.getKey(), metric);
        }
    }
}
