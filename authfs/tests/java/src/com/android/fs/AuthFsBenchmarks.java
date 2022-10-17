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

import static com.google.common.truth.Truth.assertThat;

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

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@RootPermissionTest
@RunWith(DeviceJUnit4ClassRunner.class)
public class AuthFsBenchmarks extends BaseHostJUnit4Test {
    private static final int TRIAL_COUNT = 5;

    /** Name of the measure_io binary on host. */
    private static final String MEASURE_IO_BIN_NAME = "measure_io";

    /** Path to measure_io on Microdroid. */
    private static final String MEASURE_IO_BIN_PATH = "/data/local/tmp/measure_io";

    /** fs-verity digest (sha256) of testdata/input.4m */
    private static final String DIGEST_4M =
            "sha256-f18a268d565348fb4bbf11f10480b198f98f2922eb711de149857b3cecf98a8d";

    @Rule public final AuthFsTestRule mAuthFsTestRule = new AuthFsTestRule();
    @Rule public final TestMetrics mTestMetrics = new TestMetrics();
    private MetricsProcessor mMetricsProcessor;

    @BeforeClassWithInfo
    public static void beforeClassWithDevice(TestInformation testInfo) throws Exception {
        AuthFsTestRule.setUpAndroid(testInfo);
    }

    @Before
    public void setUp() throws Exception {
        String metricsPrefix =
                MetricsProcessor.getMetricPrefix(
                        getDevice().getProperty("debug.hypervisor.metrics_tag"));
        mMetricsProcessor = new MetricsProcessor(metricsPrefix + "authfs/");
        AuthFsTestRule.startMicrodroid();
    }

    @After
    public void tearDown() throws DeviceNotAvailableException {
        AuthFsTestRule.shutdownMicrodroid();
    }

    @AfterClassWithInfo
    public static void afterClassWithDevice(TestInformation testInfo) {
        AuthFsTestRule.tearDownAndroid();
    }

    @Test
    public void seqReadRemoteFile() throws Exception {
        readRemoteFile("seq");
    }

    @Test
    public void randReadRemoteFile() throws Exception {
        readRemoteFile("rand");
    }

    @Test
    public void seqWriteRemoteFile() throws Exception {
        writeRemoteFile("seq");
    }

    @Test
    public void randWriteRemoteFile() throws Exception {
        writeRemoteFile("rand");
    }

    private void readRemoteFile(String mode) throws DeviceNotAvailableException {
        pushMeasureIoBinToMicrodroid();
        // Cache the file in memory for the host.
        mAuthFsTestRule
                .getAndroid()
                .run("cat " + mAuthFsTestRule.TEST_DIR + "/input.4m > /dev/null");

        String filePath = mAuthFsTestRule.MOUNT_DIR + "/3";
        int fileSizeMb = 4;
        String cmd = MEASURE_IO_BIN_PATH + " " + filePath + " " + fileSizeMb + " " + mode + " r";
        List<Double> rates = new ArrayList<>(TRIAL_COUNT);
        for (int i = 0; i < TRIAL_COUNT + 1; ++i) {
            mAuthFsTestRule.runFdServerOnAndroid(
                    "--open-ro 3:input.4m --open-ro 4:input.4m.fsv_meta", "--ro-fds 3:4");
            mAuthFsTestRule.runAuthFsOnMicrodroid("--remote-ro-file 3:" + DIGEST_4M);

            String rate = mAuthFsTestRule.getMicrodroid().run(cmd);
            rates.add(Double.parseDouble(rate));
        }
        reportMetrics(rates, mode + "_read", "mb_per_sec");
    }

    private void writeRemoteFile(String mode) throws DeviceNotAvailableException {
        pushMeasureIoBinToMicrodroid();
        String filePath = mAuthFsTestRule.MOUNT_DIR + "/5";
        int fileSizeMb = 8;
        String cmd = MEASURE_IO_BIN_PATH + " " + filePath + " " + fileSizeMb + " " + mode + " w";
        List<Double> rates = new ArrayList<>(TRIAL_COUNT);
        for (int i = 0; i < TRIAL_COUNT + 1; ++i) {
            mAuthFsTestRule.runFdServerOnAndroid(
                    "--open-rw 5:" + mAuthFsTestRule.TEST_OUTPUT_DIR + "/out.file", "--rw-fds 5");
            mAuthFsTestRule.runAuthFsOnMicrodroid("--remote-new-rw-file 5");

            String rate = mAuthFsTestRule.getMicrodroid().run(cmd);
            rates.add(Double.parseDouble(rate));
        }
        reportMetrics(rates, mode + "_write", "mb_per_sec");
    }

    private void pushMeasureIoBinToMicrodroid() throws DeviceNotAvailableException {
        File measureReadBin = mAuthFsTestRule.findTestFile(getBuild(), MEASURE_IO_BIN_NAME);
        assertThat(measureReadBin.exists()).isTrue();
        mAuthFsTestRule.getMicrodroidDevice().pushFile(measureReadBin, MEASURE_IO_BIN_PATH);
        assertThat(mAuthFsTestRule.getMicrodroid().run("ls " + MEASURE_IO_BIN_PATH))
                .isEqualTo(MEASURE_IO_BIN_PATH);
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
