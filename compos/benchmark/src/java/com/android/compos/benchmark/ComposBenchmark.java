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
package com.android.compos.benchmark;

import static androidx.test.platform.app.InstrumentationRegistry.getInstrumentation;

import static com.google.common.truth.TruthJUnit.assume;

import static org.junit.Assert.assertTrue;

import android.app.Instrumentation;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.os.SystemProperties;
import android.util.Log;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.sql.Timestamp;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


@RunWith(JUnit4.class)
public class ComposBenchmark {
    private static final String TAG = "ComposBenchmark";
    private static final int BUFFER_SIZE = 1024;
    private static final int ROUND_COUNT = 5;
    private static final double NANOS_IN_SEC = 1_000_000_000.0;
    private static final String METRIC_PREFIX = "avf_perf/compos/";

    private Instrumentation mInstrumentation;

    private boolean isCuttlefish() {
        String productName = SystemProperties.get("ro.product.name");
        return (null != productName)
                && (productName.startsWith("aosp_cf_x86")
                        || productName.startsWith("aosp_cf_arm")
                        || productName.startsWith("cf_x86")
                        || productName.startsWith("cf_arm"));
    }

    @Before
    public void setup() {
        mInstrumentation = getInstrumentation();
    }

    private void reportMetric(String name, String unit, double[] values) {
        double sum = 0;
        double squareSum = 0;
        double min = Double.MAX_VALUE;
        double max = Double.MIN_VALUE;

        for (double val : values) {
            sum += val;
            squareSum += val * val;
            min = val < min ? val : min;
            max = val > max ? val : max;
        }

        double average = sum / values.length;
        double variance = squareSum / values.length - average * average;
        double stdev = Math.sqrt(variance);

        Bundle bundle = new Bundle();
        bundle.putDouble(METRIC_PREFIX + name + "_average_" + unit, average);
        bundle.putDouble(METRIC_PREFIX + name + "_min_" + unit, min);
        bundle.putDouble(METRIC_PREFIX + name + "_max_" + unit, max);
        bundle.putDouble(METRIC_PREFIX + name + "_stdev_" + unit, stdev);
        mInstrumentation.sendStatus(0, bundle);
    }

    public byte[] executeCommandBlocking(String command) {
        try (
            InputStream is = new ParcelFileDescriptor.AutoCloseInputStream(
                getInstrumentation().getUiAutomation().executeShellCommand(command));
            ByteArrayOutputStream out = new ByteArrayOutputStream()
        ) {
            byte[] buf = new byte[BUFFER_SIZE];
            int length;
            while ((length = is.read(buf)) >= 0) {
                out.write(buf, 0, length);
            }
            return out.toByteArray();
        } catch (IOException e) {
            Log.e(TAG, "Error executing: " + command, e);
            return null;
        }
    }

    public String executeCommand(String command)
            throws  InterruptedException, IOException {

        getInstrumentation().getUiAutomation()
                .adoptShellPermissionIdentity();
        byte[] output = executeCommandBlocking(command);
        getInstrumentation().getUiAutomation()
                .dropShellPermissionIdentity();

        if (output == null) {
            throw new RuntimeException("Failed to run the command.");
        } else {
            String stdout = new String(output, "UTF-8");
            Log.i(TAG, "Get stdout : " + stdout);
            return stdout;
        }
    }

    @Test
    public void testGuestCompileTime() throws InterruptedException, IOException {
        assume().withMessage("Skip on CF; too slow").that(isCuttlefish()).isFalse();

        final String command = "/apex/com.android.compos/bin/composd_cmd test-compile";

        double[] compileTime = new double[ROUND_COUNT];

        for (int round = 0; round < ROUND_COUNT; ++round) {
            Long compileStartTime = System.nanoTime();
            String output = executeCommand(command);
            Long compileEndTime = System.nanoTime();

            Pattern pattern = Pattern.compile("All Ok");
            Matcher matcher = pattern.matcher(output);
            assertTrue(matcher.find());

            compileTime[round] = (compileEndTime - compileStartTime) / NANOS_IN_SEC;
        }

        reportMetric("guest_compile_time", "s", compileTime);
    }

    private Timestamp getLatestDex2oatSuccessTime()
            throws  InterruptedException, IOException, ParseException {

        final String command = "logcat -d -e dex2oat";
        String output = executeCommand(command);
        String latestTime = null;

        for (String line : output.split("[\r\n]+")) {
            Pattern pattern = Pattern.compile("dex2oat64: dex2oat took");
            Matcher matcher = pattern.matcher(line);
            if (matcher.find()) {
                latestTime = line.substring(0, 18);
            }
        }

        if (latestTime == null) {
            return null;
        }

        DateFormat formatter = new SimpleDateFormat("MM-dd hh:mm:ss.SSS");
        Date date = formatter.parse(latestTime);
        Timestamp timeStampDate = new Timestamp(date.getTime());

        return timeStampDate;
    }

    @Test
    public void testHostCompileTime()
            throws InterruptedException, IOException, ParseException {

        final String command = "/apex/com.android.art/bin/odrefresh --force-compile";

        double[] compileTime = new double[ROUND_COUNT];

        for (int round = 0; round < ROUND_COUNT; ++round) {
            Timestamp beforeCompileLatestTime = getLatestDex2oatSuccessTime();
            Long compileStartTime = System.nanoTime();
            String output = executeCommand(command);
            Long compileEndTime = System.nanoTime();
            Timestamp afterCompileLatestTime = getLatestDex2oatSuccessTime();

            assertTrue(afterCompileLatestTime != null);
            assertTrue(beforeCompileLatestTime == null
                    || beforeCompileLatestTime.before(afterCompileLatestTime));

            compileTime[round] = (compileEndTime - compileStartTime) / NANOS_IN_SEC;
        }

        reportMetric("host_compile_time", "s", compileTime);
    }

}
