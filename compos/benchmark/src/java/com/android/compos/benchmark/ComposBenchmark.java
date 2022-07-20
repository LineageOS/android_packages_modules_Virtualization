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

import static org.junit.Assert.assertTrue;

import android.app.Instrumentation;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import org.junit.After;
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
import java.time.Duration;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


@RunWith(JUnit4.class)
public class ComposBenchmark {
    private static final String TAG = "ComposBenchmark";
    private static final int BUFFER_SIZE = 1024;
    private static final int ROUND_COUNT = 10;

    private Instrumentation mInstrumentation;

    @Before
    public void setup() {
        mInstrumentation = getInstrumentation();
    }

    @After
    public void cleanup() {

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
    public void testCompilationInVM()
            throws InterruptedException, IOException {

        final String command = "/apex/com.android.compos/bin/composd_cmd test-compile";

        Long[] compileSecArray = new Long[ROUND_COUNT];

        for (int round = 0; round < ROUND_COUNT; ++round) {
            Long compileStartTime = System.nanoTime();
            String output = executeCommand(command);
            Long compileEndTime = System.nanoTime();
            Long compileSec = Duration.ofNanos(compileEndTime - compileStartTime).getSeconds();

            Pattern pattern = Pattern.compile("All Ok");
            Matcher matcher = pattern.matcher(output);
            assertTrue(matcher.find());

            compileSecArray[round] = compileSec;
        }

        Long compileSecSum = 0L;
        for (Long num: compileSecArray) {
           compileSecSum += num;
        }

        Bundle bundle = new Bundle();
        bundle.putLong("compliation_in_vm_elapse_second", compileSecSum / compileSecArray.length);
        mInstrumentation.sendStatus(0, bundle);
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
    public void testCompilationInAndroid()
            throws InterruptedException, IOException, ParseException {

        final String command = "/apex/com.android.art/bin/odrefresh --force-compile";

        Long[] compileSecArray = new Long[ROUND_COUNT];

        for (int round = 0; round < ROUND_COUNT; ++round) {
            Timestamp beforeCompileLatestTime = getLatestDex2oatSuccessTime();
            Long compileStartTime = System.nanoTime();
            String output = executeCommand(command);
            Long compileEndTime = System.nanoTime();
            Long compileSec = Duration.ofNanos(compileEndTime - compileStartTime).getSeconds();
            Timestamp afterCompileLatestTime = getLatestDex2oatSuccessTime();

            assertTrue(afterCompileLatestTime != null);
            assertTrue(beforeCompileLatestTime == null
                    || beforeCompileLatestTime.before(afterCompileLatestTime));

            compileSecArray[round] = compileSec;
        }

        Long compileSecSum = 0L;
        for (Long num: compileSecArray) {
            compileSecSum += num;
        }

        Bundle bundle = new Bundle();
        bundle.putLong("compliation_in_android_elapse_second",
                compileSecSum / compileSecArray.length);
        mInstrumentation.sendStatus(0, bundle);
    }

}
