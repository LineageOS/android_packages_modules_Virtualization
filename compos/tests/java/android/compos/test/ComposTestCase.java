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

package android.compos.test;

import static com.google.common.truth.Truth.assertThat;

import android.platform.test.annotations.RootPermissionTest;
import android.virt.test.CommandRunner;
import android.virt.test.VirtualizationTestCaseBase;

import com.android.compatibility.common.util.PollingCheck;
import com.android.tradefed.device.DeviceNotAvailableException;
import com.android.tradefed.log.LogUtil.CLog;
import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
import com.android.tradefed.util.CommandResult;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

@RootPermissionTest
@RunWith(DeviceJUnit4ClassRunner.class)
public final class ComposTestCase extends VirtualizationTestCaseBase {

    /** Path to odrefresh on Microdroid */
    private static final String ODREFRESH_BIN = "/apex/com.android.art/bin/odrefresh";

    /** Output directory of odrefresh */
    private static final String ODREFRESH_OUTPUT_DIR =
            "/data/misc/apexdata/com.android.art/dalvik-cache";

    /** Timeout of odrefresh to finish */
    private static final int ODREFRESH_TIMEOUT_MS = 10 * 60 * 1000; // 10 minutes

    /** Wait time for compsvc to be ready on boot */
    private static final int COMPSVC_READY_LATENCY_MS = 10 * 1000; // 10 seconds

    // ExitCode expanded from art/odrefresh/include/odrefresh/odrefresh.h.
    private static final int OKAY = 0;
    private static final int COMPILATION_SUCCESS = 80;

    private String mCid;

    @Before
    public void setUp() throws Exception {
        testIfDeviceIsCapable(getDevice());

        prepareVirtualizationTestSetup(getDevice());

        startComposVm();
    }

    @After
    public void tearDown() throws Exception {
        if (mCid != null) {
            shutdownMicrodroid(getDevice(), mCid);
            mCid = null;
        }

        cleanUpVirtualizationTestSetup(getDevice());
    }

    @Test
    public void testOdrefresh() throws Exception {
        waitForServiceRunning();

        CommandRunner android = new CommandRunner(getDevice());

        // Prepare the groundtruth. The compilation on Android should finish successfully.
        {
            long start = System.currentTimeMillis();
            CommandResult result =
                    android.runForResultWithTimeout(
                            ODREFRESH_TIMEOUT_MS, ODREFRESH_BIN, "--force-compile");
            long elapsed = System.currentTimeMillis() - start;
            assertThat(result.getExitCode()).isEqualTo(COMPILATION_SUCCESS);
            CLog.i("Local compilation took " + elapsed + "ms");
        }

        // Save the expected checksum for the output directory.
        String expectedChecksumSnapshot = checksumDirectoryContent(android, ODREFRESH_OUTPUT_DIR);

        // Let --check clean up the output.
        CommandResult result =
                android.runForResultWithTimeout(ODREFRESH_TIMEOUT_MS, ODREFRESH_BIN, "--check");
        assertThat(result.getExitCode()).isEqualTo(OKAY);

        // Expect the compilation in Compilation OS to finish successfully.
        {
            long start = System.currentTimeMillis();
            result =
                    android.runForResultWithTimeout(
                            ODREFRESH_TIMEOUT_MS,
                            ODREFRESH_BIN,
                            "--use-compilation-os=" + mCid,
                            "--force-compile");
            long elapsed = System.currentTimeMillis() - start;
            assertThat(result.getExitCode()).isEqualTo(COMPILATION_SUCCESS);
            CLog.i("Comp OS compilation took " + elapsed + "ms");
        }

        // Save the actual checksum for the output directory.
        String actualChecksumSnapshot = checksumDirectoryContent(android, ODREFRESH_OUTPUT_DIR);

        // Expect the output to be valid.
        result = android.runForResultWithTimeout(ODREFRESH_TIMEOUT_MS, ODREFRESH_BIN, "--verify");
        assertThat(result.getExitCode()).isEqualTo(OKAY);
        // --check can delete the output, so run later.
        result = android.runForResultWithTimeout(ODREFRESH_TIMEOUT_MS, ODREFRESH_BIN, "--check");
        assertThat(result.getExitCode()).isEqualTo(OKAY);

        // Expect the output of Comp OS to be the same as compiled on Android.
        assertThat(actualChecksumSnapshot).isEqualTo(expectedChecksumSnapshot);
    }

    private void startComposVm() throws DeviceNotAvailableException {
        final String apkName = "CompOSPayloadApp.apk";
        final String packageName = "com.android.compos.payload";
        mCid =
                startMicrodroid(
                        getDevice(),
                        getBuild(),
                        apkName,
                        packageName,
                        "assets/vm_config.json",
                        /* debug */ false);
        adbConnectToMicrodroid(getDevice(), mCid);
    }

    private void waitForServiceRunning() {
        try {
            PollingCheck.waitFor(COMPSVC_READY_LATENCY_MS, this::isServiceRunning);
        } catch (Exception e) {
            throw new RuntimeException("Service unavailable", e);
        }
    }

    private boolean isServiceRunning() {
        return tryRunOnMicrodroid("pidof compsvc") != null;
    }

    private String checksumDirectoryContent(CommandRunner runner, String path)
            throws DeviceNotAvailableException {
        return runner.run("find " + path + " -type f -exec sha256sum {} \\; | sort");
    }
}
