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

        // Expect the compilation to finish successfully.
        CommandResult result =
                android.runForResultWithTimeout(
                        ODREFRESH_TIMEOUT_MS,
                        ODREFRESH_BIN,
                        "--use-compilation-os=" + mCid,
                        "--force-compile");
        assertThat(result.getExitCode()).isEqualTo(COMPILATION_SUCCESS);

        // Expect the output to be valid.
        result = android.runForResultWithTimeout(ODREFRESH_TIMEOUT_MS, ODREFRESH_BIN, "--check");
        assertThat(result.getExitCode()).isEqualTo(OKAY);
    }

    private void startComposVm() throws Exception {
        final String apkName = "CompOSPayloadApp.apk";
        final String packageName = "com.android.compos.payload";
        mCid =
                startMicrodroid(
                        getDevice(),
                        getBuild(),
                        apkName,
                        packageName,
                        "assets/vm_config.json",
                        /* debug */ true);
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
}
