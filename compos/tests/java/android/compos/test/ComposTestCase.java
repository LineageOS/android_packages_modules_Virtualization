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

    // Binaries used in test. (These paths are valid both in host and Microdroid.)
    private static final String ODREFRESH_BIN = "/apex/com.android.art/bin/odrefresh";
    private static final String COMPOS_KEY_CMD_BIN = "/apex/com.android.compos/bin/compos_key_cmd";
    private static final String COMPOSD_CMD_BIN = "/apex/com.android.compos/bin/composd_cmd";

    /** Output directory of odrefresh */
    private static final String ODREFRESH_OUTPUT_DIR =
            "/data/misc/apexdata/com.android.art/dalvik-cache";

    /** Timeout of odrefresh to finish */
    private static final int ODREFRESH_TIMEOUT_MS = 10 * 60 * 1000; // 10 minutes

    // ExitCode expanded from art/odrefresh/include/odrefresh/odrefresh.h.
    private static final int OKAY = 0;
    private static final int COMPILATION_SUCCESS = 80;

    // Files that define the "current" instance of CompOS
    private static final String COMPOS_CURRENT_ROOT =
            "/data/misc/apexdata/com.android.compos/current/";
    private static final String INSTANCE_IMAGE = COMPOS_CURRENT_ROOT + "instance.img";
    private static final String PUBLIC_KEY = COMPOS_CURRENT_ROOT + "key.pubkey";
    private static final String PRIVATE_KEY_BLOB = COMPOS_CURRENT_ROOT + "key.blob";

    @Before
    public void setUp() throws Exception {
        testIfDeviceIsCapable(getDevice());
    }

    @After
    public void tearDown() throws Exception {
        CommandRunner android = new CommandRunner(getDevice());

        // kill stale VMs and directories
        android.tryRun("killall", "crosvm");
        android.tryRun("rm", "-rf", "/data/misc/virtualizationservice/*");
        android.tryRun("stop", "virtualizationservice");
    }

    @Test
    public void testOdrefresh() throws Exception {
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

        // Make sure the CompOS current directory actually exists
        android.run("mkdir", "-p", COMPOS_CURRENT_ROOT);

        // Create an empty image file
        android.run(COMPOS_KEY_CMD_BIN, "make-instance", INSTANCE_IMAGE);

        // Generate keys - should succeed
        android.run(
                COMPOS_KEY_CMD_BIN,
                "--start " + INSTANCE_IMAGE,
                "generate",
                PRIVATE_KEY_BLOB,
                PUBLIC_KEY);

        // Expect the compilation in Compilation OS to finish successfully.
        {
            long start = System.currentTimeMillis();
            result = android.runForResultWithTimeout(ODREFRESH_TIMEOUT_MS, COMPOSD_CMD_BIN);
            long elapsed = System.currentTimeMillis() - start;
            assertThat(result.getExitCode()).isEqualTo(0);
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

    private String checksumDirectoryContent(CommandRunner runner, String path)
            throws DeviceNotAvailableException {
        return runner.run("find " + path + " -type f -exec sha256sum {} \\; | sort");
    }
}
