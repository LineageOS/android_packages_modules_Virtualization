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
import com.android.tradefed.util.CommandStatus;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Optional;

@RootPermissionTest
@RunWith(DeviceJUnit4ClassRunner.class)
public final class ComposKeyTestCase extends VirtualizationTestCaseBase {

    /** Wait time for service to be ready on boot */
    private static final int READY_LATENCY_MS = 10 * 1000; // 10 seconds

    // Path to compos_key_cmd tool
    private static final String COMPOS_KEY_CMD_BIN = "/apex/com.android.compos/bin/compos_key_cmd";

    private String mCid;

    @Before
    public void setUp() throws Exception {
        testIfDeviceIsCapable(getDevice());

        prepareVirtualizationTestSetup(getDevice());
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
    public void testKeyService() throws Exception {
        startVm();
        waitForServiceRunning();

        CommandRunner android = new CommandRunner(getDevice());
        CommandResult result;

        // Generate keys - should succeed
        android.run(
                COMPOS_KEY_CMD_BIN,
                "--cid " + mCid,
                "generate",
                TEST_ROOT + "test_key.blob",
                TEST_ROOT + "test_key.pubkey");

        // Verify them - should also succeed, since we just generated them
        android.run(
                COMPOS_KEY_CMD_BIN,
                "--cid " + mCid,
                "verify",
                TEST_ROOT + "test_key.blob",
                TEST_ROOT + "test_key.pubkey");

        // Swap public key & blob - should fail to verify
        result =
                android.runForResult(
                        COMPOS_KEY_CMD_BIN,
                        "--cid " + mCid,
                        "verify",
                        TEST_ROOT + "test_key.pubkey",
                        TEST_ROOT + "test_key.blob");
        assertThat(result.getStatus()).isEqualTo(CommandStatus.FAILED);

        // Generate another set of keys - should succeed
        android.run(
                COMPOS_KEY_CMD_BIN,
                "--cid " + mCid,
                "generate",
                TEST_ROOT + "test_key2.blob",
                TEST_ROOT + "test_key2.pubkey");

        // They should also verify ok
        android.run(
                COMPOS_KEY_CMD_BIN,
                "--cid " + mCid,
                "verify",
                TEST_ROOT + "test_key2.blob",
                TEST_ROOT + "test_key2.pubkey");

        // Mismatched key blob & public key should fail to verify
        result =
                android.runForResult(
                        COMPOS_KEY_CMD_BIN,
                        "--cid " + mCid,
                        "verify",
                        TEST_ROOT + "test_key.pubkey",
                        TEST_ROOT + "test_key2.blob");
        assertThat(result.getStatus()).isEqualTo(CommandStatus.FAILED);
    }

    private void startVm() throws Exception {
        final String packageName = "com.android.compos.payload";
        mCid =
                startMicrodroid(
                        getDevice(),
                        getBuild(),
                        /* apkName, no need to install */ null,
                        packageName,
                        "assets/vm_test_config.json",
                        /* debug */ true,
                        /* use default memoryMib */ 0,
                        Optional.empty(),
                        Optional.empty());
        adbConnectToMicrodroid(getDevice(), mCid);
    }

    private void waitForServiceRunning() {
        try {
            PollingCheck.waitFor(READY_LATENCY_MS, this::isServiceRunning);
        } catch (Exception e) {
            throw new RuntimeException("Service unavailable", e);
        }
    }

    private boolean isServiceRunning() {
        return tryRunOnMicrodroid("pidof compsvc") != null;
    }
}
