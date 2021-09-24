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

import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
import com.android.tradefed.util.CommandResult;
import com.android.tradefed.util.CommandStatus;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

@RootPermissionTest
@RunWith(DeviceJUnit4ClassRunner.class)
public final class ComposKeyTestCase extends VirtualizationTestCaseBase {
    private static final String COMPOS_KEY_CMD_BIN = "/apex/com.android.compos/bin/compos_key_cmd";
    private static final String INSTANCE_IMAGE = TEST_ROOT + "compos_instance.img";

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
    public void testKeyService() throws Exception {
        CommandRunner android = new CommandRunner(getDevice());
        CommandResult result;

        // Create an empty image file
        android.run(COMPOS_KEY_CMD_BIN, "make-instance", INSTANCE_IMAGE);

        // Generate keys - should succeed
        android.run(
                COMPOS_KEY_CMD_BIN,
                "--start " + INSTANCE_IMAGE,
                "generate",
                TEST_ROOT + "test_key.blob",
                TEST_ROOT + "test_key.pubkey");

        // Verify them - should also succeed, since we just generated them
        android.run(
                COMPOS_KEY_CMD_BIN,
                "--start " + INSTANCE_IMAGE,
                "verify",
                TEST_ROOT + "test_key.blob",
                TEST_ROOT + "test_key.pubkey");

        // Swap public key & blob - should fail to verify
        result =
                android.runForResult(
                        COMPOS_KEY_CMD_BIN,
                        "--start " + INSTANCE_IMAGE,
                        "verify",
                        TEST_ROOT + "test_key.pubkey",
                        TEST_ROOT + "test_key.blob");
        assertThat(result.getStatus()).isEqualTo(CommandStatus.FAILED);

        // Generate another set of keys - should succeed
        android.run(
                COMPOS_KEY_CMD_BIN,
                "--start " + INSTANCE_IMAGE,
                "generate",
                TEST_ROOT + "test_key2.blob",
                TEST_ROOT + "test_key2.pubkey");

        // They should also verify ok
        android.run(
                COMPOS_KEY_CMD_BIN,
                "--start " + INSTANCE_IMAGE,
                "verify",
                TEST_ROOT + "test_key2.blob",
                TEST_ROOT + "test_key2.pubkey");

        // Mismatched key blob & public key should fail to verify
        result =
                android.runForResult(
                        COMPOS_KEY_CMD_BIN,
                        "--start " + INSTANCE_IMAGE,
                        "verify",
                        TEST_ROOT + "test_key.pubkey",
                        TEST_ROOT + "test_key2.blob");
        assertThat(result.getStatus()).isEqualTo(CommandStatus.FAILED);

        // Now, continue to test the signing operation. It's the best to do this in a new test
        // method. Since we boot a VM for each test method, and booting a VM on cuttlefish/GCE is
        // very slow, a new test method unfortunately makes the whole test module to exceed the
        // timeout configured in the test infrastructure.

        // Generate some data to sign in a writable directory
        android.run("echo something > /data/local/tmp/something.txt");

        // Sign something - should succeed
        android.run(
                COMPOS_KEY_CMD_BIN,
                "--start " + INSTANCE_IMAGE,
                "sign",
                TEST_ROOT + "test_key2.blob",
                "/data/local/tmp/something.txt");

        // Check existence of the output signature - should succeed
        android.run("test -f /data/local/tmp/something.txt.signature");
    }
}
