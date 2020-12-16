/*
 * Copyright (C) 2020 The Android Open Source Project
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

package android.virt.test;

import com.android.tradefed.log.LogUtil.CLog;
import com.android.tradefed.util.CommandResult;
import com.android.tradefed.util.CommandStatus;

import org.junit.Test;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

public class VsockTest extends VirtTestCase {
    private static final long     TIMEOUT = 2L;
    private static final TimeUnit TIMEOUT_UNIT = TimeUnit.MINUTES;
    private static final int      RETRIES = 0;

    private static final Integer  HOST_CID = 2;
    private static final Integer  GUEST_CID = 42;
    private static final Integer  GUEST_PORT = 45678;
    private static final String   TEST_MESSAGE = "HelloWorld";

    private static final String   CLIENT_PATH = "bin/vsock_client";
    private static final String   SERVER_TARGET = "virt_hostside_tests_vsock_server";

    @Test
    public void testVsockServer() throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(2);

        final String serverPath = getDevicePathForTestBinary(SERVER_TARGET);
        final String serverCmd = createCommand(serverPath, GUEST_PORT);
        final String clientCmd = createCommand(CLIENT_PATH, HOST_CID, GUEST_PORT, TEST_MESSAGE);
        final String vmCmd = getVmCommand(clientCmd, GUEST_CID);

        // Start server in Android that listens for vsock connections.
        // It will receive a message from a client in the guest VM.
        Future<?> serverTask = executor.submit(() -> {
            CommandResult res = getDevice().executeShellV2Command(
                    serverCmd, TIMEOUT, TIMEOUT_UNIT, RETRIES);
            assertEquals(TEST_MESSAGE, res.getStdout().trim());
            return null;
        });

        // Run VM that will connect to the server and send a message to it.
        Future<?> vmTask = executor.submit(() -> {
            CommandResult res = getDevice().executeShellV2Command(
                    vmCmd, TIMEOUT, TIMEOUT_UNIT, RETRIES);
            CLog.d(res.getStdout()); // print VMM output into host_log
            assertEquals(CommandStatus.SUCCESS, res.getStatus());
            return null;
        });

        // Wait for the VMM to finish sending the message.
        try {
            vmTask.get(TIMEOUT, TIMEOUT_UNIT);
        } catch (Throwable ex) {
            // The VMM either exited with a non-zero code or it timed out.
            // Kill the server process, the test has failed.
            // Note: executeShellV2Command cannot be interrupted. This will wait
            // until `serverTask` times out.
            executor.shutdownNow();
            throw ex;
        }

        // Wait for the server to finish processing the message.
        serverTask.get(TIMEOUT, TIMEOUT_UNIT);
    }
}
