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

import org.junit.Test;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

public class VsockTest extends VirtTestCase {
    private static final long     TIMEOUT = 2L;
    private static final TimeUnit TIMEOUT_UNIT = TimeUnit.MINUTES;
    private static final int      RETRIES = 0;

    private static final Integer  GUEST_PORT = 45678;
    private static final String   TEST_MESSAGE = "HelloWorld";

    private static final String   SERVER_TARGET = "vsock_server";
    private static final String   VIRT_MANAGER_COMMAND = "virtmanager";

    @Test
    public void testVsockServer() throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(2);

        final String serverPath = getDevicePathForTestBinary(SERVER_TARGET);
        final String vmConfigPath = getDevicePathForTestBinary("vm_config.json");
        final String serverCmd = createCommand(serverPath, GUEST_PORT, vmConfigPath);

        // Start Virt Manager. This will eventually be a system service, but for now we run it
        // manually.
        Future<?> virtManagerTask = executor.submit(() -> {
            CommandResult res = getDevice().executeShellV2Command(
                    VIRT_MANAGER_COMMAND, TIMEOUT, TIMEOUT_UNIT, RETRIES);
            CLog.d(res.getStdout());
            return null;
        });

        // Start server in Android that listens for vsock connections.
        // It will receive a message from a client in the guest VM.
        Future<?> serverTask = executor.submit(() -> {
            CommandResult res = getDevice().executeShellV2Command(
                    serverCmd, TIMEOUT, TIMEOUT_UNIT, RETRIES);
            assertEquals(TEST_MESSAGE, res.getStdout().trim());
            return null;
        });

        // Wait for the server to finish processing the message.
        serverTask.get(TIMEOUT, TIMEOUT_UNIT);
    }
}
