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

package android.virt.test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertThat;

import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
import com.android.tradefed.util.CommandResult;
import com.android.tradefed.util.RunUtil;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@RunWith(DeviceJUnit4ClassRunner.class)
public class MicrodroidTestCase extends BaseHostJUnit4Test {
    private static final String TEST_ROOT = "/data/local/tmp/virt/";
    private static final String VIRT_APEX = "/apex/com.android.virt/";
    private static final int TEST_VM_CID = 5;
    private static final int TEST_VM_ADB_PORT = 8000;
    private static final String MICRODROID_SERIAL = "localhost:" + TEST_VM_ADB_PORT;
    private static final long MICRODROID_BOOT_TIMEOUT_MILLIS = 15000;

    private String executeCommand(String cmd) {
        final long defaultCommandTimeoutMillis = 1000; // 1 sec
        return executeCommand(defaultCommandTimeoutMillis, cmd);
    }

    private String executeCommand(long timeout, String cmd) {
        CommandResult result = RunUtil.getDefault().runTimedCmd(timeout, cmd.split(" "));
        return result.getStdout().trim(); // remove the trailing whitespace including newline
    }

    @Test
    public void testMicrodroidBoots() throws Exception {
        // Prepare input files
        String prepareImagesCmd =
                String.format(
                        "mkdir -p %s; cd %s; "
                                + "cp %setc/microdroid_bootloader bootloader && "
                                + "cp %setc/fs/*.img . && "
                                + "cp %setc/uboot_env.img . && "
                                + "dd if=/dev/zero of=misc.img bs=4k count=256",
                        TEST_ROOT, TEST_ROOT, VIRT_APEX, VIRT_APEX, VIRT_APEX);
        getDevice().executeShellCommand(prepareImagesCmd);

        // Create os_composite.img, env_composite.img, and payload.img
        String makeOsCompositeCmd =
                String.format(
                        "cd %s; %sbin/mk_cdisk %setc/microdroid_cdisk.json os_composite.img",
                        TEST_ROOT, VIRT_APEX, VIRT_APEX);
        getDevice().executeShellCommand(makeOsCompositeCmd);
        String makeEnvCompositeCmd =
                String.format(
                        "cd %s; %sbin/mk_cdisk %setc/microdroid_cdisk_env.json env_composite.img",
                        TEST_ROOT, VIRT_APEX, VIRT_APEX);
        getDevice().executeShellCommand(makeEnvCompositeCmd);
        String makePayloadCompositeCmd =
                String.format(
                        "cd %s; %sbin/mk_payload %setc/microdroid_payload.json payload.img",
                        TEST_ROOT, VIRT_APEX, VIRT_APEX);
        getDevice().executeShellCommand(makePayloadCompositeCmd);

        // Make sure that the composite images are created
        final String osCompositeImg = TEST_ROOT + "/os_composite.img";
        final String envCompositeImg = TEST_ROOT + "/env_composite.img";
        final String payloadCompositeImg = TEST_ROOT + "/payload.img";
        CommandResult result =
                getDevice().executeShellV2Command(
                        "du -b " + osCompositeImg + " "
                                 + envCompositeImg + " "
                                 + payloadCompositeImg);
        assertThat(result.getExitCode(), is(0));
        assertThat(result.getStdout(), is(not("")));

        // Start microdroid using crosvm
        ExecutorService executor = Executors.newFixedThreadPool(1);
        String runMicrodroidCmd =
                String.format(
                        "cd %s; %sbin/crosvm run --cid=%d --disable-sandbox --bios=bootloader"
                                + " --serial=type=syslog --disk=os_composite.img"
                                + " --disk=env_composite.img --disk=payload.img",
                        TEST_ROOT, VIRT_APEX, TEST_VM_CID);
        executor.execute(
                () -> {
                    try {
                        getDevice().executeShellV2Command(runMicrodroidCmd);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                });
        // .. and wait for microdroid to boot
        // TODO(jiyong): don't wait too long. We can wait less by monitoring log from microdroid
        Thread.sleep(MICRODROID_BOOT_TIMEOUT_MILLIS);

        // Connect to microdroid and read a system property from there
        executeCommand(
                "adb -s "
                        + getDevice().getSerialNumber()
                        + " forward tcp:"
                        + TEST_VM_ADB_PORT
                        + " vsock:"
                        + TEST_VM_CID
                        + ":5555");
        executeCommand("adb connect " + MICRODROID_SERIAL);
        String prop = executeCommand("adb -s " + MICRODROID_SERIAL + " shell getprop ro.hardware");
        assertThat(prop, is("microdroid"));

        // Shutdown microdroid
        executeCommand("adb -s localhost:" + TEST_VM_ADB_PORT + " shell reboot");
    }

    @Before
    public void setUp() throws Exception {
        // delete the test root
        getDevice().executeShellCommand("rm -rf " + TEST_ROOT);

        // disconnect from microdroid
        executeCommand("adb disconnect " + MICRODROID_SERIAL);
    }

    @After
    public void shutdown() throws Exception {
        // disconnect from microdroid
        executeCommand("adb disconnect " + MICRODROID_SERIAL);

        // kill stale crosvm processes
        getDevice().executeShellV2Command("killall crosvm");
    }
}
