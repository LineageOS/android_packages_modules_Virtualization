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

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
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

    private void pushFile(String localName, String remoteName) {
        try {
            File localFile = getTestInformation().getDependencyFile(localName, false);
            Path remotePath = Paths.get(TEST_ROOT, remoteName);
            getDevice().executeShellCommand("mkdir -p " + remotePath.getParent());
            getDevice().pushFile(localFile, remotePath.toString());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

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
        pushFile("u-boot.bin", "bootloader");
        pushFile("microdroid_super.img", "super.img");
        pushFile("microdroid_boot-5.10.img", "boot.img");
        pushFile("microdroid_vendor_boot-5.10.img", "vendor_boot.img");
        pushFile("uboot_env.img", "cuttlefish_runtime.1/uboot_env.img");
        pushFile("empty.img", "userdata.img");
        pushFile("microdroid_vbmeta.img", "vbmeta.img");
        pushFile("microdroid_vbmeta_system.img", "vbmeta_system.img");
        pushFile("empty.img", "cache.img");
        getDevice().executeShellCommand("mkdir -p " + TEST_ROOT + "etc/cvd_config");
        getDevice().pushString("{}", TEST_ROOT + "etc/cvd_config/cvd_config_phone.json");

        // Run assemble_cvd to create os_composite.img
        getDevice().executeShellCommand("HOME=" + TEST_ROOT + "; "
                + "PATH=$PATH:" + VIRT_APEX + "bin; "
                + VIRT_APEX + "bin/assemble_cvd -protected_vm < /dev/null");

        // Make sure that os_composite.img is created
        final String compositeImg = TEST_ROOT + "cuttlefish_runtime/os_composite.img";
        CommandResult result = getDevice().executeShellV2Command("du -b " + compositeImg);
        assertThat(result.getExitCode(), is(0));
        assertThat(result.getStdout(), is(not("")));

        // Start microdroid using crosvm
        ExecutorService executor = Executors.newFixedThreadPool(1);
        executor.execute(() -> {
            try {
                getDevice().executeShellV2Command("cd " + TEST_ROOT + "; "
                        + VIRT_APEX + "bin/crosvm run "
                        + "--cid=" + TEST_VM_CID + " "
                        + "--disable-sandbox "
                        + "--bios=bootloader "
                        + "--serial=type=syslog "
                        + "--disk=cuttlefish_runtime/os_composite.img");
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        // .. and wait for microdroid to boot
        // TODO(jiyong): don't wait too long. We can wait less by monitoring log from microdroid
        Thread.sleep(MICRODROID_BOOT_TIMEOUT_MILLIS);

        // Connect to microdroid and read a system property from there
        executeCommand("adb forward tcp:" + TEST_VM_ADB_PORT + " vsock:" + TEST_VM_CID + ":5555");
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
