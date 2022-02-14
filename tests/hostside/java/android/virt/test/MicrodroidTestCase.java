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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.android.tradefed.device.DeviceNotAvailableException;
import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
import com.android.tradefed.util.CommandResult;
import com.android.tradefed.util.CommandStatus;
import com.android.tradefed.util.FileUtil;
import com.android.tradefed.util.RunUtil;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.util.Optional;

@RunWith(DeviceJUnit4ClassRunner.class)
public class MicrodroidTestCase extends VirtualizationTestCaseBase {
    private static final String APK_NAME = "MicrodroidTestApp.apk";
    private static final String PACKAGE_NAME = "com.android.microdroid.test";

    private static final int MIN_MEM_ARM64 = 145;
    private static final int MIN_MEM_X86_64 = 196;

    // Number of vCPUs and their affinity to host CPUs for testing purpose
    private static final int NUM_VCPUS = 3;
    private static final String CPU_AFFINITY = "0,1,2";

    // TODO(b/176805428): remove this
    private boolean isCuttlefish() throws Exception {
        String productName = getDevice().getProperty("ro.product.name");
        return (null != productName)
                && (productName.startsWith("aosp_cf_x86")
                        || productName.startsWith("aosp_cf_arm")
                        || productName.startsWith("cf_x86")
                        || productName.startsWith("cf_arm"));
    }

    private int minMemorySize() throws DeviceNotAvailableException {
        CommandRunner android = new CommandRunner(getDevice());
        String abi = android.run("getprop", "ro.product.cpu.abi");
        assertTrue(abi != null && !abi.isEmpty());
        if (abi.startsWith("arm64")) {
            return MIN_MEM_ARM64;
        } else if (abi.startsWith("x86_64")) {
            return MIN_MEM_X86_64;
        }
        fail("Unsupported ABI: " + abi);
        return 0;
    }

    @Test
    public void testMicrodroidBoots() throws Exception {
        final String configPath = "assets/vm_config.json"; // path inside the APK
        final String cid =
                startMicrodroid(
                        getDevice(),
                        getBuild(),
                        APK_NAME,
                        PACKAGE_NAME,
                        configPath,
                        /* debug */ true,
                        minMemorySize(),
                        Optional.of(NUM_VCPUS),
                        Optional.of(CPU_AFFINITY));
        adbConnectToMicrodroid(getDevice(), cid);

        // Wait until logd-init starts. The service is one of the last services that are started in
        // the microdroid boot procedure. Therefore, waiting for the service means that we wait for
        // the boot to complete. TODO: we need a better marker eventually.
        tryRunOnMicrodroid("watch -e \"getprop init.svc.logd-reinit | grep '^$'\"");

        // Test writing to /data partition
        runOnMicrodroid("echo MicrodroidTest > /data/local/tmp/test.txt");
        assertThat(runOnMicrodroid("cat /data/local/tmp/test.txt"), is("MicrodroidTest"));

        // Check if the APK & its idsig partitions exist
        final String apkPartition = "/dev/block/by-name/microdroid-apk";
        assertThat(runOnMicrodroid("ls", apkPartition), is(apkPartition));
        final String apkIdsigPartition = "/dev/block/by-name/microdroid-apk-idsig";
        assertThat(runOnMicrodroid("ls", apkIdsigPartition), is(apkIdsigPartition));
        // Check the vm-instance partition as well
        final String vmInstancePartition = "/dev/block/by-name/vm-instance";
        assertThat(runOnMicrodroid("ls", vmInstancePartition), is(vmInstancePartition));

        // Check if the native library in the APK is has correct filesystem info
        final String[] abis = runOnMicrodroid("getprop", "ro.product.cpu.abilist").split(",");
        assertThat(abis.length, is(1));
        final String testLib = "/mnt/apk/lib/" + abis[0] + "/MicrodroidTestNativeLib.so";
        final String label = "u:object_r:system_file:s0";
        assertThat(runOnMicrodroid("ls", "-Z", testLib), is(label + " " + testLib));

        // Check that no denials have happened so far
        assertThat(runOnMicrodroid("logcat -d -e 'avc:[[:space:]]{1,2}denied'"), is(""));

        assertThat(runOnMicrodroid("cat /proc/cpuinfo | grep processor | wc -l"),
                is(Integer.toString(NUM_VCPUS)));

        // Check that selinux is enabled
        assertThat(runOnMicrodroid("getenforce"), is("Enforcing"));

        // TODO(b/176805428): adb is broken for nested VM
        if (!isCuttlefish()) {
            // Check neverallow rules on microdroid
            File policyFile = FileUtil.createTempFile("microdroid_sepolicy", "");
            pullMicrodroidFile("/sys/fs/selinux/policy", policyFile);

            File generalPolicyConfFile = findTestFile("microdroid_general_sepolicy.conf");
            File sepolicyAnalyzeBin = findTestFile("sepolicy-analyze");

            CommandResult result =
                    RunUtil.getDefault()
                            .runTimedCmd(
                                    10000,
                                    sepolicyAnalyzeBin.getPath(),
                                    policyFile.getPath(),
                                    "neverallow",
                                    "-w",
                                    "-f",
                                    generalPolicyConfFile.getPath());
            assertEquals(
                    "neverallow check failed: " + result.getStderr().trim(),
                    result.getStatus(),
                    CommandStatus.SUCCESS);
        }

        shutdownMicrodroid(getDevice(), cid);
    }

    @Before
    public void setUp() throws Exception {
        testIfDeviceIsCapable(getDevice());

        prepareVirtualizationTestSetup(getDevice());

        getDevice().installPackage(findTestFile(APK_NAME), /* reinstall */ false);

        // clear the log
        getDevice().executeShellV2Command("logcat -c");
    }

    @After
    public void shutdown() throws Exception {
        cleanUpVirtualizationTestSetup(getDevice());

        getDevice().uninstallPackage(PACKAGE_NAME);
    }
}
