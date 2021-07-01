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

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(DeviceJUnit4ClassRunner.class)
public class MicrodroidTestCase extends VirtualizationTestCaseBase {
    private static final long MICRODROID_ADB_CONNECT_TIMEOUT_MINUTES = 5;

    @Test
    public void testMicrodroidBoots() throws Exception {
        final String apkName = "MicrodroidTestApp.apk";
        final String packageName = "com.android.microdroid.test";
        final String configPath = "assets/vm_config.json"; // path inside the APK
        final String cid = startMicrodroid(apkName, packageName, configPath);
        adbConnectToMicrodroid(cid, MICRODROID_ADB_CONNECT_TIMEOUT_MINUTES);

        // Test writing to /data partition
        runOnMicrodroid("echo MicrodroidTest > /data/local/tmp/test.txt");
        assertThat(runOnMicrodroid("cat /data/local/tmp/test.txt"), is("MicrodroidTest"));

        // Check if the APK & its idsig partitions exist
        final String apkPartition = "/dev/block/by-name/microdroid-apk";
        assertThat(runOnMicrodroid("ls", apkPartition), is(apkPartition));
        final String apkIdsigPartition = "/dev/block/by-name/microdroid-apk-idsig";
        assertThat(runOnMicrodroid("ls", apkIdsigPartition), is(apkIdsigPartition));

        // Check if the APK is mounted using zipfuse
        final String mountEntry = "zipfuse on /mnt/apk type fuse.zipfuse";
        assertThat(runOnMicrodroid("mount"), containsString(mountEntry));

        // Check if the native library in the APK is has correct filesystem info
        final String[] abis = runOnMicrodroid("getprop", "ro.product.cpu.abilist").split(",");
        assertThat(abis.length, is(1));
        final String testLib = "/mnt/apk/lib/" + abis[0] + "/MicrodroidTestNativeLib.so";
        final String label = "u:object_r:system_file:s0";
        assertThat(runOnMicrodroid("ls", "-Z", testLib), is(label + " " + testLib));

        // Check if the command in vm_config.json was executed by examining the side effect of the
        // command
        assertThat(runOnMicrodroid("getprop", "debug.microdroid.app.run"), is("true"));
        assertThat(runOnMicrodroid("getprop", "debug.microdroid.app.sublib.run"), is("true"));

        // Manually execute the library and check the output
        final String microdroidLauncher = "system/bin/microdroid_launcher";
        assertThat(
                runOnMicrodroid(microdroidLauncher, testLib, "arg1", "arg2"),
                is("Hello Microdroid " + testLib + " arg1 arg2"));

        // Check that keystore was found by the payload
        assertThat(runOnMicrodroid("getprop", "debug.microdroid.test.keystore"), is("PASS"));

        shutdownMicrodroid(cid);
    }

    @Before
    public void setUp() throws Exception {
        testIfDeviceIsCapable();

        prepareVirtualizationTestSetup();

        // clear the log
        getDevice().executeShellV2Command("logcat -c");
    }

    @After
    public void shutdown() throws Exception {
        cleanUpVirtualizationTestSetup();
    }
}
