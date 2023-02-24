/*
 * Copyright 2023 The Android Open Source Project
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

package com.android.microdroid.test;

import static com.android.tradefed.device.TestDevice.MicrodroidBuilder;

import static com.google.common.truth.Truth.assertThat;

import static org.junit.Assume.assumeTrue;
import static org.junit.Assume.assumeFalse;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.android.microdroid.test.host.CommandRunner;
import com.android.microdroid.test.host.MicrodroidHostTestCaseBase;
import com.android.microdroid.test.host.Pvmfw;
import com.android.tradefed.device.DeviceNotAvailableException;
import com.android.tradefed.device.TestDevice;
import com.android.tradefed.device.ITestDevice;
import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
import com.android.tradefed.util.FileUtil;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.util.Objects;
import java.io.FileNotFoundException;

/** Tests debug policy of pvmfw.bin with custom debug policy */
@RunWith(DeviceJUnit4ClassRunner.class)
public class PvmfwDebugPolicyHostTests extends MicrodroidHostTestCaseBase {
    @NonNull private static final String PVMFW_FILE_NAME = "pvmfw_test.bin";
    @NonNull private static final String BCC_FILE_NAME = "bcc.dat";
    @NonNull private static final String PACKAGE_FILE_NAME = "MicrodroidTestApp.apk";
    @NonNull private static final String PACKAGE_NAME = "com.android.microdroid.test";
    @NonNull private static final String MICRODROID_DEBUG_LEVEL = "full";
    @NonNull private static final String MICRODROID_CONFIG_PATH = "assets/vm_config_apex.json";
    private static final int BOOT_COMPLETE_TIMEOUT = 30000; // 30 seconds

    @NonNull private static final String CUSTOM_PVMFW_FILE_PREFIX = "pvmfw";
    @NonNull private static final String CUSTOM_PVMFW_FILE_SUFFIX = ".bin";
    @NonNull private static final String CUSTOM_PVMFW_IMG_PATH = TEST_ROOT + "/" + PVMFW_FILE_NAME;
    @NonNull private static final String CUSTOM_PVMFW_IMG_PATH_PROP = "hypervisor.pvmfw.path";

    @NonNull private static final String MICRODROID_CMDLINE_PATH = "/proc/cmdline";
    @NonNull private static final String MICRODROID_DT_ROOT_PATH = "/proc/device-tree";

    @NonNull
    private static final String MICRODROID_DT_BOOTARGS_PATH =
            MICRODROID_DT_ROOT_PATH + "/chosen/bootargs";

    @NonNull
    private static final String MICRODROID_DT_RAMDUMP_PATH =
            MICRODROID_DT_ROOT_PATH + "/avf/guest/common/ramdump";

    @NonNull private static final String HEX_STRING_ZERO = "00000000";
    @NonNull private static final String HEX_STRING_ONE = "00000001";

    @Nullable private static File mPvmfwBinFileOnHost;
    @Nullable private static File mBccFileOnHost;

    @Nullable private TestDevice mAndroidDevice;
    @Nullable private ITestDevice mMicrodroidDevice;
    @Nullable private File mCustomPvmfwBinFileOnHost;

    @Before
    public void setUp() throws Exception {
        mAndroidDevice = (TestDevice) Objects.requireNonNull(getDevice());
        assumeTrue(
                "Skip if protected VMs are not supported",
                mAndroidDevice.supportsMicrodroid(/* protectedVm= */ true));
        assumeFalse("Test requires setprop for using custom pvmfw and adb root", isUserBuild());

        mAndroidDevice.enableAdbRoot();

        // tradefed copies the test artfacts under /tmp when running tests,
        // so we should *find* the artifacts with the file name.
        mPvmfwBinFileOnHost =
                getTestInformation().getDependencyFile(PVMFW_FILE_NAME, /* targetFirst= */ false);
        mBccFileOnHost =
                getTestInformation().getDependencyFile(BCC_FILE_NAME, /* targetFirst= */ false);

        // Check device capability
        testIfDeviceIsCapable(mAndroidDevice);
        assumeTrue(
                "Protected VMs are not supported",
                mAndroidDevice.supportsMicrodroid(/*protectedVm=*/ true));

        // Prepare for loading pvmfw.bin
        // File will be setup in individual test,
        // and then pushed to device in launchProtectedVmAndWaitForBootCompleted.
        mCustomPvmfwBinFileOnHost =
                FileUtil.createTempFile(CUSTOM_PVMFW_FILE_PREFIX, CUSTOM_PVMFW_FILE_SUFFIX);
        mAndroidDevice.setProperty(CUSTOM_PVMFW_IMG_PATH_PROP, CUSTOM_PVMFW_IMG_PATH);

        // Prepare for launching microdroid
        mAndroidDevice.installPackage(findTestFile(PACKAGE_FILE_NAME), /* reinstall */ false);
        prepareVirtualizationTestSetup(mAndroidDevice);
        mMicrodroidDevice = null;
    }

    @After
    public void shutdown() throws Exception {
        if (!mAndroidDevice.supportsMicrodroid(/* protectedVm= */ true)) {
            return;
        }
        if (mMicrodroidDevice != null) {
            mAndroidDevice.shutdownMicrodroid(mMicrodroidDevice);
            mMicrodroidDevice = null;
        }
        mAndroidDevice.uninstallPackage(PACKAGE_NAME);

        // Cleanup for custom pvmfw.bin
        mAndroidDevice.setProperty(CUSTOM_PVMFW_IMG_PATH_PROP, "");
        FileUtil.deleteFile(mCustomPvmfwBinFileOnHost);

        cleanUpVirtualizationTestSetup(mAndroidDevice);

        mAndroidDevice.disableAdbRoot();
    }

    @Test
    public void testRamdump() throws Exception {
        Pvmfw pvmfw = createPvmfw("avf_debug_policy_with_ramdump.dtbo");
        pvmfw.serialize(mCustomPvmfwBinFileOnHost);
        mMicrodroidDevice = launchProtectedVmAndWaitForBootCompleted();

        assertThat(readMicrodroidFileAsString(MICRODROID_CMDLINE_PATH)).contains("crashkernel=");
        assertThat(readMicrodroidFileAsString(MICRODROID_DT_BOOTARGS_PATH))
                .contains("crashkernel=");
        assertThat(readMicrodroidFileAsHexString(MICRODROID_DT_RAMDUMP_PATH))
                .isEqualTo(HEX_STRING_ONE);
    }

    @Test
    public void testNoRamdump() throws Exception {
        Pvmfw pvmfw = createPvmfw("avf_debug_policy_without_ramdump.dtbo");
        pvmfw.serialize(mCustomPvmfwBinFileOnHost);
        mMicrodroidDevice = launchProtectedVmAndWaitForBootCompleted();

        assertThat(readMicrodroidFileAsString(MICRODROID_CMDLINE_PATH))
                .doesNotContain("crashkernel=");
        assertThat(readMicrodroidFileAsString(MICRODROID_DT_BOOTARGS_PATH))
                .doesNotContain("crashkernel=");
        assertThat(readMicrodroidFileAsHexString(MICRODROID_DT_RAMDUMP_PATH))
                .isEqualTo(HEX_STRING_ZERO);
    }

    @NonNull
    private String readMicrodroidFileAsString(@NonNull String path)
            throws DeviceNotAvailableException {
        return new CommandRunner(mMicrodroidDevice).run("cat", path);
    }

    @NonNull
    private String readMicrodroidFileAsHexString(@NonNull String path)
            throws DeviceNotAvailableException {
        return new CommandRunner(mMicrodroidDevice).run("xxd", "-p", path);
    }

    @NonNull
    private Pvmfw createPvmfw(@NonNull String debugPolicyFileName) throws FileNotFoundException {
        File file =
                getTestInformation()
                        .getDependencyFile(debugPolicyFileName, /* targetFirst= */ false);
        return new Pvmfw.Builder(mPvmfwBinFileOnHost, mBccFileOnHost)
                .setDebugPolicyOverlay(file)
                .build();
    }

    private ITestDevice launchProtectedVmAndWaitForBootCompleted()
            throws DeviceNotAvailableException {
        mMicrodroidDevice =
                MicrodroidBuilder.fromDevicePath(
                                getPathForPackage(PACKAGE_NAME), MICRODROID_CONFIG_PATH)
                        .debugLevel(MICRODROID_DEBUG_LEVEL)
                        .protectedVm(/* protectedVm= */ true)
                        .addBootFile(mCustomPvmfwBinFileOnHost, PVMFW_FILE_NAME)
                        .build(mAndroidDevice);
        assertThat(mMicrodroidDevice.waitForBootComplete(BOOT_COMPLETE_TIMEOUT)).isTrue();
        assertThat(mMicrodroidDevice.enableAdbRoot()).isTrue();

        return mMicrodroidDevice;
    }
}
