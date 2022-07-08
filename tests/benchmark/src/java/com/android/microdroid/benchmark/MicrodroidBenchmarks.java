/*
 * Copyright (C) 2022 The Android Open Source Project
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
package com.android.microdroid.benchmark;

import static androidx.test.platform.app.InstrumentationRegistry.getInstrumentation;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.TruthJUnit.assume;

import android.app.Instrumentation;
import android.os.Bundle;
import android.os.SystemProperties;
import android.system.virtualmachine.VirtualMachineConfig;
import android.system.virtualmachine.VirtualMachineConfig.DebugLevel;
import android.system.virtualmachine.VirtualMachineException;

import com.android.microdroid.test.MicrodroidDeviceTestBase;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.Timeout;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.IOException;

@RunWith(Parameterized.class)
public class MicrodroidBenchmarks extends MicrodroidDeviceTestBase {
    private static final String TAG = "MicrodroidBenchmarks";

    @Rule public Timeout globalTimeout = Timeout.seconds(300);

    private static final String KERNEL_VERSION = SystemProperties.get("ro.kernel.version");

    private boolean isCuttlefish() {
        String productName = SystemProperties.get("ro.product.name");
        return (null != productName)
                && (productName.startsWith("aosp_cf_x86")
                        || productName.startsWith("aosp_cf_arm")
                        || productName.startsWith("cf_x86")
                        || productName.startsWith("cf_arm"));
    }

    @Parameterized.Parameters(name = "protectedVm={0}")
    public static Object[] protectedVmConfigs() {
        return new Object[] {false, true};
    }

    @Parameterized.Parameter public boolean mProtectedVm;

    private Instrumentation mInstrumentation;

    @Before
    public void setup() {
        prepareTestSetup(mProtectedVm);
        mInstrumentation = getInstrumentation();
    }

    @After
    public void cleanup() throws VirtualMachineException {
        cleanupTestSetup();
    }

    private boolean canBootMicrodroidWithMemory(int mem)
            throws VirtualMachineException, InterruptedException, IOException {
        final int trialCount = 5;

        // returns true if succeeded at least once.
        for (int i = 0; i < trialCount; i++) {
            VirtualMachineConfig.Builder builder =
                    mInner.newVmConfigBuilder("assets/vm_config.json");
            VirtualMachineConfig normalConfig =
                    builder.debugLevel(DebugLevel.FULL).memoryMib(mem).build();
            mInner.forceCreateNewVirtualMachine("test_vm_minimum_memory", normalConfig);

            if (tryBootVm(TAG, "test_vm_minimum_memory").payloadStarted) return true;
        }

        return false;
    }

    @Test
    public void testMinimumRequiredRAM()
            throws VirtualMachineException, InterruptedException, IOException {
        assume().withMessage("Skip on CF; too slow").that(isCuttlefish()).isFalse();

        int lo = 16, hi = 512, minimum = 0;
        boolean found = false;

        while (lo <= hi) {
            int mid = (lo + hi) / 2;
            if (canBootMicrodroidWithMemory(mid)) {
                found = true;
                minimum = mid;
                hi = mid - 1;
            } else {
                lo = mid + 1;
            }
        }

        assertThat(found).isTrue();

        Bundle bundle = new Bundle();
        bundle.putInt("avf_perf/microdroid/minimum_required_memory", minimum);
        mInstrumentation.sendStatus(0, bundle);
    }
}
