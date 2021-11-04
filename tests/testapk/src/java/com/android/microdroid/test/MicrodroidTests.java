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
package com.android.microdroid.test;

import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeNoException;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.system.virtualmachine.VirtualMachine;
import android.system.virtualmachine.VirtualMachineCallback;
import android.system.virtualmachine.VirtualMachineConfig;
import android.system.virtualmachine.VirtualMachineException;
import android.system.virtualmachine.VirtualMachineManager;

import androidx.test.core.app.ApplicationProvider;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.Timeout;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class MicrodroidTests {
    @Rule public Timeout globalTimeout = Timeout.seconds(300);

    private static class Inner {
        public Context mContext;
        public VirtualMachineManager mVmm;
        public VirtualMachine mVm;
    }

    private boolean mPkvmSupported = false;
    private Inner mInner;

    @Before
    public void setup() {
        // In case when the virt APEX doesn't exist on the device, classes in the
        // android.system.virtualmachine package can't be loaded. Therefore, before using the
        // classes, check the existence of a class in the package and skip this test if not exist.
        try {
            Class.forName("android.system.virtualmachine.VirtualMachineManager");
            mPkvmSupported = true;
        } catch (ClassNotFoundException e) {
            assumeNoException(e);
            return;
        }
        mInner = new Inner();
        mInner.mContext = ApplicationProvider.getApplicationContext();
        mInner.mVmm = VirtualMachineManager.getInstance(mInner.mContext);
    }

    @After
    public void cleanup() throws VirtualMachineException {
        if (!mPkvmSupported) {
            return;
        }
        if (mInner.mVm == null) {
            return;
        }
        mInner.mVm.stop();
        mInner.mVm.delete();
    }

    private abstract static class VmEventListener implements VirtualMachineCallback {
        private final Handler mHandler;

        VmEventListener() {
            Looper.prepare();
            mHandler = new Handler(Looper.myLooper());
        }

        void runToFinish(VirtualMachine vm) throws VirtualMachineException {
            vm.setCallback(mCallback);
            vm.run();
            Looper.loop();
        }

        void forceStop(VirtualMachine vm) {
            try {
                vm.stop();
                this.onDied(vm);
                Looper.myLooper().quitSafely();
            } catch (VirtualMachineException e) {
                throw new RuntimeException(e);
            }
        }

        // This is the actual listener that is registered. Since the listener is executed in another
        // thread, post a runnable to the current thread to call the corresponding mHandler method
        // in the current thread.
        private final VirtualMachineCallback mCallback =
                new VirtualMachineCallback() {
                    @Override
                    public void onPayloadStarted(VirtualMachine vm, ParcelFileDescriptor stream) {
                        mHandler.post(() -> VmEventListener.this.onPayloadStarted(vm, stream));
                    }

                    @Override
                    public void onPayloadReady(VirtualMachine vm) {
                        mHandler.post(() -> VmEventListener.this.onPayloadReady(vm));
                    }

                    @Override
                    public void onPayloadFinished(VirtualMachine vm, int exitCode) {
                        mHandler.post(() -> VmEventListener.this.onPayloadFinished(vm, exitCode));
                    }

                    @Override
                    public void onDied(VirtualMachine vm) {
                        mHandler.post(
                                () -> {
                                    VmEventListener.this.onDied(vm);
                                    Looper.myLooper().quitSafely();
                                });
                    }
                };

        @Override
        public void onPayloadStarted(VirtualMachine vm, ParcelFileDescriptor stream) {}

        @Override
        public void onPayloadReady(VirtualMachine vm) {}

        @Override
        public void onPayloadFinished(VirtualMachine vm, int exitCode) {}

        @Override
        public void onDied(VirtualMachine vm) {}
    }

    @Test
    public void startAndStop() throws VirtualMachineException, InterruptedException {
        VirtualMachineConfig.Builder builder =
                new VirtualMachineConfig.Builder(mInner.mContext, "assets/vm_config.json");
        VirtualMachineConfig config = builder.build();

        mInner.mVm = mInner.mVmm.getOrCreate("test_vm", config);
        VmEventListener listener =
                new VmEventListener() {
                    private boolean mPayloadReadyCalled = false;
                    private boolean mPayloadStartedCalled = false;

                    @Override
                    public void onPayloadStarted(VirtualMachine vm, ParcelFileDescriptor stream) {
                        mPayloadStartedCalled = true;
                    }

                    @Override
                    public void onPayloadReady(VirtualMachine vm) {
                        mPayloadReadyCalled = true;
                        forceStop(vm);
                    }

                    @Override
                    public void onDied(VirtualMachine vm) {
                        assertTrue(mPayloadReadyCalled);
                        assertTrue(mPayloadStartedCalled);
                    }
                };
        listener.runToFinish(mInner.mVm);
    }
}
