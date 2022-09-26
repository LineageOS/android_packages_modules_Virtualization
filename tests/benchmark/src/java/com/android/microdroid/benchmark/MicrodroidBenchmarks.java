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
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;
import android.system.virtualmachine.VirtualMachine;
import android.system.virtualmachine.VirtualMachineConfig;
import android.system.virtualmachine.VirtualMachineConfig.DebugLevel;
import android.system.virtualmachine.VirtualMachineException;
import android.util.Log;

import com.android.microdroid.test.common.MetricsProcessor;
import com.android.microdroid.test.common.ProcessUtil;
import com.android.microdroid.test.device.MicrodroidDeviceTestBase;
import com.android.microdroid.testservice.IBenchmarkService;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.Timeout;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

@RunWith(Parameterized.class)
public class MicrodroidBenchmarks extends MicrodroidDeviceTestBase {
    private static final String TAG = "MicrodroidBenchmarks";
    private static final String METRIC_NAME_PREFIX = getMetricPrefix() + "microdroid/";
    private static final int IO_TEST_TRIAL_COUNT = 5;

    @Rule public Timeout globalTimeout = Timeout.seconds(300);

    private static final String APEX_ETC_FS = "/apex/com.android.virt/etc/fs/";
    private static final double SIZE_MB = 1024.0 * 1024.0;
    private static final String MICRODROID_IMG_PREFIX = "microdroid_";
    private static final String MICRODROID_IMG_SUFFIX = ".img";

    @Parameterized.Parameters(name = "protectedVm={0}")
    public static Object[] protectedVmConfigs() {
        return new Object[] {false, true};
    }

    @Parameterized.Parameter public boolean mProtectedVm;

    private final MetricsProcessor mMetricsProcessor = new MetricsProcessor(METRIC_NAME_PREFIX);

    private Instrumentation mInstrumentation;

    @Before
    public void setup() {
        prepareTestSetup(mProtectedVm);
        mInstrumentation = getInstrumentation();
    }

    private boolean canBootMicrodroidWithMemory(int mem)
            throws VirtualMachineException, InterruptedException, IOException {
        final int trialCount = 5;

        // returns true if succeeded at least once.
        for (int i = 0; i < trialCount; i++) {
            VirtualMachineConfig.Builder builder =
                    mInner.newVmConfigBuilder("assets/vm_config.json");
            VirtualMachineConfig normalConfig =
                    builder.debugLevel(DebugLevel.NONE).memoryMib(mem).build();
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
        bundle.putInt(METRIC_NAME_PREFIX + "minimum_required_memory", minimum);
        mInstrumentation.sendStatus(0, bundle);
    }

    @Test
    public void testMicrodroidBootTime()
            throws VirtualMachineException, InterruptedException, IOException {
        assume().withMessage("Skip on CF; too slow").that(isCuttlefish()).isFalse();

        final int trialCount = 10;

        List<Double> vmStartingTimeMetrics = new ArrayList<>();
        List<Double> bootTimeMetrics = new ArrayList<>();
        List<Double> bootloaderTimeMetrics = new ArrayList<>();
        List<Double> kernelBootTimeMetrics = new ArrayList<>();
        List<Double> userspaceBootTimeMetrics = new ArrayList<>();

        for (int i = 0; i < trialCount; i++) {
            VirtualMachineConfig.Builder builder =
                    mInner.newVmConfigBuilder("assets/vm_config.json");

            // To grab boot events from log, set debug mode to FULL
            VirtualMachineConfig normalConfig =
                    builder.debugLevel(DebugLevel.FULL).memoryMib(256).build();
            mInner.forceCreateNewVirtualMachine("test_vm_boot_time", normalConfig);

            BootResult result = tryBootVm(TAG, "test_vm_boot_time");
            assertThat(result.payloadStarted).isTrue();

            final double nanoToMilli = 1000000.0;
            vmStartingTimeMetrics.add(result.getVMStartingElapsedNanoTime() / nanoToMilli);
            bootTimeMetrics.add(result.endToEndNanoTime / nanoToMilli);
            bootloaderTimeMetrics.add(result.getBootloaderElapsedNanoTime() / nanoToMilli);
            kernelBootTimeMetrics.add(result.getKernelElapsedNanoTime() / nanoToMilli);
            userspaceBootTimeMetrics.add(result.getUserspaceElapsedNanoTime() / nanoToMilli);
        }

        reportMetrics(vmStartingTimeMetrics, "vm_starting_time", "ms");
        reportMetrics(bootTimeMetrics, "boot_time", "ms");
        reportMetrics(bootloaderTimeMetrics, "bootloader_time", "ms");
        reportMetrics(kernelBootTimeMetrics, "kernel_boot_time", "ms");
        reportMetrics(userspaceBootTimeMetrics, "userspace_boot_time", "ms");
    }

    @Test
    public void testMicrodroidImageSize() throws IOException {
        Bundle bundle = new Bundle();
        for (File file : new File(APEX_ETC_FS).listFiles()) {
            String name = file.getName();

            if (!name.startsWith(MICRODROID_IMG_PREFIX) || !name.endsWith(MICRODROID_IMG_SUFFIX)) {
                continue;
            }

            String base =
                    name.substring(
                            MICRODROID_IMG_PREFIX.length(),
                            name.length() - MICRODROID_IMG_SUFFIX.length());
            String metric = METRIC_NAME_PREFIX + "img_size_" + base + "_MB";
            double size = Files.size(file.toPath()) / SIZE_MB;
            bundle.putDouble(metric, size);
        }
        mInstrumentation.sendStatus(0, bundle);
    }

    @Test
    public void testVsockTransferFromHostToVM() throws Exception {
        VirtualMachineConfig config =
                mInner.newVmConfigBuilder("assets/vm_config_io.json")
                        .debugLevel(DebugLevel.FULL)
                        .build();
        List<Double> transferRates = new ArrayList<>(IO_TEST_TRIAL_COUNT);

        for (int i = 0; i < IO_TEST_TRIAL_COUNT; ++i) {
            int port = (mProtectedVm ? 5666 : 6666) + i;
            String vmName = "test_vm_io_" + i;
            mInner.forceCreateNewVirtualMachine(vmName, config);
            VirtualMachine vm = mInner.getVirtualMachineManager().get(vmName);
            BenchmarkVmListener.create(new VsockListener(transferRates, port)).runToFinish(TAG, vm);
        }
        reportMetrics(transferRates, "vsock/transfer_host_to_vm", "mb_per_sec");
    }

    @Test
    public void testVirtioBlkSeqReadRate() throws Exception {
        testVirtioBlkReadRate(/*isRand=*/ false);
    }

    @Test
    public void testVirtioBlkRandReadRate() throws Exception {
        testVirtioBlkReadRate(/*isRand=*/ true);
    }

    private void testVirtioBlkReadRate(boolean isRand) throws Exception {
        VirtualMachineConfig config =
                mInner.newVmConfigBuilder("assets/vm_config_io.json")
                        .debugLevel(DebugLevel.FULL)
                        .build();
        List<Double> readRates = new ArrayList<>(IO_TEST_TRIAL_COUNT);

        for (int i = 0; i < IO_TEST_TRIAL_COUNT + 1; ++i) {
            if (i == 1) {
                // Clear the first result because when the file was loaded the first time,
                // the data also needs to be loaded from hard drive to host. This is
                // not part of the virtio-blk IO throughput.
                readRates.clear();
            }
            String vmName = "test_vm_io_" + i;
            mInner.forceCreateNewVirtualMachine(vmName, config);
            VirtualMachine vm = mInner.getVirtualMachineManager().get(vmName);
            BenchmarkVmListener.create(new VirtioBlkListener(readRates, isRand))
                    .runToFinish(TAG, vm);
        }
        reportMetrics(
                readRates, isRand ? "virtio-blk/rand_read" : "virtio-blk/seq_read", "mb_per_sec");
    }

    private void reportMetrics(List<Double> metrics, String name, String unit) {
        Map<String, Double> stats = mMetricsProcessor.computeStats(metrics, name, unit);
        Bundle bundle = new Bundle();
        for (Map.Entry<String, Double> entry : stats.entrySet()) {
            bundle.putDouble(entry.getKey(), entry.getValue());
        }
        mInstrumentation.sendStatus(0, bundle);
    }

    private static class VirtioBlkListener implements BenchmarkVmListener.InnerListener {
        private static final String FILENAME = APEX_ETC_FS + "microdroid_super.img";

        private final long mFileSizeBytes;
        private final List<Double> mReadRates;
        private final boolean mIsRand;

        VirtioBlkListener(List<Double> readRates, boolean isRand) {
            File file = new File(FILENAME);
            try {
                mFileSizeBytes = Files.size(file.toPath());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            assertThat(mFileSizeBytes).isGreaterThan((long) SIZE_MB);
            mReadRates = readRates;
            mIsRand = isRand;
        }

        @Override
        public void onPayloadReady(VirtualMachine vm, IBenchmarkService benchmarkService)
                throws RemoteException {
            double readRate = benchmarkService.measureReadRate(FILENAME, mFileSizeBytes, mIsRand);
            mReadRates.add(readRate);
        }
    }

    private String executeCommand(String command) {
        return runInShell(TAG, mInstrumentation.getUiAutomation(), command);
    }

    @Test
    public void testMemoryUsage() throws Exception {
        final String vmName = "test_vm_mem_usage";
        VirtualMachineConfig config =
                mInner.newVmConfigBuilder("assets/vm_config_io.json")
                        .debugLevel(DebugLevel.NONE)
                        .memoryMib(256)
                        .build();
        mInner.forceCreateNewVirtualMachine(vmName, config);
        VirtualMachine vm = mInner.getVirtualMachineManager().get(vmName);
        MemoryUsageListener listener = new MemoryUsageListener(this::executeCommand);
        BenchmarkVmListener.create(listener).runToFinish(TAG, vm);

        double mem_overall = 256.0;
        double mem_total = (double) listener.mMemTotal / 1024.0;
        double mem_free = (double) listener.mMemFree / 1024.0;
        double mem_avail = (double) listener.mMemAvailable / 1024.0;
        double mem_buffers = (double) listener.mBuffers / 1024.0;
        double mem_cached = (double) listener.mCached / 1024.0;
        double mem_slab = (double) listener.mSlab / 1024.0;
        double mem_crosvm_host_rss = (double) listener.mCrosvmHostRss / 1024.0;
        double mem_crosvm_host_pss = (double) listener.mCrosvmHostPss / 1024.0;
        double mem_crosvm_guest_rss = (double) listener.mCrosvmGuestRss / 1024.0;
        double mem_crosvm_guest_pss = (double) listener.mCrosvmGuestPss / 1024.0;

        double mem_kernel = mem_overall - mem_total;
        double mem_used = mem_total - mem_free - mem_buffers - mem_cached - mem_slab;
        double mem_unreclaimable = mem_total - mem_avail;

        Bundle bundle = new Bundle();
        bundle.putDouble(METRIC_NAME_PREFIX + "mem_kernel_MB", mem_kernel);
        bundle.putDouble(METRIC_NAME_PREFIX + "mem_used_MB", mem_used);
        bundle.putDouble(METRIC_NAME_PREFIX + "mem_buffers_MB", mem_buffers);
        bundle.putDouble(METRIC_NAME_PREFIX + "mem_cached_MB", mem_cached);
        bundle.putDouble(METRIC_NAME_PREFIX + "mem_slab_MB", mem_slab);
        bundle.putDouble(METRIC_NAME_PREFIX + "mem_unreclaimable_MB", mem_unreclaimable);
        bundle.putDouble(METRIC_NAME_PREFIX + "mem_crosvm_host_rss_MB", mem_crosvm_host_rss);
        bundle.putDouble(METRIC_NAME_PREFIX + "mem_crosvm_host_pss_MB", mem_crosvm_host_pss);
        bundle.putDouble(METRIC_NAME_PREFIX + "mem_crosvm_guest_rss_MB", mem_crosvm_guest_rss);
        bundle.putDouble(METRIC_NAME_PREFIX + "mem_crosvm_guest_pss_MB", mem_crosvm_guest_pss);
        mInstrumentation.sendStatus(0, bundle);
    }

    private static class MemoryUsageListener implements BenchmarkVmListener.InnerListener {
        MemoryUsageListener(Function<String, String> shellExecutor) {
            mShellExecutor = shellExecutor;
        }

        public Function<String, String> mShellExecutor;

        public long mMemTotal;
        public long mMemFree;
        public long mMemAvailable;
        public long mBuffers;
        public long mCached;
        public long mSlab;

        public long mCrosvmHostRss;
        public long mCrosvmHostPss;
        public long mCrosvmGuestRss;
        public long mCrosvmGuestPss;

        @Override
        public void onPayloadReady(VirtualMachine vm, IBenchmarkService service)
                throws RemoteException {
            mMemTotal = service.getMemInfoEntry("MemTotal");
            mMemFree = service.getMemInfoEntry("MemFree");
            mMemAvailable = service.getMemInfoEntry("MemAvailable");
            mBuffers = service.getMemInfoEntry("Buffers");
            mCached = service.getMemInfoEntry("Cached");
            mSlab = service.getMemInfoEntry("Slab");

            try {
                List<Integer> crosvmPids =
                        ProcessUtil.getProcessMap(mShellExecutor).entrySet().stream()
                                .filter(e -> e.getValue().contains("crosvm"))
                                .map(e -> e.getKey())
                                .collect(java.util.stream.Collectors.toList());
                if (crosvmPids.size() != 1) {
                    throw new RuntimeException(
                            "expected to find exactly one crosvm processes, found "
                                    + crosvmPids.size());
                }

                mCrosvmHostRss = 0;
                mCrosvmHostPss = 0;
                mCrosvmGuestRss = 0;
                mCrosvmGuestPss = 0;
                for (ProcessUtil.SMapEntry entry :
                        ProcessUtil.getProcessSmaps(crosvmPids.get(0), mShellExecutor)) {
                    long rss = entry.metrics.get("Rss");
                    long pss = entry.metrics.get("Pss");
                    if (entry.name.contains("crosvm_guest")) {
                        mCrosvmGuestRss += rss;
                        mCrosvmGuestPss += pss;
                    } else {
                        mCrosvmHostRss += rss;
                        mCrosvmHostPss += pss;
                    }
                }
            } catch (Exception e) {
                Log.e(TAG, "Error inside onPayloadReady():" + e);
                throw new RuntimeException(e);
            }
        }
    }

    private static class VsockListener implements BenchmarkVmListener.InnerListener {
        private static final int NUM_BYTES_TO_TRANSFER = 48 * 1024 * 1024;

        private final List<Double> mReadRates;
        private final int mPort;

        VsockListener(List<Double> readRates, int port) {
            mReadRates = readRates;
            mPort = port;
        }

        @Override
        public void onPayloadReady(VirtualMachine vm, IBenchmarkService benchmarkService)
                throws RemoteException {
            AtomicReference<Double> sendRate = new AtomicReference();

            int serverFd = benchmarkService.initVsockServer(mPort);
            new Thread(() -> sendRate.set(runVsockClientAndSendData(vm))).start();
            benchmarkService.runVsockServerAndReceiveData(serverFd, NUM_BYTES_TO_TRANSFER);

            mReadRates.add(sendRate.get());
        }

        private double runVsockClientAndSendData(VirtualMachine vm) {
            try {
                ParcelFileDescriptor fd = vm.connectVsock(mPort);
                double sendRate =
                        IoVsockHostNative.measureSendRate(fd.getFd(), NUM_BYTES_TO_TRANSFER);
                fd.closeWithError("Cannot close socket file descriptor");
                return sendRate;
            } catch (Exception e) {
                Log.e(TAG, "Error inside runVsockClientAndSendData():" + e);
                throw new RuntimeException(e);
            }
        }
    }
}
