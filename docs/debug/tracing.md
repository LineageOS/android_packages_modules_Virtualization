# Hypervisor & guest tracing

## Hypervisor tracing

Starting with android14-5.15 kernel it is possible to get traces from the hypervisor.

### User space interface

The user space hypervisor tracing interface is located either at /sys/kernel/tracing/hyp or at
/sys/kernel/debug/tracing/hyp. On the Android phones it will usually be /sys/kernel/tracing/hyp,
while on QEMU it will be /sys/kernel/debug/tracing/hyp.

The user space interface is very similar to the ftrace user space interface, however there are some
differences, e.g.:

* Only boot clock is supported, and there is no way for user space to change the tracing_clock.
* Hypervisor tracing periodically polls the data from the hypervisor, this is different from the
  regular ftrace instance which pushes the events into the ring buffer.

Note: the list above is not exhaustive.

TODO(b/271412868): add more documentation on the user space interface.

### Perfetto integration

[Perfetto](https://perfetto.dev/docs/) is an open-source stack for performance instrumentation and
trace analysis widely used in  Android. Perfetto supports capturing and visualizing hypervisor
traces.

#### Capturing hypervisor traces on Android

Consider first familiarizing yourself with Perfetto documentation for recording traces on Android:
https://perfetto.dev/docs/quickstart/android-tracing.

The [record_android_trace](
https://cs.android.com/android/platform/superproject/+/master:external/perfetto/tools/record_android_trace)
script supports a shortcut to capture all hypervisor events that are  known to Perfetto:

```shell
external/perfetto/tools/record_android_trace hyp -t 15s -b 32mb -o /tmp/hyp.pftrace
```

Alternatively you can use full trace config to capture hypervisor. Example usage:

```shell
cat<<EOF>config.pbtx
duration_ms: 10000

buffers: {
    size_kb: 8960
    fill_policy: DISCARD
}

data_sources: {
    config {
        name: "linux.ftrace"
        ftrace_config {
            instance_name: "hyp"
            ftrace_events: "hyp/hyp_enter"
            ftrace_events: "hyp/hyp_exit"
        }
    }
}
EOF

./record_android_trace -c config.pbtx -o trace_file.perfetto-trace
```

If you have an Android tree checked out, then record_android_trace helper script can be located at
${REPO_ROOT}/external/perfetto/tools/record_android_traces. Otherwise, you can download the script
by following steps outlined in the [Perfetto docs](
https://perfetto.dev/docs/quickstart/android-tracing#recording-a-trace-through-the-cmdline)

#### Capturing hypervisor traces on QEMU

Perfetto supports capturing traces on Linux: https://perfetto.dev/docs/quickstart/linux-tracing.
However, since pKVM hypervisor is only supported on arm64, you will need to cross-compile Perfetto
binaries for linux-arm64 (unless you have an arm64 workstation).

1. Checkout Perfetto repository: https://perfetto.dev/docs/contributing/getting-started
2. Follow https://perfetto.dev/docs/contributing/build-instructions#cross-compiling-for-linux-arm-64
  to compile Perfetto binaries for arm64 architecture.
3. Copy the tracebox binary to QEMU
4. Run `tracebox` binary on QEMU to capture traces, it's interface is very similar to the
`record_android_trace` binary. E.g. to capture all hypervisor events run:
```shell
tracebox -t 15s -b 32mb hyp
```

## Microdroid VM tracing

IMPORTANT: Tracing is only supported for debuggable Microdroid VMs.

### Capturing trace in Microdroid

Starting with Android U, Microdroid contains Perfetto tracing binaries, which makes it possible to
capture traces inside Microdroid VM using Perfetto stack. The commands used to capture traces on
Android should work for Microdroid VM as well, with a difference that Perfetto's tracing binaries
are not enabled in Microdroid by default, so you need to manually start them by setting
`persist.traced.enable` system property to `1`.

Here is a quick example on how trace Microdroid VM:

1. First start your VM. For this example we are going to use
`adb shell /apex/com.android.virt/bin/vm run-microdroid`.

2. Set up an adb connection with the running VM:
```shell
adb shell forward tcp:9876 vsock:${CID}:5555
adb connect localhost:9876
adb -s localhost:9876 root
```
Where `${CID}` corresponds to the running Microdroid VM that you want to establish adb connection
with. List of running VMs can be obtained by running `adb shell /apex/com.android.virt/bin/vm list`.
Alternatively you can use `vm_shell` utility to connect to a running VM, i.e.: `vm_shell connect`.

3. Start Perfetto daemons and capture trace
```shell
adb -s localhost:9876 shell setprop persist.traced.enable 1
${ANDROID_BULD_TOP}/external/perfetto/tools/record_android_trace \
  -s localhost:9876 \
  -o /tmp/microdroid-trace-file.pftrace \
  -t 10s \
  -b 32mb \
  sched/sched_switch task/task_newtask sched/sched_process_exit
```

If you don't have Android repo checked out, then you can download the record_android_trace script by
following the following [instructions](
https://perfetto.dev/docs/quickstart/android-tracing#recording-a-trace-through-the-cmdline)

More documentation on Perfetto's tracing on Android is available here:
https://perfetto.dev/docs/quickstart/android-tracing

### Capturing Microdroid boot trace

TODO(b/271412868): Stay tuned, more docs are coming soon!
