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

So far it is only possible to capture hypervisor trace events by providing the full trace config
file to Perfetto. Here is the minimal

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

TODO(b/271412868): fill in this section

TODO(b/271412868): Stay tuned, more docs coming soon!

## Microdroid VM tracing

TODO(b/271412868): Stay tuned, more docs are coming soon!
