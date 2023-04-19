# Microdroid

Microdroid is a (very) lightweight version of Android that is intended to run on
on-device virtual machines. It is built from the same source code as the regular
Android, but it is much smaller; no system server, no HALs, no GUI, etc. It is
intended to host headless & native workloads only.

## Prerequisites

Any 64-bit target (either x86\_64 or arm64) is supported. 32-bit target is not
supported.

The only remaining requirement is that `com.android.virt` APEX has to be
pre-installed. To do this, add the following line in your product makefile.

```make
$(call inherit-product, packages/modules/Virtualization/apex/product_packages.mk)
```

Build the target product after adding the line, and flash it. This step needs
to be done only once for the target.

If you are using Pixel 6 and beyond or Cuttlefish (`aosp_cf_x86_64_phone`)
adding above line is not necessary as it's already done.

## Building and installing microdroid

Microdroid is part of the `com.android.virt` APEX. To build it and install to
the device:

```sh
banchan com.android.virt aosp_arm64
UNBUNDLED_BUILD_SDKS_FROM_SOURCE=true m apps_only dist
adb install out/dist/com.android.virt.apex
adb reboot
```

If your target is x86\_64 (e.g. `aosp_cf_x86_64_phone`), replace `aosp_arm64`
with `aosp_x86_64`.

## Building an app

A [vm
payload](https://android.googlesource.com/platform/packages/modules/Virtualization/+/refs/heads/master/vm_payload/)
is a shared library file that gets executed in microdroid. It is packaged as
part of an Android application.  The library should have an entry point
`AVmPayload_main` as shown below:

```C++
extern "C" int AVmPayload_main() {
  printf("Hello Microdroid!\n");
}
```

Then build it as a shared library:

```
cc_library_shared {
  name: "MyMicrodroidPayload",
  srcs: ["**/*.cpp"],
  sdk_version: "current",
}
```

Embed the shared library file in an APK:

```
android_app {
  name: "MyApp",
  srcs: ["**/*.java"],
  jni_libs: ["MyMicrodroidPayload"],
  use_embedded_native_libs: true,
  sdk_version: "current",
}
```

Finally, you build the APK.

```sh
TARGET_BUILD_APPS=MyApp m apps_only dist
```

## Running the VM payload on microdroid

First of all, install the APK to the target device.

```sh
adb install out/dist/MyApp.apk
```

There are two ways start a VM and run the payload in it.

* By manually invoking the `vm` tool via `adb shell`.
* Calling APIs programmatically in the Java app.

### Using `vm` tool

Execute the following commands to launch a VM. The VM will boot to microdroid
and then automatically execute your payload (the shared library
`MyMicrodroidPayload.so`).

```sh
TEST_ROOT=/data/local/tmp/virt
adb shell /apex/com.android.virt/bin/vm run-app \
--log $TEST_ROOT/log.txt \
--console $TEST_ROOT/console.txt \
PATH_TO_YOUR_APP \
$TEST_ROOT/MyApp.apk.idsig \
$TEST_ROOT/instance.img \
--payload-binary-name MyMicrodroidPayload.so
```

`ALL_CAP`s below are placeholders. They need to be replaced with correct
values:

* `PACKAGE_NAME_OF_YOUR_APP`: package name of your app (e.g. `com.acme.app`).
* `PATH_TO_YOUR_APP`: path to the installed APK on the device. Can be obtained
  via the following command.
  ```sh
  adb shell pm path PACKAGE_NAME_OF_YOUR_APP
  ```
  It shall report a cryptic path similar to `/data/app/~~OgZq==/com.acme.app-HudMahQ==/base.apk`.

The console output from the VM is stored to `$TEST_ROOT/console.txt` and logcat
is stored to `$TEST_ROOT/log.txt` file for debugging purpose. If you omit
`--log` or `--console` option, the console output will be emitted to the
current console and the logcat logs are sent to the main logcat in Android.

Stopping the VM can be done by pressing `Ctrl+C`.

### Using the APIs

Use the [Android Virtualization Framework Java
APIs](https://android.googlesource.com/platform/packages/modules/Virtualization/+/refs/heads/master/javalib/api/system-current.txt)
in your app to create a microdroid VM and run payload in it. The APIs currently
are @SystemApi, thus available only to privileged apps.

If you are looking for an example usage of the APIs, you may refer to the [demo
app](https://android.googlesource.com/platform/packages/modules/Virtualization/+/refs/heads/master/demo/).

## Debuggable microdroid

### Debugging features
Microdroid supports following debugging features:

- VM log
- console output
- kernel output
- logcat output
- [ramdump](../docs/debug/ramdump.md)
- crashdump
- [adb](#adb)
- [gdb](#debugging-the-payload-on-microdroid)

### Enabling debugging features
There's two ways to enable the debugging features:

#### Option 1) Running microdroid on AVF debug policy configured device

microdroid can be started with debugging features by debug policies from the
host. Host bootloader may provide debug policies to host OS's device tree for
VMs. Host bootloader MUST NOT provide debug policies for locked devices for
security reasons.

For protected VM, such device tree will be available in microdroid. microdroid
can check which debuging features is enabled.

Here are list of device tree properties for debugging features.

- `/avf/guest/common/log`: `<1>` to enable kernel log and logcat. Ignored
  otherwise.
- `/avf/guest/common/ramdump`: `<1>` to enable ramdump. Ignored otherwise.
- `/avf/guest/microdroid/adb`: `<1>` to enable `adb`. Ignored otherwise.

#### Option 2) Lauching microdroid with debug level.

microdroid can be started with debugging features. To do so, first, delete
`$TEST_ROOT/instance.img`; this is because changing debug settings requires a
new instance. Then add the `--debug=full` flag to the
`/apex/com.android.virt/bin/vm run-app` command. This will enable all debugging
features.

### ADB

If `adb` connection is enabled, launch following command.

```sh
vm_shell
```

Done. Now you are logged into Microdroid. Have fun!

Once you have an adb connection with `vm_shell`, `localhost:8000` will be the
serial of microdroid.

### Debugging the payload on microdroid

Like a normal adb device, you can debug native processes using `lldbclient.py`
script, either by running a new process, or attaching to an existing process.
Use `vm_shell` tool above, and then run `lldbclient.py`.

```sh
adb -s localhost:8000 shell 'mount -o remount,exec /data'
development/scripts/lldbclient.py -s localhost:8000 --chroot . --user '' \
    (-p PID | -n NAME | -r ...)
```

**Note:** We need to pass `--chroot .` to skip verifying device, because
microdroid doesn't match with the host's lunch target. We need to also pass
`--user ''` as there is no `su` binary in microdroid.
