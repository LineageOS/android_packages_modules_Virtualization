# Microdroid

Microdroid is a (very) lightweight version of Android that is intended to run on
on-device virtual machines. It is built from the same source code as the regular
Android, but it is much smaller; no system server, no HALs, no GUI, etc. It is
intended to host headless & native workloads only.

## Prerequisites

Any 64-bit target (either x86\_64 or arm64) is supported. 32-bit target is not
supported. Note that we currently don't support user builds; only userdebug
builds are supported.

The only remaining requirment is that `com.android.virt` APEX has to be
pre-installed. To do this, add the following line in your product makefile.

```make
$(call inherit-product, packages/modules/Virtualization/apex/product_packages.mk)
```

Build the target after adding the line, and flash it. This step needs to be done
only once for the target.

If you are using `yukawa` (VIM3L) or `aosp_cf_x86_64_phone` (Cuttlefish), adding
above line is not necessary as it's already done.

Instructions for building and flashing Android for `yukawa` can be found
[here](../docs/getting_started/yukawa.md).

## Building and installing microdroid

Microdroid is part of the `com.android.virt` APEX. To build it and install to
the device:

```sh
banchan com.android.virt aosp_arm64
m apps_only dist
adb install out/dist/com.android.virt.apex
adb reboot
```

If your target is x86\_64 (e.g. `aosp_cf_x86_64_phone`), replace `aosp_arm64`
with `aosp_x86_64`.

## Building an app

An app in microdroid is a shared library file embedded in an APK. The shared
library should have an entry point `android_native_main` as shown below:

```C++
extern "C" int android_native_main(int argc, char* argv[]) {
  printf("Hello Microdroid!\n");
}
```

Then build it as a shared library:

```
cc_library_shared {
  name: "MyMicrodroidApp",
  srcs: ["**/*.cpp"],
  sdk_version: "current",
}
```

Then you need a configuration file in JSON format that defines what to load and
execute in microdroid. The name of the file can be anything and you may have
multiple configuration files if needed.

```json
{
  "os": {"name": "microdroid"},
  "task": {
    "type": "microdroid_launcher",
    "command": "MyMicrodroidApp.so"
  },
  "apexes": [
    {"name": "com.android.adbd"},
    {"name": "com.android.i18n"},
    {"name": "com.android.os.statsd"},
    {"name": "com.android.sdkext"}
  ]
}
```

The value of `task.command` should match with the name of the shared library
defined above. The `apexes` array is the APEXes that will be imported to
microdroid. The above four APEXes are essential ones and therefore shouldn't be
omitted. In the future, you wouldn't need to add the default ones manually. If
more APEXes are required for you app, add their names too.

Embed the shared library and the VM configuration file in an APK:

```
android_app {
  name: "MyApp",
  srcs: ["**/*.java"], // if there is any java code
  jni_libs: ["MyMicrodroidApp"],
  use_embedded_native_libs: true,
  sdk_version: "current",
}

// The VM configuration file can be embedded by simply placing it at `./assets`
directory.
```

Finally, you build and sign the APK.

```sh
TARGET_BUILD_APPS=MyApp m dist
m apksigner
apksigner sign --ks path_to_keystore out/dist/MyApp.apk
```

`path_to_keystore` should be replaced with the actual path to the keystore,
which can be created as follows:

```sh
keytool -keystore my_keystore -genkey -alias my_key
```

Make sure that `.apk.idsig` file is also generated in the same directory as the
signed APK.

## Running the app on microdroid

First of all, install the signed APK to the target device.

```sh
adb install out/dist/MyApp.apk
```

### Creating `payload.img` manually (temporary step)

This is a step that needs to be done manually for now. Eventually, this will be
automatically done by a service named `virtualizationservice` which is part of
the `com.android.virt` APEX.

Create `payload.json` file:

```json
{
  "payload_config_path": "/mnt/apk/assets/VM_CONFIG_NAME,
  "system_apexes": [
    "com.android.adbd",
    "com.android.i18n",
    "com.android.os.statsd",
    "com.android.sdkext"
  ],
  "apk": {
    "name": "PACKAGE_NAME_OF_YOUR_APP",
    "path": "PATH_TO_YOUR_APP",
    "idsig_path": "PATH_TO_APK_IDSIG"
  }
}
```

`ALL_CAP`s in the above are placeholders. They need to be replaced with correct
values:

* `VM_CONFIG_FILE`: the name of the VM config file that you embedded in the APK.
* `PACKAGE_NAME_OF_YOUR_APP`: package name of your app(e.g. `com.acme.app`).
* `PATH_TO_YOUR_APP`: path to the installed APK on the device. Can be obtained
  via the following command.

```sh
adb shell pm path PACKAGE_NAME_OF_YOUR_APP
```

It shall report a cryptic path similar to
`/data/app/~~OgZq==/com.acme.app-HudMahQ==/base.apk`.

* `PATH_TO_APK_IDSIG`: path to the pushed APK idsig on the device. See below
  `adb push` command: it will be `/data/local/tmp/virt/MyApp.apk.idsig` in this
  example.

Once the file is done, execute the following command to push it to the device
and run `mk_payload` to create `payload.img`:

```sh
TEST_ROOT=/data/local/tmp/virt
adb push out/dist/MyApp.apk.idsig $TEST_ROOT/MyApp.apk.idsig
adb push path_to_payload.json $TEST_ROOT/payload.json
adb shell /apex/com.android.virt/bin/my_payload $TEST_ROOT/payload.json $TEST_ROOT/payload.img
adb shell chmod go+r $TEST_ROOT/payload*
```

### Running the VM

Execute the following commands to launch a VM. The VM will boot to microdroid
and then automatically execute your app (the shared library
`MyMicrodroidApp.so`).

```sh
TEST_ROOT=/data/local/tmp/virt
adb push packages/modules/Virtualization/microdroid/microdroid.json $TEST_ROOT/microdroid.json
adb root
adb shell setenforce 0
adb shell start virtualizationservice
adb shell /apex/com.android.virt/bin/vm run $TEST_ROOT/microdroid.json
```

The last command lets you know the CID assigned to the VM.

Note: the disabling of SELinux is a temporary step. The restriction will
eventually be removed.

Stopping the VM can be done as follows:

```sh
adb shell /apex/com.android.virt/bin/vm stop CID
```

, where `CID` is the reported CID value.

## ADB

On userdebug builds, you can have an adb connection to microdroid. To do so,

```sh
adb forward tcp:8000 vsock:$CID:5555
adb connect localhost:8000
```

`CID` should be the CID that `vm` reported upon execution of the `vm run`
command in the above. You can also check it with `adb shell
"/apex/com.android.virt/bin/vm list"`. `5555` must be
the value. `8000` however can be any port in the development machine.

Done. Now you can log into microdroid. Have fun!

```sh
$ adb -s localhost:8000 shell
```
