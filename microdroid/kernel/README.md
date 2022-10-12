# Microdroid kernel

This directory contains prebuilt images of the Linux kernel that is used in
Microdroid. The kernel is built from the same source tree as Generic Kernel
Image (GKI), but with a different config where most of the config items are
turned off to make the kernel fast & slim.

## How to build the Microdroid kernels

### Checkout the GKI source code.

```bash
repo init -u https://android.googlesource.com/kernel/manifest -b android14-5.15
repo sync
```

### Build the Microdroid kernels manually

For ARM64
```bash
FAST_BUILD=1 BUILD_CONFIG=common-modules/virtual-device/build.config.microdroid.aarch64 build/build.sh
```

For x86\_64,
```bash
FAST_BUILD=1 BUILD_CONFIG=common-modules/virtual-device/build.config.microdroid.x86_64 build/build.sh
```

Note that `FAST_BUILD=1` is not mandatory, but will make your build much faster.

## How to update Microdroid kernel prebuilts

### For manually built kernels (only for your own development)

Copy the built kernel image to the Android source tree directly, and build the virt APEX.

For ARM64,
```bash
cp out/android14-5.15/dist/Image <android_checkout>/packages/modules/Virtualization/microdroid/kernel/arm64/kernel-5.15
```

For x86\_64,
```bash
cp out/android14-5.15/dist/bzImage <android_checkout>/packages/modules/Virtualization/microdroid/kernel/arm64/kernel-5.15
```

### For official updates

Use the `download_from_ci` script to automatically fetch the built images from
a specific `<build_id>` and make commits with nice history in the message.

```bash
cd <android_checkout>/packages/modules/Virtualization
repo start <topic_name>
cd <kernel_checkout>
ANDROID_BUILD_TOP=<android_checkout> ./build/kernel/gki/download_from_ci  --update-microdroid -b <bug_id> <build_id>
cd <android_checkout>/packages/modules/Virtualization
repo upload .
```
