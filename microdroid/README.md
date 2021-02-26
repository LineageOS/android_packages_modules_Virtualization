# Microdroid

Microdroid is a (very) lightweight version of Android that is intended to run on
on-device virtual machines. It is built from the same source code as the regular
Android, but it is much smaller; no system server, no HALs, no GUI, etc. It is
intended to host headless & native workloads only.

## Building

You need a VIM3L board. Instructions for building Android for the target, and
flashing the image can be found [here](../docs/getting_started/yukawa.md).

Then you build microdroid. Note that the instruction below is very likely to
change in the future, because this is in active development. For example, the
`microdroid_*` modules will eventually be included in the `com.android.virt`
APEX, which is already in the `yukawa` (VIM3L) target.

```
$ source build/envsetup.sh
$ choosecombo 1 aosp_arm64 userdebug // actually, any arm64-based target is ok
$ m microdroid_super
$ m microdroid_boot-5.10
$ m microdroid_vendor_boot-5.10
$ m microdroid_uboot_env
```

## Installing

Push the built files to the device. In addition to that, some other files have
to be manually created, for now. In the future, you won't need these.

```
$ adb push device/google/cuttlefish_prebuilts/bootloader/crosvm_aarch64/u-boot.bin /data/local/tmp/bootloader
$ adb push $ANDROID_PRODUCT_OUT/system/etc/microdroid_super.img /data/local/tmp/super.img
$ adb push $ANDROID_PRODUCT_OUT/system/etc/microdroid_boot-5.10.img /data/local/tmp/boot.img
$ adb push $ANDROID_PRODUCT_OUT/system/etc/microdroid_vendor_boot-5.10.img /data/local/tmp/vendor_boot.img
$ adb shell mkdir /data/local/tmp/cuttlefish_runtime.1/
$ adb push $ANDROID_PRODUCT_OUT/system/etc/uboot_env.img /data/local/tmp/cuttlefish_runtime.1/
$ adb shell mkdir -p /data/local/tmp/etc/cvd_config
$ adb shell 'echo "{}" > /data/local/tmp/etc/cvd_config/cvd_config_phone.json'
$ dd if=/dev/zero of=empty.img bs=4k count=600
$ mkfs.ext4 -F empty.img
$ adb push empty.img /data/local/tmp/userdata.img
$ adb push empty.img /data/local/tmp/vbmeta.img
$ adb push empty.img /data/local/tmp/vbmeta_system.img
$ adb push empty.img /data/local/tmp/cache.img
```

## Running

Create the composite image using `assemble_cvd` and run it via `crosvm`. In the
future, this shall be done via [`virtmanager`](../virtmanager/).

```
$ adb shell 'HOME=/data/local/tmp; /apex/com.android.virt/bin/assemble_cvd < /dev/null'
$ adb shell 'cd /data/local/tmp; /apex/com.android.virt/bin/crosvm run --disable-sandbox --bios=bootloader --serial=type=stdout --disk=cuttlefish_runtime/composite.img'
```

At this moment, this doesn't boot to the shell, but to the second-stage init.
