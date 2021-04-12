# Microdroid

Microdroid is a (very) lightweight version of Android that is intended to run on
on-device virtual machines. It is built from the same source code as the regular
Android, but it is much smaller; no system server, no HALs, no GUI, etc. It is
intended to host headless & native workloads only.

## Building

You need a VIM3L board. Instructions for building Android for the target, and
flashing the image can be found [here](../docs/getting_started/yukawa.md).

Then you install `com.android.virt` APEX. All files needed to run microdroid are
included in the APEX, which is already in the `yukawa` (VIM3L) target. You can
of course build and install the APEX manually.

```
$ source build/envsetup.sh
$ choosecombo 1 aosp_arm64 userdebug // actually, any arm64-based target is ok
$ m com.android.virt
$ adb install $ANDROID_PRODUCT_OUT/system/apex/com.android.virt.apex
$ adb reboot
```

## Running

Copy the artifacts to the temp directory, create the composite image using
`mk_cdisk`, and run it via `crosvm`. For now, some other files have to be
manually created. In the future, you won't need these, and this shall be done
via [`virtmanager`](../virtmanager/).

```
$ adb shell 'cp /apex/com.android.virt/etc/microdroid_bootloader /data/local/tmp/bootloader'
$ adb shell 'cp /apex/com.android.virt/etc/fs/*.img /data/local/tmp'
$ adb shell 'cp /apex/com.android.virt/etc/uboot_env.img /data/local/tmp'
$ adb shell 'dd if=/dev/zero of=/data/local/tmp/misc.img bs=4k count=256'
$ adb shell 'cd /data/local/tmp; /apex/com.android.virt/bin/mk_cdisk /apex/com.android.virt/etc/microdroid_cdisk.json os_composite.img'
$ adb shell 'cd /data/local/tmp; /apex/com.android.virt/bin/crosvm run --cid=5 --disable-sandbox --bios=bootloader --serial=type=stdout --disk=os_composite.img'
```

The CID in `--cid` parameter can be anything greater than 2 (`VMADDR_CID_HOST`).

## ADB

```
$ adb forward tcp:8000 vsock:5:5555
$ adb connect localhost:8000
```

`5` in `vsock:5` should match with the CID number that was given to `crosvm`.
`5555` must be the value. `8000` however can be any port in the development
machine.

Done. Now you can log into microdroid. Have fun!

```
$ adb -s localhost:8000 shell
```
