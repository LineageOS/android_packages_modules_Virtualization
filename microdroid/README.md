# Microdroid

Microdroid is a (very) lightweight version of Android that is intended to run on
on-device virtual machines. It is built from the same source code as the regular
Android, but it is much smaller; no system server, no HALs, no GUI, etc. It is
intended to host headless & native workloads only.

## Building (VIM3L)

You need a VIM3L board. Instructions for building Android for the target, and
flashing the image can be found [here](../docs/getting_started/yukawa.md).

Then you install `com.android.virt` APEX. All files needed to run microdroid are
included in the APEX, which is already in the `yukawa` (VIM3L) target. You can
of course build and install the APEX manually.

```sh
$ source build/envsetup.sh
$ choosecombo 1 aosp_arm64 userdebug // actually, any arm64-based target is ok
$ TARGET_BUILD_APPS=com.android.virt m
$ adb install $ANDROID_PRODUCT_OUT/system/apex/com.android.virt.apex
$ adb reboot
```

## Building (Cloud Android)

You may use Cloud Android (cuttlefish) as well. Instructions for running a
cuttlefish device on your workstation can be found
[here](https://android.googlesource.com/device/google/cuttlefish/).

The `aosp_cf_x86_64_phone` target already includes the `com.android.virt` APEX.
So you don't need to build the APEX separately. If you want to rebuild the APEX
and install it to cuttlefish,

```sh
$ source build/envsetup.sh
$ choosecombo 1 aosp_cf_x86_64_phone userdebug
$ TARGET_BUILD_APPS=com.android.virt m
$ adb install $ANDROID_PRODUCT_OUT/system/apex/com.android.virt.apex
$ adb reboot
```

## Running

Create a config file, `microdroid.json`:

```json
{
  "bootloader": "/apex/com.android.virt/etc/microdroid_bootloader",
  "disks": [
    {
      "partitions": [
        {
          "label": "misc",
          "path": "/data/local/tmp/microdroid/misc.img"
        },
        {
          "label": "boot_a",
          "path": "/apex/com.android.virt/etc/fs/microdroid_boot-5.10.img"
        },
        {
          "label": "boot_b",
          "path": "/apex/com.android.virt/etc/fs/microdroid_boot-5.10.img"
        },
        {
          "label": "vendor_boot_a",
          "path": "/apex/com.android.virt/etc/fs/microdroid_vendor_boot-5.10.img"
        },
        {
          "label": "vendor_boot_b",
          "path": "/apex/com.android.virt/etc/fs/microdroid_vendor_boot-5.10.img"
        },
        {
          "label": "vbmeta_a",
          "path": "/apex/com.android.virt/etc/fs/microdroid_vbmeta.img"
        },
        {
          "label": "vbmeta_b",
          "path": "/apex/com.android.virt/etc/fs/microdroid_vbmeta.img"
        },
        {
          "label": "vbmeta_system_a",
          "path": "/apex/com.android.virt/etc/fs/microdroid_vbmeta_system.img"
        },
        {
          "label": "vbmeta_system_b",
          "path": "/apex/com.android.virt/etc/fs/microdroid_vbmeta_system.img"
        },
        {
          "label": "super",
          "path": "/apex/com.android.virt/etc/fs/microdroid_super.img"
        }
      ],
      "writable": false
    },
    {
      "partitions": [
        {
          "label": "uboot_env",
          "path": "/apex/com.android.virt/etc/uboot_env.img"
        }
      ],
      "writable": false
    },
    {
      "image": "/data/local/tmp/microdroid/payload.img",
      "writable": false
    },
    {
      "partitions": [
        {
          "label": "userdata",
          "path": "/data/local/tmp/microdroid/userdata.img",
          "writable": true
        }
      ],
      "writable": true
    }
  ]
}
```

Copy the artifacts to the temp directory, create the composite image using
`mk_cdisk` and copy the VM config file. For now, some other files have to be
manually created. In the future, you won't need these, and this shall be done
via [`virtualizationservice`](../virtualizationservice/).

```sh
$ adb root
$ adb shell 'mkdir /data/local/tmp/microdroid'
$ adb shell 'dd if=/dev/zero of=/data/local/tmp/microdroid/misc.img bs=4k count=256'
$ adb shell 'dd if=/dev/zero of=/data/local/tmp/microdroid/userdata.img bs=1 count=0 seek=4G'
$ adb shell 'cd /data/local/tmp/microdroid; /apex/com.android.virt/bin/mk_payload /apex/com.android.virt/etc/microdroid_payload.json payload.img'
$ adb shell 'chmod go+r /data/local/tmp/microdroid/payload*'
$ adb push microdroid.json /data/local/tmp/microdroid/microdroid.json
```

Ensure SELinux is in permissive mode to allow virtualizationservice and crosvm to open
files from `/data/local/tmp`. Opening files from this directory is
neverallow-ed and file descriptors should be passed instead but, before that is
supported, `adb shell setenforce 0` will put the device in permissive mode.

Now, run the VM and look for `adbd` starting in the logs.

```sh
$ adb shell "start virtualizationservice"
$ adb shell "RUST_BACKTRACE=1 RUST_LOG=trace /apex/com.android.virt/bin/vm run /data/local/tmp/microdroid/microdroid.json"
```

## ADB

```sh
$ CID=10
$ adb forward tcp:8000 vsock:$CID:5555
$ adb connect localhost:8000
```

`CID` should be the CID that `vm` reported was assigned to the VM. You can also
check it with `adb shell "/apex/com.android.virt/bin/vm list"`. `5555` must be
the value. `8000` however can be any port in the development machine.

Done. Now you can log into microdroid. Have fun!

```sh
$ adb -s localhost:8000 shell
```
