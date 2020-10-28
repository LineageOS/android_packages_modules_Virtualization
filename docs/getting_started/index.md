# Getting started with Protected Virtual Machines

## Prepare a device

First you will need a device that is capable of running virtual machines. On arm64, this means
a device which boots the kernel in EL2 and the kernel was built with KVM enabled.

Here are instructions for select devices:

 * [yukawa: Khadas VIM3L](yukawa.md) (arm64)
 * [goldfish: Android Emulator](goldfish.md) (x86_64)

## Running tests

Virtualization source code and relevant tests are located in
[packages/modules/Virtualization](https://android.googlesource.com/platform/packages/modules/Virtualization)
of the AOSP repository.

### Host-side tests

These are tests where the test driver runs on the "host" (your computer) and it issues commands to
the "target" (the connected device or emulator) over ADB. The tests spawn guest VMs and test
different aspects of the architecture.

You can build and run them with:
``` shell
atest VirtualizationHostTestCases
```

If you run into problems, inspect the logs produced by `atest`. Their location is printed at the
end. The `host_log_*.zip` file should contain the output of individual commands as well as VM logs.

## CrosVM

[CrosVM](https://android.googlesource.com/platform/external/crosvm/) is a Rust-based Virtual Machine
Monitor (VMM) originally built for ChromeOS and ported to Android.

It is not installed in `release` builds of Android but you will find it in `userdebug` and `eng`
builds.

### Spawning your own VMs

You can spawn your own VMs by running CrosVM directly on a rooted KVM-enabled device. If your
device is attached over ADB, you can run:
``` shell
$ adb root
$ adb push <kernel> /data/local/tmp/kernel
$ adb push <ramdisk> /data/local/tmp/ramdisk
$ adb shell crosvm run --initrd /data/local/tmp/ramdisk /data/local/tmp/kernel
```

### Syncing system files

When you're developing CrosVM, it is handy to update the system files using `adb sync` instead of
flashing the device each time. It requires root and mounting the system image as writable.

If you're using the emulator (goldfish), the following instructions will only work if it was
started with `-writable-system`.

First, disable verity checks on your device, reboot and remount the system partition.
This is only needed once:
``` shell
$ adb root
$ adb disable-verity
$ adb reboot
$ adb wait-for-device root
$ adb remount
```

Now (re-)build CrosVM and sync the system files:
``` shell
$ m crosvm
$ adb shell stop
$ adb sync
$ adb shell start
```
