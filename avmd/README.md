# The AVMD image format
---

The AVMD image format is used to descibe the verified code that a VM will
load. This repository contains tools and libraries for working with the AVMD
image format.

# What is it?

When a VM boots, it loads and verifies a set of images that control execution
within the VM. Therefore, describing what executes in a VM means describing
what is loaded. The AVMD image format is designed, for this purpose, to
describe the closure of images that can be loaded and how they should be
verified.

# Caveats

The AVMD image format will only allow Android supported signing formats. The
supported formats are currently limited to [AVB][] and [APK][].

[AVB]: https://android.googlesource.com/platform/external/avb/+/master/README.md
[APK]: https://source.android.com/security/apksigning#schemes

Verification of the images as they are loaded is the responsibility of the VM.
The VM is required to only load the images described and to verify them against
the included parameters. If the VM does not follow this requirement, the
description of the VM may not be accurate and must not be trusted. Validating
that the VM behaves as expected requires audit of all boot stages of the VM.

# Using avmdtool

The `.avmd` file can be created as follows

```bash
avmdtool create /tmp/out.avmd \
   --vbmeta pvmfw preload u-boot.bin \
   --vbmeta uboot env_vbmeta disk1/vbmeta.imb \
   --vbmeta uboot vbmeta micordoid/vbmeta.img \
   --apk microdroid payload compos.apk \
   --apk microdroid extra_apk extra_apk.apk \
   --apex-payload microdroid art_apex art.apex
```

You can read the `.avmd` file with

```bash
avmdtool dump /tmp/out.avmd
```
