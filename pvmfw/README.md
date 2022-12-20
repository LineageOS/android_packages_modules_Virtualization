# Protected Virtual Machine Firmware

## Configuration Data Format

pvmfw will expect a [header] to have been appended to its loaded binary image
at the next 4KiB boundary. It describes the configuration data entries that
pvmfw will use and, being loaded by the pvmfw loader, is necessarily trusted.

The layout of the configuration data is as follows:

```
+===============================+
|          pvmfw.bin            |
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+
|  (Padding to 4KiB alignment)  |
+===============================+ <-- HEAD
|      Magic (= 0x666d7670)     |
+-------------------------------+
|           Version             |
+-------------------------------+
|   Total Size = (TAIL - HEAD)  |
+-------------------------------+
|            Flags              |
+-------------------------------+
|           [Entry 0]           |
|  offset = (FIRST - HEAD)      |
|  size = (FIRST_END - FIRST)   |
+-------------------------------+
|           [Entry 1]           |
|  offset = (SECOND - HEAD)     |
|  size = (SECOND_END - SECOND) |
+-------------------------------+
|              ...              |
+-------------------------------+
|           [Entry n]           |
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+
| (Padding to 8-byte alignment) |
+===============================+ <-- FIRST
|        {First blob: BCC}      |
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+ <-- FIRST_END
| (Padding to 8-byte alignment) |
+===============================+ <-- SECOND
|        {Second blob: DP}      |
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+ <-- SECOND_END
| (Padding to 8-byte alignment) |
+===============================+
|              ...              |
+===============================+ <-- TAIL
```

Where the version number is encoded using a "`major.minor`" as follows

```
((major << 16) | (minor & 0xffff))
```

and defines the format of the header (which may change between major versions),
its size and, in particular, the expected number of appended blobs. Each blob is
referred to by its offset in the entry array and may be mandatory or optional
(as defined by this specification), where missing entries are denoted by a zero
size. It is therefore not allowed to trim missing optional entries from the end
of the array. The header uses the endianness of the virtual machine.

The header format itself is agnostic of the internal format of the individual
blos it refers to. In version 1.0, it describes two blobs:

- entry 0 must point to a valid [BCC Handover]
- entry 1 may point to a [DTBO] to be applied to the pVM device tree

[header]: src/config.rs
[BCC Handover]: https://pigweed.googlesource.com/open-dice/+/825e3beb6c6efcd8c35506d818c18d1e73b9834a/src/android/bcc.c#260
[DTBO]: https://android.googlesource.com/platform/external/dtc/+/refs/heads/master/Documentation/dt-object-internal.txt
