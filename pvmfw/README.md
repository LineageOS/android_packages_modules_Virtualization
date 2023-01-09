# Protected Virtual Machine Firmware

In the context of the [Android Virtualization Framework][AVF], a hypervisor
(_e.g._ [pKVM]) enforces full memory isolation between its virtual machines
(VMs) and the host.  As a result, the host is only allowed to access memory that
has been explicitly shared back by a VM. Such _protected VMs_ (“pVMs”) are
therefore able to manipulate secrets without being at risk of an attacker
stealing them by compromising the Android host.

As pVMs are started dynamically by a _virtual machine manager_ (“VMM”) running
as a host process and as pVMs must not trust the host (see [_Why
AVF?_][why-avf]), the virtual machine it configures can't be trusted either.
Furthermore, even though the isolation mentioned above allows pVMs to protect
their secrets from the host, it does not help with provisioning them during
boot. In particular, the threat model would prohibit the host from ever having
access to those secrets, preventing the VMM from passing them to the pVM.

To address these concerns the hypervisor securely loads the pVM firmware
(“pvmfw”) in the pVM from a protected memory region (this prevents the host or
any pVM from tampering with it), setting it as the entry point of the virtual
machine. As a result, pvmfw becomes the very first code that gets executed in
the pVM, allowing it to validate the environment and abort the boot sequence if
necessary. This process takes place whenever the VMM places a VM in protected
mode and can’t be prevented by the host.

Given the threat model, pvmfw is not allowed to trust the devices or device
layout provided by the virtual platform it is running on as those are configured
by the VMM. Instead, it performs all the necessary checks to ensure that the pVM
was set up as expected. For functional purposes, the interface with the
hypervisor, although trusted, is also validated.

Once it has been determined that the platform can be trusted, pvmfw derives
unique secrets for the guest through the [_Boot Certificate Chain_][BCC]
("BCC", see [Open Profile for DICE][open-dice]) that can be used to prove the
identity of the pVM to local and remote actors. If any operation or check fails,
or in case of a missing prerequisite, pvmfw will abort the boot process of the
pVM, effectively preventing non-compliant pVMs and/or guests from running.
Otherwise, it hands over the pVM to the guest kernel by jumping to its first
instruction, similarly to a bootloader.

pvmfw currently only supports AArch64.

[AVF]: https://source.android.com/docs/core/virtualization
[why-avf]: https://source.android.com/docs/core/virtualization/whyavf
[BCC]: https://pigweed.googlesource.com/open-dice/+/master/src/android/README.md
[pKVM]: https://source.android.com/docs/core/virtualization/architecture#hypervisor
[open-dice]: https://pigweed.googlesource.com/open-dice/+/refs/heads/main/docs/specification.md

## Integration

### Configuration Data

As part of the process of loading pvmfw, the loader (typically the Android
Bootloader, "ABL") is expected to pass device-specific pvmfw configuration data
by appending it to the pvmfw binary and including it in the region passed to the
hypervisor. As a result, the hypervisor will give the same protection to this
data as it does to pvmfw and will transparently load it in guest memory, making
it available to pvmfw at runtime. This enables pvmfw to be kept device-agnostic,
simplifying its adoption and distribution as a centralized signed binary, while
also being able to support device-specific details.

The configuration data will be read by pvmfw at the next 4KiB boundary from the
end of its loaded binary. Even if the pvmfw is position-independent, it will be
expected for it to also have been loaded at a 4-KiB boundary. As a result, the
location of the configuration data is implicitly passed to pvmfw and known to it
at build time.

#### Configuration Data Format

The configuration data is described using the following [header]:

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
