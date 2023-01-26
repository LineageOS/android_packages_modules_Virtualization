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

### pvmfw Loading

When running pKVM, the physical memory from which the hypervisor loads pvmfw
into guest address space is not initially populated by the hypervisor itself.
Instead, it receives a pre-loaded memory region from a trusted pvmfw loader and
only then becomes responsible for protecting it. As a result, the hypervisor is
kept generic (beyond AVF) and small as it is not expected (nor necessary) for it
to know how to interpret or obtain the content of that region.

#### Android Bootloader (ABL) Support

Starting in Android T, the `PRODUCT_BUILD_PVMFW_IMAGE` build variable controls
the generation of `pvmfw.img`, a new [ABL partition][ABL-part] containing the
pvmfw binary and following the internal format of the [`boot`][boot-img]
partition, intended to be verified and loaded by ABL on AVF-compatible devices.

To support pKVM, ABL is expected to describe the region using a reserved memory
device tree node where both address and size have been properly aligned to the
page size used by the hypervisor. For example, the following node describes a
region of size `0x40000` at address `0x80000000`:
```
reserved-memory {
    ...
    pkvm_guest_firmware {
        compatible = "linux,pkvm-guest-firmware-memory";
        reg = <0x0 0x80000000 0x40000>;
        no-map;
    }
}
```

[ABL-part]: https://source.android.com/docs/core/architecture/bootloader/partitions
[boot-img]: https://source.android.com/docs/core/architecture/bootloader/boot-image-header

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

- entry 0 must point to a valid BCC Handover (see below)
- entry 1 may point to a [DTBO] to be applied to the pVM device tree

[header]: src/config.rs
[DTBO]: https://android.googlesource.com/platform/external/dtc/+/refs/heads/master/Documentation/dt-object-internal.txt

#### Virtual Platform Boot Certificate Chain Handover

The format of the BCC entry mentioned above, compatible with the
[`BccHandover`][BccHandover] defined by the Open Profile for DICE reference
implementation, is described by the following [CDDL][CDDL]:
```
PvmfwBccHandover = {
  1 : bstr .size 32,     ; CDI_Attest
  2 : bstr .size 32,     ; CDI_Seal
  3 : Bcc,               ; Certificate chain
}
```

and contains the _Compound Device Identifiers_ ("CDIs"), used to derive the
next-stage secret, and a certificate chain, intended for pVM attestation. Note
that it differs from the `BccHandover` defined by the specification in that its
`Bcc` field is mandatory (while optional in the original).

The handover expected by pvmfw can be generated as follows:

- by passing a `BccHandover` received from a previous boot stage (_e.g._ Trusted
  Firmware, ROM bootloader, ...) to
  [`BccHandoverMainFlow`][BccHandoverMainFlow];

- by generating a `BccHandover` (as an example, see [Trusty][Trusty-BCC]) with
  both CDIs set to an arbitrary constant value and no `Bcc`, and pass it to
  `BccHandoverMainFlow`, which will both derive the pvmfw CDIs and start a
  valid certificate chain, making the pvmfw loader the root of the BCC.

The recommended DICE inputs at this stage are:

- **Code**: hash of the pvmfw image, hypervisor (`boot.img`), and other target
  code relevant to the secure execution of pvmfw (_e.g._ `vendor_boot.img`)
- **Configuration Data**: any extra input relevant to pvmfw security
- **Authority Data**: must cover all the public keys used to sign and verify the
  code contributing to the **Code** input
- **Mode Decision**: Set according to the [specification][dice-mode]. In
  particular, should only be `Normal` if secure boot is being properly enforced
  (_e.g._ locked device in [Android Verified Boot][AVB])
- **Hidden Inputs**: Factory Reset Secret (FRS, stored in a tamper evident
  storage and changes during every factory reset) or similar that changes as
  part of the device lifecycle (_e.g._ reset)

The resulting `BccHandover` is then used by pvmfw in a similar way to derive
another [DICE layer][Layering], passed to the guest through a `/reserved-memory`
device tree node marked as [`compatible=”google,open-dice”`][dice-dt].

[AVB]: https://source.android.com/docs/security/features/verifiedboot/boot-flow
[BccHandover]: https://pigweed.googlesource.com/open-dice/+/825e3beb6c/src/android/bcc.c#260
[BccHandoverMainFlow]: https://pigweed.googlesource.com/open-dice/+/825e3beb6c/src/android/bcc.c#199
[CDDL]: https://datatracker.ietf.org/doc/rfc8610
[dice-mode]: https://pigweed.googlesource.com/open-dice/+/refs/heads/main/docs/specification.md#Mode-Value-Details
[dice-dt]: https://www.kernel.org/doc/Documentation/devicetree/bindings/reserved-memory/google%2Copen-dice.yaml
[Layering]: https://pigweed.googlesource.com/open-dice/+/refs/heads/main/docs/specification.md#layering-details
[Trusty-BCC]: https://android.googlesource.com/trusty/lib/+/1696be0a8f3a7103/lib/hwbcc/common/swbcc.c#554
