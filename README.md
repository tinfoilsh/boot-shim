# Minimal TDX and AMD SEV-SNP Linux shim

This repository builds a deterministic IGVM image that enters an unmodified
upstream x86-64 Linux TDX kernel through the standard Linux boot protocol. It
contains one reset/AP assembly component and one host-side Rust packager; there
are no firmware services or private kernel interfaces.

## Build an image

The host needs Rust plus GNU `as` and `objcopy`:

```sh
cargo run --release -- build \
  --kernel /path/to/bzImage \
  --initramfs /path/to/initramfs \
  --output image.igvm
```

This writes `image.igvm` and `image.igvm.manifest.json`. The manifest records
the fixed layout, SHA-256 of each boot component, topology, measured shim size,
and expected MRTD. Builds with identical inputs are byte-identical.

To build for the pinned AMD EPYC 9275F Turin profile (family 26, model 2,
stepping 1):

```sh
cargo run --release -- build-snp \
  --kernel /path/to/bzImage \
  --initramfs /path/to/initramfs \
  --output image.igvm
```

This selects guest-policy ABI 1.51 with SMT, migration and debugging disabled,
and emits one final BSP VMSA at `0xfffffffff000`. The SNP manifest records the
expected launch measurement; ID-block signing remains outside this repository.
The SNP VMSA uses KVM's unpaged 32-bit reset contract (`CR0=0x31`); the measured
reset shim enables long mode before validating RAM and entering Linux.

The security-sensitive layout and command line are constants in
[`src/layout.rs`](src/layout.rs). The image always describes exactly 1 GiB and
four APIC IDs (0 through 3). The protected kernel payload is loaded at
`0x01000000`, the initramfs at `0x20000000`, and CPUs use the ACPI MADT
Multiprocessor Wakeup mailbox at `0x000f0000`.

## Linux contract

Use a recent unpatched upstream kernel with these facilities enabled:

- `CONFIG_INTEL_TDX_GUEST`
- `CONFIG_SMP`
- `CONFIG_ACPI` and local APIC support
- `CONFIG_BLK_DEV_INITRD`

For TDX, do not enable an unaccepted-memory boot dependency: before entering
Linux, the shim accepts every advertised ordinary-RAM page using 2-MiB accepts
with 4-KiB edges. SNP instead requires `CONFIG_UNACCEPTED_MEMORY`; its E820 map
advertises ordinary RAM as unaccepted and the shim accepts only the Linux
decompressor workspace before entry. Hotplug, suspend, kexec and AP offlining
are unsupported.

The image targets the Tinfoil/NRX TDX IGVM loader. NRX must start the reset page
in 64-bit mode with TDX private memory and the declared four-vCPU topology.

## Fixed measured layout

| Address | Contents |
| ---: | --- |
| `0x00007000` | Linux zero page and E820 map |
| `0x00020000` | measured command line |
| `0x000e0000` | RSDP, XSDT and MADT |
| `0x000f0000` | ACPI Multiprocessor Wakeup mailbox |
| `0x00100000` | identity page tables and stacks |
| `0x00120000` | reset/acceptance component |
| `0x00121000` | measured copy of the bzImage setup area |
| `0x01000000` | protected bzImage payload |
| `0x20000000` | initramfs |
| `0xfffff000` | architectural reset alias |

Shim-owned measured pages are limited to 256 KiB. Kernel, initramfs, command
line and boot-data hashes are also recorded separately in the manifest.

## Verification

```sh
cargo test --offline
cargo clippy --offline --all-targets -- -D warnings
```

Tests cover bzImage validation, exact 1-GiB E820 coverage, ACPI checksums and
MADT wakeup data, identity page tables, final IGVM parsing, and reproducible
output. Hardware launch and quote verification require a TDX host running NRX;
compare the quote's MRTD with `expected_mrtd` in the generated manifest.

For SNP, also enable `CONFIG_AMD_MEM_ENCRYPT` and `CONFIG_SEV_GUEST`. The loader
must create four single-thread vCPUs, import measured pages unchanged, expose
`GHCB_HV_FT_SNP_AP_CREATION`, and leave required private RAM invalid. The shim
PVALIDATEs and clears the decompressor workspace before direct 64-bit entry;
Linux accepts the remaining E820 unaccepted memory and starts APs through the
standard GHCB path. Compare the attestation report's `MEASUREMENT` with
`expected_snp_measurement`.
