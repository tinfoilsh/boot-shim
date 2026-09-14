# boot-shim

`boot-shim` builds deterministic IGVM images that boot an upstream x86-64 Linux kernel on Intel TDX or AMD SEV-SNP.

## Why

A confidential VM does not start in the state required by the [Linux x86 boot protocol](https://github.com/torvalds/linux/blob/master/Documentation/arch/x86/boot.rst).

OVMF, stage0, and others, obtain much of its configuration from the host. That flexibility is unnecessary when the workload is fixed before launch, and it introduces additional complexity for measuring anything loaded after the initial guest measurement.

`boot-shim` prepares the complete Linux boot environment while building the IGVM file, meaning boot can be reduced to a 4 KiB reset shim, with the responsibility of establishing processor state, initializing private RAM, and entering Linux.

## Design

At build time, the CLI validates the provided `bzImage`, lays out the kernel and initramfs, and constructs the Linux zero page, E820 map, ACPI tables, GDT, stack, command line, and identity page tables.

Already-imported pages must not be accepted or validated again on both TDX and SNP. Since some pages start already accepted, the builder builds a placement map containing the following:
- The E820 map passed to Linux.
- The pages imported from IGVM.
- The ranges initialized by the reset shim.

On TDX, every image page contributes to MRTD. The reset shim enters long mode, parks application processors in the ACPI wakeup mailbox, accepts the remaining private RAM, and jumps to Linux.

On SEV-SNP, the launch measurement covers the normal pages and one Virtual Machine Save Area (VMSA) per processor. The reset shim enters long mode, validates and clears the remaining private RAM, wakes the application processors, and jumps to Linux.

Each SEV-SNP application processor launches from its own measured VMSA into a park stub, where it waits on a Guest-Hypervisor Communication Block (GHCB) AP Reset Hold until Linux replaces its VMSA through the GHCB AP-creation call. KVM starts every non-boot processor in the wait-for-SIPI state and only an INIT takes it out, so the boot processor sends INIT-SIPI-SIPI first, as firmware would. Under SEV-ES the local APIC is reachable only through the GHCB, so the shim rescinds one measured page, makes it shared, registers it as its GHCB, and issues the three interrupt-command writes through it. The page is returned to private afterwards, and Linux registers its own GHCB.

The SNP image reaches Linux through a confidential-computing blob on the `setup_data` chain. The record and the blob share one measured page of E820 RAM, and the record claims the whole page. Linux re-reads the chain long after boot, in `pcibios_device_add()`, and `memremap()` hands back ciphertext for a page outside the RAM map, which leaves every PCI device without an MSI domain.

The project performs no later measured boot. It extends no RTMR, produces no event log, and derives no DICE identity.

## Build

The host needs Rust, GNU `as`, and GNU `objcopy`.

TDX:

```sh
cargo run --release -- build-tdx \
  --kernel /path/to/bzImage \
  --initramfs /path/to/initramfs \
  --output image.igvm
```

SEV-SNP:

```sh
cargo run --release -- build-snp \
  --kernel /path/to/bzImage \
  --initramfs /path/to/initramfs \
  --id-key /path/to/id-key.pem \
  --output image.igvm
```

Each command writes an IGVM file and an adjacent JSON manifest. The manifest contains the expected launch measurement, component hashes, memory configuration, and the report fields this image fixes.

| Option | Default | Meaning |
| --- | --- | --- |
| `--ram` | `1G` | Guest RAM, matching QEMU `-m` |
| `--vcpus` | `4` | Processor count; SNP measures one VMSA per processor |
| `--cmdline` | `panic=-1` | Linux command line |
| `--mmio-hole` | none | Additional MMIO aperture |
| `--config-hash` | zero | TDX `MRCONFIGID` or SNP `HOST_DATA` |
| `--cbit` | `51` | SNP encryption bit |
| `--guest-svn` | `0` | SNP anti-rollback version |
| `--id-key` | none | Key used to sign the SNP ID block |

The builder appends `no5lvl` because the image uses four-level page tables.

## Run on TDX

```sh
qemu-system-x86_64 -accel kvm -m 1G -smp 4 -cpu host \
  -machine q35,kernel_irqchip=split,confidential-guest-support=tdx,igvm-cfg=igvm0 \
  -object tdx-guest,id=tdx \
  -object igvm-cfg,id=igvm0,file=image.igvm \
  -nographic -nodefaults -serial stdio -no-reboot
```

Do not pass `-bios`, `-kernel`, `-initrd`, or `-append`. Add `console=ttyS0` to `--cmdline` for a serial console.

The measured command line is the one passed to `--cmdline` with `pci=noacpi
pcie_ports=compat` replacing any `pci=` or `pcie_ports=` it carried, and
`no5lvl` appended. A deployment's own PCI options are meant for a firmware boot
and would discard the host bridge windows this image measures. Applying the
substitution before calling changes nothing, so a caller that already did it
builds the same image.

Upstream QEMU supports IGVM for SEV, SEV-ES and SEV-SNP, but not TDX. Apply the
patch in [`qemu-patches/`](qemu-patches) and build QEMU with `--enable-igvm`
against libigvm 0.3 or newer:

```sh
cd qemu-10.1.0
git am /path/to/boot-shim/qemu-patches/qemu-10.1.0-0001-igvm-tdx.patch
```

The patch is named for the release it applies to and carries that release's
tarball sha256 in its message. SEV-SNP needs no QEMU patch.

## SEV-SNP policy

The SNP image uses guest policy `0x30133`, which requires firmware ABI 1.51 or newer and disables debugging and migration agents.

Pass the policy explicitly to QEMU:

```sh
-object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=6,policy=0x30133
```

The policy cannot express an SMT or single-socket requirement. KVM rejects `SNP_LAUNCH_START` for any policy that clears the SMT bit or sets `SINGLE_SOCKET`, so the report's `PLATFORM_INFO` carries both instead.

With `--id-key`, the builder signs an ID block containing the expected measurement, policy, and guest SVN. Firmware rejects a launch that does not match it.

## Memory map

`--ram` specifies the amount of guest RAM. For q35 guests with at least 2816 MiB, the builder places 2 GiB below 4 GiB, places the rest above 4 GiB, and derives the PCI aperture. Declare any additional MMIO apertures with `--mmio-hole`.

For a q35 guest with 16 GiB of RAM:

```sh
--ram 16G
```

Use the matching QEMU layout:

```sh
-m 16G -machine q35,max-ram-below-4g=2G,...
```

Private-memory initialization is linear in `--ram`. Large SNP guests may spend several seconds validating and clearing RAM.

## Linux requirements

Use an x86-64 kernel with boot protocol 2.12 or newer.

TDX requires:

```text
CONFIG_INTEL_TDX_GUEST
CONFIG_SMP
CONFIG_ACPI
CONFIG_BLK_DEV_INITRD
```

SEV-SNP also requires:

```text
CONFIG_AMD_MEM_ENCRYPT
CONFIG_SEV_GUEST
```

Hotplug, suspend, kexec, and processor offlining are unsupported.

## Attestation

The launch measurement does not cover every setting a report carries, so a
verifier checks more than the digest. Those remaining fields split in two, and
the split decides who is allowed to state them.

The manifest's `launch` object holds the fields **this image** fixes. A
different build changes them, so they belong with the measurement and are
authenticated by whatever process authenticates the manifest — the manifest
itself is unsigned.

TDX:

| Field | Value | Why the digest cannot carry it |
| --- | --- | --- |
| `mrtd` | the measurement | — |
| `mrconfigid` | `--config-hash` | Passed by the host at launch, but chosen by this build |
| `rtmr0`-`rtmr3` | zero at launch | The image extends none, so anything the guest extends later stays visible |

SEV-SNP:

| Field | Value | Why the digest cannot carry it |
| --- | --- | --- |
| `measurement` | the launch digest | — |
| `policy` | `0x30133` | The file asks for it; only a signed ID block makes the firmware refuse a launch that used another |
| `host_data` | `--config-hash` | Passed by the host at launch, but chosen by this build |
| `guest_svn` | `--guest-svn`, and zero unless `--id-key` signs one | An unsigned launch reports zero, so a non-zero SVN without a key is refused |
| `id_key_digest` | the `--id-key` digest, else zero | Zero says the firmware enforced no digest at launch |

Every other report field describes the **machine**, not the image: TDX
`ATTRIBUTES`, `XFAM`, `MROWNER`, `MROWNERCONFIG`, `SERVTD_HASH` and
`TEE_TCB_SVN`; SEV-SNP `PLATFORM_INFO`, `SIGNER_INFO`, `REPORTED_TCB`, `VMPL`,
and the identity fields an unsigned launch leaves to the host. This build cannot
observe any of them, so it does not state them. They belong to the verifier's
platform policy, alongside the trusted computing base floors and the endorsed
machine identities.

Two consequences are worth stating plainly, because the digest hides them:

- A TD launched with `DEBUG` or `MIGRATABLE` set produces a byte-identical
  MRTD. Only a policy that pins `ATTRIBUTES` catches it.
- This image's guest policy allows simultaneous multithreading because KVM
  refuses to launch a guest whose policy forbids it, so whether the host
  actually runs it is visible only in `PLATFORM_INFO`.

## Reproducible build

`cargo build` pins rustc and nothing else. rustc hands the final link to `cc`,
so the binary still depends on the host's gcc, ld and glibc: two machines
running the same pinned rustc produced different binaries from identical
source, differing only in gcc 15.2 against 13.3, binutils 2.46 against 2.42,
and glibc 2.43 against 2.39.

`default.nix` pins all of them, at the nixpkgs revision cvmimage builds
against:

```sh
nix-build              # -> result/bin/boot-shim
nix-build --check      # rebuild and fail if the output moved
```

The pin covers GNU `as` and `objcopy` deliberately: `build.rs` assembles the
reset shims with them, and those bytes land in the measured shim page, so the
assembler is part of the measurement.

Worth separating the two properties. The image is already reproducible without
any of this -- three machines with different native toolchains emit the same
IGVM bytes and the same MRTD, because the image is data this crate lays out
rather than anything the compiler chooses. What nix adds is a reproducible
*builder*, so that anyone asked to trust an `expected_mrtd` can rebuild the
thing that computed it.

## Test

```sh
cargo test --offline
cargo clippy --offline --all-targets -- -D warnings
```
