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

Each command writes an IGVM file and an adjacent JSON manifest. The manifest contains the expected launch measurement, component hashes, memory configuration, and fields that an attestation verifier must check separately.

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

The generated launch measurement does not cover every host-selected setting. In particular, MRTD does not cover TDX attributes or XFAM, and the SNP digest does not cover guest policy, platform configuration, or the reported TCB.

Verify the measurement and every field in the manifest's `attestation` object. The manifest itself is unsigned and must be authenticated by the release process. A `null` value marks a field this build cannot predict: pin it to the value observed on a trusted launch, or to the lowest one you accept.

TDX:

| Field | Required | Why the digest cannot carry it |
| --- | --- | --- |
| `attributes` | `SEPT_VE_DISABLE`, under `attributes_mask` | A TD launched with `DEBUG` or `MIGRATABLE` set produces a byte-identical MRTD |
| `xfam` | operator | The host picks it at `TDH.MNG.INIT` |
| `mrconfigid` | `--config-hash` | Passed by the host at launch |
| `mrowner`, `mrownerconfig` | zero | Passed by the host at launch |
| `servtd_hash` | zero | A TD migrates only through a bound migration TD |
| `tee_tcb_svn` | operator | The TDX module version is the host's |
| `rtmr0`-`rtmr3` | zero | The image extends no RTMR, so a later extension stays visible |

SEV-SNP:

| Field | Required | Why the digest cannot carry it |
| --- | --- | --- |
| `policy` | `0x30133` | The report records the policy the host asked for |
| `host_data` | `--config-hash` | Passed by the host at launch |
| `guest_svn` | `--guest-svn` | The only version this image carries |
| `family_id`, `image_id` | zero | Signed as zero in the ID block |
| `vmpl` | `0` | The guest runs at VMPL0 |
| `platform_info_smt_en` | `false` | The guest policy cannot refuse SMT |
| `platform_info_rapl_dis` | `true` | RAPL turns guest power draw into a side channel, and the host decides whether it runs |
| `platform_info_ciphertext_hiding_en` | operator | Not every platform offers it |
| `signer_info_mask_chip_key` | `false` | A masked chip key unroots the report from this CPU |
| `id_key_digest` | the `--id-key` digest, else zero | Zero says the firmware enforced no digest at launch |
| `author_key_digest` | zero | This image uses no author key |
| `reported_tcb` | operator | The platform TCB is the host's |

## Test

```sh
cargo test --offline
cargo clippy --offline --all-targets -- -D warnings
```
