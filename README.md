# Minimal TDX and AMD SEV-SNP Linux shim

This repository builds a deterministic boot image that enters an unmodified
upstream x86-64 Linux TDX kernel through the standard Linux boot protocol. It
contains one reset/AP assembly component and one host-side Rust packager; there
are no firmware services or private kernel interfaces.

Everything the guest starts on is a measured page. On TDX the image is a TDVF
metadata firmware, which is how a loader is told which pages to hand the TDX
module: every one of them is added with `TDH.MEM.PAGE.ADD` and, apart from the
host's own TD HOB page, extended into MRTD with `TDH.MR.EXTEND`. Nothing is
measured afterwards -- no RTMR is extended and no event log is produced -- so
the whole chain of trust is the launch digest.

## Build an image

The host needs Rust plus GNU `as` and `objcopy`:

```sh
cargo run --release -- build \
  --kernel /path/to/bzImage \
  --initramfs /path/to/initramfs \
  --output image.fw
```

This writes `image.fw` and `image.fw.manifest.json`. The manifest records the
fixed layout, SHA-256 of each boot component, topology, measured shim size, and
expected MRTD. Builds with identical inputs are byte-identical.

The image is the firmware, and the whole guest is inside it:

```sh
qemu-system-x86_64 -accel kvm -m 1G -smp 4 -cpu host \
  -machine q35,kernel_irqchip=split,confidential-guest-support=tdx \
  -object tdx-guest,id=tdx -bios image.fw \
  -nographic -nodefaults -serial stdio -no-reboot
```

`-m` must be the 1 GiB the measured E820 map describes, and `-smp` the four
vCPUs the measured MADT advertises. Nothing else on the command line reaches
the guest: there is no `-kernel`, `-initrd` or `-append`, because a host that
could supply those could supply unmeasured ones.

To build the AMD SEV-SNP variant:

```sh
cargo run --release -- build-snp \
  --kernel /path/to/bzImage \
  --initramfs /path/to/initramfs \
  --id-key /path/to/id-key.pem \
  --output image.igvm
```

This emits one BSP VMSA at `0xfffffffff000` under guest policy `0x30133`: a
minimum firmware ABI of 1.51, no migration agent and no debug. `SEV_FEATURES`
comes from the file rather than the host, so the image, not the machine,
decides that DebugSwap stays off.

The policy cannot say more than that. KVM rejects `SNP_LAUNCH_START` with
`EINVAL` for any policy that clears the SMT bit or sets `SINGLE_SOCKET`, so a
policy demanding an SMT-disabled single-socket host is not a stricter image, it
is an image that never launches. Both facts are still attested -- the report's
`PLATFORM_INFO` carries `SMT_EN` -- so they are published as verifier
requirements in the manifest instead of as policy bits.

### The ID block

`--id-key` takes a PKCS#8 PEM P-384 key and emits a signed ID block. Without
one the launch digest is only something a verifier compares after the fact: the
firmware computes it, hands it to the guest, and launches whatever it was given.
With one, `SNP_LAUNCH_FINISH` fails unless the digest the firmware computed and
the policy the host actually asked for both match the signed block:

```
$ # one byte of the measured command-line page flipped
SNP_LAUNCH_FINISH ret=-5 fw_error=11 'Bad measurement'
$ # host launches the same image under policy 0x30000 instead of 0x30133
SNP_LAUNCH_FINISH ret=-5 fw_error=7  'Policy is not allowed'
```

That second case is not hypothetical. QEMU applies an IGVM file's guest-policy
header from `qigvm_handle_policy`, which runs *after* `SNP_LAUNCH_START` has
already been issued, so the policy in the file never reaches the launch and the
guest runs under QEMU's default `0x30000` -- ABI floor 0, SMT allowed. The host
therefore has to be told the policy directly:

```sh
-object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=6,policy=0x30133
```

With a signed ID block that is fail-closed rather than a convention: a host that
forgets the argument, or picks a weaker policy, cannot start the guest at all.
`--guest-svn` sets the anti-rollback version in the same signed block, and the
manifest records the `ID_KEY_DIGEST` the report will carry for that key.

No CPU family, model or stepping appears anywhere in the build. The IGVM file
states the entire VMSA including `RDX`, which the loader applies verbatim, so no
CPU signature reaches the launch measurement. The one CPU property the image
does depend on is the C-bit position (51), which the encrypted identity map is
built around. The SNP VMSA uses KVM's unpaged 32-bit reset contract
(`CR0=0x31`); the measured reset shim enables long mode before validating RAM
and entering Linux. The SNP manifest records the expected launch measurement;
ID-block signing remains outside this repository.

The security-sensitive layout and command line are constants in
[`src/layout.rs`](src/layout.rs). `build.rs` re-emits those constants as
assembler symbols, so the reset shims address memory through the same
definitions the packager measures and cannot drift from them. Both images
describe exactly 1 GiB, with the protected kernel payload at `0x01000000` and
the initramfs at `0x20000000`. The TDX image advertises four APIC IDs (0
through 3) that start through the ACPI MADT Multiprocessor Wakeup mailbox at
`0x000f0000`; the SNP image carries a single `SnpVpContext` and therefore
advertises exactly one CPU and no wakeup structure.

## Linux contract

Use a recent unpatched upstream kernel with these facilities enabled:

- `CONFIG_INTEL_TDX_GUEST`
- `CONFIG_SMP`
- `CONFIG_ACPI` and local APIC support
- `CONFIG_BLK_DEV_INITRD`

Do not enable an unaccepted-memory boot dependency on either platform: before
entering Linux, the shim accepts every advertised ordinary-RAM page using 2-MiB
accepts with 4-KiB edges. SNP is no different -- Linux discovers unaccepted
memory only through EFI, which this boot path does not provide -- so the SNP
shim PVALIDATEs and zeroes all of it, skipping the launch-updated pages and the
VGA aperture. Revalidating an already-validated page is the hypervisor
page-aliasing attack, so those gaps are exactly the ones the packager measures.
Hotplug, suspend, kexec and AP offlining are unsupported.

The loader contract is the architectural one: `TDH.VP.INIT` starts every vCPU
at `0xfffffff0` in 32-bit protected mode with paging off and its vCPU index in
`ESI`, and the shim does the rest itself. It loads the measured GDT before it
relies on any descriptor, enables PAE paging on the measured page tables, and
enters Linux in long mode. APs never leave the shim until the operating system
claims them through the measured ACPI wakeup mailbox.

## Fixed measured layout

| Address | Contents |
| ---: | --- |
| `0x00007000` | Linux zero page and E820 map |
| `0x00020000` | measured command line |
| `0x000e0000` | RSDP, XSDT and MADT |
| `0x000f0000` | ACPI Multiprocessor Wakeup mailbox (TDX) / CPUID page (SNP) |
| `0x000f1000` | TD HOB, written by the host and measured only by address (TDX) |
| `0x000f1000` | Secrets page (SNP) |
| `0x000f2000` | CC blob and `SETUP_CC_BLOB` record (SNP) |
| `0x00100000` | identity page tables |
| `0x00107000` | measured GDT, its pseudo-descriptor, and the BSP stack |
| `0x00121000` | measured copy of the bzImage setup area |
| `0x01000000` | protected bzImage payload |
| `0x20000000` | initramfs |
| `0xfffff000` | reset/acceptance component, at the address a TD starts from |

The pages this file authors -- everything above except the kernel's own setup
area, payload and initramfs -- are limited to 256 KiB and reported as
`shim_owned_bytes`. Kernel, initramfs, command line and boot-data hashes are
also recorded separately in the manifest.

## What the measurement does not cover

A digest is not a verification policy. Neither MRTD nor the SNP launch digest
covers the configuration the host chooses at launch, so every manifest carries
an `attestation` block listing what a verifier must require from the report *in
addition* to the measurement. A `null` marks a field this build cannot predict
and the deployer has to pin.

- **TD configuration (TDX).** `ATTRIBUTES`, `XFAM`, the vCPU count and the owner
  registers are set at `TDH.MNG.INIT`, not by this file. A TD launched with
  `ATTRIBUTES.DEBUG` set -- which lets the host read guest memory and registers
  -- produces a byte-identical MRTD, so checking `expected_mrtd` alone is not a
  check at all. The manifest publishes a masked `ATTRIBUTES` requirement
  (`DEBUG` clear, `SEPT_VE_DISABLE` set) and zeros for `MRCONFIGID`, `MROWNER`
  and `MROWNERCONFIG`.
- **Guest policy and signer identity (SNP).** `POLICY`, `FAMILY_ID`, `IMAGE_ID`,
  `GUEST_SVN`, `HOST_DATA` and the two key digests are report fields, not digest
  inputs. The ID block above is what makes the first four enforced rather than
  merely published.
- **Deployment-specific data.** `--config-hash` records the value the host must
  pass as `MRCONFIGID` (48 bytes, TDX) or `HOST_DATA` (32 bytes, SNP). It is the
  only launch input a deployer can bind per deployment, and it is what a
  configuration or key hash belongs in; nothing else distinguishes two
  deployments of the same image.
- **Platform TCB.** The TDX module SVN and the SNP reported TCB are properties
  of the host. They appear in the report as `reported_tcb`/`TEE_TCB_INFO` and
  are left `null` for the deployer to pin to an acceptable floor.
- **The SNP CPUID and Secrets pages.** `SNP_LAUNCH_UPDATE` measures both by type
  and address with a zeroed `CONTENTS` field, so what this file puts in them
  cannot change the digest. The firmware's CPUID enforcement bounds the first;
  the shim itself takes no CPUID, MSR, I/O or GHCB dependency before Linux.
- **Runtime state.** This image performs no runtime measurement: it extends no
  RTMR, provides no event log, and SNP has no equivalent register. The chain of
  trust therefore closes at the kernel entry point, which is sound only because
  the image has no post-boot input to measure -- the command line is a measured
  constant, there is no `root=`, and the initramfs is measured whole. The TDX
  manifest requires all four RTMRs to still be zero, which makes that closure
  verifiable and any later extension visible. A deployment that adds persistent
  storage or host-supplied configuration has to bind it through `--config-hash`
  or a dm-verity root hash in the measured command line; it will not otherwise
  appear in any measurement.
- **vCPU state (TDX).** MRTD covers no vCPU state at all, unlike SNP where the
  whole VMSA is measured. What saves the TDX case is that the state is not the
  loader's to choose: the TDX module fixes it at `TDH.VP.INIT`. The shim treats
  everything it was handed as untrusted anyway -- it installs the measured GDT,
  its own page tables and its own segment registers before entering Linux.
- **The TD HOB.** The one page the host writes. `TDH.MEM.PAGE.ADD` puts its
  address in MRTD but nothing puts its contents there, so this image does not
  read it: the E820 map Linux boots on is a measured page instead.
- **The manifest itself.** It is a verification policy, not a trust anchor. It
  is unsigned and no measurement covers it; pin its contents through the build
  pipeline that produced the image.

## Verification

```sh
cargo test --offline
cargo clippy --offline --all-targets -- -D warnings
```

Tests cover bzImage validation, exact 1-GiB E820 coverage, ACPI checksums and
MADT wakeup data, identity page tables, the measured GDT, reading the emitted
firmware back the way QEMU does, final IGVM parsing,
reproducible output, a known-answer check of the SNP launch digest against
`sev-snp-measure`'s reference implementation, and verification of the ID block
signature over the bytes the firmware checks. Hardware launch and quote
verification require a TDX host; compare the report's MRTD with `expected_mrtd`
in the generated manifest and every field of `attestation` with the rest of the
report. On hardware that check is exact: a TDREPORT taken inside the booted
guest returns the manifest's `expected_mrtd` byte for byte, with all four RTMRs
still zero.

On SEV-SNP the launch itself is the check: a signed ID block makes the firmware
compare its own digest against `expected_snp_measurement`, so a successful
`SNP_LAUNCH_FINISH` is hardware confirmation that the packager's arithmetic is
right.

For SNP, also enable `CONFIG_AMD_MEM_ENCRYPT` and `CONFIG_SEV_GUEST`. The loader
must create exactly one vCPU from the file's VMSA, import measured pages
unchanged, leave required private RAM invalid, and populate the CPUID page. The
CPUID and Secrets page contents come from the loader and firmware, so
`SNP_LAUNCH_UPDATE` measures those two pages by type and address with a zeroed
`CONTENTS` field -- what the file puts in them cannot change the digest.
Compare the attestation report's `MEASUREMENT` with `expected_snp_measurement`.
