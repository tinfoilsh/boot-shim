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
layout, SHA-256 of each boot component, topology, measured shim size, and
expected MRTD. Builds with identical inputs are byte-identical.

Everything about the guest that is not an address is a build option, and every
one of them lands in a measured page:

| Option | Default | Reaches the digest through |
| --- | --- | --- |
| `--memory` | `1G` | the measured E820 map and the shim's accept list |
| `--vcpus` | `4` | the measured MADT (TDX only; SNP provisions one) |
| `--cmdline` | `panic=-1` | the measured command-line page |
| `--cbit` | `51` | the encrypted identity map (SNP only) |
| `--mmio-hole` | none | the E820 map and the shim's accept list |

None of them is a property of the machine, and none has a value this build can
discover, so each is a stated input rather than a constant. `no5lvl` is
appended to whatever `--cmdline` is given: the measured page tables are
four-level, so that one is a property of the image and not a preference.

`--memory` is the *top of the guest-physical map*, not the amount of RAM the
host provides -- the two differ as soon as the platform has a hole below 4 GiB,
see [Guests larger than the VMM's low-memory split](#guests-larger-than-the-vmms-low-memory-split).
It is bounded at 512 GiB, which is what the measured identity map covers.

The image is the firmware, and the whole guest is inside it:

```sh
qemu-system-x86_64 -accel kvm -m 1G -smp 4 -cpu host \
  -machine q35,kernel_irqchip=split,confidential-guest-support=tdx \
  -object tdx-guest,id=tdx -bios image.fw \
  -nographic -nodefaults -serial stdio -no-reboot
```

`-smp` must be the vCPUs the measured MADT advertises -- `--vcpus` above. `-m`
must be enough RAM that every range the shim is told to accept is backed; with
no hole declared and everything below 4 GiB that is simply `--memory`, and
above that the two values diverge as described below. Nothing else on the
command line reaches the guest: there is no `-kernel`, `-initrd` or `-append`,
because a host that could supply those could supply unmeasured ones.

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
does depend on is the C-bit position, which the encrypted identity map is built
around; nothing before Linux may take a CPUID dependency to discover it, so it
is the `--cbit` build input (51 on the EPYC parts this has been run on) and the
manifest publishes the value a verifier should expect. Every field of the VMSA
the launch digest depends on -- including the ones QEMU supplies from its own
reset state rather than reading from the file -- is checked against the pinned
set at build time, so a VMM whose reset values differ fails the build instead of
failing `SNP_LAUNCH_FINISH` on hardware with nothing to point at. The SNP VMSA
uses KVM's unpaged 32-bit reset contract (`CR0=0x31`); the measured reset shim
enables long mode before validating RAM and entering Linux.

## One map, derived once

The guest's physical map is built in exactly one place: the packager's list of
the regions it places. The E820 map Linux boots on, the sections the loader is
told to add, and the ranges the shim accepts before entering Linux are all
derived from that list, so no two of them can describe different memory.

The accept list in particular used to be a second copy, hand-written in the
assembler, that had to stay the exact complement of the section list. Nothing
enforced it, and the failure was silent in the dangerous direction: a range that
grew to cover a loaded page would have the shim accept -- or, on SNP,
re-`PVALIDATE` -- a page the loader had already written, which is the
hypervisor page-aliasing attack. There is now no second copy. The packager
writes the complement it computed into a measured data block inside the shim's
own page, and the shim walks it:

```
    lea shim_data(%rip), %rbp
    add $8, %rbp
accept_next:
    mov (%rbp), %r12
    mov 8(%rbp), %r13
    ...
```

The kernel entry point rides in the same block, so nothing is patched into the
shim by searching it for magic constants any more either.

### No machine is assumed

By default the image describes a flat span of guest RAM from zero to
`--memory`, with only the regions this file places carved out of it. It makes
no assumption about any particular VMM's legacy memory map -- in particular it
does not assume the `0xa0000`-`0xc0000` VGA aperture is MMIO, which is a q35
property and not an architectural one. That range is ordinary RAM to this
image, and the shim accepts it like any other.

A platform that really does carve out an aperture has to say so:

```sh
--mmio-hole 0xa0000:0x20000
```

A declared hole is measured like everything else: it reserves the range in the
E820 map, removes it from the shim's accept list, and is published in the
manifest as `mmio_holes` so a verifier reads the claim rather than trusting
prose about a machine type. If the platform has MMIO anywhere the image did not
declare, the accept or `PVALIDATE` fails and the shim reports a fatal error
rather than hanging -- fail-closed, and diagnosable.

### Guests larger than the VMM's low-memory split

A VMM does not give a large guest one flat span of RAM. QEMU's q35 machine puts
the first 2 GiB at zero, opens a PCI hole from there to 4 GiB, and places the
rest at 4 GiB, so `-m 16G` means RAM at `[0, 0x80000000)` and
`[0x100000000, 0x480000000)` -- not `[0, 0x400000000)`. The image has to
describe that, because the shim accepts or `PVALIDATE`s exactly what the
packager placed and nothing in a confidential guest can ask the host where its
memory is:

```sh
--memory 18G --mmio-hole 0x80000000:0x80000000
qemu-system-x86_64 -m 16G -machine q35,max-ram-below-4g=2G,...
```

`--memory` is the top of the map (18 GiB) and `-m` is the RAM behind it
(16 GiB); the 2 GiB difference is the declared hole, which is reserved in the
measured E820 map and skipped by the shim's accept list. Pin the split with
`max-ram-below-4g` rather than letting QEMU pick it: the value is measured into
the image, and QEMU chooses it from the machine type and the total RAM size, so
an unpinned split can move under a fixed image and produce a guest whose accept
list runs into MMIO. That fails closed -- the shim reports a fatal error rather
than continuing -- but it fails at boot rather than at build.

The measured identity map is one PML4 page and one PDPT page of 1-GiB pages,
covering 512 GiB, which is where `--memory` is bounded. It has to reach the
whole guest and not just the low 4 GiB: the SNP shim `PVALIDATE`s and zeroes
through this map, so a range past the end of it would page-fault with no IDT
installed.

Past 4 GiB the guest's own address space swallows the TDX reset page at
`0xfffff000`, so that page is in the placed map like everything else: reserved
in the measured E820 map, and a gap in the accept list. It has to be. A page
missing from the map is a page the shim is told to accept, and this one is the
page it is executing from -- and RAM Linux would be free to allocate over while
APs are still spinning in it. Below 4 GiB the page falls outside the map
entirely, so the digest of an existing image at `--memory 4G` or less is
unchanged by its presence in the list.

The security-sensitive addresses are constants in
[`src/layout.rs`](src/layout.rs), defined once through a macro that also emits
the table `build.rs` re-emits as assembler symbols, so the reset shims address
memory through the same definitions the packager measures and there is no
separate export list to fall out of step. The protected kernel payload is at
`0x01000000` and the initramfs at `0x20000000`. The TDX image advertises
`--vcpus` APIC IDs that start through the ACPI MADT Multiprocessor Wakeup
mailbox at `0x000f0000`; the SNP image carries a single `SnpVpContext` and
therefore advertises exactly one CPU and no wakeup structure.

## Linux contract

Use a recent unpatched upstream kernel with these facilities enabled:

- `CONFIG_INTEL_TDX_GUEST`
- `CONFIG_SMP`
- `CONFIG_ACPI` and local APIC support
- `CONFIG_BLK_DEV_INITRD`

Do not enable an unaccepted-memory boot dependency on either platform: before
entering Linux, the shim accepts every page of guest RAM using 2-MiB accepts
with 4-KiB edges. SNP is no different -- Linux discovers unaccepted memory only
through EFI, which this boot path does not provide -- so the SNP shim
PVALIDATEs and zeroes all of it. Both skip exactly the regions the packager
placed, and nothing else, because both walk the complement the packager
computed rather than a list written out beside it. Revalidating an
already-validated page is the hypervisor page-aliasing attack, so those gaps
being right is the point. Hotplug, suspend, kexec and AP offlining are
unsupported.

That work is linear in `--memory` and happens before Linux is entered, so a
large guest pays for it at every boot: the SNP shim both `PVALIDATE`s and
zeroes every page, and the host has to fault in and RMP-assign the same
memory. Expect seconds rather than milliseconds at tens of gigabytes.

The loader contract is the architectural one: `TDH.VP.INIT` starts every vCPU
at `0xfffffff0` in 32-bit protected mode with paging off and its vCPU index in
`ESI`, and the shim does the rest itself. It loads the measured GDT before it
relies on any descriptor, enables PAE paging on the measured page tables, and
enters Linux in long mode. APs never leave the shim until the operating system
claims them through the measured ACPI wakeup mailbox.

A shim that cannot accept a page it was told to accept has found a disagreement
between the image and its loader about which pages the digest covers. The SNP
shim reports that through the GHCB MSR termination request; the TDX shim
reports it through `TDG.VP.VMCALL<ReportFatalError>`, with the offending
address in `R12`. Those are the only things either shim ever says to the host,
and they happen only on the fatal path -- a failed launch is visible to the
operator instead of looking like a guest that hung.

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
| `0x00100000` | identity page tables: 1-GiB pages covering the low 512 GiB |
| `0x00107000` | measured GDT, its pseudo-descriptor, and the BSP stack |
| `0x00120000` | reset/acceptance component (SNP; TDX runs it at `0xfffff000`) |
| `0x00121000` | measured copy of the bzImage setup area |
| `0x01000000` | protected bzImage payload |
| `0x20000000` | initramfs |
| `0xfffff000` | reset/acceptance component, at the address a TD starts from |

Inside the shim's own page, offset `0xc00` holds the measured data block: the
kernel entry point followed by the ranges to accept.

The pages this file authors -- everything above except the kernel's own setup
area, payload and initramfs -- are limited to 256 KiB and reported as
`shim_owned_bytes`, computed from the same placement list as everything else.
Each component in the manifest is the SHA-256 of exactly the bytes at the
address and size it names, so a verifier can reproduce any of them from the
image without knowing how it was assembled.

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
  (`DEBUG` and `MIGRATABLE` clear, `SEPT_VE_DISABLE` set) and zeros for
  `MRCONFIGID`, `MROWNER`, `MROWNERCONFIG` and `SERVTD_HASH`. `MIGRATABLE`
  costs as much as `DEBUG` and is equally invisible in the digest: a migratable
  TD's memory and vCPU state can be exported to a migration TD and re-imported
  on another platform, which moves the trust decision to that MigTD's policy.
  Requiring `SERVTD_HASH` zero is the other half of that check, since a TD only
  migrates through a service TD bound to it. `PKS` and `KL` are guest-facing
  features that take nothing away, so the compare is masked and leaves them
  free.
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
  of the host. They appear in the report as `tee_tcb_svn`/`reported_tcb` and are
  left `null` for the deployer to pin to an acceptable floor. Without that pin a
  guest running on a host whose module or firmware is known-vulnerable verifies
  clean.
- **Host platform configuration (SNP).** `PLATFORM_INFO` reports what the host
  turned on. The manifest requires `SMT_EN` clear -- which the policy cannot
  express, see above -- and `RAPL_DIS` set, because RAPL turns guest power draw
  into a side channel the guest cannot defend against and only the host can
  disable. `CIPHERTEXT_HIDING_EN` is `null`: not every platform offers it, so
  the deployer pins it to what theirs can do. `SIGNER_INFO.MASK_CHIP_KEY` must
  be clear, since a masked chip key leaves every other field unfounded.
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
- **The platform's own memory map.** The image declares the apertures it
  believes exist -- none, unless `--mmio-hole` says otherwise -- and the
  manifest publishes them as `mmio_holes`. Nothing in the image can confirm the
  declaration; what it can do is fail closed, because MMIO where the image
  expected RAM makes the accept or `PVALIDATE` fail and the shim report a fatal
  error rather than continue.
- **The manifest itself.** It is a verification policy, not a trust anchor. It
  is unsigned and no measurement covers it; pin its contents through the build
  pipeline that produced the image.

## Verification

```sh
cargo test --offline
cargo clippy --offline --all-targets -- -D warnings
```

Tests cover bzImage validation and load-address compatibility, E820 coverage
with no gaps, that the shim's accept list read back out of the packed image is
exactly the complement of the sections the firmware declares, that a declared
MMIO hole moves both, that a guest larger than 4 GiB neither accepts the reset
page nor calls it RAM, that the published `ATTRIBUTES` requirement demands
`DEBUG` and `MIGRATABLE` clear and constrains nothing outside its own mask,
that the SNP requirements pin what the guest policy cannot express, ACPI
checksums and MADT wakeup data, that the largest
permitted vCPU count still fits the measured ACPI page, identity page tables
with and without the C-bit, the measured GDT, that every VMSA field the launch
digest depends on is rejected when perturbed, reading the emitted firmware back
the way QEMU does, final IGVM parsing, reproducible output, a known-answer check
of the SNP launch digest against `sev-snp-measure`'s reference implementation,
and verification of the ID block signature over the bytes the firmware
checks. Hardware launch and quote
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
