use crate::{
    acpi,
    boot::{self, put64, Fill, Placed, ACPI, RAM, RESERVED},
    layout::*,
    mrtd, tdvf,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, io, path::Path};

#[derive(Serialize)]
pub struct Component {
    address: String,
    size: usize,
    sha256: String,
}
// Values a verifier must require from the attestation report *in addition* to
// the measurement.  Neither MRTD nor the SNP launch digest covers the TD/VM
// configuration the host chooses at launch, so an image that publishes only a
// digest is verifiable against a host that also turned on debug.  `None` marks
// a field this build cannot predict and the deployer therefore has to pin.
pub type Required = BTreeMap<&'static str, Option<String>>;

pub fn zeros(bytes: usize) -> String {
    "00".repeat(bytes)
}

// MRCONFIGID (TDX) and HOST_DATA (SNP) are the only launch inputs a deployer
// can bind per deployment; neither enters the digest, so the manifest records
// the value the verifier has to demand.
pub fn config_field(hash: Option<&str>, bytes: usize) -> Result<String, String> {
    match hash {
        None => Ok(zeros(bytes)),
        Some(h) => {
            let h = h.trim().trim_start_matches("0x").to_ascii_lowercase();
            if h.len() != bytes * 2 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(format!("--config-hash must be {bytes} hex-encoded bytes"));
            }
            Ok(h)
        }
    }
}

#[derive(Serialize)]
struct Manifest {
    format_version: u32,
    memory_bytes: u64,
    vcpus: u32,
    command_line: String,
    mmio_holes: Vec<String>,
    kernel_entry: String,
    expected_mrtd: String,
    shim_owned_bytes: usize,
    attestation: Required,
    components: BTreeMap<&'static str, Component>,
}

// The assembler already fails on a shim that overruns its page, so its size
// is a compile-time fact and not something to re-discover at run time.
const RESET_SHIM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/reset.bin"));
const _: () = assert!(RESET_SHIM.len() == SHIM_SIZE as usize);

/// Everything both builds derive from the input files before they diverge.
pub struct Prepared {
    pub info: boot::KernelInfo,
    pub setup: Vec<u8>,
    pub kernel: Vec<u8>,
    pub initramfs: Vec<u8>,
    pub command: Vec<u8>,
    pub entry: u64,
}

pub fn prepare(
    kernel_path: &Path,
    initramfs_path: &Path,
    params: &Params,
) -> Result<Prepared, String> {
    let kernel_file = fs::read(kernel_path).map_err(io_error("read kernel"))?;
    let initramfs = fs::read(initramfs_path).map_err(io_error("read initramfs"))?;
    let info = boot::parse_bzimage(&kernel_file)?;
    let kernel = kernel_file[info.setup_bytes..].to_vec();
    let kernel_end = align_up(KERNEL_BASE + kernel.len() as u64, PAGE);
    let initramfs_end = align_up(INITRAMFS_BASE + initramfs.len() as u64, PAGE);
    if kernel_end > INITRAMFS_BASE {
        return Err("protected kernel overlaps the fixed initramfs address".into());
    }
    if KERNEL_BASE + info.init_size as u64 > INITRAMFS_BASE {
        return Err("kernel init_size overlaps the fixed initramfs address".into());
    }
    if initramfs_end > params.memory {
        return Err("initramfs exceeds the memory the image describes".into());
    }
    // boot_params addresses the initramfs with a 32-bit field.
    if initramfs_end > u32::MAX as u64 {
        return Err("initramfs does not fit below 4 GiB".into());
    }
    if info.setup_bytes > KERNEL_SETUP_AREA_SIZE as usize {
        return Err("bzImage setup area exceeds its fixed measured reservation".into());
    }
    // cmdline_size is what the kernel says it will accept, so it is read and
    // checked against the command line this image measures, never overwritten.
    if params.cmdline.len() as u32 + 1 > info.cmdline_max {
        return Err(format!(
            "command line is longer than the {} bytes this kernel accepts",
            info.cmdline_max
        ));
    }
    let mut setup = vec![0u8; KERNEL_SETUP_AREA_SIZE as usize];
    setup[..info.setup_bytes].copy_from_slice(&kernel_file[..info.setup_bytes]);
    let mut command = params.cmdline.as_bytes().to_vec();
    command.push(0);
    command.resize(PAGE as usize, 0);
    Ok(Prepared {
        info,
        setup,
        kernel,
        initramfs,
        command,
        entry: KERNEL_BASE + info.entry_offset,
    })
}

/// The block both shims read out of their own measured page: the kernel entry
/// point, then the ranges to accept as (low, high) pairs, terminated by a zero
/// pair.  The ranges are the complement of everything the packager places, so
/// the addresses a shim acts on and the addresses the digest covers are one
/// list -- there is no second, hand-written copy in the assembler to drift.
pub fn shim_data(shim: &mut [u8], entry: u64, ranges: &[(u64, u64)]) -> Result<(), String> {
    let mut data = entry.to_le_bytes().to_vec();
    for (lo, hi) in ranges {
        data.extend_from_slice(&lo.to_le_bytes());
        data.extend_from_slice(&hi.to_le_bytes());
    }
    data.extend_from_slice(&[0u8; 16]);
    if data.len() > SHIM_DATA_SIZE as usize {
        return Err(format!(
            "shim data block needs {} of {SHIM_DATA_SIZE} bytes",
            data.len()
        ));
    }
    let at = SHIM_DATA as usize;
    if shim[at..at + data.len()].iter().any(|b| *b != 0) {
        return Err("shim code overruns its data block".into());
    }
    shim[at..at + data.len()].copy_from_slice(&data);
    Ok(())
}

/// Everything this file authors, as opposed to the kernel's own setup area,
/// payload and initramfs.  Derived from the placed map so it cannot
/// under-report a page someone adds later.
pub fn shim_owned(placed: &[Placed]) -> usize {
    placed
        .iter()
        .filter(|p| p.base < KERNEL_SETUP_BASE && !matches!(p.fill, Fill::Mmio(_)))
        .map(|p| p.span() as usize)
        .sum()
}

pub fn build(
    kernel_path: &Path,
    initramfs_path: &Path,
    output: &Path,
    params: &Params,
    config_hash: Option<&str>,
) -> Result<(), String> {
    let mrconfigid = config_field(config_hash, 48)?;
    let p = prepare(kernel_path, initramfs_path, params)?;
    let acpi = acpi::build(params.vcpus, true);

    // The one authoritative map.  The E820 map Linux boots on, the sections
    // the loader adds and the ranges the shim accepts are all derived from it
    // below, so no two of them can describe different memory.
    let mut placed = vec![
        // The zero page describes the map it is itself part of, so it enters
        // as one blank page, the map is derived, and only its contents are
        // filled in afterwards.  Its span never changes, so the map does not.
        Placed::measured(ZERO_PAGE, RESERVED, vec![0u8; PAGE as usize]),
        Placed::measured(CMDLINE, RESERVED, p.command.clone()),
        Placed::measured(ACPI_BASE, ACPI, acpi.bytes.clone()),
        Placed::measured(MAILBOX, RESERVED, vec![0u8; PAGE as usize]),
        Placed::host(TD_HOB),
        Placed::measured(PAGE_TABLES, RESERVED, identity_map(0)),
        Placed::measured(BSP_STACK, RESERVED, boot::gdt_stack()),
        Placed::measured(KERNEL_SETUP_BASE, RESERVED, p.setup.clone()),
        Placed::measured(KERNEL_BASE, RAM, p.kernel.clone()),
        Placed::measured(INITRAMFS_BASE, RAM, p.initramfs.clone()),
        // The reset page, whose contents `pack` finishes and appends as the
        // last section.  It is placed here because the map has to cover it:
        // above 4 GiB of `--memory` it lies inside the guest's own address
        // space, and a page left out of the map is one the shim is told to
        // accept -- here, the page it is executing from.
        Placed::measured(RESET_ALIAS, RESERVED, vec![0u8; PAGE as usize]),
    ];
    placed.extend(params.mmio.iter().map(|(b, n)| Placed::mmio(*b, *n)));
    boot::validate(&placed, params.memory)?;
    let e820 = boot::e820(&placed, params.memory);
    let zero = boot::zero_page(&p.setup, p.info, p.initramfs.len(), acpi.rsdp, &e820)?;
    boot::fill(&mut placed, ZERO_PAGE, zero)?;

    let mut shim = RESET_SHIM.to_vec();
    shim_data(
        &mut shim,
        p.entry,
        &boot::accept_ranges(&placed, params.memory),
    )?;

    let owned = shim_owned(&placed) + SHIM_SIZE as usize;
    if owned > SHIM_LIMIT {
        return Err(format!(
            "shim-owned measured pages exceed 256 KiB: {owned}"
        ));
    }

    // Ascending GPA order, which is the order QEMU adds the sections in and
    // therefore the order the TDX module builds MRTD in.  The reset page is
    // appended by the packer instead, which is what writes the GUIDed table
    // into it; it has to end at 4 GiB, where a TD starts, and that is already
    // the highest address the map holds.
    placed.sort_by_key(|p| p.base);
    let sections = placed
        .iter()
        .filter(|p| !matches!(p.fill, Fill::Mmio(_)) && p.base != RESET_ALIAS)
        .map(|p| match p.fill {
            Fill::Host => tdvf::td_hob(p.base),
            _ => tdvf::section(p.base, p.data()),
        })
        .collect();
    let (file, sections) = tdvf::pack(sections, &shim)?;
    // Read the published file back the way QEMU will, before publishing a
    // digest that claims to describe what it loads.
    let described: Vec<_> = sections.iter().map(|s| (s.gpa, s.measured)).collect();
    if tdvf::parse(&file)? != described {
        return Err("emitted firmware does not describe the measured sections".into());
    }
    let expected_mrtd = mrtd::calculate(&pages(&sections));
    fs::write(output, &file).map_err(io_error("write firmware"))?;

    let mut components = BTreeMap::new();
    components.insert("kernel", component(KERNEL_BASE, &p.kernel));
    components.insert("kernel_setup", component(KERNEL_SETUP_BASE, &p.setup));
    components.insert("initramfs", component(INITRAMFS_BASE, &p.initramfs));
    components.insert("command_line", component(CMDLINE, &p.command));
    components.insert("acpi", component(ACPI_BASE, &acpi.bytes));
    // The packed reset page, not the shim as assembled: `pack` writes the
    // GUIDed table into it, so those are the bytes that end up at the address.
    let reset = sections.last().expect("pack appends the reset section");
    components.insert("shim", component(reset.gpa, &reset.data));
    let manifest = Manifest {
        format_version: 1,
        memory_bytes: params.memory,
        vcpus: params.vcpus,
        command_line: params.cmdline.clone(),
        mmio_holes: mmio_holes(params),
        kernel_entry: format!("0x{:08x}", p.entry),
        expected_mrtd: hex::encode(expected_mrtd),
        shim_owned_bytes: owned,
        attestation: tdx_attestation(&expected_mrtd, mrconfigid),
        components,
    };
    write_manifest(output, &manifest)
}

/// The platform apertures the image declares, published so a verifier reads
/// them from the manifest instead of trusting prose about a machine type.
pub fn mmio_holes(params: &Params) -> Vec<String> {
    params
        .mmio
        .iter()
        .map(|(base, size)| format!("0x{base:08x}:0x{size:x}"))
        .collect()
}

pub fn write_manifest<T: Serialize>(output: &Path, manifest: &T) -> Result<(), String> {
    let mut json = serde_json::to_vec_pretty(manifest).map_err(|e| e.to_string())?;
    json.push(b'\n');
    fs::write(format!("{}.manifest.json", output.display()), json)
        .map_err(io_error("write manifest"))
}

// The pages the TDX module sees, in the order it sees them.  Each is borrowed
// from the section that holds it rather than copied out of it.
fn pages(sections: &[tdvf::Section]) -> Vec<(u64, &[u8], bool)> {
    let mut out = Vec::new();
    for s in sections {
        let count = s.data.len().max(PAGE as usize) / PAGE as usize;
        for i in 0..count {
            let at = i * PAGE as usize;
            let end = (at + PAGE as usize).min(s.data.len()).max(at);
            out.push((s.gpa + i as u64 * PAGE, &s.data[at..end], s.measured));
        }
    }
    out
}

// The TD_ATTRIBUTES bits a verifier has to constrain.  MIGRATABLE costs the
// guest as much as DEBUG and is just as invisible in MRTD: a migratable TD's
// memory and vCPU state can be exported to a migration TD and re-imported on
// another platform, which moves the trust decision to that MigTD's policy.
// PKS and KL are guest-facing features that take nothing away, so the compare
// is masked and leaves them free.
const ATTR_DEBUG: u64 = 1;
const ATTR_SEPT_VE_DISABLE: u64 = 1 << 28;
const ATTR_MIGRATABLE: u64 = 1 << 29;

// MRTD covers only the pages this file provides.  ATTRIBUTES, XFAM, the vCPU
// count and the owner registers are TD configuration the host picks at
// TDH.MNG.INIT, so a TD launched with ATTRIBUTES.DEBUG set -- which lets the
// host read guest memory and registers -- produces a byte-identical MRTD.
// Checking the digest alone is therefore not a check at all.
fn tdx_attestation(mrtd: &[u8; 48], mrconfigid: String) -> Required {
    let mut r = Required::new();
    r.insert("mrtd", Some(hex::encode(mrtd)));
    let mask = ATTR_DEBUG | ATTR_SEPT_VE_DISABLE | ATTR_MIGRATABLE;
    r.insert("attributes_mask", Some(format!("0x{mask:016x}")));
    r.insert("attributes", Some(format!("0x{ATTR_SEPT_VE_DISABLE:016x}")));
    // The TD's extended-feature mask is a launch parameter this build cannot
    // predict; pin it to the value observed on a trusted first launch.
    r.insert("xfam", None);
    r.insert("mrconfigid", Some(mrconfigid));
    r.insert("mrowner", Some(zeros(48)));
    r.insert("mrownerconfig", Some(zeros(48)));
    // The hash of the service TDs bound to this one.  Zero is what says none
    // is, and in particular that no migration TD is: it is the other half of
    // requiring MIGRATABLE clear, since a TD only migrates through a MigTD.
    r.insert("servtd_hash", Some(zeros(48)));
    // The TDX module's own version, a property of the host and not of this
    // image, so it is left for the deployer to pin to an acceptable floor.
    // Without it a TD running on a known-vulnerable module verifies clean.
    r.insert("tee_tcb_svn", None);
    // This image performs no runtime measurement: it extends no RTMR and
    // provides no event log, so every register is still at its reset value
    // when Linux is entered.  Requiring zeros makes that verifiable and makes
    // any later extension -- by the guest or anything else -- visible.
    for name in ["rtmr0", "rtmr1", "rtmr2", "rtmr3"] {
        r.insert(name, Some(zeros(48)));
    }
    r
}

/// The 4-level identity map both shims run on: one PML4 page and one PDPT
/// page of 1-GiB pages, covering [0, MAP_LIMIT), which is where `Params::new`
/// bounds `--memory`.  `c_bit` is zero on TDX and the SNP C-bit position
/// elsewhere: the same table, one bit apart, so the two platforms cannot map
/// memory differently by accident.
///
/// It has to reach the whole guest and not just the low 4 GiB.  The SNP shim
/// PVALIDATEs and zeroes through this map, so every page the packager tells it
/// to validate must be addressable; a range past the end of the map would
/// page-fault with no IDT installed.  The TDX shim needs it to cover
/// RESET_ALIAS, where it is itself executing once paging is on.
pub fn identity_map(c_bit: u64) -> Vec<u8> {
    let c = if c_bit == 0 { 0 } else { 1u64 << c_bit };
    let mut v = vec![0u8; PAGE_TABLE_SIZE as usize];
    put64(&mut v, 0, (PAGE_TABLES + PAGE) | c | 3);
    for gib in 0..MAP_LIMIT / GIB {
        put64(&mut v, (PAGE + gib * 8) as usize, (gib * GIB) | c | 0x83);
    }
    v
}

pub fn component(address: u64, data: &[u8]) -> Component {
    Component {
        address: format!("0x{address:08x}"),
        size: data.len(),
        sha256: hex::encode(Sha256::digest(data)),
    }
}
pub fn io_error(action: &'static str) -> impl Fn(io::Error) -> String {
    move |e| format!("{action}: {e}")
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use tempfile::tempdir;

    pub fn params() -> Params {
        Params::new(DEFAULT_MEMORY, DEFAULT_VCPUS, None, DEFAULT_CBIT, vec![]).unwrap()
    }

    /// A bzImage-shaped stub: enough of the setup header for the packager to
    /// accept it, and nothing else.
    pub fn test_kernel() -> Vec<u8> {
        let mut kernel = vec![0u8; 8192];
        kernel[0x1f1] = 4;
        kernel[0x1fe..0x200].copy_from_slice(&0xaa55u16.to_le_bytes());
        kernel[0x202..0x206].copy_from_slice(b"HdrS");
        kernel[0x206..0x208].copy_from_slice(&0x020cu16.to_le_bytes());
        kernel[0x211] = 1;
        kernel[0x230..0x234].copy_from_slice(&0x20_0000u32.to_le_bytes());
        kernel[0x234] = 1;
        kernel[0x236] = 1;
        kernel[0x238..0x23c].copy_from_slice(&0x800u32.to_le_bytes());
        kernel[0x260..0x264].copy_from_slice(&0x20_0000u32.to_le_bytes());
        kernel
    }

    fn pdpte(map: &[u8], gpa: u64) -> u64 {
        let at = (PAGE + gpa / GIB * 8) as usize;
        u64::from_le_bytes(map[at..at + 8].try_into().unwrap())
    }

    #[test]
    fn identity_map_reaches_the_bound_memory_is_held_to() {
        let p = identity_map(0);
        // PML4[0] points at the PDPT that follows it; every PDPT entry is a
        // present, identity 1-GiB page.
        assert_eq!(
            u64::from_le_bytes(p[..8].try_into().unwrap()),
            (PAGE_TABLES + PAGE) | 3
        );
        assert_eq!(pdpte(&p, 0), 0x83);
        assert_eq!(pdpte(&p, MAP_LIMIT - GIB), (MAP_LIMIT - GIB) | 0x83);
        // The TDX shim executes at RESET_ALIAS on this map.
        assert_eq!(pdpte(&p, RESET_ALIAS) & 1, 1);
        // The encrypted map is the same table with one bit set in every entry.
        let e = identity_map(DEFAULT_CBIT as u64);
        for at in (0..PAGE_TABLE_SIZE as usize).step_by(8) {
            let (plain, enc) = (
                u64::from_le_bytes(p[at..at + 8].try_into().unwrap()),
                u64::from_le_bytes(e[at..at + 8].try_into().unwrap()),
            );
            assert_eq!(enc, if plain == 0 { 0 } else { plain | 1 << DEFAULT_CBIT });
        }
    }

    /// The SNP shim PVALIDATEs and zeroes through the measured map, so a guest
    /// whose accept list runs past the end of that map is one that page-faults
    /// with no IDT installed.  A 4-GiB map and a 16-GiB guest built cleanly.
    #[test]
    fn every_range_the_shim_is_told_to_touch_is_mapped() {
        for memory in [DEFAULT_MEMORY, 16 * GIB, MAP_LIMIT] {
            let params = Params::new(memory, 1, None, DEFAULT_CBIT, vec![]).unwrap();
            let map = identity_map(params.cbit as u64);
            let placed = vec![Placed::measured(KERNEL_BASE, RAM, vec![0u8; PAGE as usize])];
            for (_, hi) in boot::accept_ranges(&placed, params.memory) {
                assert_eq!(pdpte(&map, hi - PAGE) & 1, 1, "{hi:#x} is unmapped");
            }
        }
        assert!(Params::new(MAP_LIMIT + PAGE, 1, None, DEFAULT_CBIT, vec![]).is_err());
    }

    #[test]
    fn config_hash_is_pinned_or_zero() {
        assert_eq!(config_field(None, 32), Ok(zeros(32)));
        assert_eq!(
            config_field(Some(&"AB".repeat(32)), 32),
            Ok("ab".repeat(32))
        );
        assert!(config_field(Some("abcd"), 32).is_err());
        assert!(config_field(Some(&"zz".repeat(32)), 32).is_err());
    }

    #[test]
    fn required_cmdline_is_appended_whatever_the_deployer_asks_for() {
        assert_eq!(params().cmdline, "panic=-1 no5lvl");
        let p = Params::new(DEFAULT_MEMORY, 1, Some("quiet"), DEFAULT_CBIT, vec![]).unwrap();
        assert_eq!(p.cmdline, "quiet no5lvl");
        let p = Params::new(DEFAULT_MEMORY, 1, Some("no5lvl x"), DEFAULT_CBIT, vec![]).unwrap();
        assert_eq!(p.cmdline, "no5lvl x");
        assert!(Params::new(DEFAULT_MEMORY, 0, None, DEFAULT_CBIT, vec![]).is_err());
        assert!(Params::new(0x1000, 1, None, DEFAULT_CBIT, vec![]).is_err());
        assert!(Params::new(DEFAULT_MEMORY, MAX_VCPUS + 1, None, DEFAULT_CBIT, vec![]).is_err());
    }

    #[test]
    fn builds_byte_identical_loadable_firmware() {
        let dir = tempdir().unwrap();
        let kernel_path = dir.path().join("bzImage");
        let initramfs_path = dir.path().join("initrd");
        let a = dir.path().join("a.fw");
        let b = dir.path().join("b.fw");
        fs::write(&kernel_path, test_kernel()).unwrap();
        fs::write(&initramfs_path, b"test initramfs").unwrap();
        build(&kernel_path, &initramfs_path, &a, &params(), None).unwrap();
        build(&kernel_path, &initramfs_path, &b, &params(), None).unwrap();
        let one = fs::read(a).unwrap();
        assert_eq!(one, fs::read(b).unwrap());
        // QEMU rejects a firmware image that is not a whole number of 64-KiB
        // blocks, and finds everything else from the end of the file.
        assert_eq!(one.len() as u64 % 0x1_0000, 0);
        let sections = tdvf::parse(&one).unwrap();
        assert_eq!(sections.last().unwrap().0, RESET_ALIAS);
        assert!(sections.iter().any(|s| s.0 == TD_HOB && !s.1));
        assert!(sections.iter().all(|s| s.0 == TD_HOB || s.1));
        // The architectural reset instruction is the last 16 bytes.
        assert_eq!(one[one.len() - 16], 0xe9);
    }

    /// Reads the ranges back out of the packed reset page the way each shim
    /// will, so the list the assembler walks is checked against the list the
    /// packager measured rather than assumed to match it.
    pub fn shim_ranges(page: &[u8]) -> (u64, Vec<(u64, u64)>) {
        let at = SHIM_DATA as usize;
        let word = |i: usize| u64::from_le_bytes(page[i..i + 8].try_into().unwrap());
        let mut ranges = Vec::new();
        let mut i = at + 8;
        while word(i) != 0 || word(i + 8) != 0 {
            ranges.push((word(i), word(i + 8)));
            i += 16;
        }
        (word(at), ranges)
    }

    #[test]
    fn the_shim_accepts_exactly_what_the_packager_did_not_place() {
        let dir = tempdir().unwrap();
        let kernel_path = dir.path().join("bzImage");
        let initramfs_path = dir.path().join("initrd");
        let out = dir.path().join("a.fw");
        fs::write(&kernel_path, test_kernel()).unwrap();
        fs::write(&initramfs_path, vec![0u8; 100_000]).unwrap();
        let params = params();
        build(&kernel_path, &initramfs_path, &out, &params, None).unwrap();
        let file = fs::read(&out).unwrap();
        let (entry, ranges) = shim_ranges(&file[file.len() - PAGE as usize..]);
        assert_eq!(entry, KERNEL_BASE + 0x200);

        // Every section the firmware declares is loaded, so none of it may be
        // accepted; everything else below the top of memory must be.
        let mut want: Vec<(u64, u64)> = Vec::new();
        let mut at = 0;
        let mut placed: Vec<_> = tdvf::parse(&file)
            .unwrap()
            .iter()
            .map(|s| s.0)
            .filter(|gpa| *gpa < params.memory)
            .collect();
        placed.sort_unstable();
        for gpa in placed {
            if gpa > at {
                want.push((at, gpa));
            }
            at = at.max(gpa + PAGE);
        }
        // Sections wider than a page merge with the run that follows them, so
        // compare the accepted set rather than the exact section spans.
        let accepted: u64 = ranges.iter().map(|(l, h)| h - l).sum();
        assert!(accepted < params.memory);
        for (lo, hi) in &ranges {
            assert!(lo < hi && *hi <= params.memory);
            assert!(!tdvf::parse(&file).unwrap().iter().any(|s| {
                s.0 >= *lo && s.0 < *hi
            }));
        }
        // ...and the gaps between accepted ranges are exactly loaded pages.
        for pair in ranges.windows(2) {
            assert!(tdvf::parse(&file)
                .unwrap()
                .iter()
                .any(|s| s.0 == pair[0].1));
        }
        assert_eq!(ranges.first().unwrap().0, 0);
        assert_eq!(ranges.last().unwrap().1, params.memory);
    }

    /// A manifest component is a claim a verifier reproduces without knowing
    /// how the image was assembled: SHA-256 of exactly `size` bytes at
    /// `address`.  That has to hold for the reset page too, whose contents the
    /// packer finishes after the shim itself is built.
    #[test]
    fn every_component_hashes_the_bytes_at_the_address_it_names() {
        let dir = tempdir().unwrap();
        let kernel_path = dir.path().join("bzImage");
        let initramfs_path = dir.path().join("initrd");
        let out = dir.path().join("a.fw");
        fs::write(&kernel_path, test_kernel()).unwrap();
        fs::write(&initramfs_path, vec![7u8; 100_000]).unwrap();
        build(&kernel_path, &initramfs_path, &out, &params(), None).unwrap();
        let file = fs::read(&out).unwrap();
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(format!("{}.manifest.json", out.display())).unwrap())
                .unwrap();

        // Where each section's bytes sit in the file, read back the way QEMU
        // finds them.
        let end = file.len();
        let from_end =
            u32::from_le_bytes(file[end - 72..end - 68].try_into().unwrap()) as usize;
        let m = end - from_end;
        let count = u32::from_le_bytes(file[m + 12..m + 16].try_into().unwrap()) as usize;
        let mut at = BTreeMap::new();
        for i in 0..count {
            let e = m + 16 + 32 * i;
            let offset = u32::from_le_bytes(file[e..e + 4].try_into().unwrap()) as usize;
            let gpa = u64::from_le_bytes(file[e + 8..e + 16].try_into().unwrap());
            at.insert(gpa, offset);
        }

        let components = manifest["components"].as_object().unwrap();
        assert_eq!(components.len(), 6);
        for (name, c) in components {
            let gpa =
                u64::from_str_radix(c["address"].as_str().unwrap().trim_start_matches("0x"), 16)
                    .unwrap();
            let size = c["size"].as_u64().unwrap() as usize;
            let offset = at[&gpa];
            assert_eq!(
                hex::encode(Sha256::digest(&file[offset..offset + size])),
                c["sha256"].as_str().unwrap(),
                "component {name} does not describe the bytes at its address",
            );
        }
    }

    #[test]
    fn a_declared_mmio_hole_reaches_the_image_and_the_shim() {
        let dir = tempdir().unwrap();
        let kernel_path = dir.path().join("bzImage");
        let initramfs_path = dir.path().join("initrd");
        fs::write(&kernel_path, test_kernel()).unwrap();
        fs::write(&initramfs_path, b"test initramfs").unwrap();
        let hole = (0x000a_0000, 0x0002_0000);
        let with = Params::new(
            DEFAULT_MEMORY,
            DEFAULT_VCPUS,
            None,
            DEFAULT_CBIT,
            vec![hole],
        )
        .unwrap();
        let a = dir.path().join("a.fw");
        let b = dir.path().join("b.fw");
        build(&kernel_path, &initramfs_path, &a, &params(), None).unwrap();
        build(&kernel_path, &initramfs_path, &b, &with, None).unwrap();
        // Declaring a hole is a measured change: it moves both the E820 map
        // and the ranges the shim accepts.
        assert_ne!(fs::read(&a).unwrap(), fs::read(&b).unwrap());
        assert_eq!(mmio_holes(&with), vec!["0x000a0000:0x20000".to_string()]);

        // With no hole declared the image makes no assumption about the
        // machine: the aperture is ordinary RAM and the shim accepts it.
        let plain = fs::read(&a).unwrap();
        let (_, ranges) = shim_ranges(&plain[plain.len() - PAGE as usize..]);
        assert!(ranges.iter().any(|(l, h)| *l <= hole.0 && *h >= hole.0 + hole.1));
        // Declared, it is reserved and skipped instead.
        let held = fs::read(&b).unwrap();
        let (_, ranges) = shim_ranges(&held[held.len() - PAGE as usize..]);
        assert!(ranges
            .iter()
            .all(|(l, h)| *h <= hole.0 || *l >= hole.0 + hole.1));
    }

    /// The reset page lies inside the guest's own address space as soon as
    /// `--memory` passes 4 GiB.  Left out of the placed map it would be a page
    /// the shim is told to accept -- the page it is executing from -- and RAM
    /// Linux could allocate over while APs are still spinning in it.
    #[test]
    fn a_large_guest_leaves_the_reset_page_out_of_its_ram() {
        let dir = tempdir().unwrap();
        let kernel_path = dir.path().join("bzImage");
        let initramfs_path = dir.path().join("initrd");
        let out = dir.path().join("a.fw");
        fs::write(&kernel_path, test_kernel()).unwrap();
        fs::write(&initramfs_path, b"test initramfs").unwrap();
        let params = Params::new(8 * GIB, DEFAULT_VCPUS, None, DEFAULT_CBIT, vec![]).unwrap();
        build(&kernel_path, &initramfs_path, &out, &params, None).unwrap();
        let file = fs::read(&out).unwrap();
        let (_, ranges) = shim_ranges(&file[file.len() - PAGE as usize..]);
        assert!(ranges
            .iter()
            .all(|(lo, hi)| *hi <= RESET_ALIAS || *lo >= RESET_ALIAS + PAGE));
        // ...and the RAM above it is still accepted, so the gap is the page
        // itself and not the whole tail of the map.
        assert_eq!(ranges.last().unwrap(), &(RESET_ALIAS + PAGE, params.memory));
        // The one page the firmware occupies is reserved in the E820 map the
        // same placement derives, so Linux does not take it for free RAM.
        let e820 = boot::e820(
            &[Placed::measured(
                RESET_ALIAS,
                RESERVED,
                vec![0u8; PAGE as usize],
            )],
            params.memory,
        );
        assert!(e820
            .iter()
            .any(|(base, size, kind)| *base == RESET_ALIAS && *size == PAGE && *kind == RESERVED));
    }

    /// A TD launched with DEBUG or MIGRATABLE set produces a byte-identical
    /// MRTD, so the requirement that it has neither lives here or nowhere.
    #[test]
    fn attestation_pins_the_attributes_mrtd_cannot() {
        let r = tdx_attestation(&[0u8; 48], zeros(48));
        let bits = |key: &str| {
            u64::from_str_radix(r[key].as_deref().unwrap().trim_start_matches("0x"), 16).unwrap()
        };
        let (mask, want) = (bits("attributes_mask"), bits("attributes"));
        for bit in [ATTR_DEBUG, ATTR_MIGRATABLE] {
            assert_eq!(mask & bit, bit, "{bit:#x} is not checked");
            assert_eq!(want & bit, 0, "{bit:#x} is not required clear");
        }
        assert_eq!(want & ATTR_SEPT_VE_DISABLE, ATTR_SEPT_VE_DISABLE);
        // A masked compare: nothing is demanded outside the mask.
        assert_eq!(want & !mask, 0);
        // Requiring MIGRATABLE clear is half the check; the other half is that
        // no service TD -- in particular no migration TD -- is bound.
        assert_eq!(r["servtd_hash"], Some(zeros(48)));
        // The module version is the host's, so it is the deployer's to pin.
        assert_eq!(r["tee_tcb_svn"], None);
    }
}
