use crate::{
    acpi,
    boot::{self, put64, Fill, Placed, ACPI, RAM, RESERVED},
    layout::*,
    mrtd,
};
use igvm::{IgvmDirectiveHeader, IgvmFile, IgvmPlatformHeader, IgvmRevision};
use igvm_defs::{
    IgvmPageDataFlags, IgvmPageDataType, IgvmPlatformType, IGVM_TDX_PLATFORM_VERSION,
    IGVM_VHS_SUPPORTED_PLATFORM,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, io, path::Path};

// One compatibility mask bit: this file describes one platform.
const COMPAT: u32 = 1;

#[derive(Serialize)]
pub struct Component {
    address: String,
    size: usize,
    sha256: String,
}
// What a verifier should expect the report to say for this image: the digest,
// and the launch values this build chose. A value the host passes in is stated
// here when this build picked it, and left out when only the machine knows it.
pub type Launch = BTreeMap<&'static str, String>;

pub fn zeros(bytes: usize) -> String {
    "00".repeat(bytes)
}

// MRCONFIGID and HOST_DATA bind a deployment without entering the digest.
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
    /// Which platform's launch digest this manifest carries. A TDX image and
    /// an SNP image are not interchangeable and their measurements mean
    /// different things, so a reader should never have to infer it.
    platform: &'static str,
    memory_bytes: u64,
    vcpus: u32,
    command_line: String,
    mmio_holes: Vec<String>,
    kernel_entry: String,
    expected_mrtd: String,
    shim_owned_bytes: usize,
    launch: Launch,
    components: BTreeMap<&'static str, Component>,
}

// The assembler pads the shim to exactly one page.
const RESET_SHIM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/reset.bin"));
const _: () = assert!(RESET_SHIM.len() == SHIM_SIZE as usize);

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
    // cmdline_size is the kernel's own limit on the command line this image measures.
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
        entry: KERNEL_BASE + boot::ENTRY_64_OFFSET,
    })
}

/// The shim, with the entry point and zero-terminated accept ranges packed in.
pub fn shim(blob: &[u8], entry: u64, ranges: &[(u64, u64)]) -> Result<Vec<u8>, String> {
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
    let (mut shim, at) = (blob.to_vec(), SHIM_DATA as usize);
    if shim[at..at + data.len()].iter().any(|b| *b != 0) {
        return Err("shim code overruns its data block".into());
    }
    shim[at..at + data.len()].copy_from_slice(&data);
    Ok(shim)
}

/// The measured bytes this file authors, as opposed to the kernel and initramfs.
pub fn shim_owned(placed: &[Placed]) -> Result<usize, String> {
    let owned: usize = placed
        .iter()
        .filter(|p| p.base < KERNEL_SETUP_BASE || p.base == RESET_ALIAS)
        .filter(|p| !matches!(p.fill, Fill::Mmio(_)))
        .map(|p| p.span() as usize)
        .sum();
    if owned > SHIM_LIMIT {
        return Err(format!(
            "shim-owned measured pages exceed {SHIM_LIMIT} bytes: {owned}"
        ));
    }
    Ok(owned)
}

/// The named regions of the map, each hashed where the map places it.
pub fn components(placed: &[Placed]) -> BTreeMap<&'static str, Component> {
    placed
        .iter()
        .filter(|p| !p.name.is_empty())
        .map(|p| (p.name, component(p.base, p.data())))
        .collect()
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

    // The one authoritative map: E820, the file's pages and the accept list follow from it.
    let mut placed = vec![
        // Blank: the zero page describes the map it belongs to, so its contents come last.
        Placed::measured(ZERO_PAGE, "", RESERVED, vec![0u8; PAGE as usize]),
        Placed::measured(CMDLINE, "command_line", RESERVED, p.command.clone()),
        Placed::measured(ACPI_BASE, "acpi", ACPI, acpi.clone()),
        Placed::measured(MAILBOX, "", RESERVED, vec![0u8; PAGE as usize]),
        Placed::measured(PAGE_TABLES, "", RESERVED, identity_map(0, false)),
        Placed::measured(BSP_STACK, "", RESERVED, boot::gdt_stack()),
        Placed::measured(KERNEL_SETUP_BASE, "kernel_setup", RESERVED, p.setup.clone()),
        Placed::measured(KERNEL_BASE, "kernel", RAM, p.kernel.clone()),
        Placed::measured(INITRAMFS_BASE, "initramfs", RAM, p.initramfs.clone()),
        // The map covers the reset page, so the shim is never told to accept what it runs from.
        Placed::measured(RESET_ALIAS, "shim", RESERVED, vec![0u8; PAGE as usize]),
    ];
    placed.extend(params.mmio.iter().map(|(b, n)| Placed::mmio(*b, *n)));
    boot::validate(&placed, params.memory)?;
    let e820 = boot::e820(&placed, params.memory);
    let zero = boot::zero_page(&p.setup, p.info, p.initramfs.len(), ACPI_BASE, &e820, 0)?;
    boot::fill(&mut placed, ZERO_PAGE, zero)?;
    let accept = boot::accept_ranges(&placed, params.memory);
    boot::fill(
        &mut placed,
        RESET_ALIAS,
        shim(RESET_SHIM, p.entry, &accept)?,
    )?;
    let owned = shim_owned(&placed)?;

    // Ascending GPA order, which is the order a loader adds pages and MRTD is built in.
    placed.sort_by_key(|p| p.base);
    let pages = launch_pages(&placed)?;
    let file = igvm(&pages)?;
    // Read the file back the way a loader will, before publishing a digest for it.
    if igvm_pages(&file)? != pages {
        return Err("emitted IGVM file does not describe the measured pages".into());
    }
    let expected_mrtd = mrtd::calculate(&pages);
    fs::write(output, &file).map_err(io_error("write IGVM"))?;

    let manifest = Manifest {
        format_version: 2,
        platform: "tdx",
        memory_bytes: params.memory,
        vcpus: params.vcpus,
        command_line: params.cmdline.clone(),
        mmio_holes: mmio_holes(params),
        kernel_entry: format!("0x{:08x}", p.entry),
        expected_mrtd: hex::encode(expected_mrtd),
        shim_owned_bytes: owned,
        launch: tdx_launch(&expected_mrtd, mrconfigid),
        components: components(&placed),
    };
    write_manifest(output, &manifest)
}

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

fn launch_pages(placed: &[Placed]) -> Result<Vec<(u64, Vec<u8>)>, String> {
    let mut out = Vec::new();
    for region in placed {
        match &region.fill {
            Fill::Measured(data) => out.extend(boot::pages(region.base, data)),
            Fill::Mmio(_) => {}
            Fill::Host => {
                return Err(format!(
                    "{:#x} is placed but has no measured contents",
                    region.base
                ))
            }
        }
    }
    Ok(out)
}

/// A page a loader imports at `gpa`: 4 KiB, private and measured, which is flags of zero.
pub fn page_directive(gpa: u64, data_type: IgvmPageDataType, data: Vec<u8>) -> IgvmDirectiveHeader {
    IgvmDirectiveHeader::PageData {
        gpa,
        compatibility_mask: COMPAT,
        flags: IgvmPageDataFlags::new(),
        data_type,
        data,
    }
}

fn igvm(pages: &[(u64, Vec<u8>)]) -> Result<Vec<u8>, String> {
    let platform = IgvmPlatformHeader::SupportedPlatform(IGVM_VHS_SUPPORTED_PLATFORM {
        compatibility_mask: COMPAT,
        highest_vtl: 0,
        platform_type: IgvmPlatformType::TDX,
        platform_version: IGVM_TDX_PLATFORM_VERSION,
        // Nothing is loaded shared and the guest reads its own GPAW, so no boundary is stated.
        shared_gpa_boundary: 0,
    });
    let directives = pages
        .iter()
        .map(|(gpa, data)| page_directive(*gpa, IgvmPageDataType::NORMAL, data.clone()))
        .collect();
    let file = IgvmFile::new(IgvmRevision::V1, vec![platform], vec![], directives)
        .map_err(|e| format!("construct TDX IGVM: {e}"))?;
    let mut out = Vec::new();
    file.serialize(&mut out)
        .map_err(|e| format!("serialize TDX IGVM: {e}"))?;
    Ok(out)
}

/// Reads an image back the way a loader does, refusing any directive that is not a measured page.
pub fn igvm_pages(file: &[u8]) -> Result<Vec<(u64, Vec<u8>)>, String> {
    IgvmFile::new_from_binary(file, None)
        .map_err(|e| format!("read back TDX IGVM: {e}"))?
        .directives()
        .iter()
        .map(|d| match d {
            IgvmDirectiveHeader::PageData {
                gpa,
                compatibility_mask,
                flags,
                data_type,
                data,
            } if *compatibility_mask == COMPAT
                && *data_type == IgvmPageDataType::NORMAL
                && !flags.is_2mb_page()
                && !flags.unmeasured()
                && !flags.shared()
                && data.len() == PAGE as usize =>
            {
                Ok((*gpa, data.clone()))
            }
            _ => Err("TDX IGVM carries a directive that is not a measured page".to_string()),
        })
        .collect()
}

// What a TD launched from this image reports. ATTRIBUTES, XFAM, the owner
// registers, SERVTD_HASH and TEE_TCB_SVN are the host's to choose at
// TDH.MNG.INIT, so they belong to the verifier's platform policy, not here.
fn tdx_launch(mrtd: &[u8; 48], mrconfigid: String) -> Launch {
    let mut r = Launch::new();
    r.insert("mrtd", hex::encode(mrtd));
    r.insert("mrconfigid", mrconfigid);
    // This image extends no RTMR, so each register is still at its reset value.
    for name in ["rtmr0", "rtmr1", "rtmr2", "rtmr3"] {
        r.insert(name, zeros(48));
    }
    r
}

/// The 4-level map covering [0, MAP_LIMIT); `c_bit` is 0 on TDX and the C-bit on SNP.
pub fn identity_map(c_bit: u64, shared_alias: bool) -> Vec<u8> {
    let c = if c_bit == 0 { 0 } else { 1u64 << c_bit };
    let pages = if shared_alias { 3 } else { 2 };
    let mut v = vec![0u8; pages * PAGE as usize];
    put64(&mut v, 0, (PAGE_TABLES + PAGE) | c | 3);
    for gib in 0..MAP_LIMIT / GIB {
        put64(&mut v, (PAGE + gib * 8) as usize, (gib * GIB) | c | 0x83);
    }
    if shared_alias {
        // PML4[1] -> a second PDPT whose first entry is physical GiB 0, unencrypted.
        put64(&mut v, 8, (PAGE_TABLES + 2 * PAGE) | c | 3);
        put64(&mut v, (2 * PAGE) as usize, 0x83);
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
        Params::tdx(DEFAULT_RAM, DEFAULT_VCPUS, "", vec![]).unwrap()
    }

    /// A bzImage-shaped stub: enough of the setup header for the builder to accept it.
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
        let p = identity_map(0, false);
        // PML4[0] points at the PDPT that follows it, whose entries are 1-GiB pages.
        assert_eq!(
            u64::from_le_bytes(p[..8].try_into().unwrap()),
            (PAGE_TABLES + PAGE) | 3
        );
        assert_eq!(pdpte(&p, 0), 0x83);
        assert_eq!(pdpte(&p, MAP_LIMIT - GIB), (MAP_LIMIT - GIB) | 0x83);
        assert_eq!(pdpte(&p, RESET_ALIAS) & 1, 1);
        let e = identity_map(DEFAULT_CBIT as u64, false);
        assert_eq!(p.len(), e.len());
        for at in (0..p.len()).step_by(8) {
            let (plain, enc) = (
                u64::from_le_bytes(p[at..at + 8].try_into().unwrap()),
                u64::from_le_bytes(e[at..at + 8].try_into().unwrap()),
            );
            assert_eq!(
                enc,
                if plain == 0 {
                    0
                } else {
                    plain | 1 << DEFAULT_CBIT
                }
            );
        }
    }

    /// On SNP, PML4[1] reaches physical GiB 0 again with the C-bit clear, and nothing else.
    #[test]
    fn the_shared_alias_maps_gib_zero_unencrypted() {
        let m = identity_map(DEFAULT_CBIT as u64, true);
        assert_eq!(m.len(), 3 * PAGE as usize);
        let pml4_1 = u64::from_le_bytes(m[8..16].try_into().unwrap());
        assert_eq!(pml4_1, (PAGE_TABLES + 2 * PAGE) | 1 << DEFAULT_CBIT | 3);
        let alias = &m[2 * PAGE as usize..];
        assert_eq!(u64::from_le_bytes(alias[..8].try_into().unwrap()), 0x83);
        assert!(alias[8..].iter().all(|b| *b == 0));
        assert_eq!(SHARED_ALIAS, 512 * GIB);
    }

    /// The SNP shim PVALIDATEs and zeroes through the map, so every range it walks is mapped.
    #[test]
    fn every_range_the_shim_is_told_to_touch_is_mapped() {
        for ram in [DEFAULT_RAM, 16 * GIB, MAX_RAM] {
            let params = Params::snp(ram, DEFAULT_VCPUS, DEFAULT_CBIT, "", vec![]).unwrap();
            let map = identity_map(params.cbit as u64, true);
            let placed = vec![Placed::measured(
                KERNEL_BASE,
                "",
                RAM,
                vec![0u8; PAGE as usize],
            )];
            for (_, hi) in boot::accept_ranges(&placed, params.memory) {
                assert_eq!(pdpte(&map, hi - PAGE) & 1, 1, "{hi:#x} is unmapped");
            }
        }
        assert!(Params::snp(MAX_RAM + PAGE, DEFAULT_VCPUS, DEFAULT_CBIT, "", vec![]).is_err());
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
    fn required_cmdline_is_appended_whatever_the_operator_asks_for() {
        assert_eq!(params().cmdline, "panic=-1 no5lvl");
        let p = Params::tdx(DEFAULT_RAM, 1, "quiet", vec![]).unwrap();
        assert_eq!(p.cmdline, "quiet no5lvl");
        let p = Params::tdx(DEFAULT_RAM, 1, "no5lvl x", vec![]).unwrap();
        assert_eq!(p.cmdline, "no5lvl x");
        assert!(Params::tdx(DEFAULT_RAM, 0, "", vec![]).is_err());
        assert!(Params::tdx(0x1000, 1, "", vec![]).is_err());
        assert!(Params::tdx(DEFAULT_RAM, MAX_VCPUS + 1, "", vec![]).is_err());
    }

    /// Builds from stub inputs and returns the IGVM file and the manifest beside it.
    pub fn built(params: &Params) -> (Vec<u8>, serde_json::Value) {
        let dir = tempdir().unwrap();
        let (kernel, initramfs, out) = (
            dir.path().join("bzImage"),
            dir.path().join("initrd"),
            dir.path().join("out.igvm"),
        );
        fs::write(&kernel, test_kernel()).unwrap();
        fs::write(&initramfs, vec![7u8; 100_000]).unwrap();
        build(&kernel, &initramfs, &out, params, None).unwrap();
        let manifest = fs::read(format!("{}.manifest.json", out.display())).unwrap();
        (
            fs::read(out).unwrap(),
            serde_json::from_slice(&manifest).unwrap(),
        )
    }

    fn reset_page(file: &[u8]) -> Vec<u8> {
        let (gpa, page) = igvm_pages(file).unwrap().pop().unwrap();
        assert_eq!(gpa, RESET_ALIAS);
        page
    }

    #[test]
    fn builds_a_byte_identical_loadable_igvm_file() {
        let one = built(&params()).0;
        assert_eq!(one, built(&params()).0);
        // Read back the way a loader does: whole measured pages in ascending order.
        let pages = igvm_pages(&one).unwrap();
        assert!(pages.windows(2).all(|w| w[0].0 + PAGE <= w[1].0));
        // The architectural reset instruction is the last 16 bytes of memory.
        assert_eq!(reset_page(&one)[PAGE as usize - 16], 0xe9);
    }

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
    fn the_shim_accepts_exactly_what_the_builder_did_not_place() {
        let params = params();
        let file = built(&params).0;
        let (entry, ranges) = shim_ranges(&reset_page(&file));
        assert_eq!(entry, KERNEL_BASE + 0x200);

        let loaded: Vec<u64> = igvm_pages(&file)
            .unwrap()
            .iter()
            .map(|(gpa, _)| *gpa)
            .filter(|gpa| *gpa < params.memory)
            .collect();
        // The loader accepted every page it loaded, and accepting one twice replaces it...
        for (lo, hi) in &ranges {
            assert!(lo < hi && *hi <= params.memory);
            assert!(!loaded.iter().any(|gpa| gpa >= lo && gpa < hi));
        }
        // ...the gaps between accepted ranges are exactly those pages...
        for pair in ranges.windows(2) {
            assert!(loaded.contains(&pair[0].1));
        }
        // ...and nothing below the top of memory is left out of either list.
        let accepted: u64 = ranges.iter().map(|(l, h)| h - l).sum();
        assert_eq!(accepted + loaded.len() as u64 * PAGE, params.memory);
        assert_eq!(ranges.first().unwrap().0, 0);
        assert_eq!(ranges.last().unwrap().1, params.memory);
    }

    /// Each component is SHA-256 of exactly `size` bytes at `address`, reset page included.
    #[test]
    fn every_component_hashes_the_bytes_at_the_address_it_names() {
        let (file, manifest) = built(&params());
        let loaded: BTreeMap<u64, Vec<u8>> = igvm_pages(&file).unwrap().into_iter().collect();
        let components = manifest["components"].as_object().unwrap();
        assert_eq!(components.len(), 6);
        for (name, c) in components {
            let gpa =
                u64::from_str_radix(c["address"].as_str().unwrap().trim_start_matches("0x"), 16)
                    .unwrap();
            let size = c["size"].as_u64().unwrap() as usize;
            let mut bytes = Vec::new();
            while bytes.len() < size {
                bytes.extend_from_slice(&loaded[&(gpa + bytes.len() as u64)]);
            }
            assert_eq!(
                hex::encode(Sha256::digest(&bytes[..size])),
                c["sha256"].as_str().unwrap(),
                "component {name} does not describe the bytes at its address",
            );
        }
    }

    #[test]
    fn a_declared_mmio_hole_reaches_the_image_and_the_shim() {
        let hole = (0x000a_0000, 0x0002_0000);
        let with = Params::tdx(DEFAULT_RAM, DEFAULT_VCPUS, "", vec![hole]).unwrap();
        let (plain, held) = (built(&params()).0, built(&with).0);
        // Declaring a hole is a measured change: it moves E820 and the accept list.
        assert_ne!(plain, held);
        assert_eq!(mmio_holes(&with), vec!["0x000a0000:0x20000".to_string()]);

        let (_, ranges) = shim_ranges(&reset_page(&plain));
        assert!(ranges
            .iter()
            .any(|(l, h)| *l <= hole.0 && *h >= hole.0 + hole.1));
        let (_, ranges) = shim_ranges(&reset_page(&held));
        assert!(ranges
            .iter()
            .all(|(l, h)| *h <= hole.0 || *l >= hole.0 + hole.1));
    }

    /// A map that misses the machine QEMU builds leaves no window to assign BARs out of.
    /// Both manifests name their platform. A reader holding one of these has
    /// to know whether expected_mrtd or expected_snp_measurement is the
    /// number that matters, and should not have to guess from a filename.
    #[test]
    fn a_manifest_names_the_platform_it_measured() {
        let (_, manifest) = built(&params());
        assert_eq!(manifest["platform"], "tdx");
        assert!(manifest["expected_mrtd"].is_string());
    }

    #[test]
    fn the_pci_aperture_follows_the_ram_the_machine_has() {
        let small = Params::tdx(2 * GIB, 1, "", vec![]).unwrap();
        assert_eq!((small.memory, small.mmio.len()), (2 * GIB, 0));
        assert_eq!(Params::tdx(3 * GIB, 1, "", vec![]).unwrap().memory, 5 * GIB);
        let p = Params::tdx(8 * GIB, 1, "", vec![]).unwrap();
        assert_eq!(p.memory, 10 * GIB);
        // TDX loads the reset page inside the aperture; SNP loads nothing there.
        assert_eq!(p.mmio, vec![(2 * GIB, RESET_ALIAS - 2 * GIB)]);
        let snp = Params::snp(8 * GIB, DEFAULT_VCPUS, DEFAULT_CBIT, "", vec![]).unwrap();
        assert_eq!(snp.mmio, vec![(2 * GIB, 2 * GIB)]);

        let placed: Vec<Placed> = p
            .mmio
            .iter()
            .map(|(base, size)| Placed::mmio(*base, *size))
            .chain([Placed::measured(
                RESET_ALIAS,
                "",
                RESERVED,
                vec![0u8; PAGE as usize],
            )])
            .collect();
        let e820 = boot::e820(&placed, p.memory);
        assert!(e820
            .iter()
            .all(|(base, size, kind)| *kind != RAM || base + size <= 2 * GIB || *base >= 4 * GIB));
        assert!(e820
            .iter()
            .any(|(base, size, kind)| (*base, *size, *kind) == (4 * GIB, 6 * GIB, RAM)));
    }

    /// Past 4 GiB of map the reset page lies inside the guest's own address space.
    #[test]
    fn a_large_guest_leaves_the_reset_page_out_of_its_ram() {
        let params = Params::tdx(8 * GIB, DEFAULT_VCPUS, "", vec![]).unwrap();
        let (_, ranges) = shim_ranges(&reset_page(&built(&params).0));
        assert!(ranges
            .iter()
            .all(|(lo, hi)| *hi <= RESET_ALIAS || *lo >= RESET_ALIAS + PAGE));
        assert_eq!(ranges.last().unwrap(), &(RESET_ALIAS + PAGE, params.memory));
        // The same placement reserves it in E820, so Linux does not take it for free RAM.
        let e820 = boot::e820(
            &[Placed::measured(
                RESET_ALIAS,
                "",
                RESERVED,
                vec![0u8; PAGE as usize],
            )],
            params.memory,
        );
        assert!(e820
            .iter()
            .any(|(base, size, kind)| *base == RESET_ALIAS && *size == PAGE && *kind == RESERVED));
    }

    /// The manifest describes the image. Anything the host picks at
    /// TDH.MNG.INIT is the verifier's platform policy, and stating it here
    /// would put a build artifact in the business of asserting host facts.
    #[test]
    fn the_launch_block_states_nothing_the_host_chooses() {
        let r = tdx_launch(&[7u8; 48], zeros(48));
        for host_chosen in [
            "attributes",
            "attributes_mask",
            "xfam",
            "mrowner",
            "mrownerconfig",
            "servtd_hash",
            "tee_tcb_svn",
        ] {
            assert!(!r.contains_key(host_chosen), "{host_chosen} is the host's");
        }
        // An exact set, so a newly added host field fails even though no
        // denylist names it.
        assert_eq!(
            r.keys().copied().collect::<Vec<_>>(),
            ["mrconfigid", "mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"]
        );
        // Distinct values, so the two cannot be swapped without failing.
        assert_eq!(r["mrtd"], hex::encode([7u8; 48]));
        assert_eq!(r["mrconfigid"], zeros(48));
        for rtmr in ["rtmr0", "rtmr1", "rtmr2", "rtmr3"] {
            assert_eq!(r[rtmr], zeros(48), "{rtmr} is not a reset value");
        }
    }
}
