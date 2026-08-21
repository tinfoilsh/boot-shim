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
// Report fields a verifier requires besides the measurement; `None` is the operator's to pin.
pub type Required = BTreeMap<&'static str, Option<String>>;

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

// The assembler pads the shim to exactly one page.
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
        entry: KERNEL_BASE + info.entry_offset,
    })
}

/// The shim's data block: the kernel entry point, then zero-terminated (low, high) ranges.
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

/// The measured bytes this file authors, as opposed to the kernel and initramfs.
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

    // The one authoritative map: E820, the file's pages and the accept list all derive from it.
    let mut placed = vec![
        // Blank: the zero page describes the map it belongs to, so its contents come last.
        Placed::measured(ZERO_PAGE, RESERVED, vec![0u8; PAGE as usize]),
        Placed::measured(CMDLINE, RESERVED, p.command.clone()),
        Placed::measured(ACPI_BASE, ACPI, acpi.bytes.clone()),
        Placed::measured(MAILBOX, RESERVED, vec![0u8; PAGE as usize]),
        Placed::measured(PAGE_TABLES, RESERVED, identity_map(0)),
        Placed::measured(BSP_STACK, RESERVED, boot::gdt_stack()),
        Placed::measured(KERNEL_SETUP_BASE, RESERVED, p.setup.clone()),
        Placed::measured(KERNEL_BASE, RAM, p.kernel.clone()),
        Placed::measured(INITRAMFS_BASE, RAM, p.initramfs.clone()),
        // The map covers the reset page, so the shim is never told to accept what it runs from.
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
    boot::fill(&mut placed, RESET_ALIAS, shim.clone())?;

    let owned = shim_owned(&placed) + SHIM_SIZE as usize;
    if owned > SHIM_LIMIT {
        return Err(format!("shim-owned measured pages exceed 256 KiB: {owned}"));
    }

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

    let mut components = BTreeMap::new();
    components.insert("kernel", component(KERNEL_BASE, &p.kernel));
    components.insert("kernel_setup", component(KERNEL_SETUP_BASE, &p.setup));
    components.insert("initramfs", component(INITRAMFS_BASE, &p.initramfs));
    components.insert("command_line", component(CMDLINE, &p.command));
    components.insert("acpi", component(ACPI_BASE, &acpi.bytes));
    components.insert("shim", component(RESET_ALIAS, &shim));
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

/// The declared apertures, published so a verifier reads them from the manifest.
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

/// The pages a loader hands the TDX module, each a whole 4-KiB page this file provides.
fn launch_pages(placed: &[Placed]) -> Result<Vec<(u64, Vec<u8>)>, String> {
    let mut out = Vec::new();
    for region in placed {
        match &region.fill {
            // Nothing is loaded at an MMIO aperture and no shim accepts it.
            Fill::Mmio(_) => continue,
            Fill::Host => {
                return Err(format!(
                    "{:#x} is placed but has no measured contents",
                    region.base
                ))
            }
            Fill::Measured(data) => {
                for (i, chunk) in data.chunks(PAGE as usize).enumerate() {
                    let mut page = vec![0u8; PAGE as usize];
                    page[..chunk.len()].copy_from_slice(chunk);
                    out.push((region.base + i as u64 * PAGE, page));
                }
            }
        }
    }
    Ok(out)
}

/// The IGVM file: one measured page-data directive per page, under the TDX platform header.
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
        .map(|(gpa, data)| IgvmDirectiveHeader::PageData {
            gpa: *gpa,
            compatibility_mask: COMPAT,
            flags: IgvmPageDataFlags::new(),
            data_type: IgvmPageDataType::NORMAL,
            data: data.clone(),
        })
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

// The TD_ATTRIBUTES bits a verifier constrains; the compare is masked, so the rest stay free.
const ATTR_DEBUG: u64 = 1;
const ATTR_SEPT_VE_DISABLE: u64 = 1 << 28;
const ATTR_MIGRATABLE: u64 = 1 << 29;

// MRTD covers the pages; the host picks ATTRIBUTES, XFAM and the owner registers separately.
fn tdx_attestation(mrtd: &[u8; 48], mrconfigid: String) -> Required {
    let mut r = Required::new();
    r.insert("mrtd", Some(hex::encode(mrtd)));
    let mask = ATTR_DEBUG | ATTR_SEPT_VE_DISABLE | ATTR_MIGRATABLE;
    r.insert("attributes_mask", Some(format!("0x{mask:016x}")));
    r.insert("attributes", Some(format!("0x{ATTR_SEPT_VE_DISABLE:016x}")));
    // XFAM is a launch parameter this build cannot predict.
    r.insert("xfam", None);
    r.insert("mrconfigid", Some(mrconfigid));
    r.insert("mrowner", Some(zeros(48)));
    r.insert("mrownerconfig", Some(zeros(48)));
    // Zero says no service TD is bound, and a TD migrates only through a migration TD.
    r.insert("servtd_hash", Some(zeros(48)));
    // The module version is the host's, so the operator pins an acceptable floor.
    r.insert("tee_tcb_svn", None);
    // This image extends no RTMR, so each register is still at its reset value.
    for name in ["rtmr0", "rtmr1", "rtmr2", "rtmr3"] {
        r.insert(name, Some(zeros(48)));
    }
    r
}

/// The 4-level map covering [0, MAP_LIMIT); `c_bit` is 0 on TDX and the C-bit on SNP.
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
        let p = identity_map(0);
        // PML4[0] points at the PDPT that follows it, whose entries are 1-GiB pages.
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

    /// The SNP shim PVALIDATEs and zeroes through the map, so every range it walks is mapped.
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
    fn required_cmdline_is_appended_whatever_the_operator_asks_for() {
        assert_eq!(params().cmdline, "panic=-1 no5lvl");
        let p = Params::new(DEFAULT_MEMORY, 1, Some("quiet"), DEFAULT_CBIT, vec![]).unwrap();
        assert_eq!(p.cmdline, "quiet no5lvl");
        let p = Params::new(DEFAULT_MEMORY, 1, Some("no5lvl x"), DEFAULT_CBIT, vec![]).unwrap();
        assert_eq!(p.cmdline, "no5lvl x");
        assert!(Params::new(DEFAULT_MEMORY, 0, None, DEFAULT_CBIT, vec![]).is_err());
        assert!(Params::new(0x1000, 1, None, DEFAULT_CBIT, vec![]).is_err());
        assert!(Params::new(DEFAULT_MEMORY, MAX_VCPUS + 1, None, DEFAULT_CBIT, vec![]).is_err());
    }

    /// The reset page as a loader finds it: the last and highest page the file carries.
    fn reset_page(file: &[u8]) -> Vec<u8> {
        let (gpa, page) = igvm_pages(file).unwrap().pop().unwrap();
        assert_eq!(gpa, RESET_ALIAS);
        page
    }

    #[test]
    fn builds_a_byte_identical_loadable_igvm_file() {
        let dir = tempdir().unwrap();
        let kernel_path = dir.path().join("bzImage");
        let initramfs_path = dir.path().join("initrd");
        let a = dir.path().join("a.igvm");
        let b = dir.path().join("b.igvm");
        fs::write(&kernel_path, test_kernel()).unwrap();
        fs::write(&initramfs_path, b"test initramfs").unwrap();
        build(&kernel_path, &initramfs_path, &a, &params(), None).unwrap();
        build(&kernel_path, &initramfs_path, &b, &params(), None).unwrap();
        let one = fs::read(a).unwrap();
        assert_eq!(one, fs::read(b).unwrap());
        // Read back the way a loader does: whole measured pages in ascending order.
        let pages = igvm_pages(&one).unwrap();
        assert!(pages.windows(2).all(|w| w[0].0 + PAGE <= w[1].0));
        // The architectural reset instruction is the last 16 bytes of memory.
        assert_eq!(reset_page(&one)[PAGE as usize - 16], 0xe9);
    }

    /// Reads the ranges out of the packed reset page the way each shim does.
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
        let dir = tempdir().unwrap();
        let kernel_path = dir.path().join("bzImage");
        let initramfs_path = dir.path().join("initrd");
        let out = dir.path().join("a.igvm");
        fs::write(&kernel_path, test_kernel()).unwrap();
        fs::write(&initramfs_path, vec![0u8; 100_000]).unwrap();
        let params = params();
        build(&kernel_path, &initramfs_path, &out, &params, None).unwrap();
        let file = fs::read(&out).unwrap();
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
        let dir = tempdir().unwrap();
        let kernel_path = dir.path().join("bzImage");
        let initramfs_path = dir.path().join("initrd");
        let out = dir.path().join("a.igvm");
        fs::write(&kernel_path, test_kernel()).unwrap();
        fs::write(&initramfs_path, vec![7u8; 100_000]).unwrap();
        build(&kernel_path, &initramfs_path, &out, &params(), None).unwrap();
        let loaded: BTreeMap<u64, Vec<u8>> = igvm_pages(&fs::read(&out).unwrap())
            .unwrap()
            .into_iter()
            .collect();
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(format!("{}.manifest.json", out.display())).unwrap())
                .unwrap();

        let components = manifest["components"].as_object().unwrap();
        assert_eq!(components.len(), 6);
        for (name, c) in components {
            let gpa =
                u64::from_str_radix(c["address"].as_str().unwrap().trim_start_matches("0x"), 16)
                    .unwrap();
            let size = c["size"].as_u64().unwrap() as usize;
            // The pages the file loads from that address onwards, in order.
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
        let a = dir.path().join("a.igvm");
        let b = dir.path().join("b.igvm");
        build(&kernel_path, &initramfs_path, &a, &params(), None).unwrap();
        build(&kernel_path, &initramfs_path, &b, &with, None).unwrap();
        // Declaring a hole is a measured change: it moves E820 and the accept list.
        assert_ne!(fs::read(&a).unwrap(), fs::read(&b).unwrap());
        assert_eq!(mmio_holes(&with), vec!["0x000a0000:0x20000".to_string()]);

        // Undeclared, the aperture is ordinary RAM and the shim accepts it.
        let plain = fs::read(&a).unwrap();
        let (_, ranges) = shim_ranges(&reset_page(&plain));
        assert!(ranges
            .iter()
            .any(|(l, h)| *l <= hole.0 && *h >= hole.0 + hole.1));
        // Declared, it is reserved and the shim skips it.
        let held = fs::read(&b).unwrap();
        let (_, ranges) = shim_ranges(&reset_page(&held));
        assert!(ranges
            .iter()
            .all(|(l, h)| *h <= hole.0 || *l >= hole.0 + hole.1));
    }

    /// Past 4 GiB of `--memory` the reset page lies inside the guest's own address space.
    #[test]
    fn a_large_guest_leaves_the_reset_page_out_of_its_ram() {
        let dir = tempdir().unwrap();
        let kernel_path = dir.path().join("bzImage");
        let initramfs_path = dir.path().join("initrd");
        let out = dir.path().join("a.igvm");
        fs::write(&kernel_path, test_kernel()).unwrap();
        fs::write(&initramfs_path, b"test initramfs").unwrap();
        let params = Params::new(8 * GIB, DEFAULT_VCPUS, None, DEFAULT_CBIT, vec![]).unwrap();
        build(&kernel_path, &initramfs_path, &out, &params, None).unwrap();
        let file = fs::read(&out).unwrap();
        let (_, ranges) = shim_ranges(&reset_page(&file));
        assert!(ranges
            .iter()
            .all(|(lo, hi)| *hi <= RESET_ALIAS || *lo >= RESET_ALIAS + PAGE));
        // ...and the RAM above it is still accepted, so the gap is that page alone.
        assert_eq!(ranges.last().unwrap(), &(RESET_ALIAS + PAGE, params.memory));
        // The same placement reserves it in E820, so Linux does not take it for free RAM.
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

    /// DEBUG and MIGRATABLE leave MRTD byte-identical, so the requirement lives here.
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
        // The other half of requiring MIGRATABLE clear: no service TD is bound.
        assert_eq!(r["servtd_hash"], Some(zeros(48)));
        // The module version is the host's, so the operator pins it.
        assert_eq!(r["tee_tcb_svn"], None);
    }
}
