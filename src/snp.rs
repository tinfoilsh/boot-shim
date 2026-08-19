use crate::{acpi, boot, layout::*};
use igvm::snp_defs::{SevFeatures, SevSelector, SevVmsa};
use igvm::{
    IgvmDirectiveHeader, IgvmFile, IgvmInitializationHeader, IgvmPlatformHeader, IgvmRevision,
};
use igvm_defs::{
    IgvmPageDataFlags, IgvmPageDataType, IgvmPlatformType, IGVM_VHS_SUPPORTED_PLATFORM,
};
use serde::Serialize;
use sha2::{Digest, Sha256, Sha384};
use std::{collections::BTreeMap, fs, io, path::Path};
use zerocopy::{AsBytes, FromZeroes};

const COMPAT: u32 = 1;
const PAGE_INFO_LEN: u16 = 112;
const PAGE_NORMAL: u8 = 1;
const PAGE_VMSA: u8 = 2;
const PAGE_SECRETS: u8 = 5;
const PAGE_CPUID: u8 = 6;

#[derive(Clone)]
struct LaunchPage {
    gpa: u64,
    data: Vec<u8>,
    kind: IgvmPageDataType,
    measure_kind: u8,
}

#[derive(Serialize)]
struct Component {
    address: String,
    size: usize,
    sha256: String,
}
#[derive(Serialize)]
struct CpuProfile {
    family: u8,
    model: u8,
    stepping: u8,
    c_bit_position: u8,
    physical_address_bits: u8,
    sev_feature_mask: String,
}
#[derive(Serialize)]
struct Topology {
    sockets: u8,
    cores: u8,
    threads_per_core: u8,
    vcpus: u32,
}
#[derive(Serialize)]
struct Manifest {
    format_version: u32,
    platform: &'static str,
    memory_bytes: u64,
    topology: Topology,
    command_line: &'static str,
    kernel_entry: String,
    expected_snp_measurement: String,
    guest_policy: String,
    cpu: CpuProfile,
    shim_owned_bytes: usize,
    components: BTreeMap<&'static str, Component>,
}

pub fn build(kernel_path: &Path, initramfs_path: &Path, output: &Path) -> Result<(), String> {
    let kernel_file = fs::read(kernel_path).map_err(io_error("read kernel"))?;
    let initramfs = fs::read(initramfs_path).map_err(io_error("read initramfs"))?;
    let info = boot::parse_bzimage(&kernel_file)?;
    let kernel = &kernel_file[info.setup_bytes..];
    let kernel_end = align_up(KERNEL_BASE + kernel.len() as u64, PAGE);
    let initramfs_end = align_up(INITRAMFS_BASE + initramfs.len() as u64, PAGE);
    if kernel_end > INITRAMFS_BASE || KERNEL_BASE + info.init_size as u64 > INITRAMFS_BASE {
        return Err("protected kernel overlaps the fixed initramfs address".into());
    }
    if initramfs_end > RAM_SIZE {
        return Err("initramfs exceeds the fixed 1-GiB guest memory".into());
    }
    if info.setup_bytes > KERNEL_SETUP_AREA_SIZE {
        return Err("bzImage setup area exceeds its fixed measured reservation".into());
    }

    let acpi = acpi::build_snp();
    let zero = boot::zero_page_snp(&kernel_file, info, initramfs.len(), acpi.rsdp)?;
    let mut command = COMMAND_LINE.as_bytes().to_vec();
    command.push(0);
    command.resize(PAGE as usize, 0);
    let tables = encrypted_page_tables();
    let mut stacks = vec![0u8; 0x10_000];
    // Linux 64-bit boot protocol selectors: 0x10 code, 0x18 data.
    put64(&mut stacks, 8, 0x00cf_9b00_0000_ffff);
    put64(&mut stacks, 16, 0x00af_9b00_0000_ffff);
    put64(&mut stacks, 24, 0x00cf_9300_0000_ffff);
    let cc_blob = cc_blob();
    let mut shim = include_bytes!(concat!(env!("OUT_DIR"), "/snp_reset.bin")).to_vec();
    patch_u64(&mut shim, 0x1111111111111111, kernel_end)?;
    patch_u64(&mut shim, 0x4444444444444444, initramfs_end)?;
    let entry = KERNEL_BASE + info.entry_offset;
    patch_u64(&mut shim, 0x3333333333333333, entry)?;
    let mut setup = vec![0u8; KERNEL_SETUP_AREA_SIZE];
    setup[..info.setup_bytes].copy_from_slice(&kernel_file[..info.setup_bytes]);
    let shim_owned = zero.len()
        + command.len()
        + acpi.bytes.len()
        + 2 * PAGE as usize
        + cc_blob.len()
        + tables.len()
        + stacks.len()
        + shim.len();
    if shim_owned > SHIM_LIMIT {
        return Err(format!(
            "SNP shim-owned measured pages exceed 256 KiB: {shim_owned}"
        ));
    }

    let mut pages = Vec::new();
    add_normal(&mut pages, ZERO_PAGE, &zero);
    add_normal(&mut pages, CMDLINE, &command);
    add_normal(&mut pages, ACPI_BASE, &acpi.bytes);
    add_special(
        &mut pages,
        SNP_CPUID,
        IgvmPageDataType::CPUID_DATA,
        PAGE_CPUID,
    );
    add_special(
        &mut pages,
        SNP_SECRETS,
        IgvmPageDataType::SECRETS,
        PAGE_SECRETS,
    );
    add_normal(&mut pages, SNP_CC_BLOB, &cc_blob);
    add_normal(&mut pages, PAGE_TABLES, &tables);
    add_normal(&mut pages, BSP_STACK, &stacks);
    add_normal(&mut pages, SHIM_BASE, &shim);
    add_normal(&mut pages, KERNEL_SETUP_BASE, &setup);
    add_normal(&mut pages, KERNEL_BASE, kernel);
    add_normal(&mut pages, INITRAMFS_BASE, &initramfs);
    pages.sort_by_key(|p| p.gpa);
    validate_pages(&pages)?;

    let directive_vmsa = directive_vmsa();
    validate_vmsa(&directive_vmsa)?;
    let vmsa = vmsa_page(&directive_vmsa);
    let measurement = launch_measurement(&pages, &vmsa);
    let mut directives = vec![IgvmDirectiveHeader::RequiredMemory {
        gpa: 0,
        compatibility_mask: COMPAT,
        number_of_bytes: RAM_SIZE as u32,
        vtl2_protectable: false,
    }];
    for p in &pages {
        directives.push(IgvmDirectiveHeader::PageData {
            gpa: p.gpa,
            compatibility_mask: COMPAT,
            flags: IgvmPageDataFlags::new(),
            data_type: p.kind,
            data: p.data.clone(),
        });
    }
    // KVM consumes the VMSA last and only at this architectural high GPA.
    directives.push(IgvmDirectiveHeader::SnpVpContext {
        gpa: SNP_VMSA,
        compatibility_mask: COMPAT,
        vp_index: 0,
        vmsa: directive_vmsa.clone(),
    });
    let platform = IgvmPlatformHeader::SupportedPlatform(IGVM_VHS_SUPPORTED_PLATFORM {
        compatibility_mask: COMPAT,
        highest_vtl: 0,
        platform_type: IgvmPlatformType::SEV_SNP,
        platform_version: 1,
        shared_gpa_boundary: 0,
    });
    let file = IgvmFile::new(
        IgvmRevision::V1,
        vec![platform],
        vec![IgvmInitializationHeader::GuestPolicy {
            policy: SNP_GUEST_POLICY,
            compatibility_mask: COMPAT,
        }],
        directives,
    )
    .map_err(|e| format!("construct SNP IGVM: {e}"))?;
    let mut serialized = Vec::new();
    file.serialize(&mut serialized)
        .map_err(|e| format!("serialize SNP IGVM: {e}"))?;
    validate_serialized(&serialized)?;
    fs::write(output, &serialized).map_err(io_error("write SNP IGVM"))?;

    let mut components = BTreeMap::new();
    components.insert("kernel", component(KERNEL_BASE, &kernel_file));
    components.insert("initramfs", component(INITRAMFS_BASE, &initramfs));
    components.insert("command_line", component(CMDLINE, COMMAND_LINE.as_bytes()));
    components.insert("acpi", component(ACPI_BASE, &acpi.bytes));
    components.insert("cpuid", component(SNP_CPUID, &[0u8; 4096]));
    components.insert("cc_blob", component(SNP_CC_BLOB, &cc_blob));
    components.insert("vmsa", component(SNP_VMSA, &vmsa));
    components.insert("shim", component(SHIM_BASE, &shim));
    let manifest = Manifest {
        format_version: 1,
        platform: "sev-snp",
        memory_bytes: RAM_SIZE,
        topology: Topology {
            sockets: 1,
            cores: SNP_VCPU_COUNT as u8,
            threads_per_core: 1,
            vcpus: SNP_VCPU_COUNT,
        },
        command_line: COMMAND_LINE,
        kernel_entry: format!("0x{entry:08x}"),
        expected_snp_measurement: hex::encode(measurement),
        guest_policy: format!("0x{SNP_GUEST_POLICY:016x}"),
        cpu: CpuProfile {
            family: SNP_CPU_FAMILY,
            model: SNP_CPU_MODEL,
            stepping: SNP_CPU_STEPPING,
            c_bit_position: SNP_CBIT,
            physical_address_bits: SNP_PHYS_BITS,
            sev_feature_mask: format!("0x{SNP_SEV_FEATURES:016x}"),
        },
        shim_owned_bytes: shim_owned,
        components,
    };
    let mut json = serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?;
    json.push(b'\n');
    fs::write(format!("{}.manifest.json", output.display()), json)
        .map_err(io_error("write SNP manifest"))
}

fn directive_vmsa() -> Box<SevVmsa> {
    let mut v = SevVmsa::new_box_zeroed();
    let data = SevSelector {
        selector: 0x18,
        attrib: 0x0c93,
        limit: 0xffff_ffff,
        base: 0,
    };
    v.es = data;
    v.ss = data;
    v.ds = data;
    v.fs = data;
    v.gs = data;
    v.cs = SevSelector {
        selector: 0x08,
        attrib: 0x0c9b,
        limit: 0xffff_ffff,
        base: 0,
    };
    v.gdtr = SevSelector {
        selector: 0,
        attrib: 0,
        limit: 31,
        base: BSP_STACK,
    };
    v.idtr = SevSelector {
        selector: 0,
        attrib: 0,
        limit: 0,
        base: 0,
    };
    v.ldtr = v.idtr;
    v.tr = v.idtr;
    // KVM-compatible SNP reset state.  The reset shim enables paging and
    // long mode itself before using the encrypted identity map.
    v.efer = 0x1000;
    v.cr4 = 0x60;
    v.cr3 = 0;
    v.cr0 = 0x31;
    v.dr6 = 0xffff_0ff0;
    v.dr7 = 0x400;
    v.rflags = 2;
    v.rip = SHIM_BASE;
    v.rsp = BSP_STACK + 0x4000;
    v.rsi = ZERO_PAGE;
    v.pat = 0x0007_0406_0007_0406;
    v.xcr0 = 1;
    // QEMU/KVM's architectural reset defaults.  These must be explicit so
    // the serialized VMSA and the VMSA measured by KVM are identical.
    v.mxcsr = 0x1f80;
    v.x87_fcw = 0x037f;
    v.sev_features = SevFeatures::new().with_snp(true);
    v
}

fn validate_vmsa(v: &SevVmsa) -> Result<(), String> {
    if v.cr0 != 0x31
        || v.cr3 != 0
        || v.rip != SHIM_BASE
        || v.rsi != ZERO_PAGE
        || v.vmpl != 0
        || v.sev_features.into_bits() != SNP_SEV_FEATURES
    {
        return Err("pinned Turin VMSA invariant failed".into());
    }
    Ok(())
}

fn vmsa_page(vmsa: &SevVmsa) -> Vec<u8> {
    let mut page = vec![0u8; PAGE as usize];
    page[..vmsa.as_bytes().len()].copy_from_slice(vmsa.as_bytes());
    page
}

fn encrypted_page_tables() -> Vec<u8> {
    let c = 1u64 << SNP_CBIT;
    let mut v = vec![0u8; 6 * PAGE as usize];
    put64(&mut v, 0, (PAGE_TABLES + PAGE) | c | 3);
    for pdpt in 0..4 {
        put64(
            &mut v,
            PAGE as usize + pdpt * 8,
            (PAGE_TABLES + (2 + pdpt as u64) * PAGE) | c | 3,
        );
        for pde in 0..512 {
            let index = pdpt * 512 + pde;
            put64(
                &mut v,
                (2 + pdpt) * PAGE as usize + pde * 8,
                (index as u64 * 0x20_0000) | c | 0x83,
            );
        }
    }
    v
}

// A SETUP_CC_BLOB record for boot_params.hdr.setup_data, followed in the same
// measured page by the cc_blob_sev_info it refers to.  Linux reads the u32
// directly after the setup_data header as the blob's address, so the blob
// itself must not sit there.
const CC_BLOB_INFO: usize = 32;
fn cc_blob() -> Vec<u8> {
    let mut v = vec![0u8; PAGE as usize];
    put32(&mut v, 8, 7); // SETUP_CC_BLOB
    put32(&mut v, 12, 4);
    put32(&mut v, 16, (SNP_CC_BLOB + CC_BLOB_INFO as u64) as u32);
    v[CC_BLOB_INFO..CC_BLOB_INFO + 4].copy_from_slice(b"AMDE");
    v[CC_BLOB_INFO + 4..CC_BLOB_INFO + 6].copy_from_slice(&1u16.to_le_bytes());
    put64(&mut v, CC_BLOB_INFO + 8, SNP_SECRETS);
    put32(&mut v, CC_BLOB_INFO + 16, PAGE as u32);
    put64(&mut v, CC_BLOB_INFO + 24, SNP_CPUID);
    put32(&mut v, CC_BLOB_INFO + 32, PAGE as u32);
    v
}

fn launch_measurement(pages: &[LaunchPage], vmsa: &[u8]) -> [u8; 48] {
    let mut digest = [0u8; 48];
    for p in pages {
        digest = extend(digest, p.gpa, p.measure_kind, &p.data);
    }
    extend(digest, SNP_VMSA, PAGE_VMSA, vmsa)
}

fn extend(old: [u8; 48], gpa: u64, kind: u8, contents: &[u8]) -> [u8; 48] {
    let content: [u8; 48] = Sha384::digest(contents).into();
    let mut info = [0u8; 112];
    info[..48].copy_from_slice(&old);
    info[48..96].copy_from_slice(&content);
    info[96..98].copy_from_slice(&PAGE_INFO_LEN.to_le_bytes());
    info[98] = kind;
    info[104..112].copy_from_slice(&gpa.to_le_bytes());
    Sha384::digest(info).into()
}
fn add_normal(out: &mut Vec<LaunchPage>, base: u64, data: &[u8]) {
    for (i, chunk) in data.chunks(PAGE as usize).enumerate() {
        let mut d = vec![0; PAGE as usize];
        d[..chunk.len()].copy_from_slice(chunk);
        out.push(LaunchPage {
            gpa: base + i as u64 * PAGE,
            data: d,
            kind: IgvmPageDataType::NORMAL,
            measure_kind: PAGE_NORMAL,
        });
    }
}
fn add_special(out: &mut Vec<LaunchPage>, gpa: u64, kind: IgvmPageDataType, measure_kind: u8) {
    out.push(LaunchPage {
        gpa,
        data: vec![0; PAGE as usize],
        kind,
        measure_kind,
    });
}
fn validate_pages(p: &[LaunchPage]) -> Result<(), String> {
    for w in p.windows(2) {
        if w[0].gpa + PAGE > w[1].gpa {
            return Err(format!("SNP launch pages overlap at {:#x}", w[1].gpa));
        }
    }
    Ok(())
}
fn validate_serialized(v: &[u8]) -> Result<(), String> {
    IgvmFile::new_from_binary(v, None).map_err(|e| format!("verify final SNP IGVM: {e}"))?;
    Ok(())
}
fn patch_u64(data: &mut [u8], marker: u64, value: u64) -> Result<(), String> {
    let n = marker.to_le_bytes();
    let h: Vec<_> = data
        .windows(8)
        .enumerate()
        .filter(|(_, w)| *w == n)
        .map(|(i, _)| i)
        .collect();
    if h.len() != 1 {
        return Err(format!(
            "SNP reset marker {marker:#x} occurs {} times",
            h.len()
        ));
    }
    data[h[0]..h[0] + 8].copy_from_slice(&value.to_le_bytes());
    Ok(())
}
fn component(address: u64, data: &[u8]) -> Component {
    Component {
        address: format!("0x{address:012x}"),
        size: data.len(),
        sha256: hex::encode(Sha256::digest(data)),
    }
}
fn put32(v: &mut [u8], at: usize, n: u32) {
    v[at..at + 4].copy_from_slice(&n.to_le_bytes())
}
fn put64(v: &mut [u8], at: usize, n: u64) {
    v[at..at + 8].copy_from_slice(&n.to_le_bytes())
}
fn io_error(action: &'static str) -> impl Fn(io::Error) -> String {
    move |e| format!("{action}: {e}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    #[test]
    fn vmsa_is_pinned_turin_state() {
        let v = directive_vmsa();
        assert_eq!(vmsa_page(&v).len(), 4096);
        assert_eq!(v.cr0, 0x31);
        assert_eq!(v.cr3, 0);
        assert_eq!(v.cr4, 0x60);
        assert_eq!(v.efer, 0x1000);
        assert_eq!(v.cs.selector, 0x08);
        assert_eq!(v.cs.attrib, 0x0c9b);
        assert_eq!(v.mxcsr, 0x1f80);
        assert_eq!(v.x87_fcw, 0x037f);
        assert_eq!(v.rsi, ZERO_PAGE);
    }
    #[test]
    fn tables_are_encrypted_identity_maps() {
        let p = encrypted_page_tables();
        let e = u64::from_le_bytes(p[8192..8200].try_into().unwrap());
        assert_eq!(e & (1u64 << SNP_CBIT), 1u64 << SNP_CBIT);
        assert_eq!(e & 0x83, 0x83);
    }
    #[test]
    fn cc_blob_points_to_special_pages() {
        let c = cc_blob();
        let info = CC_BLOB_INFO;
        assert_eq!(u32::from_le_bytes(c[8..12].try_into().unwrap()), 7);
        assert_eq!(u32::from_le_bytes(c[12..16].try_into().unwrap()), 4);
        assert_eq!(
            u32::from_le_bytes(c[16..20].try_into().unwrap()) as u64,
            SNP_CC_BLOB + info as u64
        );
        assert_eq!(&c[info..info + 4], b"AMDE");
        assert_eq!(
            u64::from_le_bytes(c[info + 8..info + 16].try_into().unwrap()),
            SNP_SECRETS
        );
        assert_eq!(
            u64::from_le_bytes(c[info + 24..info + 32].try_into().unwrap()),
            SNP_CPUID
        );
    }
    #[test]
    fn measurement_changes_with_content() {
        let mut p = Vec::new();
        add_normal(&mut p, 0x1000, &[0; 4096]);
        let v = vmsa_page(&directive_vmsa());
        let a = launch_measurement(&p, &v);
        p[0].data[0] = 1;
        assert_ne!(a, launch_measurement(&p, &v));
    }
    #[test]
    fn builds_reproducible_parseable_snp_images() {
        let dir = tempdir().unwrap();
        let kernel_path = dir.path().join("bzImage");
        let initramfs_path = dir.path().join("initrd");
        let a = dir.path().join("a.igvm");
        let b = dir.path().join("b.igvm");
        let mut kernel = vec![0u8; 8192];
        kernel[0x1f1] = 4;
        kernel[0x1fe..0x200].copy_from_slice(&0xaa55u16.to_le_bytes());
        kernel[0x202..0x206].copy_from_slice(b"HdrS");
        kernel[0x206..0x208].copy_from_slice(&0x020cu16.to_le_bytes());
        kernel[0x211] = 1;
        kernel[0x236] = 1;
        kernel[0x260..0x264].copy_from_slice(&0x20_0000u32.to_le_bytes());
        fs::write(&kernel_path, kernel).unwrap();
        fs::write(&initramfs_path, b"test initramfs").unwrap();
        build(&kernel_path, &initramfs_path, &a).unwrap();
        build(&kernel_path, &initramfs_path, &b).unwrap();
        assert_eq!(fs::read(a).unwrap(), fs::read(b).unwrap());
    }
}
