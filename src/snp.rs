use crate::{
    acpi,
    boot::{self, put32, put64},
    image::{component, config_field, io_error, patch_u64, zeros, Component, Required},
    layout::*,
};
use igvm::snp_defs::{SevFeatures, SevSelector, SevVmsa};
use igvm::{
    IgvmDirectiveHeader, IgvmFile, IgvmInitializationHeader, IgvmPlatformHeader, IgvmRevision,
};
use igvm_defs::{
    IgvmPageDataFlags, IgvmPageDataType, IgvmPlatformType, IGVM_VHS_SNP_ID_BLOCK_PUBLIC_KEY,
    IGVM_VHS_SNP_ID_BLOCK_SIGNATURE, IGVM_VHS_SUPPORTED_PLATFORM,
};
use p384::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    pkcs8::DecodePrivateKey,
};
use serde::Serialize;
use sha2::{Digest, Sha384};
use std::{collections::BTreeMap, fs, path::Path};
use zerocopy::{AsBytes, FromZeroes};

const COMPAT: u32 = 1;
const PAGE_INFO_LEN: u16 = 112;
const PAGE_NORMAL: u8 = 1;
const PAGE_VMSA: u8 = 2;
const PAGE_SECRETS: u8 = 5;
const PAGE_CPUID: u8 = 6;
// "SEV Secure Nested Paging Firmware ABI" 8.18: ECDSA P-384 over SHA-384.
const ID_KEY_ECDSA_P384: u32 = 1;
const ID_CURVE_P384: u32 = 2;
// The version QEMU stamps into the block it hands the firmware, so the
// signature has to be computed over the same value.
const ID_BLOCK_VERSION: u32 = 1;

#[derive(Clone)]
struct LaunchPage {
    gpa: u64,
    data: Vec<u8>,
    kind: IgvmPageDataType,
    measure_kind: u8,
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
    c_bit_position: u8,
    sev_features: String,
    shim_owned_bytes: usize,
    attestation: Required,
    components: BTreeMap<&'static str, Component>,
}

pub fn build(
    kernel_path: &Path,
    initramfs_path: &Path,
    output: &Path,
    config_hash: Option<&str>,
    id_key: Option<&Path>,
    guest_svn: u32,
) -> Result<(), String> {
    let host_data = config_field(config_hash, 32)?;
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
    if info.setup_bytes > KERNEL_SETUP_AREA_SIZE as usize {
        return Err("bzImage setup area exceeds its fixed measured reservation".into());
    }

    let acpi = acpi::build_snp();
    let zero = boot::zero_page_snp(&kernel_file, info, initramfs.len(), acpi.rsdp)?;
    let mut command = COMMAND_LINE.as_bytes().to_vec();
    command.push(0);
    command.resize(PAGE as usize, 0);
    let tables = encrypted_page_tables();
    let stacks = boot::gdt_stack();
    let cc_blob = cc_blob();
    let mut shim = include_bytes!(concat!(env!("OUT_DIR"), "/snp_reset.bin")).to_vec();
    patch_u64(&mut shim, MARK_KERNEL_END, kernel_end)?;
    patch_u64(&mut shim, MARK_INITRAMFS_END, initramfs_end)?;
    let entry = KERNEL_BASE + info.entry_offset;
    patch_u64(&mut shim, MARK_ENTRY, entry)?;
    if shim.len() != SHIM_SIZE as usize {
        return Err("reset shim is not the single page the layout reserves".into());
    }
    let mut setup = vec![0u8; KERNEL_SETUP_AREA_SIZE as usize];
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
    let signed = match id_key {
        None => None,
        Some(path) => {
            let pem = fs::read_to_string(path).map_err(io_error("read ID key"))?;
            let block = id_block(&pem, &measurement, guest_svn)?;
            directives.push(block.header);
            Some(block.key_digest)
        }
    };
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
        c_bit_position: SNP_CBIT,
        sev_features: format!("0x{SNP_SEV_FEATURES:016x}"),
        shim_owned_bytes: shim_owned,
        attestation: snp_attestation(&measurement, host_data, guest_svn, signed),
        components,
    };
    let mut json = serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?;
    json.push(b'\n');
    fs::write(format!("{}.manifest.json", output.display()), json)
        .map_err(io_error("write SNP manifest"))
}

// A signed ID block turns the launch digest from something a verifier checks
// after the fact into something the SEV firmware enforces: SNP_LAUNCH_FINISH
// fails unless the digest it computed and the policy the host asked for match
// this block, and the block is signed, so neither can be swapped.  It also
// carries GUEST_SVN, which is the only version this image has and therefore
// the only thing a verifier can require a floor on; FAMILY_ID and IMAGE_ID
// stay zero but are signed as such, so a host cannot invent values for them.
struct IdBlock {
    header: IgvmDirectiveHeader,
    key_digest: [u8; 48],
}

fn id_block(pem: &str, ld: &[u8; 48], guest_svn: u32) -> Result<IdBlock, String> {
    let key = SigningKey::from_pkcs8_pem(pem).map_err(|e| format!("parse ID key: {e}"))?;
    // The 0x60-byte block the firmware verifies.  QEMU rebuilds it from the
    // IGVM header and substitutes the file's guest policy, so the signature
    // has to cover exactly these bytes.
    let mut block = [0u8; 0x60];
    block[..48].copy_from_slice(ld);
    block[0x50..0x54].copy_from_slice(&ID_BLOCK_VERSION.to_le_bytes());
    block[0x54..0x58].copy_from_slice(&guest_svn.to_le_bytes());
    block[0x58..0x60].copy_from_slice(&SNP_GUEST_POLICY.to_le_bytes());
    let signature: Signature = key.sign(&block);
    let point = key.verifying_key().to_encoded_point(false);
    let public = IGVM_VHS_SNP_ID_BLOCK_PUBLIC_KEY {
        curve: ID_CURVE_P384,
        reserved: 0,
        qx: le72(point.x().ok_or("ID key is not an affine point")?),
        qy: le72(point.y().ok_or("ID key is not an affine point")?),
    };
    Ok(IdBlock {
        key_digest: key_digest(&public),
        header: IgvmDirectiveHeader::SnpIdBlock {
            compatibility_mask: COMPAT,
            author_key_enabled: 0,
            reserved: [0; 3],
            ld: *ld,
            family_id: [0; 16],
            image_id: [0; 16],
            version: ID_BLOCK_VERSION,
            guest_svn,
            id_key_algorithm: ID_KEY_ECDSA_P384,
            author_key_algorithm: 0,
            id_key_signature: Box::new(IGVM_VHS_SNP_ID_BLOCK_SIGNATURE {
                r_comp: le72(&signature.r().to_bytes()),
                s_comp: le72(&signature.s().to_bytes()),
            }),
            id_public_key: Box::new(public),
            author_key_signature: Box::new(IGVM_VHS_SNP_ID_BLOCK_SIGNATURE::new_zeroed()),
            author_public_key: Box::new(IGVM_VHS_SNP_ID_BLOCK_PUBLIC_KEY::new_zeroed()),
        },
    })
}

// The firmware stores every ECDSA component little-endian in a 72-byte field.
fn le72(big_endian: &[u8]) -> [u8; 72] {
    let mut v = [0u8; 72];
    for (at, byte) in big_endian.iter().rev().enumerate() {
        v[at] = *byte;
    }
    v
}

// ID_KEY_DIGEST in the attestation report is SHA-384 over the firmware's
// 0x404-byte public key structure, not over the IGVM one, so a verifier can
// only match it if the packager hashes the same layout.
fn key_digest(public: &IGVM_VHS_SNP_ID_BLOCK_PUBLIC_KEY) -> [u8; 48] {
    let mut sev_key = [0u8; 0x404];
    sev_key[..4].copy_from_slice(&public.curve.to_le_bytes());
    sev_key[4..76].copy_from_slice(&public.qx);
    sev_key[76..148].copy_from_slice(&public.qy);
    Sha384::digest(sev_key).into()
}

// The launch digest covers the pages and the VMSA and nothing else.  The guest
// policy, the owner-supplied HOST_DATA, the launch IDs and the signer identity
// are all separate report fields, so they have to be required separately.
fn snp_attestation(
    measurement: &[u8; 48],
    host_data: String,
    guest_svn: u32,
    signed: Option<[u8; 48]>,
) -> Required {
    let mut r = Required::new();
    r.insert("measurement", Some(hex::encode(measurement)));
    r.insert("policy", Some(format!("0x{SNP_GUEST_POLICY:016x}")));
    r.insert("vmpl", Some("0".into()));
    r.insert("family_id", Some(zeros(16)));
    r.insert("image_id", Some(zeros(16)));
    r.insert("guest_svn", Some(guest_svn.to_string()));
    r.insert("host_data", Some(host_data));
    // The guest policy cannot forbid SMT, so the report has to: PLATFORM_INFO
    // records whether the host had SMT enabled at launch.
    r.insert("platform_info_smt_en", Some("false".into()));
    // Without an ID block the firmware never compares its digest to anything,
    // and both signer digests stay zero -- which is itself the check that says
    // "this launch was unenforced".
    r.insert("id_key_digest", Some(signed.map_or(zeros(48), hex::encode)));
    r.insert("author_key_digest", Some(zeros(48)));
    // The platform TCB is a property of the host, not of this image; pin it to
    // the floor the deployer is willing to accept.
    r.insert("reported_tcb", None);
    r
}

fn directive_vmsa() -> Box<SevVmsa> {
    let mut v = SevVmsa::new_box_zeroed();
    let data = SevSelector {
        selector: BOOT_DS as u16,
        attrib: 0x0c93,
        limit: 0xffff_ffff,
        base: 0,
    };
    v.es = data;
    v.ss = data;
    v.ds = data;
    v.fs = data;
    v.gs = data;
    // The VMSA enters 32-bit protected mode; the shim far-returns to BOOT_CS.
    v.cs = SevSelector {
        selector: BOOT_CS32 as u16,
        attrib: 0x0c9b,
        limit: 0xffff_ffff,
        base: 0,
    };
    v.gdtr = SevSelector {
        selector: 0,
        attrib: 0,
        limit: GDT_LIMIT as u32,
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
    v.rsp = BSP_STACK_TOP;
    v.rsi = ZERO_PAGE;
    v.pat = 0x0007_0406_0007_0406;
    v.xcr0 = 1;
    // Architectural x86 reset values.  QEMU applies the GPRs, segments and
    // control registers above from this file but not these, so they have to
    // match the VMM's reset state for the measured VMSA to be identical.
    // RDX is left zero deliberately: QEMU applies it from here too, so the
    // CPU's family/model/stepping signature never reaches the measurement.
    v.mxcsr = 0x1f80;
    v.x87_fcw = 0x037f;
    v.sev_features = SevFeatures::new().with_snp(true);
    v
}

fn validate_vmsa(v: &SevVmsa) -> Result<(), String> {
    if v.cr0 != 0x31
        || v.cr3 != 0
        || v.rdx != 0
        || v.rip != SHIM_BASE
        || v.rsi != ZERO_PAGE
        || v.vmpl != 0
        || v.sev_features.into_bits() != SNP_SEV_FEATURES
    {
        return Err("SNP VMSA invariant failed".into());
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
    let mut v = vec![0u8; PAGE_TABLE_SIZE as usize];
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

// SNP_LAUNCH_UPDATE hashes page contents into PAGE_INFO only for NORMAL and
// VMSA pages.  Every other type -- including the CPUID and Secrets pages,
// whose contents the loader and firmware supply -- is measured by type and
// address alone, with a zeroed CONTENTS field.
fn extend(old: [u8; 48], gpa: u64, kind: u8, page: &[u8]) -> [u8; 48] {
    let content: [u8; 48] = match kind {
        PAGE_NORMAL | PAGE_VMSA => Sha384::digest(page).into(),
        _ => [0u8; 48],
    };
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    #[test]
    fn vmsa_is_the_pinned_reset_state() {
        let v = directive_vmsa();
        assert_eq!(vmsa_page(&v).len(), 4096);
        assert_eq!(v.cr0, 0x31);
        assert_eq!(v.cr3, 0);
        assert_eq!(v.cr4, 0x60);
        assert_eq!(v.efer, 0x1000);
        assert_eq!(v.rdx, 0);
        assert_eq!(v.cs.selector, BOOT_CS32 as u16);
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
    fn measurement_matches_the_reference_implementation() {
        // Known answer from sev-snp-measure's GCTX over the same page set:
        // one normal page, a Secrets page, a CPUID page and the VMSA.
        let mut p = Vec::new();
        let mut data = vec![0u8; PAGE as usize];
        data[0] = 1;
        add_normal(&mut p, 0x1000, &data);
        add_special(&mut p, 0x2000, IgvmPageDataType::SECRETS, PAGE_SECRETS);
        add_special(&mut p, 0x3000, IgvmPageDataType::CPUID_DATA, PAGE_CPUID);
        assert_eq!(
            hex::encode(launch_measurement(&p, &vec![0u8; PAGE as usize])),
            "64fba8d7f08e6c2b07f7a3fd610e2965a1683a3ca18ad66a73acc84e5cc2ebfb\
1721d1bcfebf8752aeac62b6fd5f8ace"
        );
    }
    #[test]
    fn special_pages_are_measured_without_their_contents() {
        let mut a = Vec::new();
        add_special(&mut a, SNP_SECRETS, IgvmPageDataType::SECRETS, PAGE_SECRETS);
        let mut b = a.clone();
        b[0].data[0] = 1;
        let v = vmsa_page(&directive_vmsa());
        assert_eq!(launch_measurement(&a, &v), launch_measurement(&b, &v));
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
    const TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDD0QDbBc0T8m1BaeqCi\nGs30ddBtXsErRa5QX3eaeSYi11MZKeppqiBMm/fTnGxPP5KhZANiAASckeCIZYA6\nb96kAUX3v1H2Sk2iG+J23noMD403RN6PcnjsZWTIFa28YQYERl1BHB11uqFBzFG/\nOxpazENHn+p1pqw7y1frLk6qB4Gyi48pTb49fUOfkfqAPXA1xjy1tUg=\n-----END PRIVATE KEY-----\n";

    // The firmware verifies this signature over exactly these bytes before it
    // will enforce anything, so the test rebuilds the block the way the
    // firmware sees it -- including the public key round-tripped through the
    // little-endian 72-byte fields -- and checks it against the signature.
    #[test]
    fn id_block_signature_covers_the_digest_and_the_policy() {
        use p384::ecdsa::{signature::Verifier, VerifyingKey};
        let ld = [0x5au8; 48];
        let block = id_block(TEST_KEY, &ld, 7).unwrap();
        let IgvmDirectiveHeader::SnpIdBlock {
            ld: written,
            guest_svn,
            id_key_algorithm,
            id_key_signature,
            id_public_key,
            author_key_enabled,
            ..
        } = block.header
        else {
            panic!("not an ID block")
        };
        assert_eq!(written, ld);
        assert_eq!(guest_svn, 7);
        assert_eq!(id_key_algorithm, ID_KEY_ECDSA_P384);
        assert_eq!(author_key_enabled, 0);
        assert_eq!(id_public_key.curve, ID_CURVE_P384);

        let mut signed = [0u8; 0x60];
        signed[..48].copy_from_slice(&ld);
        signed[0x50..0x54].copy_from_slice(&ID_BLOCK_VERSION.to_le_bytes());
        signed[0x54..0x58].copy_from_slice(&7u32.to_le_bytes());
        signed[0x58..0x60].copy_from_slice(&SNP_GUEST_POLICY.to_le_bytes());
        let point = p384::EncodedPoint::from_affine_coordinates(
            &be48(&id_public_key.qx).into(),
            &be48(&id_public_key.qy).into(),
            false,
        );
        let verifying = VerifyingKey::from_encoded_point(&point).unwrap();
        let signature = Signature::from_scalars(
            be48(&id_key_signature.r_comp),
            be48(&id_key_signature.s_comp),
        )
        .unwrap();
        verifying.verify(&signed, &signature).unwrap();
        // A block signed for a different policy must not verify against ours.
        signed[0x58] ^= 1;
        assert!(verifying.verify(&signed, &signature).is_err());
    }

    fn be48(le: &[u8; 72]) -> [u8; 48] {
        let mut v = [0u8; 48];
        for (at, byte) in le[..48].iter().rev().enumerate() {
            v[at] = *byte;
        }
        v
    }

    // RFC 6979 signing keeps a signed image byte-identical across builds.
    #[test]
    fn signing_is_deterministic() {
        let a = id_block(TEST_KEY, &[1; 48], 0).unwrap();
        let b = id_block(TEST_KEY, &[1; 48], 0).unwrap();
        assert_eq!(a.key_digest, b.key_digest);
        assert_eq!(format!("{:?}", a.header), format!("{:?}", b.header));
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
        build(&kernel_path, &initramfs_path, &a, None, None, 0).unwrap();
        build(&kernel_path, &initramfs_path, &b, None, None, 0).unwrap();
        assert_eq!(fs::read(a).unwrap(), fs::read(b).unwrap());
    }
}
