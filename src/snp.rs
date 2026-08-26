use crate::{
    acpi,
    boot::{self, put32, put64, Fill, Placed, ACPI, RAM, RESERVED},
    image::{
        component, components, config_field, identity_map, io_error, mmio_holes, page_directive,
        prepare, shim, shim_owned, write_manifest, zeros, Component, Required,
    },
    layout::*,
};
use igvm::snp_defs::{SevFeatures, SevSelector, SevVmsa};
use igvm::{
    IgvmDirectiveHeader, IgvmFile, IgvmInitializationHeader, IgvmPlatformHeader, IgvmRevision,
};
use igvm_defs::{
    IgvmPageDataType, IgvmPlatformType, IGVM_VHS_SNP_ID_BLOCK_PUBLIC_KEY,
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
// IGVM states a required-memory span in 32 bits, so a larger guest takes several.
const REQUIRED_MEMORY_MAX: u64 = 0xffff_f000;

// The PAGE_INFO structure SNP_LAUNCH_UPDATE digests, one per launch page.
const PAGE_INFO_LEN: u16 = 112;
const PAGE_INFO_CONTENTS: usize = 48;
const PAGE_INFO_LENGTH: usize = 96;
const PAGE_INFO_TYPE: usize = 98;
const PAGE_INFO_GPA: usize = 104;
const PAGE_NORMAL: u8 = 1;
const PAGE_VMSA: u8 = 2;
const PAGE_SECRETS: u8 = 5;
const PAGE_CPUID: u8 = 6;

// "SEV Secure Nested Paging Firmware ABI" 8.18: ECDSA P-384 over SHA-384.
const ID_KEY_ECDSA_P384: u32 = 1;
const ID_CURVE_P384: u32 = 2;
// QEMU stamps this version into the block, so the signature covers the same value.
const ID_BLOCK_VERSION: u32 = 1;
// The block the firmware verifies, and the fields the signature covers.
const ID_BLOCK_LEN: usize = 0x60;
const ID_BLOCK_LD: usize = 0;
const ID_BLOCK_VERSION_AT: usize = 0x50;
const ID_BLOCK_SVN: usize = 0x54;
const ID_BLOCK_POLICY: usize = 0x58;
// The firmware's own public key structure, which ID_KEY_DIGEST is taken over.
const SEV_KEY_LEN: usize = 0x404;
const SEV_KEY_CURVE: usize = 0;
const SEV_KEY_QX: usize = 4;
const SEV_KEY_QY: usize = 76;
const ECDSA_COMPONENT_LEN: usize = 72;

// The VMSA reset state, pinned here because the launch digest covers all of it.
const VMSA_CR0: u64 = 0x31;
const VMSA_CR4: u64 = 0x60;
const VMSA_EFER: u64 = 0x1000;
const VMSA_RFLAGS: u64 = 2;
const VMSA_XCR0: u64 = 1;
const VMSA_PAT: u64 = 0x0007_0406_0007_0406;
const VMSA_DR6: u64 = 0xffff_0ff0;
const VMSA_DR7: u64 = 0x400;
const VMSA_MXCSR: u32 = 0x1f80;
const VMSA_X87_FCW: u16 = 0x037f;
const SEG_CODE32_ATTR: u16 = 0x0c9b;
const SEG_DATA_ATTR: u16 = 0x0c93;
const SEG_LIMIT: u32 = 0xffff_ffff;

const SNP_SHIM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/snp_reset.bin"));
const _: () = assert!(SNP_SHIM.len() == SHIM_SIZE as usize);

#[derive(Clone)]
struct LaunchPage {
    gpa: u64,
    data: Vec<u8>,
    kind: IgvmPageDataType,
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
    command_line: String,
    mmio_holes: Vec<String>,
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
    params: &Params,
    config_hash: Option<&str>,
    id_key: Option<&Path>,
    guest_svn: u32,
) -> Result<(), String> {
    let host_data = config_field(config_hash, 32)?;
    let p = prepare(kernel_path, initramfs_path, params)?;
    let acpi = acpi::build(SNP_VCPU_COUNT, false);

    // The one authoritative map, as on TDX: E820, the imported pages and the accept list.
    let mut placed = vec![
        // Blank: the zero page describes the map it belongs to, so its contents come last.
        Placed::measured(ZERO_PAGE, "", RESERVED, vec![0u8; PAGE as usize]),
        Placed::measured(CMDLINE, "command_line", RESERVED, p.command.clone()),
        Placed::measured(ACPI_BASE, "acpi", ACPI, acpi.clone()),
        Placed::host(SNP_CPUID),
        Placed::host(SNP_SECRETS),
        Placed::measured(SNP_CC_BLOB, "cc_blob", RAM, cc_blob()),
        Placed::measured(PAGE_TABLES, "", RESERVED, identity_map(params.cbit as u64)),
        Placed::measured(BSP_STACK, "", RESERVED, boot::gdt_stack()),
        Placed::measured(SHIM_BASE, "shim", RESERVED, vec![0u8; PAGE as usize]),
        Placed::measured(KERNEL_SETUP_BASE, "kernel_setup", RESERVED, p.setup.clone()),
        Placed::measured(KERNEL_BASE, "kernel", RAM, p.kernel.clone()),
        Placed::measured(INITRAMFS_BASE, "initramfs", RAM, p.initramfs.clone()),
    ];
    placed.extend(params.mmio.iter().map(|(b, n)| Placed::mmio(*b, *n)));
    boot::validate(&placed, params.memory)?;
    let e820 = boot::e820(&placed, params.memory);
    // The setup_data chain is one measured SETUP_CC_BLOB record.
    let zero = boot::zero_page(
        &p.setup,
        p.info,
        p.initramfs.len(),
        ACPI_BASE,
        &e820,
        SNP_CC_BLOB,
    )?;
    boot::fill(&mut placed, ZERO_PAGE, zero)?;
    let accept = boot::accept_ranges(&placed, params.memory);
    boot::fill(&mut placed, SHIM_BASE, shim(SNP_SHIM, p.entry, &accept)?)?;
    let owned = shim_owned(&placed)?;

    placed.sort_by_key(|p| p.base);
    let mut pages = Vec::new();
    for region in &placed {
        match &region.fill {
            // The loader and firmware fill these two, so both are measured by address alone.
            Fill::Host if region.base == SNP_CPUID => {
                add_special(&mut pages, region.base, IgvmPageDataType::CPUID_DATA)
            }
            Fill::Host => add_special(&mut pages, region.base, IgvmPageDataType::SECRETS),
            Fill::Measured(data) => add_normal(&mut pages, region.base, data),
            Fill::Mmio(_) => {}
        }
    }
    validate_pages(&pages)?;

    let directive_vmsa = directive_vmsa();
    validate_vmsa(&directive_vmsa)?;
    let vmsa = vmsa_page(&directive_vmsa);
    let measurement = launch_measurement(&pages, &vmsa);
    // The loader must find memory wherever E820 claims some and none in the apertures.
    let mut spans: Vec<(u64, u64)> = Vec::new();
    for (base, size, _) in &e820 {
        match spans.last_mut() {
            Some(last) if last.1 == *base => last.1 = base + size,
            _ => spans.push((*base, base + size)),
        }
    }
    let mut directives = Vec::new();
    for (base, end) in spans {
        let mut at = base;
        while at < end {
            let bytes = (end - at).min(REQUIRED_MEMORY_MAX);
            directives.push(IgvmDirectiveHeader::RequiredMemory {
                gpa: at,
                compatibility_mask: COMPAT,
                number_of_bytes: bytes as u32,
                vtl2_protectable: false,
            });
            at += bytes;
        }
    }
    directives.extend(
        pages
            .iter()
            .map(|p| page_directive(p.gpa, p.kind, p.data.clone())),
    );
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
    IgvmFile::new_from_binary(&serialized, None)
        .map_err(|e| format!("verify final SNP IGVM: {e}"))?;
    fs::write(output, &serialized).map_err(io_error("write SNP IGVM"))?;

    let mut components = components(&placed);
    components.insert("vmsa", component(SNP_VMSA, &vmsa));
    let manifest = Manifest {
        format_version: 1,
        platform: "sev-snp",
        memory_bytes: params.memory,
        topology: Topology {
            sockets: 1,
            cores: SNP_VCPU_COUNT as u8,
            threads_per_core: 1,
            vcpus: SNP_VCPU_COUNT,
        },
        command_line: params.cmdline.clone(),
        mmio_holes: mmio_holes(params),
        kernel_entry: format!("0x{:08x}", p.entry),
        expected_snp_measurement: hex::encode(measurement),
        guest_policy: format!("0x{SNP_GUEST_POLICY:016x}"),
        c_bit_position: params.cbit,
        sev_features: format!("0x{SNP_SEV_FEATURES:016x}"),
        shim_owned_bytes: owned,
        attestation: snp_attestation(&measurement, host_data, guest_svn, signed),
        components,
    };
    write_manifest(output, &manifest)
}

// SNP_LAUNCH_FINISH fails unless the digest and policy match this signed block.
struct IdBlock {
    header: IgvmDirectiveHeader,
    key_digest: [u8; 48],
}

fn id_block(pem: &str, ld: &[u8; 48], guest_svn: u32) -> Result<IdBlock, String> {
    let key = SigningKey::from_pkcs8_pem(pem).map_err(|e| format!("parse ID key: {e}"))?;
    // QEMU rebuilds the block from the IGVM header, so the signature covers these bytes.
    let mut block = [0u8; ID_BLOCK_LEN];
    block[ID_BLOCK_LD..ID_BLOCK_LD + 48].copy_from_slice(ld);
    block[ID_BLOCK_VERSION_AT..ID_BLOCK_VERSION_AT + 4]
        .copy_from_slice(&ID_BLOCK_VERSION.to_le_bytes());
    block[ID_BLOCK_SVN..ID_BLOCK_SVN + 4].copy_from_slice(&guest_svn.to_le_bytes());
    block[ID_BLOCK_POLICY..ID_BLOCK_POLICY + 8].copy_from_slice(&SNP_GUEST_POLICY.to_le_bytes());
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
fn le72(big_endian: &[u8]) -> [u8; ECDSA_COMPONENT_LEN] {
    let mut v = [0u8; ECDSA_COMPONENT_LEN];
    for (at, byte) in big_endian.iter().rev().enumerate() {
        v[at] = *byte;
    }
    v
}

// ID_KEY_DIGEST is SHA-384 over the firmware's key structure, not the IGVM one.
fn key_digest(public: &IGVM_VHS_SNP_ID_BLOCK_PUBLIC_KEY) -> [u8; 48] {
    let mut sev_key = [0u8; SEV_KEY_LEN];
    sev_key[SEV_KEY_CURVE..SEV_KEY_CURVE + 4].copy_from_slice(&public.curve.to_le_bytes());
    sev_key[SEV_KEY_QX..SEV_KEY_QX + ECDSA_COMPONENT_LEN].copy_from_slice(&public.qx);
    sev_key[SEV_KEY_QY..SEV_KEY_QY + ECDSA_COMPONENT_LEN].copy_from_slice(&public.qy);
    Sha384::digest(sev_key).into()
}

// The launch digest covers the pages and the VMSA; every other field is required here.
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
    // The policy cannot forbid SMT, so PLATFORM_INFO is where the report records it.
    r.insert("platform_info_smt_en", Some("false".into()));
    // RAPL turns guest power draw into a side channel, and the host decides whether it runs.
    r.insert("platform_info_rapl_dis", Some("true".into()));
    // Ciphertext hiding keeps the host out of guest ciphertext; not every platform offers it.
    r.insert("platform_info_ciphertext_hiding_en", None);
    // A masked chip key unroots the report from this CPU, leaving every other check unfounded.
    r.insert("signer_info_mask_chip_key", Some("false".into()));
    // Both digests zero says the firmware compared its launch digest against nothing.
    r.insert("id_key_digest", Some(signed.map_or(zeros(48), hex::encode)));
    r.insert("author_key_digest", Some(zeros(48)));
    // The platform TCB is the host's, so the operator pins an acceptable floor.
    r.insert("reported_tcb", None);
    r
}

fn directive_vmsa() -> Box<SevVmsa> {
    let mut v = SevVmsa::new_box_zeroed();
    let data = SevSelector {
        selector: BOOT_DS as u16,
        attrib: SEG_DATA_ATTR,
        limit: SEG_LIMIT,
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
        attrib: SEG_CODE32_ATTR,
        limit: SEG_LIMIT,
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
    // The KVM reset state the shim starts from, paging and long mode left to it.
    v.efer = VMSA_EFER;
    v.cr4 = VMSA_CR4;
    v.cr3 = 0;
    v.cr0 = VMSA_CR0;
    v.dr6 = VMSA_DR6;
    v.dr7 = VMSA_DR7;
    v.rflags = VMSA_RFLAGS;
    v.rip = SHIM_BASE;
    v.rsp = BSP_STACK_TOP;
    v.rsi = ZERO_PAGE;
    v.pat = VMSA_PAT;
    v.xcr0 = VMSA_XCR0;
    // RDX stays zero, so no CPU family, model or stepping reaches the measurement.
    v.mxcsr = VMSA_MXCSR;
    v.x87_fcw = VMSA_X87_FCW;
    v.sev_features = SevFeatures::new().with_snp(true);
    v
}

// QEMU supplies from its own reset state every field this file leaves unstated.
fn validate_vmsa(v: &SevVmsa) -> Result<(), String> {
    let data = |s: &SevSelector, sel: u64, attrib: u16| {
        s.selector == sel as u16 && s.attrib == attrib && s.limit == SEG_LIMIT && s.base == 0
    };
    let pinned = v.cr0 == VMSA_CR0
        && v.cr3 == 0
        && v.cr4 == VMSA_CR4
        && v.efer == VMSA_EFER
        && v.rdx == 0
        && v.rip == SHIM_BASE
        && v.rsp == BSP_STACK_TOP
        && v.rsi == ZERO_PAGE
        && v.rflags == VMSA_RFLAGS
        && v.vmpl == 0
        && v.dr6 == VMSA_DR6
        && v.dr7 == VMSA_DR7
        && v.pat == VMSA_PAT
        && v.xcr0 == VMSA_XCR0
        && v.mxcsr == VMSA_MXCSR
        && v.x87_fcw == VMSA_X87_FCW
        && v.gdtr.base == BSP_STACK
        && v.gdtr.limit == GDT_LIMIT as u32
        && v.idtr.limit == 0
        && data(&v.cs, BOOT_CS32, SEG_CODE32_ATTR)
        && data(&v.ds, BOOT_DS, SEG_DATA_ATTR)
        && data(&v.ss, BOOT_DS, SEG_DATA_ATTR)
        && v.sev_features.into_bits() == SNP_SEV_FEATURES;
    if !pinned {
        return Err("SNP VMSA invariant failed".into());
    }
    Ok(())
}

fn vmsa_page(vmsa: &SevVmsa) -> Vec<u8> {
    let mut page = vec![0u8; PAGE as usize];
    page[..vmsa.as_bytes().len()].copy_from_slice(vmsa.as_bytes());
    page
}

// The setup_data record Linux reads, and the cc_blob_sev_info it addresses.
const SETUP_DATA_TYPE: usize = 8;
const SETUP_DATA_LEN: usize = 12;
const SETUP_DATA_DATA: usize = 16;
const SETUP_DATA_HEADER: u32 = 16;
const SETUP_CC_BLOB: u32 = 7;
// The blob follows the record in the same page, clear of the address Linux reads.
const CC_BLOB_INFO: usize = 32;
const CC_MAGIC: &[u8; 4] = b"AMDE";
const CC_VERSION: usize = 4;
const CC_SECRETS_PHYS: usize = 8;
const CC_SECRETS_LEN: usize = 16;
const CC_CPUID_PHYS: usize = 24;
const CC_CPUID_LEN: usize = 32;

// One measured page inside the E820 RAM map, where `memremap()` reads it as plaintext.
fn cc_blob() -> Vec<u8> {
    let mut v = vec![0u8; PAGE as usize];
    put32(&mut v, SETUP_DATA_TYPE, SETUP_CC_BLOB);
    // The record claims the whole page, so Linux reserves all of it.
    put32(&mut v, SETUP_DATA_LEN, PAGE as u32 - SETUP_DATA_HEADER);
    put32(
        &mut v,
        SETUP_DATA_DATA,
        (SNP_CC_BLOB + CC_BLOB_INFO as u64) as u32,
    );
    v[CC_BLOB_INFO..CC_BLOB_INFO + 4].copy_from_slice(CC_MAGIC);
    v[CC_BLOB_INFO + CC_VERSION..CC_BLOB_INFO + CC_VERSION + 2]
        .copy_from_slice(&1u16.to_le_bytes());
    put64(&mut v, CC_BLOB_INFO + CC_SECRETS_PHYS, SNP_SECRETS);
    put32(&mut v, CC_BLOB_INFO + CC_SECRETS_LEN, PAGE as u32);
    put64(&mut v, CC_BLOB_INFO + CC_CPUID_PHYS, SNP_CPUID);
    put32(&mut v, CC_BLOB_INFO + CC_CPUID_LEN, PAGE as u32);
    v
}

fn launch_measurement(pages: &[LaunchPage], vmsa: &[u8]) -> [u8; 48] {
    let mut digest = [0u8; 48];
    for p in pages {
        digest = extend(digest, p.gpa, measure_kind(p.kind), &p.data);
    }
    extend(digest, SNP_VMSA, PAGE_VMSA, vmsa)
}

// The PAGE_INFO type SNP_LAUNCH_UPDATE stamps on each imported page.
fn measure_kind(kind: IgvmPageDataType) -> u8 {
    match kind {
        IgvmPageDataType::SECRETS => PAGE_SECRETS,
        IgvmPageDataType::CPUID_DATA => PAGE_CPUID,
        _ => PAGE_NORMAL,
    }
}

// SNP_LAUNCH_UPDATE hashes page contents only for NORMAL and VMSA pages.
fn extend(old: [u8; 48], gpa: u64, kind: u8, page: &[u8]) -> [u8; 48] {
    let content: [u8; 48] = match kind {
        PAGE_NORMAL | PAGE_VMSA => Sha384::digest(page).into(),
        _ => [0u8; 48],
    };
    let mut info = [0u8; PAGE_INFO_LEN as usize];
    info[..PAGE_INFO_CONTENTS].copy_from_slice(&old);
    info[PAGE_INFO_CONTENTS..PAGE_INFO_LENGTH].copy_from_slice(&content);
    info[PAGE_INFO_LENGTH..PAGE_INFO_TYPE].copy_from_slice(&PAGE_INFO_LEN.to_le_bytes());
    info[PAGE_INFO_TYPE] = kind;
    info[PAGE_INFO_GPA..PAGE_INFO_GPA + 8].copy_from_slice(&gpa.to_le_bytes());
    Sha384::digest(info).into()
}
fn add_normal(out: &mut Vec<LaunchPage>, base: u64, data: &[u8]) {
    out.extend(boot::pages(base, data).map(|(gpa, data)| LaunchPage {
        gpa,
        data,
        kind: IgvmPageDataType::NORMAL,
    }));
}
fn add_special(out: &mut Vec<LaunchPage>, gpa: u64, kind: IgvmPageDataType) {
    out.push(LaunchPage {
        gpa,
        data: vec![0; PAGE as usize],
        kind,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::tests::{params, test_kernel};
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
        assert!(validate_vmsa(&v).is_ok());
        // Drift in the state QEMU supplies changes the measurement, so none goes unchecked.
        for break_it in [
            (|v: &mut SevVmsa| v.dr6 = 0) as fn(&mut SevVmsa),
            |v| v.dr7 = 0,
            |v| v.pat = 0,
            |v| v.xcr0 = 0,
            |v| v.mxcsr = 0,
            |v| v.x87_fcw = 0,
            |v| v.cr4 = 0,
            |v| v.efer = 0,
            |v| v.rsp = 0,
            |v| v.rflags = 0,
            |v| v.gdtr.base = 0,
            |v| v.idtr.limit = 1,
            |v| v.cs.attrib = 0,
            |v| v.ds.selector = 0,
        ] {
            let mut v = directive_vmsa();
            break_it(&mut v);
            assert!(validate_vmsa(&v).is_err());
        }
    }
    #[test]
    fn cc_blob_points_to_special_pages() {
        let c = cc_blob();
        let info = CC_BLOB_INFO;
        assert_eq!(u32::from_le_bytes(c[8..12].try_into().unwrap()), 7);
        assert_eq!(
            u32::from_le_bytes(c[12..16].try_into().unwrap()) + SETUP_DATA_HEADER,
            PAGE as u32
        );
        // ...and the chain ends here: `pcibios_device_add()` walks it long after boot.
        assert_eq!(u64::from_le_bytes(c[0..8].try_into().unwrap()), 0);
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
        // Known answer from sev-snp-measure over one normal, Secrets, CPUID and VMSA page.
        let mut p = Vec::new();
        let mut data = vec![0u8; PAGE as usize];
        data[0] = 1;
        add_normal(&mut p, 0x1000, &data);
        add_special(&mut p, 0x2000, IgvmPageDataType::SECRETS);
        add_special(&mut p, 0x3000, IgvmPageDataType::CPUID_DATA);
        assert_eq!(
            hex::encode(launch_measurement(&p, &vec![0u8; PAGE as usize])),
            "64fba8d7f08e6c2b07f7a3fd610e2965a1683a3ca18ad66a73acc84e5cc2ebfb\
1721d1bcfebf8752aeac62b6fd5f8ace"
        );
    }
    #[test]
    fn special_pages_are_measured_without_their_contents() {
        let mut a = Vec::new();
        add_special(&mut a, SNP_SECRETS, IgvmPageDataType::SECRETS);
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

    // The firmware enforces nothing until it verifies this signature over these bytes.
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

        let mut signed = [0u8; ID_BLOCK_LEN];
        signed[ID_BLOCK_LD..ID_BLOCK_LD + 48].copy_from_slice(&ld);
        signed[ID_BLOCK_VERSION_AT..ID_BLOCK_VERSION_AT + 4]
            .copy_from_slice(&ID_BLOCK_VERSION.to_le_bytes());
        signed[ID_BLOCK_SVN..ID_BLOCK_SVN + 4].copy_from_slice(&7u32.to_le_bytes());
        signed[ID_BLOCK_POLICY..ID_BLOCK_POLICY + 8]
            .copy_from_slice(&SNP_GUEST_POLICY.to_le_bytes());
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
        signed[ID_BLOCK_POLICY] ^= 1;
        assert!(verifying.verify(&signed, &signature).is_err());
    }

    fn be48(le: &[u8; ECDSA_COMPONENT_LEN]) -> [u8; 48] {
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
        let (k, i, out) = (
            dir.path().join("bzImage"),
            dir.path().join("initrd"),
            dir.path().join("out.igvm"),
        );
        fs::write(&k, test_kernel()).unwrap();
        fs::write(&i, vec![7u8; 100_000]).unwrap();
        build(&k, &i, &out, &params(), None, None, 0).unwrap();
        let one = fs::read(&out).unwrap();
        build(&k, &i, &out, &params(), None, None, 0).unwrap();
        assert_eq!(one, fs::read(&out).unwrap());
    }

    /// The policy cannot express these and the digest does not cover them.
    #[test]
    fn snp_attestation_pins_what_the_policy_cannot() {
        let r = snp_attestation(&[0u8; 48], zeros(32), 0, None);
        assert_eq!(r["platform_info_smt_en"], Some("false".into()));
        assert_eq!(r["platform_info_rapl_dis"], Some("true".into()));
        assert_eq!(r["signer_info_mask_chip_key"], Some("false".into()));
        assert_eq!(r["platform_info_ciphertext_hiding_en"], None);
        assert_eq!(r["id_key_digest"], Some(zeros(48)));
        assert_eq!(r["author_key_digest"], Some(zeros(48)));
    }
}
