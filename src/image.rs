use crate::{acpi, boot, boot::put64, layout::*, mrtd};
use igvm::{
    IgvmDirectiveHeader, IgvmFile, IgvmInitializationHeader, IgvmPlatformHeader, IgvmRevision,
};
use igvm_defs::{
    IgvmPageDataFlags, IgvmPageDataType, IgvmPlatformType, IGVM_VHS_SUPPORTED_PLATFORM,
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
    command_line: &'static str,
    kernel_entry: String,
    expected_mrtd: String,
    shim_owned_bytes: usize,
    attestation: Required,
    components: BTreeMap<&'static str, Component>,
}

pub fn build(
    kernel_path: &Path,
    initramfs_path: &Path,
    output: &Path,
    config_hash: Option<&str>,
) -> Result<(), String> {
    let mrconfigid = config_field(config_hash, 48)?;
    let kernel_file = fs::read(kernel_path).map_err(io_error("read kernel"))?;
    let initramfs = fs::read(initramfs_path).map_err(io_error("read initramfs"))?;
    let info = boot::parse_bzimage(&kernel_file)?;
    let kernel = &kernel_file[info.setup_bytes..];
    let kernel_end = align_up(KERNEL_BASE + kernel.len() as u64, PAGE);
    let initramfs_end = align_up(INITRAMFS_BASE + initramfs.len() as u64, PAGE);
    if kernel_end > INITRAMFS_BASE {
        return Err("protected kernel overlaps the fixed initramfs address".into());
    }
    if KERNEL_BASE + info.init_size as u64 > INITRAMFS_BASE {
        return Err("kernel init_size overlaps the fixed initramfs address".into());
    }
    if initramfs_end > RAM_SIZE {
        return Err("initramfs exceeds the fixed 1-GiB guest memory".into());
    }

    let acpi = acpi::build();
    let zero = boot::zero_page(&kernel_file, info, initramfs.len(), acpi.rsdp)?;
    let mut command = COMMAND_LINE.as_bytes().to_vec();
    command.push(0);
    command.resize(PAGE as usize, 0);
    let page_tables = page_tables();
    let mailbox = vec![0u8; PAGE as usize];
    let stacks = boot::gdt_stack();
    let mut shim = include_bytes!(concat!(env!("OUT_DIR"), "/reset.bin")).to_vec();
    patch_u64(&mut shim, MARK_KERNEL_END, kernel_end)?;
    patch_u64(&mut shim, MARK_INITRAMFS_END, initramfs_end)?;
    let entry = KERNEL_BASE + info.entry_offset;
    patch_u64(&mut shim, MARK_ENTRY, entry)?;
    if shim.len() != SHIM_SIZE as usize {
        return Err("reset shim is not the single page the layout reserves".into());
    }
    if info.setup_bytes > KERNEL_SETUP_AREA_SIZE as usize {
        return Err("bzImage setup area exceeds its fixed measured reservation".into());
    }
    let mut kernel_setup = vec![0u8; KERNEL_SETUP_AREA_SIZE as usize];
    kernel_setup[..info.setup_bytes].copy_from_slice(&kernel_file[..info.setup_bytes]);

    let shim_owned = zero.len()
        + command.len()
        + acpi.bytes.len()
        + mailbox.len()
        + page_tables.len()
        + stacks.len()
        + shim.len();
    if shim_owned > SHIM_LIMIT {
        return Err(format!(
            "shim-owned measured pages exceed 256 KiB: {shim_owned}"
        ));
    }

    let mut pages: Vec<(u64, Vec<u8>, bool)> = Vec::new();
    add_pages(&mut pages, ZERO_PAGE, &zero, true);
    add_pages(&mut pages, CMDLINE, &command, true);
    add_pages(&mut pages, ACPI_BASE, &acpi.bytes, true);
    add_pages(&mut pages, MAILBOX, &mailbox, true);
    add_pages(&mut pages, PAGE_TABLES, &page_tables, true);
    add_pages(&mut pages, BSP_STACK, &stacks, true);
    add_pages(&mut pages, SHIM_BASE, &shim, true);
    add_pages(&mut pages, KERNEL_SETUP_BASE, &kernel_setup, true);
    add_pages(&mut pages, KERNEL_BASE, kernel, true);
    add_pages(&mut pages, INITRAMFS_BASE, &initramfs, true);
    // Reset alias is what the NRX loader exposes at the architectural reset GPA.
    add_pages(&mut pages, RESET_ALIAS, &shim, true);
    pages.sort_by_key(|p| p.0);
    validate_non_overlapping(&pages)?;

    let expected_mrtd = mrtd::calculate(&pages);
    let mut directives = Vec::new();
    for (gpa, data, measured) in &pages {
        let mut flags = IgvmPageDataFlags::new();
        flags.set_unmeasured(!measured);
        directives.push(IgvmDirectiveHeader::PageData {
            gpa: *gpa,
            compatibility_mask: 1,
            flags,
            data_type: IgvmPageDataType::NORMAL,
            data: data.clone(),
        });
    }
    directives.push(IgvmDirectiveHeader::RequiredMemory {
        gpa: 0,
        compatibility_mask: 1,
        number_of_bytes: RAM_SIZE as u32,
        vtl2_protectable: false,
    });
    let platform = IgvmPlatformHeader::SupportedPlatform(IGVM_VHS_SUPPORTED_PLATFORM {
        compatibility_mask: 1,
        highest_vtl: 0,
        platform_type: IgvmPlatformType::TDX,
        platform_version: 1,
        shared_gpa_boundary: 1u64 << 47,
    });
    let file = IgvmFile::new(
        IgvmRevision::V1,
        vec![platform],
        vec![IgvmInitializationHeader::GuestPolicy {
            policy: 0,
            compatibility_mask: 1,
        }],
        directives,
    )
    .map_err(|e| format!("construct IGVM: {e}"))?;
    let mut serialized = Vec::new();
    file.serialize(&mut serialized)
        .map_err(|e| format!("serialize IGVM: {e}"))?;
    fs::write(output, &serialized).map_err(io_error("write IGVM"))?;

    // Parse our public output before committing its manifest.
    IgvmFile::new_from_binary(&serialized, None).map_err(|e| format!("verify final IGVM: {e}"))?;
    let mut components = BTreeMap::new();
    components.insert("kernel", component(KERNEL_BASE, &kernel_file));
    components.insert("initramfs", component(INITRAMFS_BASE, &initramfs));
    components.insert("command_line", component(CMDLINE, COMMAND_LINE.as_bytes()));
    components.insert("acpi", component(ACPI_BASE, &acpi.bytes));
    components.insert("shim", component(SHIM_BASE, &shim));
    let manifest = Manifest {
        format_version: 1,
        memory_bytes: RAM_SIZE,
        vcpus: VCPU_COUNT,
        command_line: COMMAND_LINE,
        kernel_entry: format!("0x{entry:08x}"),
        expected_mrtd: hex::encode(expected_mrtd),
        shim_owned_bytes: shim_owned,
        attestation: tdx_attestation(&expected_mrtd, mrconfigid),
        components,
    };
    let manifest_path = format!("{}.manifest.json", output.display());
    let mut json = serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?;
    json.push(b'\n');
    fs::write(manifest_path, json).map_err(io_error("write manifest"))?;
    Ok(())
}

// MRTD covers only the pages this file provides.  ATTRIBUTES, XFAM, the vCPU
// count and the owner registers are TD configuration the host picks at
// TDH.MNG.INIT, so a TD launched with ATTRIBUTES.DEBUG set -- which lets the
// host read guest memory and registers -- produces a byte-identical MRTD.
// Checking the digest alone is therefore not a check at all.
fn tdx_attestation(mrtd: &[u8; 48], mrconfigid: String) -> Required {
    let mut r = Required::new();
    r.insert("mrtd", Some(hex::encode(mrtd)));
    // ATTRIBUTES.DEBUG (bit 0) must be clear and SEPT_VE_DISABLE (bit 28) set;
    // no other bit is constrained, so the check is a masked compare.
    r.insert(
        "attributes_mask",
        Some(format!("0x{:016x}", 0x1000_0001u64)),
    );
    r.insert("attributes", Some(format!("0x{:016x}", 0x1000_0000u64)));
    // The TD's extended-feature mask is a launch parameter this build cannot
    // predict; pin it to the value observed on a trusted first launch.
    r.insert("xfam", None);
    r.insert("mrconfigid", Some(mrconfigid));
    r.insert("mrowner", Some(zeros(48)));
    r.insert("mrownerconfig", Some(zeros(48)));
    // This image performs no runtime measurement: it extends no RTMR and
    // provides no event log, so every register is still at its reset value
    // when Linux is entered.  Requiring zeros makes that verifiable and makes
    // any later extension -- by the guest or anything else -- visible.
    for name in ["rtmr0", "rtmr1", "rtmr2", "rtmr3"] {
        r.insert(name, Some(zeros(48)));
    }
    r
}

fn page_tables() -> Vec<u8> {
    let mut v = vec![0u8; PAGE_TABLE_SIZE as usize];
    put64(&mut v, 0, (PAGE_TABLES + PAGE) | 3);
    for pdpt in 0..4 {
        put64(
            &mut v,
            PAGE as usize + pdpt * 8,
            (PAGE_TABLES + (2 + pdpt as u64) * PAGE) | 3,
        );
        for pde in 0..512 {
            let index = pdpt * 512 + pde;
            put64(
                &mut v,
                (2 + pdpt) * PAGE as usize + pde * 8,
                (index as u64 * 0x20_0000) | 0x83,
            );
        }
    }
    v
}
fn add_pages(out: &mut Vec<(u64, Vec<u8>, bool)>, base: u64, data: &[u8], measured: bool) {
    for (i, chunk) in data.chunks(PAGE as usize).enumerate() {
        let mut page = vec![0; PAGE as usize];
        page[..chunk.len()].copy_from_slice(chunk);
        out.push((base + i as u64 * PAGE, page, measured));
    }
}
fn validate_non_overlapping(pages: &[(u64, Vec<u8>, bool)]) -> Result<(), String> {
    for pair in pages.windows(2) {
        if pair[0].0 + PAGE > pair[1].0 {
            return Err(format!("measured regions overlap at {:#x}", pair[1].0));
        }
    }
    Ok(())
}
pub fn patch_u64(data: &mut [u8], marker: u64, value: u64) -> Result<(), String> {
    let needle = marker.to_le_bytes();
    let hits: Vec<_> = data
        .windows(8)
        .enumerate()
        .filter(|(_, w)| *w == needle)
        .map(|(i, _)| i)
        .collect();
    if hits.len() != 1 {
        return Err(format!(
            "reset component marker {marker:#x} occurs {} times",
            hits.len()
        ));
    }
    data[hits[0]..hits[0] + 8].copy_from_slice(&value.to_le_bytes());
    Ok(())
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
mod tests {
    use super::*;
    use tempfile::tempdir;
    #[test]
    fn page_tables_identity_map_one_gib() {
        let p = page_tables();
        assert_eq!(
            u64::from_le_bytes(p[2 * 4096..2 * 4096 + 8].try_into().unwrap()),
            0x83
        );
        assert_eq!(
            u64::from_le_bytes(p[5 * 4096 + 511 * 8..6 * 4096].try_into().unwrap()) & !0xfff,
            0xffe0_0000
        );
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
    fn builds_byte_identical_parseable_images() {
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
        build(&kernel_path, &initramfs_path, &a, None).unwrap();
        build(&kernel_path, &initramfs_path, &b, None).unwrap();
        let one = fs::read(a).unwrap();
        let two = fs::read(b).unwrap();
        assert_eq!(one, two);
        IgvmFile::new_from_binary(&one, None).unwrap();
    }
}
