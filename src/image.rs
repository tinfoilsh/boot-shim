use crate::{acpi, boot, boot::put64, layout::*, mrtd, tdvf};
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

    // Ascending GPA order, which is the order QEMU adds the sections in and
    // therefore the order the TDX module builds MRTD in.  The reset page is
    // appended by the packer: it has to end at 4 GiB, where a TD starts.
    let sections = vec![
        tdvf::section(ZERO_PAGE, &zero),
        tdvf::section(CMDLINE, &command),
        tdvf::section(ACPI_BASE, &acpi.bytes),
        tdvf::section(MAILBOX, &vec![0u8; PAGE as usize]),
        tdvf::td_hob(TD_HOB),
        tdvf::section(PAGE_TABLES, &page_tables()),
        tdvf::section(BSP_STACK, &boot::gdt_stack()),
        tdvf::section(KERNEL_SETUP_BASE, &kernel_setup),
        tdvf::section(KERNEL_BASE, kernel),
        tdvf::section(INITRAMFS_BASE, &initramfs),
    ];
    let (file, sections) = tdvf::pack(sections, &shim)?;
    validate_non_overlapping(&sections)?;
    // Read the published file back the way QEMU will, before publishing a
    // digest that claims to describe what it loads.
    let described: Vec<_> = sections.iter().map(|s| (s.gpa, s.measured)).collect();
    if tdvf::parse(&file)? != described {
        return Err("emitted firmware does not describe the measured sections".into());
    }
    // Everything this file authors, as opposed to the kernel's own setup
    // area, payload and initramfs.
    let shim_owned: usize = sections
        .iter()
        .filter(|s| s.gpa < KERNEL_SETUP_BASE || s.gpa == RESET_ALIAS)
        .map(|s| s.data.len().max(PAGE as usize))
        .sum();
    if shim_owned > SHIM_LIMIT {
        return Err(format!(
            "shim-owned measured pages exceed 256 KiB: {shim_owned}"
        ));
    }
    let expected_mrtd = mrtd::calculate(&pages(&sections));
    fs::write(output, &file).map_err(io_error("write firmware"))?;

    let mut components = BTreeMap::new();
    components.insert("kernel", component(KERNEL_BASE, &kernel_file));
    components.insert("initramfs", component(INITRAMFS_BASE, &initramfs));
    components.insert("command_line", component(CMDLINE, COMMAND_LINE.as_bytes()));
    components.insert("acpi", component(ACPI_BASE, &acpi.bytes));
    components.insert("shim", component(RESET_ALIAS, &shim));
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

// The pages the TDX module sees, in the order it sees them: one
// TDH.MEM.PAGE.ADD per page in section order, and 16 TDH.MR.EXTEND per page
// for the sections the metadata marks measured.
fn pages(sections: &[tdvf::Section]) -> Vec<(u64, Vec<u8>, bool)> {
    let mut out = Vec::new();
    for s in sections {
        let count = s.data.len().max(PAGE as usize) / PAGE as usize;
        for i in 0..count {
            let at = i * PAGE as usize;
            let mut page = vec![0u8; PAGE as usize];
            let end = (at + PAGE as usize).min(s.data.len());
            if at < end {
                page[..end - at].copy_from_slice(&s.data[at..end]);
            }
            out.push((s.gpa + i as u64 * PAGE, page, s.measured));
        }
    }
    out
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
fn validate_non_overlapping(sections: &[tdvf::Section]) -> Result<(), String> {
    for pair in sections.windows(2) {
        let end = pair[0].gpa + align_up(pair[0].data.len().max(PAGE as usize) as u64, PAGE);
        if end > pair[1].gpa {
            return Err(format!("measured regions overlap at {:#x}", pair[1].gpa));
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
    fn page_tables_identity_map_four_gib() {
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
    fn test_kernel() -> Vec<u8> {
        let mut kernel = vec![0u8; 8192];
        kernel[0x1f1] = 4;
        kernel[0x1fe..0x200].copy_from_slice(&0xaa55u16.to_le_bytes());
        kernel[0x202..0x206].copy_from_slice(b"HdrS");
        kernel[0x206..0x208].copy_from_slice(&0x020cu16.to_le_bytes());
        kernel[0x211] = 1;
        kernel[0x236] = 1;
        kernel[0x260..0x264].copy_from_slice(&0x20_0000u32.to_le_bytes());
        kernel
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
        build(&kernel_path, &initramfs_path, &a, None).unwrap();
        build(&kernel_path, &initramfs_path, &b, None).unwrap();
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
}
