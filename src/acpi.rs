use crate::layout::{ACPI_BASE, MAILBOX, SNP_VCPU_COUNT, VCPU_COUNT};

pub struct AcpiTables {
    pub bytes: Vec<u8>,
    pub rsdp: u64,
}

pub fn build() -> AcpiTables {
    build_for(VCPU_COUNT, true)
}

pub fn build_snp() -> AcpiTables {
    build_for(SNP_VCPU_COUNT, false)
}

fn build_for(cpus: u32, wakeup: bool) -> AcpiTables {
    let rsdp = ACPI_BASE;
    let xsdt = ACPI_BASE + 0x100;
    let fadt = ACPI_BASE + 0x200;
    let dsdt = ACPI_BASE + 0x400;
    let madt = ACPI_BASE + 0x500;
    let mut bytes = vec![0u8; 4096];

    bytes[0..8].copy_from_slice(b"RSD PTR ");
    bytes[9..15].copy_from_slice(b"TINFOI");
    bytes[15] = 2;
    bytes[20..24].copy_from_slice(&36u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&xsdt.to_le_bytes());
    bytes[8] = checksum(&bytes[0..20]);
    bytes[32] = checksum(&bytes[0..36]);

    let xo = (xsdt - ACPI_BASE) as usize;
    header(&mut bytes[xo..], b"XSDT", 52, 1);
    bytes[xo + 36..xo + 44].copy_from_slice(&fadt.to_le_bytes());
    bytes[xo + 44..xo + 52].copy_from_slice(&madt.to_le_bytes());
    finish(&mut bytes[xo..xo + 52]);

    // ACPICA refuses to load a namespace without a DSDT and reads the DSDT
    // pointer out of the FADT, so both have to exist even though this machine
    // has no AML to run and no ACPI hardware: without them acpi_load_tables()
    // fails and Linux disables ACPI after acpi_boot_init() has already
    // programmed interrupt routing from the MADT.
    let fo = (fadt - ACPI_BASE) as usize;
    header(&mut bytes[fo..], b"FACP", 276, 6);
    bytes[fo + 40..fo + 44].copy_from_slice(&(dsdt as u32).to_le_bytes());
    bytes[fo + 112..fo + 116].copy_from_slice(&0x0010_0001u32.to_le_bytes()); // HW_REDUCED | WBINVD
    bytes[fo + 131] = 5; // FADT 6.5
    bytes[fo + 140..fo + 148].copy_from_slice(&dsdt.to_le_bytes());
    finish(&mut bytes[fo..fo + 276]);

    let do_ = (dsdt - ACPI_BASE) as usize;
    header(&mut bytes[do_..], b"DSDT", 36, 2);
    finish(&mut bytes[do_..do_ + 36]);

    let mo = (madt - ACPI_BASE) as usize;
    let madt_len = 44 + cpus as usize * 8 + if wakeup { 16 } else { 0 };
    header(&mut bytes[mo..], b"APIC", madt_len as u32, 6);
    bytes[mo + 36..mo + 40].copy_from_slice(&0xfee0_0000u32.to_le_bytes());
    bytes[mo + 40..mo + 44].copy_from_slice(&1u32.to_le_bytes());
    let mut at = mo + 44;
    for id in 0..cpus {
        bytes[at] = 0;
        bytes[at + 1] = 8;
        bytes[at + 2] = id as u8;
        bytes[at + 3] = id as u8;
        bytes[at + 4..at + 8].copy_from_slice(&1u32.to_le_bytes());
        at += 8;
    }
    // ACPI 6.5 MADT type 16: Multiprocessor Wakeup, version 0.
    if wakeup {
        bytes[at] = 16;
        bytes[at + 1] = 16;
        bytes[at + 2..at + 4].copy_from_slice(&0u16.to_le_bytes());
        bytes[at + 4..at + 8].copy_from_slice(&0u32.to_le_bytes());
        bytes[at + 8..at + 16].copy_from_slice(&MAILBOX.to_le_bytes());
    }
    finish(&mut bytes[mo..mo + madt_len]);
    AcpiTables { bytes, rsdp }
}

fn header(dst: &mut [u8], signature: &[u8; 4], len: u32, revision: u8) {
    dst[0..4].copy_from_slice(signature);
    dst[4..8].copy_from_slice(&len.to_le_bytes());
    dst[8] = revision;
    dst[10..16].copy_from_slice(b"TINFOI");
    dst[16..24].copy_from_slice(b"TDXSHIM ");
    dst[24..28].copy_from_slice(&1u32.to_le_bytes());
    dst[28..32].copy_from_slice(b"TFNL");
    dst[32..36].copy_from_slice(&1u32.to_le_bytes());
}
fn checksum(v: &[u8]) -> u8 {
    (0u8).wrapping_sub(v.iter().fold(0u8, |a, b| a.wrapping_add(*b)))
}
fn finish(v: &mut [u8]) {
    v[9] = 0;
    v[9] = checksum(v);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tables_have_valid_checksums_and_wakeup() {
        let a = build();
        assert_eq!(
            a.bytes[0..36].iter().fold(0u8, |x, y| x.wrapping_add(*y)),
            0
        );
        let mo = 0x500;
        let len = u32::from_le_bytes(a.bytes[mo + 4..mo + 8].try_into().unwrap()) as usize;
        assert_eq!(
            a.bytes[mo..mo + len]
                .iter()
                .fold(0u8, |x, y| x.wrapping_add(*y)),
            0
        );
        assert_eq!(a.bytes[mo + 44 + VCPU_COUNT as usize * 8], 16);
    }
    #[test]
    fn snp_madt_advertises_only_the_provisioned_cpu() {
        let a = build_snp();
        let len = u32::from_le_bytes(a.bytes[0x504..0x508].try_into().unwrap());
        assert_eq!(len, 44 + SNP_VCPU_COUNT * 8);
        // Without a wakeup structure Linux has no way to start an AP, so any
        // extra Local APIC entry would promise a CPU that can never run.
        assert_eq!(SNP_VCPU_COUNT, 1);
    }
}
