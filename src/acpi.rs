use crate::layout::{ACPI_BASE, MAILBOX, VCPU_COUNT};

pub struct AcpiTables {
    pub bytes: Vec<u8>,
    pub rsdp: u64,
}

pub fn build() -> AcpiTables {
    let rsdp = ACPI_BASE;
    let xsdt = ACPI_BASE + 0x100;
    let madt = ACPI_BASE + 0x200;
    let mut bytes = vec![0u8; 4096];

    bytes[0..8].copy_from_slice(b"RSD PTR ");
    bytes[9..15].copy_from_slice(b"TINFOI");
    bytes[15] = 2;
    bytes[20..24].copy_from_slice(&36u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&xsdt.to_le_bytes());
    bytes[8] = checksum(&bytes[0..20]);
    bytes[32] = checksum(&bytes[0..36]);

    let xo = (xsdt - ACPI_BASE) as usize;
    header(&mut bytes[xo..], b"XSDT", 44, 1);
    bytes[xo + 36..xo + 44].copy_from_slice(&madt.to_le_bytes());
    finish(&mut bytes[xo..xo + 44]);

    let mo = (madt - ACPI_BASE) as usize;
    let madt_len = 44 + VCPU_COUNT as usize * 8 + 16;
    header(&mut bytes[mo..], b"APIC", madt_len as u32, 6);
    bytes[mo + 36..mo + 40].copy_from_slice(&0xfee0_0000u32.to_le_bytes());
    bytes[mo + 40..mo + 44].copy_from_slice(&1u32.to_le_bytes());
    let mut at = mo + 44;
    for id in 0..VCPU_COUNT {
        bytes[at] = 0;
        bytes[at + 1] = 8;
        bytes[at + 2] = id as u8;
        bytes[at + 3] = id as u8;
        bytes[at + 4..at + 8].copy_from_slice(&1u32.to_le_bytes());
        at += 8;
    }
    // ACPI 6.5 MADT type 16: Multiprocessor Wakeup, version 0.
    bytes[at] = 16;
    bytes[at + 1] = 16;
    bytes[at + 2..at + 4].copy_from_slice(&0u16.to_le_bytes());
    bytes[at + 4..at + 8].copy_from_slice(&0u32.to_le_bytes());
    bytes[at + 8..at + 16].copy_from_slice(&MAILBOX.to_le_bytes());
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
        let mo = 0x200;
        let len = u32::from_le_bytes(a.bytes[mo + 4..mo + 8].try_into().unwrap()) as usize;
        assert_eq!(
            a.bytes[mo..mo + len]
                .iter()
                .fold(0u8, |x, y| x.wrapping_add(*y)),
            0
        );
        assert_eq!(a.bytes[mo + 44 + VCPU_COUNT as usize * 8], 16);
    }
}
