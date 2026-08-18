use crate::layout::*;

const SETUP_HEADER: usize = 0x1f1;
const E820_TABLE: usize = 0x2d0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelInfo {
    pub setup_bytes: usize,
    pub protected_size: usize,
    pub entry_offset: u64,
    pub init_size: u32,
}

pub fn parse_bzimage(image: &[u8]) -> Result<KernelInfo, String> {
    if image.len() < 0x268 {
        return Err("bzImage is shorter than its setup header".into());
    }
    if get16(image, 0x1fe) != 0xaa55 || &image[0x202..0x206] != b"HdrS" {
        return Err("not an x86 Linux bzImage".into());
    }
    if get16(image, 0x206) < 0x020c {
        return Err("Linux boot protocol 2.12 or newer is required".into());
    }
    if image[0x211] & 1 == 0 {
        return Err("kernel is not a bzImage".into());
    }
    if image[0x236] & 1 == 0 {
        return Err("kernel does not advertise a 64-bit entry".into());
    }
    let setup_sects = if image[0x1f1] == 0 {
        4
    } else {
        image[0x1f1] as usize
    };
    let setup_bytes = (setup_sects + 1) * 512;
    if setup_bytes + 0x200 >= image.len() {
        return Err("bzImage has no protected-mode payload".into());
    }
    Ok(KernelInfo {
        setup_bytes,
        protected_size: image.len() - setup_bytes,
        entry_offset: 0x200,
        init_size: get32(image, 0x260),
    })
}

pub fn zero_page(
    kernel: &[u8],
    info: KernelInfo,
    initramfs_len: usize,
    rsdp: u64,
) -> Result<Vec<u8>, String> {
    let mut page = vec![0u8; PAGE as usize];
    let header_end = 0x290.min(kernel.len()).min(page.len());
    page[SETUP_HEADER..header_end].copy_from_slice(&kernel[SETUP_HEADER..header_end]);
    page[0x210] = 0xff;
    page[0x211] |= 0x80;
    put32(&mut page, 0x218, INITRAMFS_BASE as u32);
    put32(&mut page, 0x21c, initramfs_len as u32);
    put32(&mut page, 0x228, CMDLINE as u32);
    put32(&mut page, 0x238, COMMAND_LINE.len() as u32 + 1);
    put32(&mut page, 0x214, KERNEL_BASE as u32);
    put32(&mut page, 0x260, info.init_size);
    put64(&mut page, 0x70, rsdp);

    let entries = e820();
    page[0x1e8] = entries.len() as u8;
    for (index, entry) in entries.iter().enumerate() {
        let at = E820_TABLE + index * 20;
        put64(&mut page, at, entry.0);
        put64(&mut page, at + 8, entry.1);
        put32(&mut page, at + 16, entry.2);
    }
    Ok(page)
}

pub fn e820() -> Vec<(u64, u64, u32)> {
    vec![
        (0, ZERO_PAGE, 2),
        (ZERO_PAGE, PAGE, 2),
        (ZERO_PAGE + PAGE, CMDLINE - ZERO_PAGE - PAGE, 1),
        (CMDLINE, PAGE, 2),
        (CMDLINE + PAGE, ACPI_BASE - CMDLINE - PAGE, 1),
        (ACPI_BASE, PAGE, 3),
        (ACPI_BASE + PAGE, 0x1f_000, 2),
        (0x0010_0000, 0x50_000, 2),
        (0x0015_0000, RAM_SIZE - 0x0015_0000, 1),
    ]
}

fn get16(v: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(v[at..at + 2].try_into().unwrap())
}
fn get32(v: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(v[at..at + 4].try_into().unwrap())
}
fn put32(v: &mut [u8], at: usize, n: u32) {
    v[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
fn put64(v: &mut [u8], at: usize, n: u64) {
    v[at..at + 8].copy_from_slice(&n.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn e820_is_exactly_one_gib() {
        let map = e820();
        assert_eq!(map.first().unwrap().0, 0);
        assert_eq!(map.last().unwrap().0 + map.last().unwrap().1, RAM_SIZE);
        for pair in map.windows(2) {
            assert_eq!(pair[0].0 + pair[0].1, pair[1].0);
        }
    }
    #[test]
    fn malformed_kernel_is_rejected() {
        assert!(parse_bzimage(&[0; 0x300]).is_err());
    }
}
