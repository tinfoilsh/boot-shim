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

pub fn zero_page_snp(
    kernel: &[u8],
    info: KernelInfo,
    initramfs_len: usize,
    rsdp: u64,
) -> Result<Vec<u8>, String> {
    let mut page = zero_page(kernel, info, initramfs_len, rsdp)?;
    let entries = e820_snp();
    page[0x1e8] = entries.len() as u8;
    for (index, entry) in entries.iter().enumerate() {
        let at = E820_TABLE + index * 20;
        put64(&mut page, at, entry.0);
        put64(&mut page, at + 8, entry.1);
        put32(&mut page, at + 16, entry.2);
    }
    // boot_params.hdr.setup_data -> measured SETUP_CC_BLOB record.
    put64(&mut page, 0x250, SNP_CC_BLOB);
    Ok(page)
}

// The measured GDT and the 64 KiB BSP stack that grows down towards it.  A
// selector is its own byte offset, so BOOT_CS32/BOOT_CS/BOOT_DS index this
// table directly.  Both shims run on it: SNP loads it from the measured VMSA's
// GDTR, TDX `lgdt`s the pseudo-descriptor that follows the entries.  Without
// it Linux would be entered on whatever descriptors the loader left behind,
// which no measurement covers.
pub fn gdt_stack() -> Vec<u8> {
    let mut v = vec![0u8; BSP_STACK_SIZE as usize];
    put64(&mut v, BOOT_CS32 as usize, 0x00cf_9b00_0000_ffff);
    put64(&mut v, BOOT_CS as usize, 0x00af_9b00_0000_ffff);
    put64(&mut v, BOOT_DS as usize, 0x00cf_9300_0000_ffff);
    let at = (GDT_PTR - BSP_STACK) as usize;
    v[at..at + 2].copy_from_slice(&(GDT_LIMIT as u16).to_le_bytes());
    put64(&mut v, at + 2, BSP_STACK);
    v
}

const RAM: u32 = 1;
const RESERVED: u32 = 2;
const ACPI: u32 = 3;

fn e820_snp() -> Vec<(u64, u64, u32)> {
    vec![
        (0, ZERO_PAGE, RESERVED),
        (ZERO_PAGE, PAGE, RESERVED),
        (ZERO_PAGE + PAGE, CMDLINE - ZERO_PAGE - PAGE, RAM),
        (CMDLINE, PAGE, RESERVED),
        (CMDLINE + PAGE, VGA_HOLE - CMDLINE - PAGE, RAM),
        (VGA_HOLE, ACPI_BASE - VGA_HOLE, RESERVED),
        // Type 3, not RESERVED: under SEV ioremap() maps an e820 RESERVED
        // range decrypted, so ACPICA's late remap of the tables would read
        // ciphertext.  Only IORES_DESC_ACPI_TABLES keeps the C-bit set.
        (ACPI_BASE, PAGE, ACPI),
        (ACPI_BASE + PAGE, PAGE_TABLES - ACPI_BASE - PAGE, RESERVED),
        (PAGE_TABLES, KERNEL_SETUP_END - PAGE_TABLES, RESERVED),
        (KERNEL_SETUP_END, RAM_SIZE - KERNEL_SETUP_END, RAM),
    ]
}

pub fn e820() -> Vec<(u64, u64, u32)> {
    vec![
        (0, ZERO_PAGE, RESERVED),
        (ZERO_PAGE, PAGE, RESERVED),
        (ZERO_PAGE + PAGE, CMDLINE - ZERO_PAGE - PAGE, RAM),
        (CMDLINE, PAGE, RESERVED),
        (CMDLINE + PAGE, ACPI_BASE - CMDLINE - PAGE, RAM),
        (ACPI_BASE, PAGE, ACPI),
        (ACPI_BASE + PAGE, PAGE_TABLES - ACPI_BASE - PAGE, RESERVED),
        (PAGE_TABLES, KERNEL_SETUP_END - PAGE_TABLES, RESERVED),
        (KERNEL_SETUP_END, RAM_SIZE - KERNEL_SETUP_END, RAM),
    ]
}

fn get16(v: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(v[at..at + 2].try_into().unwrap())
}
fn get32(v: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(v[at..at + 4].try_into().unwrap())
}
pub fn put32(v: &mut [u8], at: usize, n: u32) {
    v[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
pub fn put64(v: &mut [u8], at: usize, n: u64) {
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
    fn gdt_is_addressed_by_its_own_selectors() {
        let v = gdt_stack();
        assert_eq!(v.len(), BSP_STACK_SIZE as usize);
        // A null descriptor at 0 and a 64-bit code descriptor at __BOOT_CS.
        assert_eq!(&v[..8], &[0u8; 8]);
        assert_eq!(v[BOOT_CS as usize + 6] & 0x20, 0x20);
        let at = (GDT_PTR - BSP_STACK) as usize;
        assert_eq!(
            u16::from_le_bytes(v[at..at + 2].try_into().unwrap()) as u64,
            GDT_LIMIT
        );
        assert_eq!(
            u64::from_le_bytes(v[at + 2..at + 10].try_into().unwrap()),
            BSP_STACK
        );
    }
    #[test]
    fn malformed_kernel_is_rejected() {
        assert!(parse_bzimage(&[0; 0x300]).is_err());
    }

    #[test]
    fn snp_e820_covers_one_gib_without_unaccepted_memory() {
        let map = e820_snp();
        assert!(map
            .iter()
            .all(|e| e.2 == RAM || e.2 == RESERVED || e.2 == ACPI));
        assert!(map.iter().any(|e| e.0 == ACPI_BASE && e.2 == ACPI));
        // The q35 legacy hole holds launch-updated pages and MMIO, never RAM.
        assert!(map.iter().any(|e| e.0 == VGA_HOLE && e.2 == RESERVED));
        assert_eq!(map.first().unwrap().0, 0);
        assert_eq!(map.last().unwrap().0 + map.last().unwrap().1, RAM_SIZE);
        for pair in map.windows(2) {
            assert_eq!(pair[0].0 + pair[0].1, pair[1].0);
        }
    }
}
