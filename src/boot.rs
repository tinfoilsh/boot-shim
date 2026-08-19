use crate::layout::*;

const SETUP_HEADER: usize = 0x1f1;
const E820_TABLE: usize = 0x2d0;
// boot_params has room for exactly this many E820 entries.
const E820_MAX: usize = 128;

pub const RAM: u32 = 1;
pub const RESERVED: u32 = 2;
pub const ACPI: u32 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelInfo {
    pub setup_bytes: usize,
    pub protected_size: usize,
    pub entry_offset: u64,
    pub init_size: u32,
    pub cmdline_max: u32,
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
    // The payload goes to the fixed KERNEL_BASE whatever the kernel asked for,
    // so a kernel that cannot be moved there has to be refused rather than
    // loaded somewhere it will not run.
    let alignment = get32(image, 0x230) as u64;
    if alignment == 0 || !alignment.is_power_of_two() || !KERNEL_BASE.is_multiple_of(alignment) {
        return Err("kernel alignment is not satisfied by the fixed load address".into());
    }
    if image[0x234] == 0 && get64(image, 0x258) != KERNEL_BASE {
        return Err("kernel is not relocatable and prefers a different load address".into());
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
        cmdline_max: get32(image, 0x238),
    })
}

pub fn zero_page(
    setup: &[u8],
    info: KernelInfo,
    initramfs_len: usize,
    rsdp: u64,
    e820: &[(u64, u64, u32)],
) -> Result<Vec<u8>, String> {
    if e820.len() > E820_MAX {
        return Err(format!("E820 map needs {} of {E820_MAX} entries", e820.len()));
    }
    let mut page = vec![0u8; PAGE as usize];
    page[SETUP_HEADER..0x290].copy_from_slice(&setup[SETUP_HEADER..0x290]);
    page[0x210] = 0xff;
    page[0x211] |= 0x80;
    put32(&mut page, 0x218, INITRAMFS_BASE as u32);
    put32(&mut page, 0x21c, initramfs_len as u32);
    put32(&mut page, 0x228, CMDLINE as u32);
    put32(&mut page, 0x214, KERNEL_BASE as u32);
    put32(&mut page, 0x260, info.init_size);
    put64(&mut page, 0x70, rsdp);

    page[0x1e8] = e820.len() as u8;
    for (index, entry) in e820.iter().enumerate() {
        let at = E820_TABLE + index * 20;
        put64(&mut page, at, entry.0);
        put64(&mut page, at + 8, entry.1);
        put32(&mut page, at + 16, entry.2);
    }
    Ok(page)
}

pub fn zero_page_snp(
    setup: &[u8],
    info: KernelInfo,
    initramfs_len: usize,
    rsdp: u64,
    e820: &[(u64, u64, u32)],
) -> Result<Vec<u8>, String> {
    let mut page = zero_page(setup, info, initramfs_len, rsdp, e820)?;
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

/// What a placed span holds.  Ordinary RAM is everything these leave over.
pub enum Fill {
    /// Contents this file provides and measures.
    Measured(Vec<u8>),
    /// One page whose contents the loader or the firmware supplies: the TD HOB
    /// on TDX, the CPUID and Secrets pages on SNP.  Declared and measured by
    /// address, never by content, and never accepted by a shim.
    Host,
    /// A platform MMIO aperture the deployer declared.  Not memory: nothing is
    /// loaded there and no shim ever accepts it.
    Mmio(u64),
}

/// A span of the guest map this image places.  One list decides all three of
/// the E820 map Linux boots on, the sections the loader is told to add, and
/// the ranges the shim accepts -- so those three cannot drift apart.
pub struct Placed {
    pub base: u64,
    pub e820: u32,
    pub fill: Fill,
}

impl Placed {
    pub fn measured(base: u64, e820: u32, data: Vec<u8>) -> Placed {
        Placed {
            base,
            e820,
            fill: Fill::Measured(data),
        }
    }
    pub fn host(base: u64) -> Placed {
        Placed {
            base,
            e820: RESERVED,
            fill: Fill::Host,
        }
    }
    pub fn mmio(base: u64, size: u64) -> Placed {
        Placed {
            base,
            e820: RESERVED,
            fill: Fill::Mmio(size),
        }
    }
    /// The page-aligned span this occupies in the guest map.
    pub fn span(&self) -> u64 {
        match &self.fill {
            Fill::Measured(d) => align_up(d.len() as u64, PAGE).max(PAGE),
            Fill::Host => PAGE,
            Fill::Mmio(n) => *n,
        }
    }
    pub fn data(&self) -> &[u8] {
        match &self.fill {
            Fill::Measured(d) => d,
            _ => &[],
        }
    }
}

/// Fill in the contents of an already-placed region.  The replacement has to
/// occupy the same span, so a map derived from the region before it was filled
/// -- the zero page describes the very map it belongs to -- stays valid.
pub fn fill(placed: &mut [Placed], base: u64, data: Vec<u8>) -> Result<(), String> {
    let region = placed
        .iter_mut()
        .find(|p| p.base == base)
        .ok_or_else(|| format!("nothing is placed at {base:#x}"))?;
    let span = region.span();
    region.fill = Fill::Measured(data);
    if region.span() != span {
        return Err(format!("contents for {base:#x} do not fit its placed span"));
    }
    Ok(())
}

fn spans(placed: &[Placed]) -> Vec<(u64, u64, u32)> {
    let mut v: Vec<_> = placed
        .iter()
        .map(|p| (p.base, p.base + p.span(), p.e820))
        .collect();
    v.sort_unstable();
    v
}

/// Rejects a map whose placed spans overlap, which would otherwise become an
/// E820 map and an accept list that disagree about who owns a page.
pub fn validate(placed: &[Placed], memory: u64) -> Result<(), String> {
    for pair in spans(placed).windows(2) {
        if pair[0].1 > pair[1].0 {
            return Err(format!("placed regions overlap at {:#x}", pair[1].0));
        }
    }
    for p in placed {
        if !p.base.is_multiple_of(PAGE) {
            return Err(format!("placed region {:#x} is not page-aligned", p.base));
        }
        if p.base >= memory && p.base != RESET_ALIAS {
            return Err(format!(
                "placed region {:#x} lies outside the memory the image describes",
                p.base
            ));
        }
    }
    Ok(())
}

/// The E820 map Linux boots on: every placed span under its own type, every
/// gap between them as RAM, adjacent runs of a type coalesced.
pub fn e820(placed: &[Placed], memory: u64) -> Vec<(u64, u64, u32)> {
    let mut out: Vec<(u64, u64, u32)> = Vec::new();
    let mut push = |base: u64, end: u64, kind: u32| {
        if base >= end {
            return;
        }
        match out.last_mut() {
            Some(last) if last.0 + last.1 == base && last.2 == kind => last.1 += end - base,
            _ => out.push((base, end - base, kind)),
        }
    };
    let mut at = 0;
    for (lo, hi, kind) in spans(placed) {
        if lo >= memory {
            break;
        }
        push(at, lo, RAM);
        push(lo.max(at), hi.min(memory), kind);
        at = at.max(hi);
    }
    push(at, memory, RAM);
    out
}

/// The ranges a shim accepts: [0, memory) minus everything placed.  The loader
/// already accepted the pages it loaded, and accepting one twice is how a page
/// gets silently replaced, so the complement is exactly the right list.
pub fn accept_ranges(placed: &[Placed], memory: u64) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut at = 0;
    for (lo, hi, _) in spans(placed) {
        if lo > at {
            out.push((at, lo.min(memory)));
        }
        at = at.max(hi);
    }
    out.push((at, memory));
    out.retain(|(lo, hi)| lo < hi);
    out
}

fn get16(v: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(v[at..at + 2].try_into().unwrap())
}
fn get32(v: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(v[at..at + 4].try_into().unwrap())
}
fn get64(v: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(v[at..at + 8].try_into().unwrap())
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

    fn map() -> Vec<Placed> {
        vec![
            Placed::measured(ZERO_PAGE, RESERVED, vec![0; PAGE as usize]),
            Placed::measured(ACPI_BASE, ACPI, vec![0; PAGE as usize]),
            Placed::host(TD_HOB),
            Placed::measured(KERNEL_BASE, RAM, vec![0; PAGE as usize]),
        ]
    }

    #[test]
    fn e820_tiles_the_whole_span_without_gaps() {
        let map = map();
        let e = e820(&map, DEFAULT_MEMORY);
        assert_eq!(e.first().unwrap().0, 0);
        assert_eq!(e.last().unwrap().0 + e.last().unwrap().1, DEFAULT_MEMORY);
        for pair in e.windows(2) {
            assert_eq!(pair[0].0 + pair[0].1, pair[1].0);
        }
        assert!(e.iter().any(|x| x.0 == ACPI_BASE && x.2 == ACPI));
        // A measured region that Linux may still use stays RAM, and coalesces
        // with the RAM around it rather than punching a hole in it.
        assert!(!e.iter().any(|x| x.0 == KERNEL_BASE));
    }

    #[test]
    fn accept_ranges_are_exactly_the_complement_of_the_placed_map() {
        let map = map();
        let ranges = accept_ranges(&map, DEFAULT_MEMORY);
        let placed: Vec<_> = map.iter().map(|p| (p.base, p.base + p.span())).collect();
        // Nothing placed is ever accepted: that is the page-aliasing attack.
        for (lo, hi) in &ranges {
            assert!(placed.iter().all(|(a, b)| hi <= a || lo >= b));
        }
        // ...and nothing else is left out.
        let covered: u64 = ranges.iter().map(|(l, h)| h - l).sum();
        let taken: u64 = placed.iter().map(|(l, h)| h - l).sum();
        assert_eq!(covered + taken, DEFAULT_MEMORY);
    }

    #[test]
    fn a_declared_mmio_hole_is_reserved_and_never_accepted() {
        let mut map = map();
        map.push(Placed::mmio(0x30_0000, 0x2_0000));
        assert!(e820(&map, DEFAULT_MEMORY)
            .iter()
            .any(|x| x.0 == 0x30_0000 && x.1 == 0x2_0000 && x.2 == RESERVED));
        assert!(accept_ranges(&map, DEFAULT_MEMORY)
            .iter()
            .all(|(l, h)| *h <= 0x30_0000 || *l >= 0x32_0000));
    }

    #[test]
    fn overlapping_placement_is_rejected() {
        let mut map = map();
        map.push(Placed::mmio(ACPI_BASE, PAGE));
        assert!(validate(&map, DEFAULT_MEMORY).is_err());
        assert!(validate(&map[..1], DEFAULT_MEMORY).is_ok());
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
}
