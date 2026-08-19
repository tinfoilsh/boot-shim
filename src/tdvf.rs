// The QEMU/TDVF container.  A TD's initial memory is not something a loader
// can write directly: it is added page by page with TDH.MEM.PAGE.ADD, and
// MRTD is the running digest of those calls.  QEMU learns which pages to add
// from a metadata table inside the firmware image, found through a GUIDed
// table at a fixed distance from the end of the file, so this module's only
// job is to place the measured sections in a file and describe them exactly
// as they will be added.
use crate::layout::*;

// TDVF section types and attributes (TDVF Design Guide, section 11).
pub const BFV: u32 = 0;
pub const TD_HOB_SECTION: u32 = 2;
const MR_EXTEND: u32 = 1;

const SIGNATURE: u32 = 0x4656_4454; // "TDVF"
// e47a6535-984a-4798-865e-4685a7bf8ec2, little-endian mixed-endian form.
const METADATA_GUID: [u8; 16] = [
    0x35, 0x65, 0x7a, 0xe4, 0x4a, 0x98, 0x98, 0x47, 0x86, 0x5e, 0x46, 0x85, 0xa7, 0xbf, 0x8e, 0xc2,
];
// 96b582de-1fb2-45f7-baea-a366c55a082d, the footer of OVMF's GUIDed table.
const FOOTER_GUID: [u8; 16] = [
    0xde, 0x82, 0xb5, 0x96, 0xb2, 0x1f, 0xf7, 0x45, 0xba, 0xea, 0xa3, 0x66, 0xc5, 0x5a, 0x08, 0x2d,
];
// QEMU reads the footer 48 bytes from the end and the reset vector lives in
// the 32 bytes after it, so the tail of the file is fixed to the byte.
const TABLE_FOOTER: usize = 48;
const ENTRY: usize = 4 + 2 + 16;
const TAIL: usize = TABLE_FOOTER + 2 + ENTRY;
// The shim's data block and this table share the reset page and must not meet.
const _: () = assert!(SHIM_DATA + SHIM_DATA_SIZE <= PAGE - TAIL as u64);
// `-bios` is rejected unless the file is a whole number of 64-KiB blocks.
const BLOCK: u64 = 0x1_0000;

pub struct Section {
    pub gpa: u64,
    pub data: Vec<u8>,
    pub kind: u32,
    pub measured: bool,
}

pub fn section(gpa: u64, data: &[u8]) -> Section {
    let mut data = data.to_vec();
    data.resize(align_up(data.len() as u64, PAGE) as usize, 0);
    Section {
        gpa,
        data,
        kind: BFV,
        measured: true,
    }
}

// The TD HOB is the one page the host fills in: QEMU writes its own memory
// map there and adds it unmeasured.  Nothing in this image reads it -- the
// E820 map Linux uses is a measured page -- but QEMU exits if no section
// declares where it goes.
pub fn td_hob(gpa: u64) -> Section {
    Section {
        gpa,
        data: Vec::new(),
        kind: TD_HOB_SECTION,
        measured: false,
    }
}

/// Packs `sections` plus the reset page into a firmware image.  The reset
/// page has to be last: it ends at 4 GiB, where the TD starts fetching, and
/// it carries the GUIDed table whose position is defined from the file's end.
/// The returned sections are in the order QEMU adds them, which is the order
/// MRTD is computed over.
pub fn pack(mut sections: Vec<Section>, shim: &[u8]) -> Result<(Vec<u8>, Vec<Section>), String> {
    let mut offsets = Vec::new();
    let mut cursor = 0u64;
    for s in &sections {
        offsets.push(cursor);
        cursor += s.data.len() as u64;
    }
    let metadata_at = cursor;
    let entries = sections.len() + 1;
    cursor += (16 + 32 * entries) as u64;
    let size = align_up(cursor + PAGE, BLOCK);
    let reset_at = size - PAGE;
    offsets.push(reset_at);

    let mut reset = shim.to_vec();
    reset.resize(PAGE as usize, 0);
    guid_table(&mut reset, size - metadata_at)?;
    sections.push(section(RESET_ALIAS, &reset));

    let mut file = vec![0u8; size as usize];
    let mut metadata = Vec::new();
    metadata.extend_from_slice(&SIGNATURE.to_le_bytes());
    metadata.extend_from_slice(&(16 + 32 * entries as u32).to_le_bytes());
    metadata.extend_from_slice(&1u32.to_le_bytes());
    metadata.extend_from_slice(&(entries as u32).to_le_bytes());
    for (s, offset) in sections.iter().zip(&offsets) {
        let size = align_up(s.data.len().max(PAGE as usize) as u64, PAGE);
        metadata.extend_from_slice(&(*offset as u32).to_le_bytes());
        metadata.extend_from_slice(&(s.data.len() as u32).to_le_bytes());
        metadata.extend_from_slice(&s.gpa.to_le_bytes());
        metadata.extend_from_slice(&size.to_le_bytes());
        metadata.extend_from_slice(&s.kind.to_le_bytes());
        metadata.extend_from_slice(&if s.measured { MR_EXTEND } else { 0 }.to_le_bytes());
        let at = *offset as usize;
        file[at..at + s.data.len()].copy_from_slice(&s.data);
    }
    let at = metadata_at as usize;
    file[at..at + metadata.len()].copy_from_slice(&metadata);
    Ok((file, sections))
}

// One entry -- the offset of the metadata table, counted back from the end of
// the file -- in OVMF's GUIDed table format: each entry is its data, then its
// own length, then its GUID, and the table is addressed backwards from a
// footer at a fixed distance from the end.
fn guid_table(reset: &mut [u8], metadata_from_end: u64) -> Result<(), String> {
    let end = reset.len();
    let at = end - TAIL;
    if reset[at..end - 32].iter().any(|b| *b != 0) {
        return Err("reset shim overruns the GUIDed table at the end of the image".into());
    }
    reset[at..at + 4].copy_from_slice(&(metadata_from_end as u32).to_le_bytes());
    reset[at + 4..at + 6].copy_from_slice(&(ENTRY as u16).to_le_bytes());
    reset[at + 6..at + 22].copy_from_slice(&METADATA_GUID);
    reset[at + 22..at + 24].copy_from_slice(&((ENTRY + 18) as u16).to_le_bytes());
    reset[at + 24..at + 40].copy_from_slice(&FOOTER_GUID);
    Ok(())
}

/// Reads an image back the way QEMU does -- GUIDed table at a fixed distance
/// from the end, then the metadata table it points at -- and returns each
/// section's address and whether it is measured.  The packager checks its own
/// output with this before it publishes a digest for it.
pub fn parse(file: &[u8]) -> Result<Vec<(u64, bool)>, String> {
    let end = file.len();
    if end < TAIL || file[end - TABLE_FOOTER..end - 32] != FOOTER_GUID {
        return Err("no GUIDed table at the end of the image".into());
    }
    let at = end - TAIL;
    if file[at + 6..at + 22] != METADATA_GUID {
        return Err("GUIDed table does not carry the TDX metadata offset".into());
    }
    let from_end = u32::from_le_bytes(file[at..at + 4].try_into().unwrap()) as usize;
    let m = end
        .checked_sub(from_end)
        .ok_or("TDX metadata offset points outside the image")?;
    if file[m..m + 4] != SIGNATURE.to_le_bytes() || file[m + 8..m + 12] != 1u32.to_le_bytes() {
        return Err("TDX metadata is not a version 1 TDVF table".into());
    }
    let count = u32::from_le_bytes(file[m + 12..m + 16].try_into().unwrap()) as usize;
    if u32::from_le_bytes(file[m + 4..m + 8].try_into().unwrap()) as usize != 16 + 32 * count {
        return Err("TDX metadata length disagrees with its section count".into());
    }
    let mut out = Vec::new();
    for i in 0..count {
        let e = m + 16 + 32 * i;
        let raw = u32::from_le_bytes(file[e + 4..e + 8].try_into().unwrap()) as usize;
        let offset = u32::from_le_bytes(file[e..e + 4].try_into().unwrap()) as usize;
        let gpa = u64::from_le_bytes(file[e + 8..e + 16].try_into().unwrap());
        let size = u64::from_le_bytes(file[e + 16..e + 24].try_into().unwrap());
        let kind = u32::from_le_bytes(file[e + 24..e + 28].try_into().unwrap());
        let attributes = u32::from_le_bytes(file[e + 28..e + 32].try_into().unwrap());
        if size < raw as u64 || size % PAGE != 0 || gpa % PAGE != 0 {
            return Err(format!("section {i} is not a page-aligned range"));
        }
        if (kind == TD_HOB_SECTION) != (raw == 0) || offset + raw > file.len() {
            return Err(format!("section {i} carries the wrong amount of data"));
        }
        out.push((gpa, attributes & MR_EXTEND != 0));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn packed_sections_survive_a_qemu_shaped_read() {
        let (file, sections) = pack(
            vec![section(0x7000, &[1u8; 4096]), td_hob(0xf1000)],
            &[0x90u8; 64],
        )
        .unwrap();
        assert_eq!(file.len() as u64 % BLOCK, 0);
        assert_eq!(
            parse(&file).unwrap(),
            sections
                .iter()
                .map(|s| (s.gpa, s.measured))
                .collect::<Vec<_>>()
        );
    }
    #[test]
    fn a_shim_that_reaches_the_table_is_rejected() {
        assert!(pack(vec![section(0x7000, &[1u8; 4096])], &[0x90u8; 4090]).is_err());
    }
}
