use sha2::{Digest, Sha384};
use crate::layout::PAGE;

// The pages the TDX module sees, in the order it sees them: one
// TDH.MEM.PAGE.ADD per page, and 16 TDH.MR.EXTEND per page for the sections
// the metadata marks measured.  Each page is borrowed from the section that
// holds it and zero-padded here, so nothing is copied to hash it.
pub fn calculate(pages: &[(u64, &[u8], bool)]) -> [u8; 48] {
    let mut hash = Sha384::new();
    for (gpa, data, measured) in pages {
        let mut add = [0u8; 128];
        add[..12].copy_from_slice(b"MEM.PAGE.ADD");
        add[16..24].copy_from_slice(&gpa.to_le_bytes());
        hash.update(add);
        if *measured {
            let mut page = [0u8; PAGE as usize];
            page[..data.len()].copy_from_slice(data);
            for offset in (0..PAGE as usize).step_by(256) {
                let mut extend = [0u8; 128];
                extend[..9].copy_from_slice(b"MR.EXTEND");
                extend[16..24].copy_from_slice(&(gpa + offset as u64).to_le_bytes());
                hash.update(extend);
                hash.update(&page[offset..offset + 256]);
            }
        }
    }
    hash.finalize().into()
}
