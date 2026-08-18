use sha2::{Digest, Sha384};

pub fn calculate(pages: &[(u64, Vec<u8>, bool)]) -> [u8; 48] {
    let mut hash = Sha384::new();
    for (gpa, data, measured) in pages {
        let mut add = [0u8; 128];
        add[..12].copy_from_slice(b"MEM.PAGE.ADD");
        add[16..24].copy_from_slice(&gpa.to_le_bytes());
        hash.update(add);
        if *measured {
            let mut page = [0u8; 4096];
            page[..data.len()].copy_from_slice(data);
            for offset in (0..4096).step_by(256) {
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
