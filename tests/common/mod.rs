use std::{io::Read, path::Path};

pub fn finding_bytes(path: impl AsRef<Path>) -> Vec<u8> {
    let mut bytes = Vec::new();
    shenron::findings_io::open(path.as_ref())
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    bytes
}

#[allow(dead_code)]
pub fn finding_text(path: impl AsRef<Path>) -> String {
    String::from_utf8(finding_bytes(path)).unwrap()
}
