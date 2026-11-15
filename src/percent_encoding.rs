//! Literal byte decoding shared by local analyses; invalid escapes and `+` stay unchanged.

pub(crate) fn hex_pair(a: u8, b: u8) -> Option<u8> {
    Some(((a as char).to_digit(16)? * 16 + (b as char).to_digit(16)?) as u8)
}

pub(crate) fn decode_once(bytes: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Some(value) = hex_pair(bytes[i + 1], bytes[i + 2]) {
                decoded.push(value);
                i += 3;
                continue;
            }
        }
        decoded.push(bytes[i]);
        i += 1;
    }
    decoded
}
