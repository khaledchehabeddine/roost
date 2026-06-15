#![allow(dead_code)]

const REPEAT_CAP: usize = 256 * 1024;

pub fn bytes_from_seed(data: &[u8]) -> Vec<u8> {
    let Some(text) = text(data) else {
        return data.to_vec();
    };
    if let Some(hex) = text.strip_prefix("hex:") {
        return hex_bytes(hex).unwrap_or_default();
    }
    if let Some(repeat) = text.strip_prefix("repeat:") {
        return repeat_bytes(repeat).unwrap_or_default();
    }
    data.to_vec()
}

pub fn text(data: &[u8]) -> Option<&str> {
    std::str::from_utf8(data).ok().map(str::trim)
}

pub fn field<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.lines().find_map(|line| {
        let (field_name, value) = line.trim().split_once(':')?;
        (field_name.trim() == name).then_some(value.trim())
    })
}

pub fn hex_field(text: &str, name: &str) -> Option<Vec<u8>> {
    field(text, name).and_then(hex_bytes)
}

pub fn u64_field(text: &str, name: &str, default: u64) -> u64 {
    field(text, name)
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

pub fn hex_bytes(hex: &str) -> Option<Vec<u8>> {
    let filtered: String = hex.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    (!filtered.is_empty() && filtered.len() % 2 == 0)
        .then(|| hex::decode(filtered).ok())
        .flatten()
}

pub fn array_32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let len = bytes.len().min(out.len());
    out[..len].copy_from_slice(&bytes[..len]);
    out
}

fn repeat_bytes(repeat: &str) -> Option<Vec<u8>> {
    let (byte, count) = repeat.split_once(':')?;
    let byte = u8::from_str_radix(byte.trim(), 16).ok()?;
    let count = count.trim().parse::<usize>().ok()?.min(REPEAT_CAP);
    Some(vec![byte; count])
}
