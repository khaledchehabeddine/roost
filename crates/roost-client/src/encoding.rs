//! Conversions between the host's strings and byte arrays and Roost's fixed-size values.

use crate::error::RoostError;

/// Returns `bytes` as lowercase hexadecimal digits.
pub(crate) fn hex_text(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Parses an identifier written as exactly `2 * N` lowercase hexadecimal digits.
pub(crate) fn hex_identifier<const N: usize>(
    value: &str,
    label: &str,
) -> Result<[u8; N], RoostError> {
    let invalid = || RoostError::InvalidData {
        reason: format!("{label} must be {} lowercase hex digits", N * 2),
    };
    let digits = value.as_bytes();
    if digits.len() != N * 2 {
        return Err(invalid());
    }
    let mut bytes = [0u8; N];
    for (byte, &[high, low]) in bytes.iter_mut().zip(digits.as_chunks::<2>().0) {
        let high = hex_digit(high).ok_or_else(invalid)?;
        let low = hex_digit(low).ok_or_else(invalid)?;
        *byte = (high << 4) | low;
    }
    Ok(bytes)
}

/// Parses a non-empty identifier written as an even number of lowercase hexadecimal digits.
pub(crate) fn hex_bytes(value: &str, label: &str) -> Result<Vec<u8>, RoostError> {
    let invalid = || RoostError::InvalidData {
        reason: format!("{label} must be an even number of lowercase hex digits"),
    };
    let (pairs, rest) = value.as_bytes().as_chunks::<2>();
    if pairs.is_empty() || !rest.is_empty() {
        return Err(invalid());
    }
    pairs
        .iter()
        .map(|&[high, low]| {
            Ok((hex_digit(high).ok_or_else(invalid)? << 4) | hex_digit(low).ok_or_else(invalid)?)
        })
        .collect()
}

fn hex_digit(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

pub(crate) fn fixed_32(bytes: &[u8], label: &str) -> Result<[u8; 32], RoostError> {
    bytes.try_into().map_err(|_| RoostError::InvalidData {
        reason: format!("{label} must be 32 bytes"),
    })
}

pub(crate) fn fixed_64(bytes: &[u8], label: &str) -> Result<[u8; 64], RoostError> {
    bytes.try_into().map_err(|_| RoostError::InvalidData {
        reason: format!("{label} must be 64 bytes"),
    })
}
