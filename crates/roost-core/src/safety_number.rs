//! Safety Number derivation from permanent Identity Keys.

use roost_protocol::{
    PUBLIC_KEY_LEN, parse_ed25519_verifying_key_bytes, validate_x25519_public_key,
};
use std::error::Error;
use std::fmt;

const SAFETY_NUMBER_DOMAIN_TAG: &[u8] = b"AetherSafetyNumber-v1:";
const SAFETY_NUMBER_DIGITS: usize = 60;
const SAFETY_NUMBER_GROUP_SIZE: usize = 5;
const SAFETY_NUMBER_GROUPS: usize = 12;

/// A permanent Identity Key used for IK-bound safety, trust, and certificate decisions.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct IdentityKey {
    /// Canonical X25519 public key bytes.
    pub x25519_public_key: [u8; PUBLIC_KEY_LEN],
    /// Canonical Ed25519 verifying-key bytes.
    pub ed25519_verifying_key: [u8; PUBLIC_KEY_LEN],
}

impl IdentityKey {
    /// Returns the canonical Identity Key encoding used for Safety Numbers and IK-keyed state.
    #[must_use]
    pub fn canonical_encoding(&self) -> [u8; roost_protocol::IDENTITY_KEY_ENCODING_LEN] {
        roost_protocol::identity_key_encoding(&self.x25519_public_key, &self.ed25519_verifying_key)
    }
}

/// A Safety Number derived from two permanent Identity Keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SafetyNumber {
    /// BLAKE3 derivation bytes before display reduction.
    pub raw_bytes: [u8; 32],
    /// 60-digit decimal value grouped as 12 blocks of five digits.
    pub grouped_decimal: String,
}

/// Errors returned by Safety Number derivation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SafetyNumberError {
    /// One Identity Key uses a non-canonical or weak public-key encoding.
    InvalidIdentityKey,
}

impl fmt::Display for SafetyNumberError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentityKey => write!(f, "identity key encoding is invalid"),
        }
    }
}

impl Error for SafetyNumberError {}

/// Derives the display Safety Number for two permanent Identity Keys.
///
/// Both inputs must use canonical X25519 and Ed25519 public-key encodings. Discovery Keys are not
/// inputs, so Discovery Key rotation does not change the Safety Number for the same two Identity
/// Keys. The two canonical IK encodings are sorted before hashing so both parties derive the same
/// value.
///
/// # Errors
/// - [`SafetyNumberError::InvalidIdentityKey`] if either Identity Key is non-canonical or weak.
pub fn derive_safety_number(
    first: IdentityKey,
    second: IdentityKey,
) -> Result<SafetyNumber, SafetyNumberError> {
    validate_identity_key(&first)?;
    validate_identity_key(&second)?;

    let mut encodings = [first.canonical_encoding(), second.canonical_encoding()];
    encodings.sort();

    let mut hasher = blake3::Hasher::new();
    hasher.update(SAFETY_NUMBER_DOMAIN_TAG);
    hasher.update(&encodings[0]);
    hasher.update(&encodings[1]);
    let raw_bytes = *hasher.finalize().as_bytes();

    Ok(SafetyNumber {
        raw_bytes,
        grouped_decimal: grouped_decimal(&raw_bytes),
    })
}

pub(crate) fn identity_key_is_valid(identity_key: &IdentityKey) -> bool {
    validate_x25519_public_key(&identity_key.x25519_public_key)
        && parse_ed25519_verifying_key_bytes(&identity_key.ed25519_verifying_key).is_some()
}

fn validate_identity_key(identity_key: &IdentityKey) -> Result<(), SafetyNumberError> {
    identity_key_is_valid(identity_key)
        .then_some(())
        .ok_or(SafetyNumberError::InvalidIdentityKey)
}

fn grouped_decimal(raw_bytes: &[u8; 32]) -> String {
    let mut digits = [0u8; SAFETY_NUMBER_DIGITS];
    for byte in raw_bytes {
        let mut carry = u16::from(*byte);
        for digit in &mut digits {
            let value = u16::from(*digit) * 256 + carry;
            *digit = (value % 10) as u8;
            carry = value / 10;
        }
    }

    let mut display = String::with_capacity(SAFETY_NUMBER_DIGITS + SAFETY_NUMBER_GROUPS - 1);
    for group in (0..SAFETY_NUMBER_GROUPS).rev() {
        if group != SAFETY_NUMBER_GROUPS - 1 {
            display.push(' ');
        }
        let start = group * SAFETY_NUMBER_GROUP_SIZE;
        let end = start + SAFETY_NUMBER_GROUP_SIZE;
        for digit in digits[start..end].iter().rev() {
            display.push(char::from(b'0' + *digit));
        }
    }
    display
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_reduction_left_pads_to_sixty_digits() {
        let mut raw_bytes = [0u8; 32];
        raw_bytes[31] = 7;

        assert_eq!(
            grouped_decimal(&raw_bytes),
            "00000 00000 00000 00000 00000 00000 00000 00000 00000 00000 00000 00007"
        );
    }
}
