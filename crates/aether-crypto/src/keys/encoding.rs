use super::signing::VerifyingKey;
use curve25519_dalek::{montgomery::MontgomeryPoint, traits::Identity};
use subtle::ConstantTimeEq;

const PUBLIC_KEY_LEN: usize = 32;

pub(crate) fn validate_x25519_public_key(bytes: &[u8; PUBLIC_KEY_LEN]) -> bool {
    is_canonical_x25519_public_key(bytes) && !is_low_order_x25519_public_key(bytes)
}

/// Parses 32 bytes into an Ed25519 verifying key, rejecting anything a bundle would reject.
///
/// Stricter than [`VerifyingKey::from_bytes`] in two ways that matter for keys arriving from the
/// network: the encoding must be canonical, so one key has exactly one representation and cannot be
/// re-encoded to look like a different one, and the point must not be weak — a small-order key
/// makes signatures verifiable under keys nobody controls.
///
/// Public because every entry point that accepts a foreign verifying key has to apply the same
/// standard. Bundle constructors call it on the way in; a caller verifying a bare signature under a
/// bare key has no bundle and would otherwise have to settle for the laxer parser.
pub fn parse_ed25519_verifying_key_bytes(bytes: &[u8; PUBLIC_KEY_LEN]) -> Option<VerifyingKey> {
    let verifying_key = VerifyingKey::from_bytes(bytes).ok()?;
    let recompressed = verifying_key.to_edwards().compress().to_bytes();
    let canonical: bool = recompressed.ct_eq(bytes).into();
    (!verifying_key.is_weak() && canonical).then_some(verifying_key)
}

fn is_canonical_x25519_public_key(bytes: &[u8; PUBLIC_KEY_LEN]) -> bool {
    let modulus = x25519_field_modulus();
    for i in (0..PUBLIC_KEY_LEN).rev() {
        if bytes[i] < modulus[i] {
            return true;
        }
        if bytes[i] > modulus[i] {
            return false;
        }
    }
    false
}

fn is_low_order_x25519_public_key(bytes: &[u8; PUBLIC_KEY_LEN]) -> bool {
    let shared = MontgomeryPoint(*bytes).mul_clamped([0xff; PUBLIC_KEY_LEN]);
    shared.ct_eq(&MontgomeryPoint::identity()).into()
}

fn x25519_field_modulus() -> [u8; PUBLIC_KEY_LEN] {
    let mut modulus = [0xff; PUBLIC_KEY_LEN];
    modulus[0] = 0xed;
    modulus[PUBLIC_KEY_LEN - 1] = 0x7f;
    modulus
}
