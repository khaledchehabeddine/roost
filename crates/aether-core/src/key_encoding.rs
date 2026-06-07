use aether_crypto::VerifyingKey;
use curve25519_dalek::{montgomery::MontgomeryPoint, traits::Identity};
use subtle::ConstantTimeEq;

pub(crate) const PUBLIC_KEY_LEN: usize = 32;

pub(crate) fn validate_x25519_public_key(bytes: &[u8; PUBLIC_KEY_LEN]) -> bool {
    is_canonical_x25519_public_key(bytes) && !is_low_order_x25519_public_key(bytes)
}

pub(crate) fn parse_ed25519_verifying_key(bytes: &[u8]) -> Option<VerifyingKey> {
    let bytes: [u8; PUBLIC_KEY_LEN] = bytes.try_into().ok()?;
    parse_ed25519_verifying_key_bytes(&bytes)
}

pub(crate) fn parse_ed25519_verifying_key_bytes(
    bytes: &[u8; PUBLIC_KEY_LEN],
) -> Option<VerifyingKey> {
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
