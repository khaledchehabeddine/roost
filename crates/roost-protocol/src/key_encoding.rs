use curve25519_dalek::{montgomery::MontgomeryPoint, traits::Identity};
use ed25519_dalek::VerifyingKey;
use subtle::ConstantTimeEq;

/// Length of an X25519 or Ed25519 public key encoding.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Returns whether an X25519 public key is canonically encoded and not low order.
pub fn is_valid_x25519_public_key(bytes: &[u8; PUBLIC_KEY_LEN]) -> bool {
    is_canonical_x25519_public_key(bytes) && !is_low_order_x25519_public_key(bytes)
}

/// Parses a canonical, non-weak Ed25519 public key.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_validation_rejects_non_canonical_key() {
        let mut base_point_plus_modulus = x25519_field_modulus();
        base_point_plus_modulus[0] += 9;
        let mut base_point_with_high_bit = [0; PUBLIC_KEY_LEN];
        base_point_with_high_bit[0] = 9;
        base_point_with_high_bit[PUBLIC_KEY_LEN - 1] = 0x80;
        for key in [base_point_plus_modulus, base_point_with_high_bit] {
            assert!(!is_valid_x25519_public_key(&key));
        }
    }

    #[test]
    fn x25519_validation_rejects_low_order_keys() {
        let mut twist_low_order = x25519_field_modulus();
        twist_low_order[0] -= 1;
        for key in [[0; PUBLIC_KEY_LEN], twist_low_order] {
            assert!(!is_valid_x25519_public_key(&key));
        }
    }
}
