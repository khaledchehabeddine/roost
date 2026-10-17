use curve25519_dalek::{montgomery::MontgomeryPoint, traits::Identity};
use ed25519_dalek::VerifyingKey;
use subtle::ConstantTimeEq;

/// Length of a Curve25519 public key encoding.
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

const IDENTITY_KEY_DOMAIN_TAG: &[u8] = b"AetherIK-v1:";
/// Length of the canonical two-half Identity Key encoding.
pub const IDENTITY_KEY_ENCODING_LEN: usize = IDENTITY_KEY_DOMAIN_TAG.len() + PUBLIC_KEY_LEN * 2;

/// Encodes the two public Identity Key halves with their canonical domain tag.
///
/// Callers validate both key halves at their input boundary before using this encoding as an identity.
#[must_use]
pub fn identity_key_encoding(
    x25519_public_key: &[u8; PUBLIC_KEY_LEN],
    ed25519_verifying_key: &[u8; PUBLIC_KEY_LEN],
) -> [u8; IDENTITY_KEY_ENCODING_LEN] {
    let mut encoding = [0u8; IDENTITY_KEY_ENCODING_LEN];
    let offset = IDENTITY_KEY_DOMAIN_TAG.len();
    encoding[..offset].copy_from_slice(IDENTITY_KEY_DOMAIN_TAG);
    encoding[offset..offset + PUBLIC_KEY_LEN].copy_from_slice(x25519_public_key);
    encoding[offset + PUBLIC_KEY_LEN..].copy_from_slice(ed25519_verifying_key);
    encoding
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_validation_rejects_non_canonical_key() {
        assert!(!is_valid_x25519_public_key(&x25519_field_modulus()));
    }

    #[test]
    fn x25519_validation_rejects_low_order_keys() {
        let mut twist_low_order = x25519_field_modulus();
        twist_low_order[0] -= 1;

        for key in [[0; PUBLIC_KEY_LEN], twist_low_order] {
            assert!(!is_valid_x25519_public_key(&key));
        }
    }

    #[test]
    fn identity_key_encoding_changes_with_each_half() {
        let expected = identity_key_encoding(&[0x01; 32], &[0x02; 32]);

        assert_ne!(identity_key_encoding(&[0x03; 32], &[0x02; 32]), expected);
        assert_ne!(identity_key_encoding(&[0x01; 32], &[0x03; 32]), expected);
    }
}
