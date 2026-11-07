use crate::key_encoding::{
    PUBLIC_KEY_LEN, is_valid_x25519_public_key, parse_ed25519_verifying_key_bytes,
};
use subtle::{Choice, ConstantTimeEq};

const IDENTITY_KEY_DOMAIN_TAG: &[u8] = b"RoostIK-v1:";
const IDENTITY_KEY_ENCODING_LEN: usize = IDENTITY_KEY_DOMAIN_TAG.len() + PUBLIC_KEY_LEN * 2;

/// The public halves of a permanent identity key, which safety numbers, trust, and sender
/// certificates use.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct IdentityKey {
    /// Canonical X25519 public key bytes.
    pub x25519_public_key: [u8; PUBLIC_KEY_LEN],
    /// Canonical Ed25519 verifying-key bytes.
    pub ed25519_verifying_key: [u8; PUBLIC_KEY_LEN],
}

impl IdentityKey {
    /// Returns the encoding that safety numbers and contact state compare.
    ///
    /// Check the key with [`IdentityKey::is_valid`] before using this encoding as an identity.
    #[must_use]
    pub fn canonical_encoding(&self) -> [u8; IDENTITY_KEY_ENCODING_LEN] {
        let mut encoding = [0u8; IDENTITY_KEY_ENCODING_LEN];
        let offset = IDENTITY_KEY_DOMAIN_TAG.len();
        encoding[..offset].copy_from_slice(IDENTITY_KEY_DOMAIN_TAG);
        encoding[offset..offset + PUBLIC_KEY_LEN].copy_from_slice(&self.x25519_public_key);
        encoding[offset + PUBLIC_KEY_LEN..].copy_from_slice(&self.ed25519_verifying_key);
        encoding
    }

    /// Returns whether both halves are canonical, and neither is low order or weak.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        is_valid_x25519_public_key(&self.x25519_public_key)
            && parse_ed25519_verifying_key_bytes(&self.ed25519_verifying_key).is_some()
    }
}

impl ConstantTimeEq for IdentityKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.x25519_public_key.ct_eq(&other.x25519_public_key)
            & self
                .ed25519_verifying_key
                .ct_eq(&other.ed25519_verifying_key)
    }
}
