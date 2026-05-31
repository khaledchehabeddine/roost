//! Provides signed X25519 pre-keys for the X3DH-lite handshake.

use crate::error::CryptoError;
use crate::keys::SigningKeyPair;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::{CryptoRng, RngCore};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// Domain separator for signatures over signed pre-key public keys.
const SIGNED_PREKEY_DOMAIN: &[u8] = b"aether-spk-v1:";

/// An X25519 pre-key signed by an Ed25519 identity key.
///
/// The secret key is zeroed on drop. The public key, signature, and creation timestamp remain
/// available through accessors and bundle export.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SignedPreKey {
    secret_key: StaticSecret,
    #[zeroize(skip)]
    public_key: PublicKey,
    #[zeroize(skip)]
    signature: Signature,
    #[zeroize(skip)]
    created_at: u64,
}

impl SignedPreKey {
    /// Returns the X25519 public key.
    pub fn public(&self) -> &PublicKey {
        &self.public_key
    }

    /// Returns the Ed25519 signature over this signed pre-key's public key.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Returns the Unix timestamp (seconds) when this signed pre-key was generated.
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Performs an X25519 Diffie-Hellman exchange between this signed pre-key's secret and `peer`.
    pub fn diffie_hellman(&self, peer: &PublicKey) -> SharedSecret {
        self.secret_key.diffie_hellman(peer)
    }

    /// Exports the signed pre-key's secret bytes for secure persistence.
    pub fn to_secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secret_key.to_bytes())
    }

    /// Restores a signed pre-key from its persisted parts.
    pub fn from_secret_bytes(secret: [u8; 32], signature: [u8; 64], created_at: u64) -> Self {
        let secret_key = StaticSecret::from(secret);
        let public_key = PublicKey::from(&secret_key);
        let signature = Signature::from_bytes(&signature);
        SignedPreKey {
            secret_key,
            public_key,
            signature,
            created_at,
        }
    }

    /// Returns the public form of this signed pre-key for distribution to peers.
    pub fn bundle(&self) -> SignedPreKeyBundle {
        SignedPreKeyBundle {
            public_key: self.public_key,
            signature: self.signature,
            created_at: self.created_at,
        }
    }
}

/// Public signed pre-key material distributed to peers.
///
/// The identity verifying key is not embedded. Callers pass it to [`verify_bundle`] separately.
#[derive(Clone, Debug)]
pub struct SignedPreKeyBundle {
    /// X25519 public key used by the peer during handshake root-key derivation.
    pub public_key: PublicKey,
    /// Ed25519 signature over the domain-separated signed pre-key payload.
    pub signature: Signature,
    /// Unix timestamp in seconds when the signed pre-key was generated.
    pub created_at: u64,
}

/// Generates a signed pre-key using the identity signing key and `rng`.
#[must_use]
pub fn generate_signed_prekey<R: RngCore + CryptoRng>(
    rng: &mut R,
    identity: &SigningKeyPair,
    created_at: u64,
) -> SignedPreKey {
    let secret_key = StaticSecret::random_from_rng(&mut *rng);
    let public_key = PublicKey::from(&secret_key);
    let payload = signed_prekey_payload(&public_key);
    let signature = identity.sign(&payload);
    SignedPreKey {
        secret_key,
        public_key,
        signature,
        created_at,
    }
}

/// Verifies that a signed pre-key bundle belongs to an identity verifying key.
///
/// # Errors
/// - [`CryptoError::SignatureInvalid`] when the signature does not validate.
pub fn verify_bundle(
    bundle: &SignedPreKeyBundle,
    identity_verifying_key: &VerifyingKey,
) -> Result<(), CryptoError> {
    let payload = signed_prekey_payload(&bundle.public_key);
    identity_verifying_key
        .verify(&payload, &bundle.signature)
        .map_err(|_| CryptoError::SignatureInvalid)
}

fn signed_prekey_payload(public_key: &PublicKey) -> Vec<u8> {
    let mut payload = Vec::with_capacity(SIGNED_PREKEY_DOMAIN.len() + 32);
    payload.extend_from_slice(SIGNED_PREKEY_DOMAIN);
    payload.extend_from_slice(public_key.as_bytes());
    payload
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{generate_key_pair, generate_signing_key_pair};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    const FIXED_CREATED_AT: u64 = 1_700_000_000;

    fn seeded_rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([4u8; 32])
    }

    #[test]
    fn bundle_fields_match_signed_prekey() {
        let mut rng = seeded_rng();
        let identity = generate_signing_key_pair(&mut rng);
        let signed_prekey = generate_signed_prekey(&mut rng, &identity, FIXED_CREATED_AT);
        let bundle = signed_prekey.bundle();
        assert_eq!(
            bundle.public_key.as_bytes(),
            signed_prekey.public().as_bytes()
        );
        assert_eq!(
            bundle.signature.to_bytes(),
            signed_prekey.signature().to_bytes()
        );
        assert_eq!(bundle.created_at, signed_prekey.created_at());
    }

    #[test]
    fn generate_and_verify_round_trip() {
        let mut rng = seeded_rng();
        let identity = generate_signing_key_pair(&mut rng);
        let signed_prekey = generate_signed_prekey(&mut rng, &identity, FIXED_CREATED_AT);
        let bundle = signed_prekey.bundle();
        assert!(verify_bundle(&bundle, &identity.verifying).is_ok());
    }

    #[test]
    fn verify_rejects_tampered_public_key() {
        let mut rng = seeded_rng();
        let identity = generate_signing_key_pair(&mut rng);
        let signed_prekey = generate_signed_prekey(&mut rng, &identity, FIXED_CREATED_AT);
        let mut bundle = signed_prekey.bundle();
        let mut public_key_bytes = *bundle.public_key.as_bytes();
        public_key_bytes[0] ^= 0x01;
        bundle.public_key = PublicKey::from(public_key_bytes);
        assert!(matches!(
            verify_bundle(&bundle, &identity.verifying),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let mut rng = seeded_rng();
        let identity = generate_signing_key_pair(&mut rng);
        let signed_prekey = generate_signed_prekey(&mut rng, &identity, FIXED_CREATED_AT);
        let bundle = signed_prekey.bundle();
        let mut signature_bytes = bundle.signature.to_bytes();
        signature_bytes[0] ^= 0x01;
        let tampered = SignedPreKeyBundle {
            public_key: bundle.public_key,
            signature: Signature::from_bytes(&signature_bytes),
            created_at: bundle.created_at,
        };
        assert!(matches!(
            verify_bundle(&tampered, &identity.verifying),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn verify_rejects_wrong_identity() {
        let mut rng = seeded_rng();
        let identity_a = generate_signing_key_pair(&mut rng);
        let identity_b = generate_signing_key_pair(&mut rng);
        let signed_prekey = generate_signed_prekey(&mut rng, &identity_a, FIXED_CREATED_AT);
        let bundle = signed_prekey.bundle();
        assert!(matches!(
            verify_bundle(&bundle, &identity_b.verifying),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn signature_without_domain_prefix_fails_verification() {
        let mut rng = seeded_rng();
        let identity = generate_signing_key_pair(&mut rng);
        let key_pair = generate_key_pair(&mut rng);
        let bare_signature = identity.sign(key_pair.public.as_bytes());
        let bundle = SignedPreKeyBundle {
            public_key: key_pair.public,
            signature: bare_signature,
            created_at: FIXED_CREATED_AT,
        };
        assert!(matches!(
            verify_bundle(&bundle, &identity.verifying),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn from_secret_bytes_round_trip() {
        let mut rng = seeded_rng();
        let identity = generate_signing_key_pair(&mut rng);
        let original = generate_signed_prekey(&mut rng, &identity, FIXED_CREATED_AT);
        let restored = SignedPreKey::from_secret_bytes(
            *original.to_secret_bytes(),
            original.signature().to_bytes(),
            original.created_at(),
        );
        assert_eq!(restored.public().as_bytes(), original.public().as_bytes());
        assert_eq!(
            restored.signature().to_bytes(),
            original.signature().to_bytes()
        );
        assert_eq!(restored.created_at(), original.created_at());
        assert_eq!(*restored.to_secret_bytes(), *original.to_secret_bytes());
    }

    #[test]
    fn restored_bundle_verifies_against_original_identity() {
        let mut rng = seeded_rng();
        let identity = generate_signing_key_pair(&mut rng);
        let original = generate_signed_prekey(&mut rng, &identity, FIXED_CREATED_AT);
        let restored = SignedPreKey::from_secret_bytes(
            *original.to_secret_bytes(),
            original.signature().to_bytes(),
            original.created_at(),
        );
        let bundle = restored.bundle();
        assert!(verify_bundle(&bundle, &identity.verifying).is_ok());
    }

    #[test]
    fn diffie_hellman_after_from_secret_bytes() {
        let mut rng = seeded_rng();
        let identity = generate_signing_key_pair(&mut rng);
        let original = generate_signed_prekey(&mut rng, &identity, FIXED_CREATED_AT);
        let restored = SignedPreKey::from_secret_bytes(
            *original.to_secret_bytes(),
            original.signature().to_bytes(),
            original.created_at(),
        );
        let peer = generate_key_pair(&mut rng);
        let original_shared_secret = original.diffie_hellman(&peer.public);
        let restored_shared_secret = restored.diffie_hellman(&peer.public);
        assert_eq!(
            original_shared_secret.as_bytes(),
            restored_shared_secret.as_bytes()
        );
    }
}
