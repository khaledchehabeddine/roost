use crate::error::CryptoError;
use crate::keys::SigningKeyPair;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Prevents signed pre-key signatures from being confused with signatures over any other 32-byte
/// payload the identity key might sign in a different context.
const SPK_DOMAIN: &[u8] = b"hermes-spk-v1:";

/// X25519 keypair signed by an Ed25519 identity key. Rotated periodically so a leaked signed
/// pre-key expires at the next rotation.
///
/// ZeroizeOnDrop scrubs the secret on drop. `#[zeroize(skip)]` is required because
/// `ed25519_dalek::Signature` doesn't impl `Zeroize`.
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

    /// Returns the Ed25519 signature over `SPK_DOMAIN || public_key`.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Returns the Unix timestamp (seconds) when this signed pre-key was generated.
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Performs an X25519 Diffie–Hellman exchange between this signed pre-key's secret and
    /// `peer`.
    pub fn diffie_hellman(&self, peer: &PublicKey) -> SharedSecret {
        self.secret_key.diffie_hellman(peer)
    }

    /// Exports the signed pre-key's secret bytes for secure storage. Intended only for
    /// `hermes-core::SignedPreKeyManager` persistence.
    pub fn to_secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secret_key.to_bytes())
    }

    /// Restores a [`SignedPreKey`] from its persisted parts (secret bytes, signature, timestamp).
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

/// Public form of a [`SignedPreKey`]. Identity verifying key is not embedded — [`verify_bundle`]
/// takes it separately to match the X3DH-lite contract.
#[derive(Clone, Debug)]
pub struct SignedPreKeyBundle {
    /// X25519 public key the peer uses to derive the second and third X3DH-lite DH outputs.
    pub public_key: PublicKey,
    /// Ed25519 signature over `SPK_DOMAIN || public_key.as_bytes()`, produced by the owning
    /// identity's signing key.
    pub signature: Signature,
    /// Unix timestamp (seconds) at generation. Used by responders to gate session establishment
    /// on signed-pre-key freshness.
    pub created_at: u64,
}

/// Generates a fresh [`SignedPreKey`], signing `SPK_DOMAIN || public_key.as_bytes()` with
/// `identity`'s Ed25519 key.
#[must_use]
pub fn generate_signed_prekey(identity: &SigningKeyPair, created_at: u64) -> SignedPreKey {
    let secret_key = StaticSecret::random_from_rng(OsRng);
    let public_key = PublicKey::from(&secret_key);
    let payload = spk_signed_payload(&public_key);
    let signature = identity.sign(&payload);
    SignedPreKey {
        secret_key,
        public_key,
        signature,
        created_at,
    }
}

/// Verifies that `bundle.signature` is `peer_identity`'s Ed25519 signature over
/// `SPK_DOMAIN || bundle.public_key.as_bytes()` — signatures produced over the bare pubkey will
/// fail.
///
/// # Errors
/// - [`CryptoError::SignatureInvalid`] when the signature does not validate.
pub fn verify_bundle(
    bundle: &SignedPreKeyBundle,
    peer_identity: &VerifyingKey,
) -> Result<(), CryptoError> {
    let payload = spk_signed_payload(&bundle.public_key);
    peer_identity
        .verify(&payload, &bundle.signature)
        .map_err(|_| CryptoError::SignatureInvalid)
}

fn spk_signed_payload(public_key: &PublicKey) -> Vec<u8> {
    let mut buf = Vec::with_capacity(SPK_DOMAIN.len() + 32);
    buf.extend_from_slice(SPK_DOMAIN);
    buf.extend_from_slice(public_key.as_bytes());
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{generate_key_pair, generate_signing_key_pair};

    const FIXED_TS: u64 = 1_700_000_000;

    #[test]
    fn generate_and_verify_round_trip() {
        let identity = generate_signing_key_pair();
        let spk = generate_signed_prekey(&identity, FIXED_TS);
        let bundle = spk.bundle();
        assert!(verify_bundle(&bundle, &identity.verifying).is_ok());
    }

    #[test]
    fn verify_rejects_tampered_pubkey() {
        let identity = generate_signing_key_pair();
        let spk = generate_signed_prekey(&identity, FIXED_TS);
        let mut bundle = spk.bundle();
        let mut pk_bytes = *bundle.public_key.as_bytes();
        pk_bytes[0] ^= 0x01;
        bundle.public_key = PublicKey::from(pk_bytes);
        assert!(matches!(
            verify_bundle(&bundle, &identity.verifying),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let identity = generate_signing_key_pair();
        let spk = generate_signed_prekey(&identity, FIXED_TS);
        let bundle = spk.bundle();
        let mut sig_bytes = bundle.signature.to_bytes();
        sig_bytes[0] ^= 0x01;
        let tampered = SignedPreKeyBundle {
            public_key: bundle.public_key,
            signature: Signature::from_bytes(&sig_bytes),
            created_at: bundle.created_at,
        };
        assert!(matches!(
            verify_bundle(&tampered, &identity.verifying),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn verify_rejects_wrong_identity() {
        let identity_a = generate_signing_key_pair();
        let identity_b = generate_signing_key_pair();
        let spk = generate_signed_prekey(&identity_a, FIXED_TS);
        let bundle = spk.bundle();
        assert!(matches!(
            verify_bundle(&bundle, &identity_b.verifying),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn signature_without_domain_prefix_fails_verification() {
        let identity = generate_signing_key_pair();
        let kp = generate_key_pair();
        let bare_signature = identity.sign(kp.public.as_bytes());
        let bundle = SignedPreKeyBundle {
            public_key: kp.public,
            signature: bare_signature,
            created_at: FIXED_TS,
        };
        assert!(matches!(
            verify_bundle(&bundle, &identity.verifying),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn bundle_fields_match_signed_prekey() {
        let identity = generate_signing_key_pair();
        let spk = generate_signed_prekey(&identity, FIXED_TS);
        let bundle = spk.bundle();
        assert_eq!(bundle.public_key.as_bytes(), spk.public().as_bytes());
        assert_eq!(bundle.signature.to_bytes(), spk.signature().to_bytes());
        assert_eq!(bundle.created_at, spk.created_at());
    }

    #[test]
    fn from_secret_bytes_round_trip() {
        let identity = generate_signing_key_pair();
        let original = generate_signed_prekey(&identity, FIXED_TS);
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
    fn diffie_hellman_after_from_secret_bytes() {
        let identity = generate_signing_key_pair();
        let spk = generate_signed_prekey(&identity, FIXED_TS);
        let restored = SignedPreKey::from_secret_bytes(
            *spk.to_secret_bytes(),
            spk.signature().to_bytes(),
            spk.created_at(),
        );
        let peer = generate_key_pair();
        let dh_orig = spk.diffie_hellman(&peer.public);
        let dh_restored = restored.diffie_hellman(&peer.public);
        assert_eq!(dh_orig.as_bytes(), dh_restored.as_bytes());
    }

    #[test]
    fn restored_bundle_verifies_against_original_identity() {
        let identity = generate_signing_key_pair();
        let original = generate_signed_prekey(&identity, FIXED_TS);
        let restored = SignedPreKey::from_secret_bytes(
            *original.to_secret_bytes(),
            original.signature().to_bytes(),
            original.created_at(),
        );
        let bundle = restored.bundle();
        assert!(verify_bundle(&bundle, &identity.verifying).is_ok());
    }
}
