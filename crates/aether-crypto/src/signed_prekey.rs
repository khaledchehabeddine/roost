//! Provides signed X25519 pre-keys for the X3DH handshake.

use crate::error::CryptoError;
use crate::keys::{
    SigningKeyPair, StaticSignatureContext, validate_x25519_public_key, verify_with_static_context,
};
use ed25519_dalek::{Signature, VerifyingKey};
use rand::{CryptoRng, RngCore};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// Domain separator for signatures over signed pre-key public keys and epoch metadata.
const SIGNED_PREKEY_CONTEXT: StaticSignatureContext =
    StaticSignatureContext::new(b'A', b"etherSPK-v1:");

/// An X25519 pre-key signed by an Ed25519 signing key.
///
/// The secret key is zeroed on drop. The public key, signature, epoch, and creation timestamp
/// remain available through accessors and bundle export.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SignedPreKey {
    secret_key: StaticSecret,
    #[zeroize(skip)]
    public_key: PublicKey,
    #[zeroize(skip)]
    signature: Signature,
    #[zeroize(skip)]
    epoch: u32,
    #[zeroize(skip)]
    created_at: u64,
}

impl SignedPreKey {
    /// Returns the X25519 public key.
    pub fn public(&self) -> &PublicKey {
        &self.public_key
    }

    /// Returns the Ed25519 signature over
    /// `public_key[32] || epoch.to_be_bytes() || created_at.to_be_bytes()` under the signed
    /// pre-key signature context.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Returns the discovery-key epoch this signed pre-key was produced under.
    pub fn epoch(&self) -> u32 {
        self.epoch
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

    /// Restores a signed pre-key from secret bytes and stored metadata.
    ///
    /// The public key is derived from `secret`. The stored signature is not verified here.
    pub fn from_secret_bytes(
        secret: [u8; 32],
        signature: [u8; 64],
        epoch: u32,
        created_at: u64,
    ) -> Self {
        let secret_key = StaticSecret::from(secret);
        let public_key = PublicKey::from(&secret_key);
        let signature = Signature::from_bytes(&signature);
        SignedPreKey {
            secret_key,
            public_key,
            signature,
            epoch,
            created_at,
        }
    }

    /// Returns the public form of this signed pre-key for distribution to peers.
    pub fn bundle(&self) -> SignedPreKeyBundle {
        SignedPreKeyBundle {
            public_key: self.public_key,
            signature: self.signature,
            epoch: self.epoch,
            created_at: self.created_at,
        }
    }
}

/// Public signed pre-key material distributed to peers.
///
/// The signer's verifying key is not embedded. Pass the verifying key to
/// [`verify_signed_prekey_bundle`].
#[derive(Clone, Debug)]
pub struct SignedPreKeyBundle {
    /// X25519 public key used by the peer during handshake root-key derivation.
    pub public_key: PublicKey,
    /// Ed25519 signature over
    /// `public_key[32] || epoch.to_be_bytes() || created_at.to_be_bytes()` under the signed
    /// pre-key signature context.
    pub signature: Signature,
    /// Discovery-key epoch this signed pre-key was produced under.
    pub epoch: u32,
    /// Unix timestamp in seconds covered by [`Self::signature`].
    pub created_at: u64,
}

impl SignedPreKeyBundle {
    /// Builds a bundle from received wire bytes.
    ///
    /// This validates byte lengths only. Call [`verify_signed_prekey_bundle`] with the discovery
    /// verifying key to authenticate the parsed fields.
    ///
    /// # Errors
    /// - [`CryptoError::InvalidKeyEncoding`] when the public key or signature has the wrong
    ///   length.
    pub fn from_bytes(
        public_key: &[u8],
        signature: &[u8],
        epoch: u32,
        created_at: u64,
    ) -> Result<Self, CryptoError> {
        let public_key_bytes: [u8; 32] = public_key
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyEncoding)?;
        if !validate_x25519_public_key(&public_key_bytes) {
            return Err(CryptoError::InvalidKeyEncoding);
        }
        let signature_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyEncoding)?;
        Ok(Self {
            public_key: PublicKey::from(public_key_bytes),
            signature: Signature::from_bytes(&signature_bytes),
            epoch,
            created_at,
        })
    }
}

/// Generates a signed pre-key with the supplied Ed25519 signing key.
#[must_use]
pub fn generate_signed_prekey<R: RngCore + CryptoRng>(
    rng: &mut R,
    signing_key: &SigningKeyPair,
    epoch: u32,
    created_at: u64,
) -> SignedPreKey {
    let secret_key = StaticSecret::random_from_rng(&mut *rng);
    let public_key = PublicKey::from(&secret_key);
    let payload = signed_prekey_payload(&public_key, epoch, created_at);
    let signature = signing_key.sign_with_static_context(SIGNED_PREKEY_CONTEXT, &payload);
    SignedPreKey {
        secret_key,
        public_key,
        signature,
        epoch,
        created_at,
    }
}

/// Verifies a signed pre-key bundle against the verifying key that signed it.
///
/// # Errors
/// - [`CryptoError::SignatureInvalid`] when the signature does not validate.
pub fn verify_signed_prekey_bundle(
    bundle: &SignedPreKeyBundle,
    signer_verifying_key: &VerifyingKey,
) -> Result<(), CryptoError> {
    let payload = signed_prekey_payload(&bundle.public_key, bundle.epoch, bundle.created_at);
    verify_with_static_context(
        signer_verifying_key,
        SIGNED_PREKEY_CONTEXT,
        &payload,
        &bundle.signature,
    )
}

fn signed_prekey_payload(public_key: &PublicKey, epoch: u32, created_at: u64) -> Vec<u8> {
    let mut payload = Vec::with_capacity(32 + 4 + 8);
    payload.extend_from_slice(public_key.as_bytes());
    payload.extend_from_slice(&epoch.to_be_bytes());
    payload.extend_from_slice(&created_at.to_be_bytes());
    payload
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{generate_key_pair, generate_signing_key_pair};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    const FIXED_CREATED_AT: u64 = 1_700_000_000;
    const FIXED_EPOCH: u32 = 7;

    fn seeded_rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([4u8; 32])
    }

    #[test]
    fn generate_and_verify_round_trip() {
        let mut rng = seeded_rng();
        let signing_key = generate_signing_key_pair(&mut rng);
        let signed_prekey =
            generate_signed_prekey(&mut rng, &signing_key, FIXED_EPOCH, FIXED_CREATED_AT);
        let bundle = signed_prekey.bundle();
        assert!(verify_signed_prekey_bundle(&bundle, &signing_key.verifying).is_ok());
    }

    #[test]
    fn bundle_fields_match_signed_prekey() {
        let mut rng = seeded_rng();
        let signing_key = generate_signing_key_pair(&mut rng);
        let signed_prekey =
            generate_signed_prekey(&mut rng, &signing_key, FIXED_EPOCH, FIXED_CREATED_AT);
        let bundle = signed_prekey.bundle();
        assert_eq!(
            bundle.public_key.as_bytes(),
            signed_prekey.public().as_bytes()
        );
        assert_eq!(
            bundle.signature.to_bytes(),
            signed_prekey.signature().to_bytes()
        );
        assert_eq!(bundle.epoch, signed_prekey.epoch());
        assert_eq!(bundle.created_at, signed_prekey.created_at());
    }

    #[test]
    fn verify_rejects_tampered_public_key() {
        let mut rng = seeded_rng();
        let signing_key = generate_signing_key_pair(&mut rng);
        let signed_prekey =
            generate_signed_prekey(&mut rng, &signing_key, FIXED_EPOCH, FIXED_CREATED_AT);
        let mut bundle = signed_prekey.bundle();
        let mut public_key_bytes = *bundle.public_key.as_bytes();
        public_key_bytes[0] ^= 0x01;
        bundle.public_key = PublicKey::from(public_key_bytes);
        assert!(matches!(
            verify_signed_prekey_bundle(&bundle, &signing_key.verifying),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let mut rng = seeded_rng();
        let signing_key = generate_signing_key_pair(&mut rng);
        let signed_prekey =
            generate_signed_prekey(&mut rng, &signing_key, FIXED_EPOCH, FIXED_CREATED_AT);
        let bundle = signed_prekey.bundle();
        let mut signature_bytes = bundle.signature.to_bytes();
        signature_bytes[0] ^= 0x01;
        let tampered = SignedPreKeyBundle {
            public_key: bundle.public_key,
            signature: Signature::from_bytes(&signature_bytes),
            epoch: bundle.epoch,
            created_at: bundle.created_at,
        };
        assert!(matches!(
            verify_signed_prekey_bundle(&tampered, &signing_key.verifying),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn verify_rejects_wrong_signer() {
        let mut rng = seeded_rng();
        let signing_key = generate_signing_key_pair(&mut rng);
        let wrong_signing_key = generate_signing_key_pair(&mut rng);
        let signed_prekey =
            generate_signed_prekey(&mut rng, &signing_key, FIXED_EPOCH, FIXED_CREATED_AT);
        let bundle = signed_prekey.bundle();
        assert!(matches!(
            verify_signed_prekey_bundle(&bundle, &wrong_signing_key.verifying),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn verify_rejects_tampered_epoch() {
        let mut rng = seeded_rng();
        let signing_key = generate_signing_key_pair(&mut rng);
        let signed_prekey =
            generate_signed_prekey(&mut rng, &signing_key, FIXED_EPOCH, FIXED_CREATED_AT);
        let bundle = signed_prekey.bundle();
        let tampered = SignedPreKeyBundle {
            public_key: bundle.public_key,
            signature: bundle.signature,
            epoch: bundle.epoch + 1,
            created_at: bundle.created_at,
        };
        assert!(matches!(
            verify_signed_prekey_bundle(&tampered, &signing_key.verifying),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn verify_rejects_tampered_created_at() {
        let mut rng = seeded_rng();
        let signing_key = generate_signing_key_pair(&mut rng);
        let signed_prekey =
            generate_signed_prekey(&mut rng, &signing_key, FIXED_EPOCH, FIXED_CREATED_AT);
        let bundle = signed_prekey.bundle();
        let tampered = SignedPreKeyBundle {
            public_key: bundle.public_key,
            signature: bundle.signature,
            epoch: bundle.epoch,
            created_at: bundle.created_at + 1,
        };
        assert!(matches!(
            verify_signed_prekey_bundle(&tampered, &signing_key.verifying),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn signature_without_domain_prefix_fails_verification() {
        let mut rng = seeded_rng();
        let signing_key = generate_signing_key_pair(&mut rng);
        let key_pair = generate_key_pair(&mut rng);
        let bare_signature = signing_key.sign(key_pair.public.as_bytes());
        let bundle = SignedPreKeyBundle {
            public_key: key_pair.public,
            signature: bare_signature,
            epoch: FIXED_EPOCH,
            created_at: FIXED_CREATED_AT,
        };
        assert!(matches!(
            verify_signed_prekey_bundle(&bundle, &signing_key.verifying),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn bundle_from_bytes_round_trip_preserves_fields() {
        let mut rng = seeded_rng();
        let signing_key = generate_signing_key_pair(&mut rng);
        let signed_prekey =
            generate_signed_prekey(&mut rng, &signing_key, FIXED_EPOCH, FIXED_CREATED_AT);
        let bundle = signed_prekey.bundle();

        let parsed = SignedPreKeyBundle::from_bytes(
            bundle.public_key.as_bytes(),
            &bundle.signature.to_bytes(),
            bundle.epoch,
            bundle.created_at,
        )
        .unwrap();

        assert_eq!(parsed.public_key.as_bytes(), bundle.public_key.as_bytes());
        assert_eq!(parsed.signature.to_bytes(), bundle.signature.to_bytes());
        assert_eq!(parsed.epoch, bundle.epoch);
        assert_eq!(parsed.created_at, bundle.created_at);
    }

    #[test]
    fn bundle_from_bytes_rejects_wrong_lengths() {
        assert!(matches!(
            SignedPreKeyBundle::from_bytes(&[0u8; 31], &[0u8; 64], FIXED_EPOCH, FIXED_CREATED_AT),
            Err(CryptoError::InvalidKeyEncoding)
        ));
        assert!(matches!(
            SignedPreKeyBundle::from_bytes(&[0u8; 32], &[0u8; 63], FIXED_EPOCH, FIXED_CREATED_AT),
            Err(CryptoError::InvalidKeyEncoding)
        ));
    }

    #[test]
    fn from_secret_bytes_round_trip() {
        let mut rng = seeded_rng();
        let signing_key = generate_signing_key_pair(&mut rng);
        let original =
            generate_signed_prekey(&mut rng, &signing_key, FIXED_EPOCH, FIXED_CREATED_AT);
        let restored = SignedPreKey::from_secret_bytes(
            *original.to_secret_bytes(),
            original.signature().to_bytes(),
            original.epoch(),
            original.created_at(),
        );
        assert_eq!(restored.public().as_bytes(), original.public().as_bytes());
        assert_eq!(
            restored.signature().to_bytes(),
            original.signature().to_bytes()
        );
        assert_eq!(restored.epoch(), original.epoch());
        assert_eq!(restored.created_at(), original.created_at());
        assert_eq!(*restored.to_secret_bytes(), *original.to_secret_bytes());
    }

    #[test]
    fn from_secret_bytes_restores_diffie_hellman_secret() {
        let mut rng = seeded_rng();
        let signing_key = generate_signing_key_pair(&mut rng);
        let original =
            generate_signed_prekey(&mut rng, &signing_key, FIXED_EPOCH, FIXED_CREATED_AT);
        let restored = SignedPreKey::from_secret_bytes(
            *original.to_secret_bytes(),
            original.signature().to_bytes(),
            original.epoch(),
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
