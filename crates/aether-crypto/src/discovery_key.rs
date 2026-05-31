//! Provides rotatable discovery keys signed by the permanent identity key.
//!
//! A discovery key is a rotatable pair of independent Ed25519 signing material and X25519
//! key-agreement material, signed by the permanent identity key. The discovery key's Ed25519 key
//! signs the signed pre-key bundle, so rotating the discovery key refreshes published material
//! without touching the identity key. Each discovery key carries a monotonic epoch and a creation
//! timestamp, both covered by the identity-key signature.
//!
//! See `aether-core`'s `0003-two-key-identity` decision record for the identity-vs-discovery split.

use crate::error::CryptoError;
use crate::keys::{SigningKeyPair, generate_signing_key_pair};
use crate::signed_prekey::{SignedPreKey, generate_signed_prekey};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::{CryptoRng, RngCore};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::{ZeroizeOnDrop, Zeroizing};

// Domain separator for identity-key signatures over discovery keys.
const DISCOVERY_KEY_DOMAIN: &[u8] = b"aether-dk-v1:";

/// A rotatable discovery key: X25519 key-agreement material plus an Ed25519 signing key, both
/// signed by the permanent identity key.
///
/// The two secrets are zeroed on drop. The public keys, identity signature, epoch, and timestamp
/// remain available through accessors and [`Self::bundle`].
#[derive(ZeroizeOnDrop)]
pub struct DiscoveryKey {
    key_agreement_secret: StaticSecret,
    signing: SigningKeyPair,
    #[zeroize(skip)]
    key_agreement_public: PublicKey,
    #[zeroize(skip)]
    identity_signature: Signature,
    #[zeroize(skip)]
    epoch: u32,
    #[zeroize(skip)]
    created_at: u64,
}

impl DiscoveryKey {
    /// Returns the X25519 key-agreement public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.key_agreement_public
    }

    /// Returns the Ed25519 verifying key that validates this discovery key's signed pre-keys.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.signing.verifying
    }

    /// Returns the identity-key signature over this discovery key.
    pub fn identity_signature(&self) -> &Signature {
        &self.identity_signature
    }

    /// Returns the rotation epoch.
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Returns the Unix timestamp (seconds) when this discovery key was generated.
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Performs an X25519 Diffie-Hellman exchange between this discovery key's secret and `peer`.
    pub fn diffie_hellman(&self, peer: &PublicKey) -> SharedSecret {
        self.key_agreement_secret.diffie_hellman(peer)
    }

    /// Returns the public form of this discovery key for distribution to peers.
    pub fn bundle(&self) -> DiscoveryKeyBundle {
        DiscoveryKeyBundle {
            public_key: self.key_agreement_public,
            verifying_key: self.signing.verifying,
            signature: self.identity_signature,
            epoch: self.epoch,
            created_at: self.created_at,
        }
    }

    /// Exports the X25519 key-agreement secret bytes for secure persistence.
    pub fn key_agreement_secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.key_agreement_secret.to_bytes())
    }

    /// Exports the Ed25519 signing secret bytes for secure persistence.
    pub fn signing_secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        self.signing.to_signing_bytes()
    }

    /// Restores a discovery key from its persisted parts.
    ///
    /// The public keys are derived from the secret bytes; the identity signature, epoch, and
    /// timestamp are taken as given. The caller verifies the signature with
    /// [`verify_discovery_key_bundle`] after restoring.
    pub fn from_parts(
        key_agreement_secret: [u8; 32],
        signing_secret: [u8; 32],
        identity_signature: [u8; 64],
        epoch: u32,
        created_at: u64,
    ) -> Self {
        let key_agreement_secret = StaticSecret::from(key_agreement_secret);
        let key_agreement_public = PublicKey::from(&key_agreement_secret);
        let signing = SigningKeyPair::from_signing_bytes(signing_secret);
        let identity_signature = Signature::from_bytes(&identity_signature);
        DiscoveryKey {
            key_agreement_secret,
            signing,
            key_agreement_public,
            identity_signature,
            epoch,
            created_at,
        }
    }
}

/// Public discovery-key material distributed to peers.
///
/// The identity verifying key is not embedded. Callers pass it to [`verify_discovery_key_bundle`]
/// separately, then verify signed pre-keys against this bundle's [`Self::verifying_key`].
#[derive(Clone, Debug)]
pub struct DiscoveryKeyBundle {
    /// X25519 key-agreement public key.
    pub public_key: PublicKey,
    /// Ed25519 verifying key that validates this discovery key's signed pre-keys.
    pub verifying_key: VerifyingKey,
    /// Identity-key signature over the domain-separated discovery-key payload.
    pub signature: Signature,
    /// Rotation epoch, monotonic within a storage lineage.
    pub epoch: u32,
    /// Unix timestamp in seconds when the discovery key was generated.
    pub created_at: u64,
}

impl DiscoveryKeyBundle {
    /// Builds a bundle from received wire bytes, validating each encoding.
    ///
    /// The X25519 public key and signature are length-validated (32 and 64 bytes). The Ed25519
    /// verifying key is decoded with [`VerifyingKey::from_bytes`], which rejects encodings that do
    /// not decompress to a valid Edwards point. X25519 has no equivalent rejection: `x25519-dalek`
    /// accepts any 32 bytes and RFC 7748 prescribes masking, not rejection; the X25519 public key
    /// is authenticated by the identity-key signature instead.
    ///
    /// # Errors
    /// - [`CryptoError::InvalidKeyEncoding`] when a field has the wrong length or the verifying key
    ///   does not decompress to a valid Edwards point.
    pub fn from_bytes(
        public_key: &[u8],
        verifying_key: &[u8],
        signature: &[u8],
        epoch: u32,
        created_at: u64,
    ) -> Result<Self, CryptoError> {
        let public_key_bytes: [u8; 32] = public_key
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyEncoding)?;
        let verifying_key_bytes: [u8; 32] = verifying_key
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyEncoding)?;
        let signature_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyEncoding)?;
        let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
            .map_err(|_| CryptoError::InvalidKeyEncoding)?;
        Ok(DiscoveryKeyBundle {
            public_key: PublicKey::from(public_key_bytes),
            verifying_key,
            signature: Signature::from_bytes(&signature_bytes),
            epoch,
            created_at,
        })
    }
}

/// Generates a discovery key using `rng`, signed by the identity signing key.
///
/// The X25519 key-agreement secret and the Ed25519 signing key are drawn independently from `rng`.
#[must_use]
pub fn generate_discovery_key<R: RngCore + CryptoRng>(
    rng: &mut R,
    identity: &SigningKeyPair,
    epoch: u32,
    created_at: u64,
) -> DiscoveryKey {
    let key_agreement_secret = StaticSecret::random_from_rng(&mut *rng);
    let key_agreement_public = PublicKey::from(&key_agreement_secret);
    let signing = generate_signing_key_pair(rng);
    let payload =
        discovery_key_payload(&key_agreement_public, &signing.verifying, epoch, created_at);
    let identity_signature = identity.sign(&payload);
    DiscoveryKey {
        key_agreement_secret,
        signing,
        key_agreement_public,
        identity_signature,
        epoch,
        created_at,
    }
}

/// Verifies that a discovery-key bundle was signed by an identity verifying key.
///
/// # Errors
/// - [`CryptoError::SignatureInvalid`] when the signature does not validate.
pub fn verify_discovery_key_bundle(
    bundle: &DiscoveryKeyBundle,
    identity_verifying_key: &VerifyingKey,
) -> Result<(), CryptoError> {
    let payload = discovery_key_payload(
        &bundle.public_key,
        &bundle.verifying_key,
        bundle.epoch,
        bundle.created_at,
    );
    identity_verifying_key
        .verify(&payload, &bundle.signature)
        .map_err(|_| CryptoError::SignatureInvalid)
}

/// Generates a signed pre-key whose bundle is signed by `discovery_key`.
///
/// This is the correct path for identity publication under the two-key identity: the signed
/// pre-key is verified with the discovery key's [`DiscoveryKey::verifying_key`], not the identity
/// key. The discovery key's signing secret stays inside this crate.
#[must_use]
pub fn generate_signed_prekey_for_discovery_key<R: RngCore + CryptoRng>(
    rng: &mut R,
    discovery_key: &DiscoveryKey,
    created_at: u64,
) -> SignedPreKey {
    generate_signed_prekey(rng, &discovery_key.signing, created_at)
}

fn discovery_key_payload(
    key_agreement_public: &PublicKey,
    verifying_key: &VerifyingKey,
    epoch: u32,
    created_at: u64,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(DISCOVERY_KEY_DOMAIN.len() + 32 + 32 + 4 + 8);
    payload.extend_from_slice(DISCOVERY_KEY_DOMAIN);
    payload.extend_from_slice(key_agreement_public.as_bytes());
    payload.extend_from_slice(verifying_key.as_bytes());
    payload.extend_from_slice(&epoch.to_be_bytes());
    payload.extend_from_slice(&created_at.to_be_bytes());
    payload
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signed_prekey::verify_bundle;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    const FIXED_EPOCH: u32 = 7;
    const FIXED_CREATED_AT: u64 = 1_700_000_000;

    fn seeded_rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([5u8; 32])
    }

    #[test]
    fn bundle_verifies_under_identity_key() {
        let mut rng = seeded_rng();
        let identity = generate_signing_key_pair(&mut rng);
        let discovery_key =
            generate_discovery_key(&mut rng, &identity, FIXED_EPOCH, FIXED_CREATED_AT);
        let bundle = discovery_key.bundle();
        assert!(verify_discovery_key_bundle(&bundle, &identity.verifying).is_ok());
    }

    #[test]
    fn bundle_fields_match_discovery_key() {
        let mut rng = seeded_rng();
        let identity = generate_signing_key_pair(&mut rng);
        let discovery_key =
            generate_discovery_key(&mut rng, &identity, FIXED_EPOCH, FIXED_CREATED_AT);
        let bundle = discovery_key.bundle();
        assert_eq!(
            bundle.public_key.as_bytes(),
            discovery_key.public_key().as_bytes()
        );
        assert_eq!(
            bundle.verifying_key.as_bytes(),
            discovery_key.verifying_key().as_bytes()
        );
        assert_eq!(
            bundle.signature.to_bytes(),
            discovery_key.identity_signature().to_bytes()
        );
        assert_eq!(bundle.epoch, FIXED_EPOCH);
        assert_eq!(bundle.created_at, FIXED_CREATED_AT);
    }

    #[test]
    fn verify_rejects_wrong_identity() {
        let mut rng = seeded_rng();
        let identity = generate_signing_key_pair(&mut rng);
        let other_identity = generate_signing_key_pair(&mut rng);
        let bundle =
            generate_discovery_key(&mut rng, &identity, FIXED_EPOCH, FIXED_CREATED_AT).bundle();
        assert!(matches!(
            verify_discovery_key_bundle(&bundle, &other_identity.verifying),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn verify_rejects_tampered_key_agreement_public() {
        let mut rng = seeded_rng();
        let identity = generate_signing_key_pair(&mut rng);
        let mut bundle =
            generate_discovery_key(&mut rng, &identity, FIXED_EPOCH, FIXED_CREATED_AT).bundle();
        let mut public_key_bytes = *bundle.public_key.as_bytes();
        public_key_bytes[0] ^= 0x01;
        bundle.public_key = PublicKey::from(public_key_bytes);
        assert!(matches!(
            verify_discovery_key_bundle(&bundle, &identity.verifying),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn verify_rejects_tampered_verifying_key() {
        let mut rng = seeded_rng();
        let identity = generate_signing_key_pair(&mut rng);
        let mut bundle =
            generate_discovery_key(&mut rng, &identity, FIXED_EPOCH, FIXED_CREATED_AT).bundle();
        // Swap in a different, valid verifying key; the signed payload no longer matches.
        bundle.verifying_key = generate_signing_key_pair(&mut rng).verifying;
        assert!(matches!(
            verify_discovery_key_bundle(&bundle, &identity.verifying),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn verify_rejects_tampered_epoch() {
        let mut rng = seeded_rng();
        let identity = generate_signing_key_pair(&mut rng);
        let mut bundle =
            generate_discovery_key(&mut rng, &identity, FIXED_EPOCH, FIXED_CREATED_AT).bundle();
        bundle.epoch += 1;
        assert!(matches!(
            verify_discovery_key_bundle(&bundle, &identity.verifying),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn verify_rejects_tampered_created_at() {
        let mut rng = seeded_rng();
        let identity = generate_signing_key_pair(&mut rng);
        let mut bundle =
            generate_discovery_key(&mut rng, &identity, FIXED_EPOCH, FIXED_CREATED_AT).bundle();
        bundle.created_at += 1;
        assert!(matches!(
            verify_discovery_key_bundle(&bundle, &identity.verifying),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn signature_without_domain_prefix_fails_verification() {
        let mut rng = seeded_rng();
        let identity = generate_signing_key_pair(&mut rng);
        let discovery_key =
            generate_discovery_key(&mut rng, &identity, FIXED_EPOCH, FIXED_CREATED_AT);
        let mut bundle = discovery_key.bundle();
        // Re-sign the same fields without the domain separator.
        let mut bare_payload = Vec::new();
        bare_payload.extend_from_slice(bundle.public_key.as_bytes());
        bare_payload.extend_from_slice(bundle.verifying_key.as_bytes());
        bare_payload.extend_from_slice(&bundle.epoch.to_be_bytes());
        bare_payload.extend_from_slice(&bundle.created_at.to_be_bytes());
        bundle.signature = identity.sign(&bare_payload);
        assert!(matches!(
            verify_discovery_key_bundle(&bundle, &identity.verifying),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn signing_and_key_agreement_secrets_are_independent() {
        let mut rng = seeded_rng();
        let identity = generate_signing_key_pair(&mut rng);
        let discovery_key =
            generate_discovery_key(&mut rng, &identity, FIXED_EPOCH, FIXED_CREATED_AT);
        assert_ne!(
            *discovery_key.key_agreement_secret_bytes(),
            *discovery_key.signing_secret_bytes()
        );
    }

    #[test]
    fn from_parts_round_trip() {
        let mut rng = seeded_rng();
        let identity = generate_signing_key_pair(&mut rng);
        let original = generate_discovery_key(&mut rng, &identity, FIXED_EPOCH, FIXED_CREATED_AT);
        let restored = DiscoveryKey::from_parts(
            *original.key_agreement_secret_bytes(),
            *original.signing_secret_bytes(),
            original.identity_signature().to_bytes(),
            original.epoch(),
            original.created_at(),
        );
        assert_eq!(
            restored.public_key().as_bytes(),
            original.public_key().as_bytes()
        );
        assert_eq!(
            restored.verifying_key().as_bytes(),
            original.verifying_key().as_bytes()
        );
        assert_eq!(
            restored.identity_signature().to_bytes(),
            original.identity_signature().to_bytes()
        );
        assert_eq!(restored.epoch(), original.epoch());
        assert_eq!(restored.created_at(), original.created_at());
        // The restored bundle still verifies against the original identity.
        assert!(verify_discovery_key_bundle(&restored.bundle(), &identity.verifying).is_ok());
    }

    #[test]
    fn from_bytes_accepts_valid_bundle() {
        let mut rng = seeded_rng();
        let identity = generate_signing_key_pair(&mut rng);
        let bundle =
            generate_discovery_key(&mut rng, &identity, FIXED_EPOCH, FIXED_CREATED_AT).bundle();
        let parsed = DiscoveryKeyBundle::from_bytes(
            bundle.public_key.as_bytes(),
            bundle.verifying_key.as_bytes(),
            &bundle.signature.to_bytes(),
            bundle.epoch,
            bundle.created_at,
        )
        .unwrap();
        assert!(verify_discovery_key_bundle(&parsed, &identity.verifying).is_ok());
    }

    #[test]
    fn from_bytes_rejects_invalid_verifying_key() {
        // Find a 32-byte value that is not a valid Edwards point (decompression fails). Roughly
        // half of all encodings are non-decompressable, so a small scan always finds one.
        let mut bytes = [0u8; 32];
        while VerifyingKey::from_bytes(&bytes).is_ok() {
            bytes[0] = bytes[0]
                .checked_add(1)
                .expect("a non-decompressable Ed25519 encoding exists in 0..=255");
        }
        let result = DiscoveryKeyBundle::from_bytes(
            &[0u8; 32],
            &bytes,
            &[0u8; 64],
            FIXED_EPOCH,
            FIXED_CREATED_AT,
        );
        assert!(matches!(result, Err(CryptoError::InvalidKeyEncoding)));
    }

    #[test]
    fn from_bytes_rejects_wrong_lengths() {
        assert!(matches!(
            DiscoveryKeyBundle::from_bytes(&[0u8; 31], &[0u8; 32], &[0u8; 64], 0, 0),
            Err(CryptoError::InvalidKeyEncoding)
        ));
        assert!(matches!(
            DiscoveryKeyBundle::from_bytes(&[0u8; 32], &[0u8; 32], &[0u8; 63], 0, 0),
            Err(CryptoError::InvalidKeyEncoding)
        ));
    }

    #[test]
    fn from_bytes_accepts_any_32_byte_x25519_public() {
        // X25519 has no canonical-rejection check; only length is validated.
        let mut rng = seeded_rng();
        let verifying_key = generate_signing_key_pair(&mut rng).verifying;
        let result = DiscoveryKeyBundle::from_bytes(
            &[0xFFu8; 32],
            verifying_key.as_bytes(),
            &[0u8; 64],
            FIXED_EPOCH,
            FIXED_CREATED_AT,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn discovery_signed_prekey_verifies_under_discovery_key_only() {
        let mut rng = seeded_rng();
        let identity = generate_signing_key_pair(&mut rng);
        let discovery_key =
            generate_discovery_key(&mut rng, &identity, FIXED_EPOCH, FIXED_CREATED_AT);
        let signed_prekey =
            generate_signed_prekey_for_discovery_key(&mut rng, &discovery_key, FIXED_CREATED_AT);
        let bundle = signed_prekey.bundle();
        assert!(verify_bundle(&bundle, discovery_key.verifying_key()).is_ok());
        // The identity key did not sign the prekey; only the discovery key did.
        assert!(matches!(
            verify_bundle(&bundle, &identity.verifying),
            Err(CryptoError::SignatureInvalid)
        ));
    }
}
