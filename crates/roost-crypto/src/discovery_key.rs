//! Provides rotatable discovery keys signed by the permanent identity key.
//!
//! A discovery key pairs X25519 key-agreement material with an Ed25519 signing key. The identity
//! signature covers the public keys, epoch, and creation timestamp. The discovery signing key signs
//! signed pre-key public keys.

use crate::keys::{
    PublicIdentityKey, PublicKeyError, SigningKeyPair, generate_signing_key_pair,
    identity_key_binding_payload, is_valid_x25519_public_key, parse_ed25519_verifying_key_bytes,
    verify_with_context,
};
use crate::signed_prekey::{SignedPreKey, generate_signed_prekey};
use ed25519_dalek::{Signature, VerifyingKey};
use rand::{CryptoRng, RngCore};
use roost_protocol::SignatureError;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::{ZeroizeOnDrop, Zeroizing};

// Domain separator for identity-key signatures over discovery keys (IK→DK).
const DISCOVERY_KEY_CONTEXT: &[u8] = b"AetherDK-v1:";

// Domain separator for discovery-key signatures over identity keys (DK→IK).
const DISCOVERY_TO_IDENTITY_CONTEXT: &[u8] = b"AetherDKToIK-v1:";

/// A rotatable discovery key signed by the identity key.
///
/// Holds X25519 key-agreement material and an Ed25519 signing key. The two secret keys are zeroed
/// on drop.
#[derive(ZeroizeOnDrop)]
pub struct DiscoveryKey {
    key_agreement_secret: StaticSecret,
    signing: SigningKeyPair,
    #[zeroize(skip)]
    key_agreement_public: PublicKey,
    #[zeroize(skip)]
    epoch: u32,
    #[zeroize(skip)]
    created_at_secs: u64,
    #[zeroize(skip)]
    identity_signature: Signature,
}

impl DiscoveryKey {
    /// Restores a discovery key from secret bytes.
    ///
    /// Public keys are derived from the secret bytes. The caller must verify the restored key
    /// with [`verify_public_discovery_key`].
    pub fn from_secret_bytes(
        key_agreement_secret: [u8; 32],
        signing_secret: [u8; 32],
        epoch: u32,
        created_at_secs: u64,
        identity_signature: [u8; 64],
    ) -> Self {
        let key_agreement_secret = StaticSecret::from(key_agreement_secret);
        let key_agreement_public = PublicKey::from(&key_agreement_secret);
        let signing = SigningKeyPair::from_signing_bytes(signing_secret);
        let identity_signature = Signature::from_bytes(&identity_signature);
        DiscoveryKey {
            key_agreement_secret,
            signing,
            key_agreement_public,
            epoch,
            created_at_secs,
            identity_signature,
        }
    }

    /// Returns the X25519 key-agreement public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.key_agreement_public
    }

    /// Returns the rotation epoch.
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Returns the Unix timestamp (seconds) when this discovery key was generated.
    pub fn created_at_secs(&self) -> u64 {
        self.created_at_secs
    }

    /// Returns the identity-key signature over this discovery key.
    pub fn identity_signature(&self) -> &Signature {
        &self.identity_signature
    }

    /// Performs an X25519 Diffie-Hellman exchange between this discovery key's secret and `peer`.
    pub fn diffie_hellman(&self, peer: &PublicKey) -> SharedSecret {
        self.key_agreement_secret.diffie_hellman(peer)
    }

    /// Returns the public form of this discovery key for distribution to peers.
    pub fn public(&self) -> PublicDiscoveryKey {
        PublicDiscoveryKey {
            public_key: self.key_agreement_public,
            verifying_key: self.signing.verifying,
            epoch: self.epoch,
            created_at_secs: self.created_at_secs,
            signature: self.identity_signature,
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

    /// Signs `identity`'s public halves with this discovery key's Ed25519 half.
    ///
    /// This is the DK→IK half of the mutual binding. A peer starting from a discovery
    /// key verifies it to learn that the discovery key really authorized the identity it was
    /// handed, without trusting whoever handed it over.
    ///
    /// The signature covers only the two identity public halves — no epoch, no timestamp. The
    /// IK→DK direction needs an epoch because one permanent identity key signs many discovery keys
    /// over its lifetime; this direction does not, because a fresh discovery key is minted per
    /// epoch and so already identifies the epoch it belongs to.
    pub fn sign_identity_binding(
        &self,
        identity: &PublicIdentityKey,
    ) -> Result<Signature, SignatureError> {
        self.signing.sign_with_context(
            DISCOVERY_TO_IDENTITY_CONTEXT,
            &identity_key_binding_payload(&identity.public_key, &identity.verifying_key),
        )
    }
}

/// Verifies that `discovery_verifying_key` signed `identity`'s public halves.
///
/// The DK→IK half of the mutual binding. Verify both directions before trusting a
/// discovery-key-to-identity mapping: this one proves the discovery key authorized the identity,
/// and [`verify_public_discovery_key`] proves the identity authorized the discovery key.
pub fn verify_discovery_to_identity_binding(
    identity: &PublicIdentityKey,
    discovery_verifying_key: &VerifyingKey,
    signature: &Signature,
) -> Result<(), PublicKeyError> {
    verify_with_context(
        discovery_verifying_key,
        DISCOVERY_TO_IDENTITY_CONTEXT,
        &identity_key_binding_payload(&identity.public_key, &identity.verifying_key),
        signature,
    )
    .map_err(Into::into)
}

/// Public discovery-key material distributed to peers.
///
/// Verify this key with the identity verifying key before trusting [`Self::verifying_key`].
#[derive(Clone, Debug)]
pub struct PublicDiscoveryKey {
    /// X25519 key-agreement public key.
    pub public_key: PublicKey,
    /// Ed25519 verifying key that validates this discovery key's signed pre-keys.
    pub verifying_key: VerifyingKey,
    /// Rotation epoch, monotonic within a storage lineage.
    pub epoch: u32,
    /// Unix timestamp in seconds when the discovery key was generated.
    pub created_at_secs: u64,
    /// Identity-key signature over the domain-separated discovery-key payload.
    pub signature: Signature,
}

impl PublicDiscoveryKey {
    /// Builds a public discovery key from received wire bytes.
    ///
    /// This validates encodings only. `public_key` accepts any 32-byte X25519 value, while
    /// `verifying_key` must decode to a valid Ed25519 point. Call
    /// [`verify_public_discovery_key`] to authenticate the parsed fields.
    pub fn from_bytes(
        public_key: &[u8],
        verifying_key: &[u8],
        epoch: u32,
        created_at_secs: u64,
        signature: &[u8],
    ) -> Result<Self, PublicKeyError> {
        let public_key_bytes: [u8; 32] = public_key
            .try_into()
            .map_err(|_| PublicKeyError::InvalidKeyEncoding)?;
        if !is_valid_x25519_public_key(&public_key_bytes) {
            return Err(PublicKeyError::InvalidKeyEncoding);
        }
        let verifying_key_bytes: [u8; 32] = verifying_key
            .try_into()
            .map_err(|_| PublicKeyError::InvalidKeyEncoding)?;
        let verifying_key = parse_ed25519_verifying_key_bytes(&verifying_key_bytes)
            .ok_or(PublicKeyError::InvalidKeyEncoding)?;
        let signature_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| PublicKeyError::InvalidKeyEncoding)?;
        Ok(PublicDiscoveryKey {
            public_key: PublicKey::from(public_key_bytes),
            verifying_key,
            epoch,
            created_at_secs,
            signature: Signature::from_bytes(&signature_bytes),
        })
    }
}

/// Generates a discovery key using `rng`, signed by the identity signing key.
///
/// The X25519 key-agreement secret and the Ed25519 signing key are drawn independently from `rng`.
pub fn generate_discovery_key<R: RngCore + CryptoRng>(
    rng: &mut R,
    identity: &SigningKeyPair,
    epoch: u32,
    created_at_secs: u64,
) -> Result<DiscoveryKey, SignatureError> {
    let key_agreement_secret = StaticSecret::random_from_rng(&mut *rng);
    let key_agreement_public = PublicKey::from(&key_agreement_secret);
    let signing = generate_signing_key_pair(rng);
    let payload = discovery_key_payload(
        &key_agreement_public,
        &signing.verifying,
        epoch,
        created_at_secs,
    );
    let identity_signature = identity.sign_with_context(DISCOVERY_KEY_CONTEXT, &payload)?;
    Ok(DiscoveryKey {
        key_agreement_secret,
        signing,
        key_agreement_public,
        epoch,
        created_at_secs,
        identity_signature,
    })
}

/// Verifies a public discovery key was signed by the identity verifying key.
pub fn verify_public_discovery_key(
    bundle: &PublicDiscoveryKey,
    identity_verifying_key: &VerifyingKey,
) -> Result<(), PublicKeyError> {
    let payload = discovery_key_payload(
        &bundle.public_key,
        &bundle.verifying_key,
        bundle.epoch,
        bundle.created_at_secs,
    );
    verify_with_context(
        identity_verifying_key,
        DISCOVERY_KEY_CONTEXT,
        &payload,
        &bundle.signature,
    )
    .map_err(Into::into)
}

fn discovery_key_payload(
    key_agreement_public: &PublicKey,
    verifying_key: &VerifyingKey,
    epoch: u32,
    created_at_secs: u64,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(32 + 32 + 4 + 8);
    payload.extend_from_slice(key_agreement_public.as_bytes());
    payload.extend_from_slice(verifying_key.as_bytes());
    payload.extend_from_slice(&epoch.to_be_bytes());
    payload.extend_from_slice(&created_at_secs.to_be_bytes());
    payload
}

/// Generates a signed pre-key signed by `discovery_key`.
///
/// This keeps the discovery signing key private while producing a signed pre-key that verifies
/// with [`PublicDiscoveryKey::verifying_key`]. The caller allocates `id` uniquely within this
/// discovery key's epoch.
pub fn generate_signed_prekey_for_discovery_key<R: RngCore + CryptoRng>(
    rng: &mut R,
    discovery_key: &DiscoveryKey,
    id: u64,
    created_at_secs: u64,
) -> Result<SignedPreKey, SignatureError> {
    generate_signed_prekey(
        rng,
        &discovery_key.signing,
        id,
        discovery_key.epoch,
        created_at_secs,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{PublicIdentityKey, sign_identity_key_binding};
    use crate::signed_prekey::verify_public_signed_prekey;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    const FIXED_EPOCH: u32 = 7;
    const FIXED_CREATED_AT_SECS: u64 = 1_700_000_000;

    struct DiscoveryKeySetup {
        rng: ChaCha20Rng,
        identity: SigningKeyPair,
        discovery_key: DiscoveryKey,
    }

    fn seeded_rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([5u8; 32])
    }

    fn setup() -> DiscoveryKeySetup {
        let mut rng = seeded_rng();
        let identity = generate_signing_key_pair(&mut rng);
        let discovery_key =
            generate_discovery_key(&mut rng, &identity, FIXED_EPOCH, FIXED_CREATED_AT_SECS)
                .unwrap();
        DiscoveryKeySetup {
            rng,
            identity,
            discovery_key,
        }
    }

    #[test]
    fn from_secret_bytes_round_trip() {
        let setup = setup();
        let original = &setup.discovery_key;
        let restored = DiscoveryKey::from_secret_bytes(
            *original.key_agreement_secret_bytes(),
            *original.signing_secret_bytes(),
            original.epoch(),
            original.created_at_secs(),
            original.identity_signature().to_bytes(),
        );
        assert_eq!(
            restored.public_key().as_bytes(),
            original.public_key().as_bytes()
        );
        assert_eq!(
            restored.public().verifying_key.as_bytes(),
            original.public().verifying_key.as_bytes()
        );
        assert_eq!(restored.epoch(), original.epoch());
        assert_eq!(restored.created_at_secs(), original.created_at_secs());
        assert_eq!(
            restored.identity_signature().to_bytes(),
            original.identity_signature().to_bytes()
        );
    }

    #[test]
    fn public_fields_match_discovery_key() {
        let setup = setup();
        let bundle = setup.discovery_key.public();
        assert_eq!(
            bundle.public_key.as_bytes(),
            setup.discovery_key.public_key().as_bytes()
        );
        assert_eq!(
            bundle.verifying_key.as_bytes(),
            setup.discovery_key.public().verifying_key.as_bytes()
        );
        assert_eq!(bundle.epoch, FIXED_EPOCH);
        assert_eq!(bundle.created_at_secs, FIXED_CREATED_AT_SECS);
        assert_eq!(
            bundle.signature.to_bytes(),
            setup.discovery_key.identity_signature().to_bytes()
        );
    }

    #[test]
    fn discovery_key_zeroizes_on_drop() {
        fn assert_zeroizes_on_drop<T: zeroize::ZeroizeOnDrop>() {}

        assert_zeroizes_on_drop::<DiscoveryKey>();
    }

    #[test]
    fn from_bytes_round_trip_preserves_bundle_fields() {
        let setup = setup();
        let bundle = setup.discovery_key.public();
        let parsed = PublicDiscoveryKey::from_bytes(
            bundle.public_key.as_bytes(),
            bundle.verifying_key.as_bytes(),
            bundle.epoch,
            bundle.created_at_secs,
            &bundle.signature.to_bytes(),
        )
        .unwrap();
        assert_eq!(parsed.public_key.as_bytes(), bundle.public_key.as_bytes());
        assert_eq!(
            parsed.verifying_key.as_bytes(),
            bundle.verifying_key.as_bytes()
        );
        assert_eq!(parsed.epoch, bundle.epoch);
        assert_eq!(parsed.created_at_secs, bundle.created_at_secs);
        assert_eq!(parsed.signature.to_bytes(), bundle.signature.to_bytes());
    }

    #[test]
    fn from_bytes_rejects_wrong_lengths() {
        assert!(matches!(
            PublicDiscoveryKey::from_bytes(&[0u8; 31], &[0u8; 32], 0, 0, &[0u8; 64]),
            Err(PublicKeyError::InvalidKeyEncoding)
        ));
        assert!(matches!(
            PublicDiscoveryKey::from_bytes(&[0u8; 32], &[0u8; 31], 0, 0, &[0u8; 64]),
            Err(PublicKeyError::InvalidKeyEncoding)
        ));
        assert!(matches!(
            PublicDiscoveryKey::from_bytes(&[0u8; 32], &[0u8; 32], 0, 0, &[0u8; 63]),
            Err(PublicKeyError::InvalidKeyEncoding)
        ));
    }

    #[test]
    fn from_bytes_rejects_invalid_verifying_key() {
        let non_decompressible_ed25519_verifying_key_bytes = [
            0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        let result = PublicDiscoveryKey::from_bytes(
            &[0u8; 32],
            &non_decompressible_ed25519_verifying_key_bytes,
            FIXED_EPOCH,
            FIXED_CREATED_AT_SECS,
            &[0u8; 64],
        );
        assert!(matches!(result, Err(PublicKeyError::InvalidKeyEncoding)));
    }

    #[test]
    fn from_bytes_rejects_non_canonical_x25519_public() {
        let setup = setup();
        let result = PublicDiscoveryKey::from_bytes(
            &[0xFFu8; 32],
            setup.identity.verifying.as_bytes(),
            FIXED_EPOCH,
            FIXED_CREATED_AT_SECS,
            &[0u8; 64],
        );
        assert!(matches!(result, Err(PublicKeyError::InvalidKeyEncoding)));
    }

    #[test]
    fn verify_accepts_bundle_signed_by_identity_key() {
        let setup = setup();
        let bundle = setup.discovery_key.public();
        assert!(verify_public_discovery_key(&bundle, &setup.identity.verifying).is_ok());
    }

    #[test]
    fn verify_rejects_wrong_identity() {
        let mut setup = setup();
        let other_identity = generate_signing_key_pair(&mut setup.rng);
        let bundle = setup.discovery_key.public();
        assert!(matches!(
            verify_public_discovery_key(&bundle, &other_identity.verifying),
            Err(PublicKeyError::Signature(SignatureError::SignatureInvalid))
        ));
    }

    #[test]
    fn verify_rejects_tampered_signed_fields() {
        let mut setup = setup();
        let identity = &setup.identity.verifying;

        let mut bundle = setup.discovery_key.public();
        let mut public_key_bytes = *bundle.public_key.as_bytes();
        public_key_bytes[0] ^= 0x01;
        bundle.public_key = PublicKey::from(public_key_bytes);
        assert!(matches!(
            verify_public_discovery_key(&bundle, identity),
            Err(PublicKeyError::Signature(SignatureError::SignatureInvalid))
        ));

        let mut bundle = setup.discovery_key.public();
        bundle.verifying_key = generate_signing_key_pair(&mut setup.rng).verifying;
        assert!(matches!(
            verify_public_discovery_key(&bundle, identity),
            Err(PublicKeyError::Signature(SignatureError::SignatureInvalid))
        ));

        let mut bundle = setup.discovery_key.public();
        bundle.epoch += 1;
        assert!(matches!(
            verify_public_discovery_key(&bundle, identity),
            Err(PublicKeyError::Signature(SignatureError::SignatureInvalid))
        ));

        let mut bundle = setup.discovery_key.public();
        bundle.created_at_secs += 1;
        assert!(matches!(
            verify_public_discovery_key(&bundle, identity),
            Err(PublicKeyError::Signature(SignatureError::SignatureInvalid))
        ));
    }

    #[test]
    fn verify_rejects_signature_without_domain_prefix() {
        let setup = setup();
        let mut bundle = setup.discovery_key.public();
        let mut bare_payload = Vec::new();
        bare_payload.extend_from_slice(bundle.public_key.as_bytes());
        bare_payload.extend_from_slice(bundle.verifying_key.as_bytes());
        bare_payload.extend_from_slice(&bundle.epoch.to_be_bytes());
        bare_payload.extend_from_slice(&bundle.created_at_secs.to_be_bytes());
        bundle.signature = setup.identity.sign(&bare_payload);
        assert!(matches!(
            verify_public_discovery_key(&bundle, &setup.identity.verifying),
            Err(PublicKeyError::Signature(SignatureError::SignatureInvalid))
        ));
    }

    #[test]
    fn discovery_signed_prekey_verifies_under_discovery_key_only() {
        let mut setup = setup();
        let signed_prekey = generate_signed_prekey_for_discovery_key(
            &mut setup.rng,
            &setup.discovery_key,
            0,
            FIXED_CREATED_AT_SECS,
        )
        .unwrap();
        let bundle = signed_prekey.public();
        assert!(
            verify_public_signed_prekey(&bundle, &setup.discovery_key.public().verifying_key)
                .is_ok()
        );
        assert!(matches!(
            verify_public_signed_prekey(&bundle, &setup.identity.verifying),
            Err(PublicKeyError::Signature(SignatureError::SignatureInvalid))
        ));
    }

    /// Builds a verifiable public identity key from fixed secret bytes.
    fn public_identity_key(signing_secret: [u8; 32], x25519_public: [u8; 32]) -> PublicIdentityKey {
        let signing = SigningKeyPair::from_signing_bytes(signing_secret);
        let public_key = PublicKey::from(x25519_public);
        let binding_signature = sign_identity_key_binding(&signing, &public_key).unwrap();
        PublicIdentityKey {
            public_key,
            verifying_key: signing.verifying,
            binding_signature,
        }
    }

    #[test]
    fn identity_binding_verifies_under_discovery_verifying_key() {
        let setup = setup();
        let identity = public_identity_key([0x11u8; 32], [0x22u8; 32]);

        let signature = setup
            .discovery_key
            .sign_identity_binding(&identity)
            .unwrap();

        assert!(
            verify_discovery_to_identity_binding(
                &identity,
                &setup.discovery_key.public().verifying_key,
                &signature,
            )
            .is_ok()
        );
    }

    #[test]
    fn identity_binding_rejects_wrong_discovery_key() {
        let mut setup = setup();
        let identity = public_identity_key([0x11u8; 32], [0x22u8; 32]);
        let other_discovery = generate_discovery_key(
            &mut setup.rng,
            &setup.identity,
            FIXED_EPOCH,
            FIXED_CREATED_AT_SECS,
        )
        .unwrap();

        let signature = setup
            .discovery_key
            .sign_identity_binding(&identity)
            .unwrap();

        assert!(matches!(
            verify_discovery_to_identity_binding(
                &identity,
                &other_discovery.public().verifying_key,
                &signature,
            ),
            Err(PublicKeyError::Signature(SignatureError::SignatureInvalid))
        ));
    }

    #[test]
    fn identity_binding_rejects_tampered_identity_halves() {
        let setup = setup();
        let identity = public_identity_key([0x11u8; 32], [0x22u8; 32]);
        let signature = setup
            .discovery_key
            .sign_identity_binding(&identity)
            .unwrap();
        let verifying_key = &setup.discovery_key.public().verifying_key;

        let mut tampered_x25519 = public_identity_key([0x11u8; 32], [0x22u8; 32]);
        let mut public_key_bytes = *tampered_x25519.public_key.as_bytes();
        public_key_bytes[0] ^= 0x01;
        tampered_x25519.public_key = PublicKey::from(public_key_bytes);
        assert!(matches!(
            verify_discovery_to_identity_binding(&tampered_x25519, verifying_key, &signature),
            Err(PublicKeyError::Signature(SignatureError::SignatureInvalid))
        ));

        let tampered_ed25519 = public_identity_key([0x44u8; 32], [0x22u8; 32]);
        assert!(matches!(
            verify_discovery_to_identity_binding(&tampered_ed25519, verifying_key, &signature),
            Err(PublicKeyError::Signature(SignatureError::SignatureInvalid))
        ));
    }

    #[test]
    fn identity_binding_rejects_signature_without_domain_prefix() {
        let setup = setup();
        let identity = public_identity_key([0x11u8; 32], [0x22u8; 32]);

        let mut bare_payload = Vec::new();
        bare_payload.extend_from_slice(identity.public_key.as_bytes());
        bare_payload.extend_from_slice(identity.verifying_key.as_bytes());
        let signature = setup.discovery_key.signing.sign(&bare_payload);

        assert!(matches!(
            verify_discovery_to_identity_binding(
                &identity,
                &setup.discovery_key.public().verifying_key,
                &signature,
            ),
            Err(PublicKeyError::Signature(SignatureError::SignatureInvalid))
        ));
    }

    /// The two directions cover identical bytes, so only the context separates them. A discovery
    /// key signing the identity halves under the identity-binding context must not satisfy the
    /// discovery-to-identity check.
    #[test]
    fn identity_binding_rejects_signature_made_under_identity_binding_context() {
        let setup = setup();
        let identity = public_identity_key([0x11u8; 32], [0x22u8; 32]);

        let signature =
            sign_identity_key_binding(&setup.discovery_key.signing, &identity.public_key).unwrap();

        assert!(matches!(
            verify_discovery_to_identity_binding(
                &identity,
                &setup.discovery_key.public().verifying_key,
                &signature,
            ),
            Err(PublicKeyError::Signature(SignatureError::SignatureInvalid))
        ));
    }
}
