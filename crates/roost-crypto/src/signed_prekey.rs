use crate::keys::{
    KeyGenerationError, PublicKeyError, SigningKeyPair, contributory_diffie_hellman,
    generate_static_secret,
};
use ed25519_dalek::{Signature, VerifyingKey};
use rand::{CryptoRng, RngCore};
use roost_protocol::verify_with_context;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// Domain separator for signatures over signed pre-key public keys and epoch metadata.
const SIGNED_PREKEY_CONTEXT: &[u8] = b"RoostSPK-v1:";

/// An X25519 pre-key signed by an Ed25519 signing key.
///
/// The secret key is zeroed on drop. The public key, signature, epoch, and creation timestamp
/// remain available through accessors and [`Self::public`].
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SignedPreKey {
    secret_key: StaticSecret,
    #[zeroize(skip)]
    public_key: PublicKey,
    #[zeroize(skip)]
    signature: Signature,
    #[zeroize(skip)]
    id: u64,
    #[zeroize(skip)]
    epoch: u32,
    #[zeroize(skip)]
    created_at_secs: u64,
}

impl SignedPreKey {
    /// Returns the stable identifier allocated within the discovery-key epoch.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Returns the X25519 public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Returns the Ed25519 signature over
    /// `public_key[32] || epoch.to_be_bytes() || created_at_secs.to_be_bytes()` under the signed
    /// pre-key signature context.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Returns the discovery-key epoch this signed pre-key was produced under.
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Returns the Unix timestamp (seconds) when this signed pre-key was generated.
    pub fn created_at_secs(&self) -> u64 {
        self.created_at_secs
    }

    /// Derives a shared secret with `peer`, or `None` when `peer` forces a known one.
    pub(crate) fn diffie_hellman(&self, peer: &PublicKey) -> Option<SharedSecret> {
        contributory_diffie_hellman(&self.secret_key, peer)
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
        id: u64,
        epoch: u32,
        created_at_secs: u64,
    ) -> Self {
        let secret_key = StaticSecret::from(secret);
        let public_key = PublicKey::from(&secret_key);
        let signature = Signature::from_bytes(&signature);
        SignedPreKey {
            secret_key,
            public_key,
            signature,
            id,
            epoch,
            created_at_secs,
        }
    }

    /// Returns the public form of this signed pre-key for distribution to peers.
    pub fn public(&self) -> PublicSignedPreKey {
        PublicSignedPreKey {
            public_key: self.public_key,
            signature: self.signature,
            id: self.id,
            epoch: self.epoch,
            created_at_secs: self.created_at_secs,
        }
    }
}

/// Public signed pre-key material distributed to peers.
///
/// The signer's verifying key is not embedded. Pass the verifying key to
/// [`verify_public_signed_prekey`].
#[derive(Clone, Debug)]
pub struct PublicSignedPreKey {
    /// X25519 public key used by the peer during handshake root-key derivation.
    pub public_key: PublicKey,
    /// Ed25519 signature over
    /// `public_key[32] || epoch.to_be_bytes() || created_at_secs.to_be_bytes()` under the signed
    /// pre-key signature context.
    pub signature: Signature,
    /// Stable unsigned identifier allocated within [`Self::epoch`].
    ///
    /// The identifier is lookup metadata and is not covered by [`Self::signature`]. A host that
    /// needs it authenticated as transport metadata must include it in its Transport Binding.
    pub id: u64,
    /// Discovery-key epoch this signed pre-key was produced under.
    pub epoch: u32,
    /// Unix timestamp in seconds covered by [`Self::signature`].
    pub created_at_secs: u64,
}

/// Generates a signed pre-key with the supplied Ed25519 signing key and caller-allocated
/// identifier.
///
/// `id` is stable lookup metadata within one discovery-key epoch. It is not part of the signature
/// payload; a route-bound caller authenticates it as associated data with the encrypted initial.
pub(crate) fn generate_signed_prekey<R: RngCore + CryptoRng>(
    rng: &mut R,
    signing_key: &SigningKeyPair,
    id: u64,
    epoch: u32,
    created_at_secs: u64,
) -> Result<SignedPreKey, KeyGenerationError> {
    let secret_key = generate_static_secret(rng).map_err(KeyGenerationError::Randomness)?;
    let public_key = PublicKey::from(&secret_key);
    let payload = signed_prekey_payload(&public_key, epoch, created_at_secs);
    let signature = signing_key.sign_with_context(SIGNED_PREKEY_CONTEXT, &payload)?;
    Ok(SignedPreKey {
        secret_key,
        public_key,
        signature,
        id,
        epoch,
        created_at_secs,
    })
}

/// Verifies a public signed pre-key against the verifying key that signed it.
pub fn verify_public_signed_prekey(
    bundle: &PublicSignedPreKey,
    signer_verifying_key: &VerifyingKey,
) -> Result<(), PublicKeyError> {
    let payload = signed_prekey_payload(&bundle.public_key, bundle.epoch, bundle.created_at_secs);
    verify_with_context(
        signer_verifying_key,
        SIGNED_PREKEY_CONTEXT,
        &payload,
        &bundle.signature,
    )
    .map_err(Into::into)
}

fn signed_prekey_payload(public_key: &PublicKey, epoch: u32, created_at_secs: u64) -> Vec<u8> {
    let mut payload = Vec::with_capacity(32 + 4 + 8);
    payload.extend_from_slice(public_key.as_bytes());
    payload.extend_from_slice(&epoch.to_be_bytes());
    payload.extend_from_slice(&created_at_secs.to_be_bytes());
    payload
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{generate_key_pair, generate_signing_key_pair};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use roost_protocol::SignatureError;

    const FIXED_CREATED_AT_SECS: u64 = 1_700_000_000;
    const FIXED_EPOCH: u32 = 7;
    const FIXED_ID: u64 = 11;

    fn seeded_rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([4u8; 32])
    }

    #[test]
    fn generated_signature_covers_domain_key_epoch_and_creation_time() {
        let mut rng = seeded_rng();
        let signing_key = generate_signing_key_pair(&mut rng).unwrap();
        let signed_prekey = generate_signed_prekey(
            &mut rng,
            &signing_key,
            FIXED_ID,
            FIXED_EPOCH,
            FIXED_CREATED_AT_SECS,
        )
        .unwrap();
        let bundle = signed_prekey.public();
        let mut message = bundle.public_key.as_bytes().to_vec();
        message.extend_from_slice(&FIXED_EPOCH.to_be_bytes());
        message.extend_from_slice(&FIXED_CREATED_AT_SECS.to_be_bytes());
        let mut signed = b"RoostSPK-v1:".to_vec();
        signed.extend_from_slice(&u32::try_from(message.len()).unwrap().to_be_bytes());
        signed.extend_from_slice(&message);
        assert_eq!(bundle.signature, signing_key.sign(&signed));
        verify_public_signed_prekey(&bundle, &signing_key.verifying).unwrap();
    }

    #[test]
    fn public_fields_match_signed_prekey() {
        let mut rng = seeded_rng();
        let signing_key = generate_signing_key_pair(&mut rng).unwrap();
        let signed_prekey = generate_signed_prekey(
            &mut rng,
            &signing_key,
            FIXED_ID,
            FIXED_EPOCH,
            FIXED_CREATED_AT_SECS,
        )
        .unwrap();
        let bundle = signed_prekey.public();
        assert_eq!(
            bundle.public_key.as_bytes(),
            signed_prekey.public_key().as_bytes()
        );
        assert_eq!(
            bundle.signature.to_bytes(),
            signed_prekey.signature().to_bytes()
        );
        assert_eq!(bundle.id, signed_prekey.id());
        assert_eq!(bundle.epoch, signed_prekey.epoch());
        assert_eq!(bundle.created_at_secs, signed_prekey.created_at_secs());
    }

    #[test]
    fn verify_rejects_tampered_public_key() {
        let mut rng = seeded_rng();
        let signing_key = generate_signing_key_pair(&mut rng).unwrap();
        let signed_prekey = generate_signed_prekey(
            &mut rng,
            &signing_key,
            FIXED_ID,
            FIXED_EPOCH,
            FIXED_CREATED_AT_SECS,
        )
        .unwrap();
        let mut bundle = signed_prekey.public();
        let mut public_key_bytes = *bundle.public_key.as_bytes();
        public_key_bytes[0] ^= 0x01;
        bundle.public_key = PublicKey::from(public_key_bytes);
        assert!(matches!(
            verify_public_signed_prekey(&bundle, &signing_key.verifying),
            Err(PublicKeyError::Signature(SignatureError::SignatureInvalid))
        ));
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let mut rng = seeded_rng();
        let signing_key = generate_signing_key_pair(&mut rng).unwrap();
        let signed_prekey = generate_signed_prekey(
            &mut rng,
            &signing_key,
            FIXED_ID,
            FIXED_EPOCH,
            FIXED_CREATED_AT_SECS,
        )
        .unwrap();
        let bundle = signed_prekey.public();
        let mut signature_bytes = bundle.signature.to_bytes();
        signature_bytes[0] ^= 0x01;
        let tampered = PublicSignedPreKey {
            public_key: bundle.public_key,
            signature: Signature::from_bytes(&signature_bytes),
            id: bundle.id,
            epoch: bundle.epoch,
            created_at_secs: bundle.created_at_secs,
        };
        assert!(matches!(
            verify_public_signed_prekey(&tampered, &signing_key.verifying),
            Err(PublicKeyError::Signature(SignatureError::SignatureInvalid))
        ));
    }

    #[test]
    fn verify_rejects_wrong_signer() {
        let mut rng = seeded_rng();
        let signing_key = generate_signing_key_pair(&mut rng).unwrap();
        let wrong_signing_key = generate_signing_key_pair(&mut rng).unwrap();
        let signed_prekey = generate_signed_prekey(
            &mut rng,
            &signing_key,
            FIXED_ID,
            FIXED_EPOCH,
            FIXED_CREATED_AT_SECS,
        )
        .unwrap();
        let bundle = signed_prekey.public();
        assert!(matches!(
            verify_public_signed_prekey(&bundle, &wrong_signing_key.verifying),
            Err(PublicKeyError::Signature(SignatureError::SignatureInvalid))
        ));
    }

    #[test]
    fn verify_rejects_tampered_epoch() {
        let mut rng = seeded_rng();
        let signing_key = generate_signing_key_pair(&mut rng).unwrap();
        let signed_prekey = generate_signed_prekey(
            &mut rng,
            &signing_key,
            FIXED_ID,
            FIXED_EPOCH,
            FIXED_CREATED_AT_SECS,
        )
        .unwrap();
        let bundle = signed_prekey.public();
        let tampered = PublicSignedPreKey {
            public_key: bundle.public_key,
            signature: bundle.signature,
            id: bundle.id,
            epoch: bundle.epoch + 1,
            created_at_secs: bundle.created_at_secs,
        };
        assert!(matches!(
            verify_public_signed_prekey(&tampered, &signing_key.verifying),
            Err(PublicKeyError::Signature(SignatureError::SignatureInvalid))
        ));
    }

    #[test]
    fn verify_rejects_tampered_created_at() {
        let mut rng = seeded_rng();
        let signing_key = generate_signing_key_pair(&mut rng).unwrap();
        let signed_prekey = generate_signed_prekey(
            &mut rng,
            &signing_key,
            FIXED_ID,
            FIXED_EPOCH,
            FIXED_CREATED_AT_SECS,
        )
        .unwrap();
        let bundle = signed_prekey.public();
        let tampered = PublicSignedPreKey {
            public_key: bundle.public_key,
            signature: bundle.signature,
            id: bundle.id,
            epoch: bundle.epoch,
            created_at_secs: bundle.created_at_secs + 1,
        };
        assert!(matches!(
            verify_public_signed_prekey(&tampered, &signing_key.verifying),
            Err(PublicKeyError::Signature(SignatureError::SignatureInvalid))
        ));
    }

    #[test]
    fn signature_without_domain_prefix_fails_verification() {
        let mut rng = seeded_rng();
        let signing_key = generate_signing_key_pair(&mut rng).unwrap();
        let key_pair = generate_key_pair(&mut rng).unwrap();
        let bare_signature = signing_key.sign(key_pair.public.as_bytes());
        let bundle = PublicSignedPreKey {
            public_key: key_pair.public,
            signature: bare_signature,
            id: FIXED_ID,
            epoch: FIXED_EPOCH,
            created_at_secs: FIXED_CREATED_AT_SECS,
        };
        assert!(matches!(
            verify_public_signed_prekey(&bundle, &signing_key.verifying),
            Err(PublicKeyError::Signature(SignatureError::SignatureInvalid))
        ));
    }

    #[test]
    fn from_secret_bytes_round_trip() {
        let mut rng = seeded_rng();
        let signing_key = generate_signing_key_pair(&mut rng).unwrap();
        let original = generate_signed_prekey(
            &mut rng,
            &signing_key,
            FIXED_ID,
            FIXED_EPOCH,
            FIXED_CREATED_AT_SECS,
        )
        .unwrap();
        let restored = SignedPreKey::from_secret_bytes(
            *original.to_secret_bytes(),
            original.signature().to_bytes(),
            original.id(),
            original.epoch(),
            original.created_at_secs(),
        );
        assert_eq!(
            restored.public_key().as_bytes(),
            original.public_key().as_bytes()
        );
        assert_eq!(
            restored.signature().to_bytes(),
            original.signature().to_bytes()
        );
        assert_eq!(restored.epoch(), original.epoch());
        assert_eq!(restored.id(), original.id());
        assert_eq!(restored.created_at_secs(), original.created_at_secs());
        assert_eq!(*restored.to_secret_bytes(), *original.to_secret_bytes());
    }

    #[test]
    fn from_secret_bytes_restores_diffie_hellman_secret() {
        let mut rng = seeded_rng();
        let signing_key = generate_signing_key_pair(&mut rng).unwrap();
        let original = generate_signed_prekey(
            &mut rng,
            &signing_key,
            FIXED_ID,
            FIXED_EPOCH,
            FIXED_CREATED_AT_SECS,
        )
        .unwrap();
        let restored = SignedPreKey::from_secret_bytes(
            *original.to_secret_bytes(),
            original.signature().to_bytes(),
            original.id(),
            original.epoch(),
            original.created_at_secs(),
        );
        let peer = generate_key_pair(&mut rng).unwrap();
        let original_shared_secret = original.diffie_hellman(&peer.public).unwrap();
        let restored_shared_secret = restored.diffie_hellman(&peer.public).unwrap();
        assert_eq!(
            original_shared_secret.as_bytes(),
            restored_shared_secret.as_bytes()
        );
    }
}
