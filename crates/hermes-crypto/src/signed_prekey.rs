use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::CryptoError;
use crate::keys::SigningKeyPair;

/// A signed prekey (SPK) — an X25519 keypair signed by an Ed25519 identity key.
///
/// SPKs bridge forward secrecy between the long-lived identity key and the per-message
/// ephemeral keys of the Double Ratchet. They are rotated on a fixed schedule (default
/// every 7 days) to bound the impact of a compromise.
///
/// Holds the X25519 secret — never expose this across FFI as raw bytes.
//
// Safety: Holds X25519 secret material. Deliberately omits Clone, Debug, and Serialize per
// .claude/rules/crypto.md. ZeroizeOnDrop scrubs the secret when the struct is dropped.
//
// `secret_key` zeroes via x25519-dalek's zeroize feature; non-secret fields are skipped
// because they hold no sensitive data (`Signature` does not implement `Zeroize`, and
// `PublicKey`/`u64` carry no secrets).
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

/// Public, advertisable form of a signed prekey.
///
/// Contains the SPK public key, the Ed25519 signature over its 32 public-key bytes, and
/// the issuance timestamp. The owner's identity verifying key is NOT embedded —
/// [`verify_bundle`] takes it as a separate parameter, matching the X3DH-lite contract.
#[derive(Clone, Debug)]
pub struct PreKeyBundle {
    pub public_key: PublicKey,
    pub signature: Signature,
    pub created_at: u64,
}

impl SignedPreKey {
    /// Returns the X25519 public key.
    pub fn public(&self) -> &PublicKey {
        &self.public_key
    }

    /// Returns the Ed25519 signature over the 32-byte X25519 public key.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Returns the issuance timestamp in Unix seconds.
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Performs an X25519 Diffie–Hellman exchange using the SPK secret.
    pub fn diffie_hellman(&self, peer: &PublicKey) -> SharedSecret {
        self.secret_key.diffie_hellman(peer)
    }

    /// Exports the SPK secret bytes for secure storage.
    ///
    /// Wrapped in [`Zeroizing`] so the bytes are scrubbed when dropped. Intended for
    /// `hermes-core::SignedPreKeyManager` persistence — not for application code.
    pub fn to_secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secret_key.to_bytes())
    }

    /// Reconstructs a [`SignedPreKey`] from stored bytes.
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

    /// Returns the public-form bundle suitable for advertisement.
    pub fn bundle(&self) -> PreKeyBundle {
        PreKeyBundle {
            public_key: self.public_key,
            signature: self.signature,
            created_at: self.created_at,
        }
    }
}

/// Generates a fresh signed prekey signed by the supplied identity key.
///
/// Uses [`OsRng`] for the X25519 keypair and signs the public-key bytes with `identity`.
#[must_use]
pub fn generate_signed_prekey(identity: &SigningKeyPair, created_at: u64) -> SignedPreKey {
    let secret_key = StaticSecret::random_from_rng(OsRng);
    let public_key = PublicKey::from(&secret_key);
    let signature = identity.sign(public_key.as_bytes());
    SignedPreKey {
        secret_key,
        public_key,
        signature,
        created_at,
    }
}

/// Verifies that a [`PreKeyBundle`] was signed by the claimed identity key.
///
/// Returns `Ok(())` if `bundle.signature` validates against `bundle.public_key.as_bytes()`
/// using `peer_identity`. Returns [`CryptoError::SignatureInvalid`] otherwise.
pub fn verify_bundle(
    bundle: &PreKeyBundle,
    peer_identity: &VerifyingKey,
) -> Result<(), CryptoError> {
    peer_identity
        .verify(bundle.public_key.as_bytes(), &bundle.signature)
        .map_err(|_| CryptoError::SignatureInvalid)
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
        let tampered = PreKeyBundle {
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
