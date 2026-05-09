//! UniFFI record types for public identity and signed pre-key material.

use hermes_core::Identity as CoreIdentity;
use hermes_crypto::SignedPreKeyBundle as CoreSignedPreKeyBundle;

/// Identity material exposed through UniFFI.
///
/// Contains only public key material. It is safe to cache and send to peers.
#[derive(uniffi::Record)]
pub struct Identity {
    /// X25519 public key bytes. Always 32 bytes.
    pub public_key: Vec<u8>,
    /// Ed25519 verifying key bytes. Always 32 bytes.
    pub verifying_key: Vec<u8>,
}

impl From<CoreIdentity> for Identity {
    fn from(id: CoreIdentity) -> Self {
        Identity {
            public_key: id.public_key().as_bytes().to_vec(),
            verifying_key: id.verifying_key().as_bytes().to_vec(),
        }
    }
}

/// Public signed pre-key material a peer uses to start a session with this identity.
///
/// The owning identity signs [`SignedPreKeyBundle::public_key`] with its Ed25519 key. The identity
/// verifying key is not embedded. Verifiers retrieve it separately and pass it alongside this
/// bundle.
#[derive(uniffi::Record)]
pub struct SignedPreKeyBundle {
    /// X25519 public key bytes. Always 32 bytes.
    pub public_key: Vec<u8>,
    /// Ed25519 signature over `public_key`. Always 64 bytes.
    pub signature: Vec<u8>,
    /// Unix timestamp in seconds when this signed pre-key was generated.
    pub created_at: u64,
}

impl From<CoreSignedPreKeyBundle> for SignedPreKeyBundle {
    fn from(b: CoreSignedPreKeyBundle) -> Self {
        SignedPreKeyBundle {
            public_key: b.public_key.as_bytes().to_vec(),
            signature: b.signature.to_bytes().to_vec(),
            created_at: b.created_at,
        }
    }
}
