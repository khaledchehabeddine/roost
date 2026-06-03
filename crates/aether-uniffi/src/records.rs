//! UniFFI public identity and publication records.

use aether_core::{Identity as CoreIdentity, PublicationBundle as CorePublicationBundle};
use aether_crypto::{
    DiscoveryKeyBundle as CoreDiscoveryKeyBundle, SignedPreKeyBundle as CoreSignedPreKeyBundle,
};

/// Public identity material exposed through UniFFI.
///
/// Contains only public key material and is safe to cache or send to peers.
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

/// Public signed pre-key material used to start a session.
///
/// Verify this bundle with the matching discovery-key verifying key.
#[derive(uniffi::Record)]
pub struct SignedPreKeyBundle {
    /// X25519 public key bytes. Always 32 bytes.
    pub public_key: Vec<u8>,
    /// Ed25519 signature over `public_key`. Always 64 bytes.
    pub signature: Vec<u8>,
    /// Discovery-key epoch this signed pre-key is bound to.
    pub epoch: u32,
    /// Generated timestamp in Unix seconds.
    pub created_at: u64,
}

impl From<CoreSignedPreKeyBundle> for SignedPreKeyBundle {
    fn from(b: CoreSignedPreKeyBundle) -> Self {
        SignedPreKeyBundle {
            public_key: b.public_key.as_bytes().to_vec(),
            signature: b.signature.to_bytes().to_vec(),
            epoch: b.epoch,
            created_at: b.created_at,
        }
    }
}

/// Public discovery-key material a peer uses to verify this identity's signed pre-keys.
///
/// Verify this bundle with the identity verifying key before trusting [`Self::verifying_key`].
#[derive(uniffi::Record)]
pub struct DiscoveryKeyBundle {
    /// X25519 key-agreement public key bytes. Always 32 bytes.
    pub public_key: Vec<u8>,
    /// Ed25519 verifying key bytes that validate this discovery key's signed pre-keys. Always 32 bytes.
    pub verifying_key: Vec<u8>,
    /// Identity-key Ed25519 signature over this discovery key. Always 64 bytes.
    pub signature: Vec<u8>,
    /// Rotation epoch, monotonic within one storage lineage.
    pub epoch: u32,
    /// Generated timestamp in Unix seconds.
    pub created_at: u64,
}

impl From<CoreDiscoveryKeyBundle> for DiscoveryKeyBundle {
    fn from(b: CoreDiscoveryKeyBundle) -> Self {
        DiscoveryKeyBundle {
            public_key: b.public_key.as_bytes().to_vec(),
            verifying_key: b.verifying_key.as_bytes().to_vec(),
            signature: b.signature.to_bytes().to_vec(),
            epoch: b.epoch,
            created_at: b.created_at,
        }
    }
}

/// A publishable discovery-key bundle and signed pre-key pair.
///
/// The signed pre-key verifies with the included discovery key.
#[derive(uniffi::Record)]
pub struct PublicationBundle {
    /// Discovery-key bundle for this publication.
    pub discovery_key: DiscoveryKeyBundle,
    /// Signed pre-key bundle for this publication.
    pub signed_prekey: SignedPreKeyBundle,
}

impl From<CorePublicationBundle> for PublicationBundle {
    fn from(b: CorePublicationBundle) -> Self {
        PublicationBundle {
            discovery_key: b.discovery_key.into(),
            signed_prekey: b.signed_prekey.into(),
        }
    }
}
