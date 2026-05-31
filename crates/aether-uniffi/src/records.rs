//! UniFFI record types for public identity and signed pre-key material.

use aether_core::{
    DiscoveryKeyRotationBundle as CoreDiscoveryKeyRotationBundle, Identity as CoreIdentity,
};
use aether_crypto::{
    DiscoveryKeyBundle as CoreDiscoveryKeyBundle, SignedPreKeyBundle as CoreSignedPreKeyBundle,
};

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

/// Public discovery-key material a peer uses to verify this identity's signed pre-keys.
///
/// The permanent identity key signs this bundle; the identity verifying key is not embedded.
/// Verifiers retrieve it separately and verify this bundle against it, then verify signed pre-keys
/// against [`DiscoveryKeyBundle::verifying_key`].
#[derive(uniffi::Record)]
pub struct DiscoveryKeyBundle {
    /// X25519 key-agreement public key bytes. Always 32 bytes.
    pub public_key: Vec<u8>,
    /// Ed25519 verifying key bytes that validate this discovery key's signed pre-keys. Always 32 bytes.
    pub verifying_key: Vec<u8>,
    /// Identity-key Ed25519 signature over this discovery key. Always 64 bytes.
    pub signature: Vec<u8>,
    /// Rotation epoch, monotonic within a storage lineage.
    pub epoch: u32,
    /// Unix timestamp in seconds when this discovery key was generated.
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

/// The discovery-key and signed-pre-key bundles produced by a single discovery-key rotation.
#[derive(uniffi::Record)]
pub struct DiscoveryKeyRotationBundle {
    /// The freshly generated discovery-key bundle.
    pub discovery_key: DiscoveryKeyBundle,
    /// The freshly generated signed pre-key, signed by the new discovery key.
    pub signed_prekey: SignedPreKeyBundle,
}

impl From<CoreDiscoveryKeyRotationBundle> for DiscoveryKeyRotationBundle {
    fn from(b: CoreDiscoveryKeyRotationBundle) -> Self {
        DiscoveryKeyRotationBundle {
            discovery_key: b.discovery_key.into(),
            signed_prekey: b.signed_prekey.into(),
        }
    }
}
