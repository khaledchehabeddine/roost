//! UniFFI public identity and publication records.

use crate::error::AetherError;
use aether_core::{
    Identity as CoreIdentity, IdentityError, PublicationBundle as CorePublicationBundle,
};
use aether_crypto::{
    DiscoveryKeyBundle as CoreDiscoveryKeyBundle, IdentityKeyBundle as CoreIdentityKeyBundle,
    OneTimePreKeyBundle as CoreOneTimePreKeyBundle, PreKeyBundle as CorePreKeyBundle, PublicKey,
    Signature, SignedPreKeyBundle as CoreSignedPreKeyBundle,
};

/// Public identity material exposed through UniFFI.
///
/// Contains only public key material and is safe to cache or send to peers.
#[derive(Clone, uniffi::Record)]
pub struct Identity {
    /// X25519 public key bytes. Always 32 bytes.
    pub x25519_public_key: Vec<u8>,
    /// Ed25519 verifying key bytes. Always 32 bytes.
    pub ed25519_verifying_key: Vec<u8>,
    /// Ed25519 signature binding the X25519 and Ed25519 identity halves. Always 64 bytes.
    pub identity_binding_signature: Vec<u8>,
}

impl Identity {
    pub(crate) fn from_core(id: CoreIdentity) -> Result<Self, IdentityError> {
        let bundle = id.identity_key_bundle()?;
        Ok(Identity {
            x25519_public_key: bundle.public_key.as_bytes().to_vec(),
            ed25519_verifying_key: bundle.verifying_key.as_bytes().to_vec(),
            identity_binding_signature: bundle.binding_signature.to_bytes().to_vec(),
        })
    }

    pub(crate) fn to_core(&self) -> Result<CoreIdentityKeyBundle, AetherError> {
        CoreIdentityKeyBundle::from_bytes(
            &self.x25519_public_key,
            &self.ed25519_verifying_key,
            &self.identity_binding_signature,
        )
        .map_err(AetherError::from)
    }
}

/// Public signed pre-key material used to start a session.
///
/// Verify this bundle with the matching discovery-key verifying key.
#[derive(Clone, uniffi::Record)]
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

impl SignedPreKeyBundle {
    pub(crate) fn to_core(&self) -> Result<CoreSignedPreKeyBundle, AetherError> {
        Ok(CoreSignedPreKeyBundle {
            public_key: public_key_from_vec(&self.public_key)?,
            signature: signature_from_vec(&self.signature)?,
            epoch: self.epoch,
            created_at: self.created_at,
        })
    }
}

/// Public one-time pre-key material used to start a session.
///
/// The secret half stays in Rust-managed secure storage and is consumed at most once.
#[derive(Clone, uniffi::Record)]
pub struct OneTimePreKeyBundle {
    /// One-time pre-key identifier within the current discovery-key epoch.
    pub id: u64,
    /// X25519 public key bytes. Always 32 bytes.
    pub public_key: Vec<u8>,
    /// Discovery-key epoch this one-time pre-key is bound to.
    pub epoch: u32,
    /// Generated timestamp in Unix seconds.
    pub created_at: u64,
}

impl From<CoreOneTimePreKeyBundle> for OneTimePreKeyBundle {
    fn from(b: CoreOneTimePreKeyBundle) -> Self {
        OneTimePreKeyBundle {
            id: b.id,
            public_key: b.public_key.as_bytes().to_vec(),
            epoch: b.epoch,
            created_at: b.created_at,
        }
    }
}

impl OneTimePreKeyBundle {
    pub(crate) fn to_core(&self) -> Result<CoreOneTimePreKeyBundle, AetherError> {
        CoreOneTimePreKeyBundle::from_bytes(self.id, &self.public_key, self.epoch, self.created_at)
            .map_err(AetherError::from)
    }
}

/// Public discovery-key material a peer uses to verify this identity's signed pre-keys.
///
/// Verify this bundle with the identity verifying key before trusting [`Self::verifying_key`].
#[derive(Clone, uniffi::Record)]
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

impl DiscoveryKeyBundle {
    pub(crate) fn to_core(&self) -> Result<CoreDiscoveryKeyBundle, AetherError> {
        CoreDiscoveryKeyBundle::from_bytes(
            &self.public_key,
            &self.verifying_key,
            self.epoch,
            self.created_at,
            &self.signature,
        )
        .map_err(AetherError::from)
    }
}

/// A publishable discovery-key bundle and signed pre-key pair.
///
/// The signed pre-key verifies with the included discovery key.
#[derive(Clone, uniffi::Record)]
pub struct PublicationBundle {
    /// Version of the public pre-key bundle format.
    pub version: u8,
    /// Discovery-key bundle for this publication.
    pub discovery_key: DiscoveryKeyBundle,
    /// Signed pre-key bundle for this publication.
    pub signed_prekey: SignedPreKeyBundle,
}

impl From<CorePublicationBundle> for PublicationBundle {
    fn from(b: CorePublicationBundle) -> Self {
        PublicationBundle {
            version: b.version,
            discovery_key: b.discovery_key.into(),
            signed_prekey: b.signed_prekey.into(),
        }
    }
}

impl PublicationBundle {
    pub(crate) fn to_prekey_bundle(
        &self,
        one_time_prekey: Option<OneTimePreKeyBundle>,
    ) -> Result<CorePreKeyBundle, AetherError> {
        Ok(CorePreKeyBundle {
            version: self.version,
            discovery_key: self.discovery_key.to_core()?,
            signed_prekey: self.signed_prekey.to_core()?,
            one_time_prekey: one_time_prekey
                .as_ref()
                .map(OneTimePreKeyBundle::to_core)
                .transpose()?,
        })
    }
}

pub(crate) fn fixed_32(bytes: &[u8], label: &str) -> Result<[u8; 32], AetherError> {
    bytes.try_into().map_err(|_| AetherError::InvalidData {
        reason: format!("{label} must be 32 bytes"),
    })
}

pub(crate) fn fixed_16(bytes: &[u8], label: &str) -> Result<[u8; 16], AetherError> {
    bytes.try_into().map_err(|_| AetherError::InvalidData {
        reason: format!("{label} must be 16 bytes"),
    })
}

pub(crate) fn fixed_64(bytes: &[u8], label: &str) -> Result<[u8; 64], AetherError> {
    bytes.try_into().map_err(|_| AetherError::InvalidData {
        reason: format!("{label} must be 64 bytes"),
    })
}

fn public_key_from_vec(bytes: &[u8]) -> Result<PublicKey, AetherError> {
    Ok(PublicKey::from(fixed_32(bytes, "public key")?))
}

fn signature_from_vec(bytes: &[u8]) -> Result<Signature, AetherError> {
    Ok(Signature::from_bytes(&fixed_64(bytes, "signature")?))
}
