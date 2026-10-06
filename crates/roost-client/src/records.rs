//! UniFFI public identity and publication records.

use crate::error::RoostError;
use crate::protocol::IdentityKey;
use crate::time::{millis_from_secs, whole_secs_from_millis};
use roost_core::{
    Identity as CoreIdentity, IdentityError, PublicationBundle as CorePublicationBundle,
};
use roost_core::{
    PreKeyBundle as CorePreKeyBundle, PublicDiscoveryKey as CorePublicDiscoveryKey,
    PublicIdentityKey as CorePublicIdentityKey, PublicKey,
    PublicOneTimePreKey as CorePublicOneTimePreKey, PublicSignedPreKey as CorePublicSignedPreKey,
    Signature,
};

/// An identity's public keys, safe to cache or send to peers.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct Identity {
    /// The Identity Key.
    pub key: IdentityKey,
    /// The signature that binds the Identity Key's agreement key to its signing key. Always 64
    /// bytes.
    pub binding_signature: Vec<u8>,
}

impl Identity {
    pub(crate) fn from_core(identity: CoreIdentity) -> Result<Self, IdentityError> {
        Ok(Self::from_public(identity.public()?))
    }

    pub(crate) fn from_public(public: CorePublicIdentityKey) -> Self {
        Identity {
            key: IdentityKey {
                agreement_key: public.public_key.as_bytes().to_vec(),
                signing_key: public.verifying_key.as_bytes().to_vec(),
            },
            binding_signature: public.binding_signature.to_bytes().to_vec(),
        }
    }

    pub(crate) fn to_core(&self) -> Result<CorePublicIdentityKey, RoostError> {
        CorePublicIdentityKey::from_bytes(
            &self.key.agreement_key,
            &self.key.signing_key,
            &self.binding_signature,
        )
        .map_err(RoostError::from)
    }
}

/// Public signed pre-key material used to start a session.
///
/// Verify this key with the matching discovery-key verifying key.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct PublicSignedPreKey {
    /// Stable unsigned identifier within the discovery-key epoch. A host that needs this lookup
    /// value authenticated as transport metadata must include it in its Transport Binding.
    pub id: u64,
    /// X25519 public key bytes. Always 32 bytes.
    pub public_key: Vec<u8>,
    /// Ed25519 signature over `public_key`, `epoch`, and the creation time in whole Unix seconds.
    /// Always 64 bytes.
    pub signature: Vec<u8>,
    /// Discovery-key epoch this signed pre-key is bound to.
    pub epoch: u32,
    /// Creation time in Unix milliseconds, always a whole number of seconds.
    pub created_at_millis: u64,
}

impl PublicSignedPreKey {
    pub(crate) fn from_core(b: CorePublicSignedPreKey) -> Result<Self, RoostError> {
        Ok(PublicSignedPreKey {
            id: b.id,
            public_key: b.public_key.as_bytes().to_vec(),
            signature: b.signature.to_bytes().to_vec(),
            epoch: b.epoch,
            created_at_millis: millis_from_secs(b.created_at_secs, "signed pre-key creation time")?,
        })
    }

    pub(crate) fn to_core(&self) -> Result<CorePublicSignedPreKey, RoostError> {
        Ok(CorePublicSignedPreKey {
            id: self.id,
            public_key: public_key_from_vec(&self.public_key)?,
            signature: signature_from_vec(&self.signature)?,
            epoch: self.epoch,
            created_at_secs: whole_secs_from_millis(
                self.created_at_millis,
                "signed pre-key created_at_millis",
            )?,
        })
    }
}

/// Public one-time pre-key material used to start a session.
///
/// The secret half stays in Rust-managed secure storage and is consumed at most once.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct PublicOneTimePreKey {
    /// One-time pre-key identifier within the current discovery-key epoch.
    pub id: u64,
    /// X25519 public key bytes. Always 32 bytes.
    pub public_key: Vec<u8>,
    /// Discovery-key epoch this one-time pre-key is bound to.
    pub epoch: u32,
    /// Creation time in Unix milliseconds, always a whole number of seconds.
    pub created_at_millis: u64,
}

impl PublicOneTimePreKey {
    pub(crate) fn from_core(b: CorePublicOneTimePreKey) -> Result<Self, RoostError> {
        Ok(PublicOneTimePreKey {
            id: b.id,
            public_key: b.public_key.as_bytes().to_vec(),
            epoch: b.epoch,
            created_at_millis: millis_from_secs(
                b.created_at_secs,
                "one-time pre-key creation time",
            )?,
        })
    }

    pub(crate) fn to_core(&self) -> Result<CorePublicOneTimePreKey, RoostError> {
        let created_at_secs =
            whole_secs_from_millis(self.created_at_millis, "one-time pre-key created_at_millis")?;
        CorePublicOneTimePreKey::from_bytes(self.id, &self.public_key, self.epoch, created_at_secs)
            .map_err(RoostError::from)
    }
}

/// Public discovery-key material a peer uses to verify this identity's signed pre-keys.
///
/// Verify this key with the identity verifying key before trusting [`Self::verifying_key`].
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct PublicDiscoveryKey {
    /// X25519 key-agreement public key bytes. Always 32 bytes.
    pub public_key: Vec<u8>,
    /// Ed25519 verifying key bytes that validate this discovery key's signed pre-keys. Always 32 bytes.
    pub verifying_key: Vec<u8>,
    /// Identity-key Ed25519 signature over this discovery key. Always 64 bytes.
    pub signature: Vec<u8>,
    /// Rotation epoch, monotonic within one storage lineage.
    pub epoch: u32,
    /// Creation time in Unix milliseconds, always a whole number of seconds.
    pub created_at_millis: u64,
}

impl PublicDiscoveryKey {
    pub(crate) fn from_core(b: CorePublicDiscoveryKey) -> Result<Self, RoostError> {
        Ok(PublicDiscoveryKey {
            public_key: b.public_key.as_bytes().to_vec(),
            verifying_key: b.verifying_key.as_bytes().to_vec(),
            signature: b.signature.to_bytes().to_vec(),
            epoch: b.epoch,
            created_at_millis: millis_from_secs(b.created_at_secs, "discovery-key creation time")?,
        })
    }

    pub(crate) fn to_core(&self) -> Result<CorePublicDiscoveryKey, RoostError> {
        CorePublicDiscoveryKey::from_bytes(
            &self.public_key,
            &self.verifying_key,
            self.epoch,
            whole_secs_from_millis(self.created_at_millis, "discovery-key created_at_millis")?,
            &self.signature,
        )
        .map_err(RoostError::from)
    }
}

/// A publishable public discovery key and signed pre-key pair.
///
/// The signed pre-key verifies with the included discovery key.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct PublicationBundle {
    /// Version of the public pre-key bundle format.
    pub version: u8,
    /// Public discovery key for this publication.
    ///
    /// Its `signature` field is the IK→DK half of the mutual binding.
    pub discovery_key: PublicDiscoveryKey,
    /// The DK→IK half of the mutual binding: [`Self::discovery_key`] signing the identity it
    /// belongs to. Always 64 bytes.
    ///
    /// Publish this alongside the discovery key. A relay verifies both directions before accepting
    /// a registration and rejects it when either fails.
    pub discovery_to_identity: Vec<u8>,
    /// Public commitment to this inbox's recipient delivery capability. Always 32
    /// bytes.
    ///
    /// Register this value. Never register the capability itself — that is a bearer secret, and
    /// handing it to the relay would defeat the point of committing to it.
    pub recipient_delivery_verifier: Vec<u8>,
    /// Public signed pre-key for this publication.
    pub signed_prekey: PublicSignedPreKey,
}

impl PublicationBundle {
    pub(crate) fn from_core(b: CorePublicationBundle) -> Result<Self, RoostError> {
        Ok(PublicationBundle {
            version: b.version,
            discovery_key: PublicDiscoveryKey::from_core(b.discovery_key)?,
            discovery_to_identity: b.discovery_to_identity.to_bytes().to_vec(),
            recipient_delivery_verifier: b.recipient_delivery_verifier.as_bytes().to_vec(),
            signed_prekey: PublicSignedPreKey::from_core(b.signed_prekey)?,
        })
    }
}

/// Everything one inbox rotation produces.
///
/// Publish and register [`Self::publication`]; persist [`Self::capability`] in secure storage and
/// give it only to authorized contacts. The two are returned together so a new inbox cannot be
/// published while contacts still hold the previous inbox's capability.
#[derive(Clone, uniffi::Record)]
pub struct InboxRotation {
    /// Material to publish and register for the new inbox.
    pub publication: PublicationBundle,
    /// The new inbox's recipient delivery capability. Always 32 bytes, and secret.
    pub capability: Vec<u8>,
}

impl PublicationBundle {
    /// The DK→IK half as a signature, rejecting anything that is not 64 bytes.
    ///
    /// Separate from [`Self::to_prekey_bundle`] because [`CorePreKeyBundle`] has no field for it:
    /// the binding is verified against the responder identity, which a prekey bundle does not
    /// carry. Session initiation checks it before any handshake work.
    pub(crate) fn discovery_to_identity_signature(&self) -> Result<Signature, RoostError> {
        Ok(Signature::from_bytes(&fixed_64(
            &self.discovery_to_identity,
            "discovery_to_identity",
        )?))
    }

    pub(crate) fn to_prekey_bundle(
        &self,
        one_time_prekey: Option<PublicOneTimePreKey>,
    ) -> Result<CorePreKeyBundle, RoostError> {
        Ok(CorePreKeyBundle {
            version: self.version,
            discovery_key: self.discovery_key.to_core()?,
            signed_prekey: self.signed_prekey.to_core()?,
            one_time_prekey: one_time_prekey
                .as_ref()
                .map(PublicOneTimePreKey::to_core)
                .transpose()?,
        })
    }
}

pub(crate) fn fixed_32(bytes: &[u8], label: &str) -> Result<[u8; 32], RoostError> {
    bytes.try_into().map_err(|_| RoostError::InvalidData {
        reason: format!("{label} must be 32 bytes"),
    })
}

pub(crate) fn fixed_16(bytes: &[u8], label: &str) -> Result<[u8; 16], RoostError> {
    bytes.try_into().map_err(|_| RoostError::InvalidData {
        reason: format!("{label} must be 16 bytes"),
    })
}

pub(crate) fn fixed_64(bytes: &[u8], label: &str) -> Result<[u8; 64], RoostError> {
    bytes.try_into().map_err(|_| RoostError::InvalidData {
        reason: format!("{label} must be 64 bytes"),
    })
}

fn public_key_from_vec(bytes: &[u8]) -> Result<PublicKey, RoostError> {
    Ok(PublicKey::from(fixed_32(bytes, "public key")?))
}

fn signature_from_vec(bytes: &[u8]) -> Result<Signature, RoostError> {
    Ok(Signature::from_bytes(&fixed_64(bytes, "signature")?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use roost_crypto::KeyPair;

    #[test]
    fn prekey_records_preserve_unsigned_id_boundaries() {
        let public_key = KeyPair::from_secret_bytes([0x42; 32])
            .public
            .as_bytes()
            .to_vec();
        let signed = PublicSignedPreKey {
            id: u64::MAX,
            public_key: public_key.clone(),
            signature: vec![0; 64],
            epoch: u32::MAX,
            created_at_millis: u64::MAX / 1_000 * 1_000,
        };
        let one_time = PublicOneTimePreKey {
            id: u64::MAX,
            public_key,
            epoch: u32::MAX,
            created_at_millis: u64::MAX / 1_000 * 1_000,
        };

        assert_eq!(signed.to_core().unwrap().id, u64::MAX);
        assert_eq!(one_time.to_core().unwrap().id, u64::MAX);
    }
}
