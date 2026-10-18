use crate::encoding::{fixed_32, fixed_64};
use crate::error::RoostError;
use crate::identity::Identity;
use crate::time::{millis_from_secs, whole_secs_from_millis};
use roost_core::{
    PreKeyBundle as CorePreKeyBundle, PublicDiscoveryKey as CorePublicDiscoveryKey, PublicKey,
    PublicOneTimePreKey as CorePublicOneTimePreKey, PublicSignedPreKey as CorePublicSignedPreKey,
    PublicationBundle as CorePublicationBundle, Signature,
};

/// A signed prekey's public half, which peers use to start a Session.
///
/// Verify it with the matching Discovery Key's verifying key.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct PublicSignedPreKey {
    /// Stable unsigned identifier within the Discovery Key epoch. A host that needs this lookup
    /// value authenticated as transport metadata must include it in its Transport Binding.
    pub id: u64,
    /// X25519 public key bytes. Always 32 bytes.
    pub public_key: Vec<u8>,
    /// Ed25519 signature over `public_key`, `epoch`, and the creation time in whole Unix seconds.
    /// Always 64 bytes.
    pub signature: Vec<u8>,
    /// Discovery Key epoch this signed prekey is bound to.
    pub epoch: u32,
    /// Creation time in Unix milliseconds, always a whole number of seconds.
    pub created_at_millis: u64,
}

impl PublicSignedPreKey {
    pub(crate) fn from_core(signed_prekey: CorePublicSignedPreKey) -> Result<Self, RoostError> {
        Ok(PublicSignedPreKey {
            id: signed_prekey.id,
            public_key: signed_prekey.public_key.as_bytes().to_vec(),
            signature: signed_prekey.signature.to_bytes().to_vec(),
            epoch: signed_prekey.epoch,
            created_at_millis: millis_from_secs(
                signed_prekey.created_at_secs,
                "signed prekey creation time",
            )?,
        })
    }

    fn to_core(&self) -> Result<CorePublicSignedPreKey, RoostError> {
        Ok(CorePublicSignedPreKey {
            id: self.id,
            public_key: PublicKey::from(fixed_32(&self.public_key, "signed prekey public key")?),
            signature: Signature::from_bytes(&fixed_64(
                &self.signature,
                "signed prekey signature",
            )?),
            epoch: self.epoch,
            created_at_secs: whole_secs_from_millis(
                self.created_at_millis,
                "signed prekey created_at_millis",
            )?,
        })
    }
}

/// A one-time prekey's public half, which peers use to start a Session.
///
/// Its secret half stays in SecureStorage, and Roost uses it at most once.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct PublicOneTimePreKey {
    /// One-time prekey identifier within the current Discovery Key epoch.
    pub id: u64,
    /// X25519 public key bytes. Always 32 bytes.
    pub public_key: Vec<u8>,
    /// Discovery Key epoch this one-time prekey is bound to.
    pub epoch: u32,
    /// Creation time in Unix milliseconds, always a whole number of seconds.
    pub created_at_millis: u64,
}

impl PublicOneTimePreKey {
    pub(crate) fn from_core(one_time_prekey: CorePublicOneTimePreKey) -> Result<Self, RoostError> {
        Ok(PublicOneTimePreKey {
            id: one_time_prekey.id,
            public_key: one_time_prekey.public_key.as_bytes().to_vec(),
            epoch: one_time_prekey.epoch,
            created_at_millis: millis_from_secs(
                one_time_prekey.created_at_secs,
                "one-time prekey creation time",
            )?,
        })
    }

    fn to_core(&self) -> Result<CorePublicOneTimePreKey, RoostError> {
        let created_at_secs =
            whole_secs_from_millis(self.created_at_millis, "one-time prekey created_at_millis")?;
        CorePublicOneTimePreKey::from_bytes(self.id, &self.public_key, self.epoch, created_at_secs)
            .map_err(RoostError::from)
    }
}

/// A Discovery Key's public half, which peers use to verify this identity's signed prekeys.
///
/// Verify it with the Identity Key's signing key before trusting [`Self::verifying_key`].
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct PublicDiscoveryKey {
    /// X25519 key-agreement public key bytes. Always 32 bytes.
    pub public_key: Vec<u8>,
    /// Ed25519 verifying key bytes that validate this Discovery Key's signed prekeys. Always 32
    /// bytes.
    pub verifying_key: Vec<u8>,
    /// The Identity Key's Ed25519 signature over this Discovery Key. Always 64 bytes.
    pub signature: Vec<u8>,
    /// Rotation epoch, monotonic within one storage lineage.
    pub epoch: u32,
    /// Creation time in Unix milliseconds, always a whole number of seconds.
    pub created_at_millis: u64,
}

impl PublicDiscoveryKey {
    fn from_core(discovery_key: CorePublicDiscoveryKey) -> Result<Self, RoostError> {
        Ok(PublicDiscoveryKey {
            public_key: discovery_key.public_key.as_bytes().to_vec(),
            verifying_key: discovery_key.verifying_key.as_bytes().to_vec(),
            signature: discovery_key.signature.to_bytes().to_vec(),
            epoch: discovery_key.epoch,
            created_at_millis: millis_from_secs(
                discovery_key.created_at_secs,
                "Discovery Key creation time",
            )?,
        })
    }

    pub(crate) fn from_contact(
        discovery_key: roost_core::ContactDiscoveryKey,
    ) -> Result<Self, RoostError> {
        Ok(PublicDiscoveryKey {
            public_key: discovery_key.x25519_public_key.to_vec(),
            verifying_key: discovery_key.ed25519_verifying_key.to_vec(),
            signature: discovery_key.identity_signature.to_vec(),
            epoch: discovery_key.epoch,
            created_at_millis: millis_from_secs(
                discovery_key.created_at_secs,
                "contact Discovery Key creation time",
            )?,
        })
    }

    fn to_core(&self) -> Result<CorePublicDiscoveryKey, RoostError> {
        CorePublicDiscoveryKey::from_bytes(
            &self.public_key,
            &self.verifying_key,
            self.epoch,
            whole_secs_from_millis(self.created_at_millis, "Discovery Key created_at_millis")?,
            &self.signature,
        )
        .map_err(RoostError::from)
    }
}

/// A Discovery Key and signed prekey to publish together.
///
/// The signed prekey verifies with the included Discovery Key.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct PublicationBundle {
    /// Version of the public prekey bundle format.
    pub version: u8,
    /// The Discovery Key, whose signature is the Identity Key's half of the binding between the
    /// two keys.
    pub discovery_key: PublicDiscoveryKey,
    /// [`Self::discovery_key`]'s signature over the identity it belongs to, the other half of that
    /// binding. Always 64 bytes.
    ///
    /// Publish this alongside the Discovery Key. A relay verifies both halves before accepting a
    /// registration and rejects it when either fails.
    pub discovery_to_identity: Vec<u8>,
    /// Public commitment to this inbox's Delivery Capability. Always 32 bytes.
    ///
    /// Register this value. The capability itself is a secret that Roost shares with contacts only
    /// inside Inbox Grants.
    pub recipient_delivery_verifier: Vec<u8>,
    /// Public signed prekey for this publication.
    pub signed_prekey: PublicSignedPreKey,
}

impl PublicationBundle {
    pub(crate) fn from_core(publication: CorePublicationBundle) -> Result<Self, RoostError> {
        Ok(PublicationBundle {
            version: publication.version,
            discovery_key: PublicDiscoveryKey::from_core(publication.discovery_key)?,
            discovery_to_identity: publication.discovery_to_identity.to_bytes().to_vec(),
            recipient_delivery_verifier: publication
                .recipient_delivery_verifier
                .as_bytes()
                .to_vec(),
            signed_prekey: PublicSignedPreKey::from_core(publication.signed_prekey)?,
        })
    }
}

/// A contact's published keys as the app fetched them from the Relay, to start a Session with.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct PreKeyBundle {
    /// The contact's identity.
    pub identity: Identity,
    /// The contact's Discovery Key, both binding signatures, and signed prekey.
    pub publication: PublicationBundle,
    /// The one-time prekey the Relay handed out, absent once the contact's pool ran out.
    pub one_time_prekey: Option<PublicOneTimePreKey>,
}

impl PreKeyBundle {
    // The Discovery Key's signature over the identity travels beside the prekey bundle, which has
    // no field for it, since it verifies against the identity the bundle doesn't carry.
    pub(crate) fn to_core(&self) -> Result<roost_core::PeerPreKeyBundle, RoostError> {
        let publication = &self.publication;
        Ok(roost_core::PeerPreKeyBundle {
            identity_key: self.identity.to_core()?,
            discovery_to_identity: Signature::from_bytes(&fixed_64(
                &publication.discovery_to_identity,
                "discovery_to_identity",
            )?),
            bundle: CorePreKeyBundle {
                version: publication.version,
                discovery_key: publication.discovery_key.to_core()?,
                signed_prekey: publication.signed_prekey.to_core()?,
                one_time_prekey: self
                    .one_time_prekey
                    .as_ref()
                    .map(PublicOneTimePreKey::to_core)
                    .transpose()?,
            },
        })
    }
}
