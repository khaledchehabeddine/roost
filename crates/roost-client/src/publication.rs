use crate::encoding::{fixed_32, fixed_64};
use crate::error::RoostError;
use crate::identity::Identity;
use crate::time::{millis_from_secs, whole_secs_from_millis};
use roost_core::{
    ContactDiscoveryKey, PreKeyBundle as CorePreKeyBundle,
    PublicDiscoveryKey as CorePublicDiscoveryKey, PublicKey,
    PublicOneTimePreKey as CorePublicOneTimePreKey, PublicSignedPreKey as CorePublicSignedPreKey,
    PublicationBundle as CorePublicationBundle, Signature,
};

/// A signed prekey's public half, which peers use to start a session.
///
/// Verify it with the matching discovery key's verifying key.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct PublicSignedPreKey {
    /// Stable unsigned identifier within the discovery key epoch. An app that needs this lookup
    /// value authenticated as transport metadata must include it in its transport binding.
    pub id: u64,
    /// X25519 public key bytes. Always 32 bytes.
    pub public_key: Vec<u8>,
    /// Ed25519 signature over `public_key`, `epoch`, and the creation time in whole Unix seconds.
    /// Always 64 bytes.
    pub signature: Vec<u8>,
    /// Discovery key epoch this signed prekey is bound to.
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

/// A one-time prekey's public half, which peers use to start a session.
///
/// Its secret half stays in SecureStorage, and Roost uses it at most once.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct PublicOneTimePreKey {
    /// One-time prekey identifier within the current discovery key epoch.
    pub id: u64,
    /// X25519 public key bytes. Always 32 bytes.
    pub public_key: Vec<u8>,
    /// Discovery key epoch this one-time prekey is bound to.
    pub epoch: u32,
}

impl PublicOneTimePreKey {
    pub(crate) fn from_core(one_time_prekey: CorePublicOneTimePreKey) -> Self {
        PublicOneTimePreKey {
            id: one_time_prekey.id,
            public_key: one_time_prekey.public_key.as_bytes().to_vec(),
            epoch: one_time_prekey.epoch,
        }
    }

    fn to_core(&self) -> Result<CorePublicOneTimePreKey, RoostError> {
        CorePublicOneTimePreKey::from_bytes(self.id, &self.public_key, self.epoch)
            .map_err(RoostError::from)
    }
}

/// A discovery key's public half, which peers use to verify this identity's signed prekeys.
///
/// Verify it with the identity key's signing key before trusting [`Self::verifying_key`].
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct PublicDiscoveryKey {
    /// X25519 key-agreement public key bytes. Always 32 bytes.
    pub public_key: Vec<u8>,
    /// Ed25519 verifying key bytes that validate this discovery key's signed prekeys. Always 32
    /// bytes.
    pub verifying_key: Vec<u8>,
    /// The identity key's Ed25519 signature over this discovery key. Always 64 bytes.
    pub signature: Vec<u8>,
    /// Rotation epoch, monotonic within one storage lineage.
    pub epoch: u32,
    /// Creation time in Unix milliseconds, always a whole number of seconds.
    ///
    /// After the device clock moves back, this can be later than now.
    pub created_at_millis: u64,
}

impl PublicDiscoveryKey {
    fn from_core(discovery_key: CorePublicDiscoveryKey) -> Result<Self, RoostError> {
        Ok(PublicDiscoveryKey {
            public_key: discovery_key.public_key.as_bytes().to_vec(),
            verifying_key: discovery_key.verifying_key.as_bytes().to_vec(),
            signature: discovery_key.identity_signature.to_bytes().to_vec(),
            epoch: discovery_key.epoch,
            created_at_millis: millis_from_secs(
                discovery_key.created_at_secs,
                "discovery key creation time",
            )?,
        })
    }

    pub(crate) fn from_contact(discovery_key: ContactDiscoveryKey) -> Result<Self, RoostError> {
        Ok(PublicDiscoveryKey {
            public_key: discovery_key.x25519_public_key.to_vec(),
            verifying_key: discovery_key.ed25519_verifying_key.to_vec(),
            signature: discovery_key.identity_signature.to_vec(),
            epoch: discovery_key.epoch,
            created_at_millis: millis_from_secs(
                discovery_key.created_at_secs,
                "contact discovery key creation time",
            )?,
        })
    }

    fn to_core(&self) -> Result<CorePublicDiscoveryKey, RoostError> {
        CorePublicDiscoveryKey::from_bytes(
            &self.public_key,
            &self.verifying_key,
            self.epoch,
            whole_secs_from_millis(self.created_at_millis, "discovery key created_at_millis")?,
            &self.signature,
        )
        .map_err(RoostError::from)
    }
}

/// A discovery key and signed prekey to publish together.
///
/// The signed prekey verifies with the included discovery key.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct PublicationBundle {
    /// The discovery key, whose signature is the identity key's half of the binding between the
    /// two keys.
    pub discovery_key: PublicDiscoveryKey,
    /// [`Self::discovery_key`]'s signature over the identity it belongs to, the other half of that
    /// binding. Always 64 bytes.
    ///
    /// Publish this alongside the discovery key. A relay verifies both halves before accepting a
    /// registration and rejects it when either fails.
    pub discovery_to_identity: Vec<u8>,
    /// Public commitment to this inbox's delivery capability. Always 32 bytes.
    ///
    /// Register this value. The capability itself is a secret that Roost shares with contacts only
    /// inside inbox grants.
    pub recipient_delivery_verifier: Vec<u8>,
    /// Public signed prekey for this publication.
    pub signed_prekey: PublicSignedPreKey,
}

impl PublicationBundle {
    pub(crate) fn from_core(publication: CorePublicationBundle) -> Result<Self, RoostError> {
        Ok(PublicationBundle {
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

/// A contact's identity and discovery key, decoded from a contact link with their binding
/// signatures verified.
#[derive(Debug, uniffi::Record)]
pub struct ContactPublication {
    /// The contact's identity.
    pub identity: Identity,
    /// The discovery key the contact had when they made the link.
    pub discovery_key: PublicDiscoveryKey,
}

/// Decodes the contact publication from a contact link and verifies the signatures that bind its
/// identity and discovery key.
///
/// It reads and writes no state, so the app can check a link before the user decides anything,
/// even for someone who is already a contact. To ask the link's owner to be a contact, fetch the
/// prekey bundle for [`ContactPublication::discovery_key`] from the relay, and pass it in a
/// [`PreKeyBundle`] with [`ContactPublication::identity`]. When the owner is already a contact,
/// fetch the bundle only if [`is_newer_discovery_key`] says the link's key is newer than the
/// stored one, then pass it in
/// [`OutgoingMessage::prekey_bundle`](crate::OutgoingMessage::prekey_bundle).
///
/// A valid publication shows only that whoever holds the identity made it. Compare safety numbers
/// to learn who that is.
///
/// # Errors
/// - [`RoostError::UnsupportedVersion`] if the link uses a format this version of Roost doesn't
///   read, such as one from a newer app.
/// - [`RoostError::AuthenticationFailed`] if a signature doesn't verify, so the link was forged
///   or altered.
/// - [`RoostError::InvalidData`] if the bytes are malformed.
#[uniffi::export]
pub fn decode_contact_publication(bytes: Vec<u8>) -> Result<ContactPublication, RoostError> {
    let publication = roost_core::ContactPublication::decode(&bytes)?;
    Ok(ContactPublication {
        identity: Identity::from_public(publication.identity),
        discovery_key: PublicDiscoveryKey::from_core(publication.discovery_key)?,
    })
}

/// Returns whether `candidate` is newer than `current`, the discovery key stored for the same
/// contact.
///
/// A newer discovery key has a later creation time, or the same creation time and a higher epoch,
/// since a restored backup can repeat an epoch. Any key is newer than no stored key. Check a
/// contact link's discovery key against
/// [`ContactState::discovery_key`](crate::ContactState::discovery_key) before fetching its bundle,
/// since each fetch of a contact's current bundle uses up one of its one-time prekeys. It checks
/// no signatures, so pass only a key from [`decode_contact_publication`] whose identity matches the
/// contact's.
///
/// # Errors
/// - [`RoostError::InvalidData`] if either discovery key is malformed.
#[uniffi::export]
pub fn is_newer_discovery_key(
    candidate: PublicDiscoveryKey,
    current: Option<PublicDiscoveryKey>,
) -> Result<bool, RoostError> {
    let candidate = ContactDiscoveryKey::from(&candidate.to_core()?);
    let current = current
        .as_ref()
        .map(PublicDiscoveryKey::to_core)
        .transpose()?;
    Ok(current.is_none_or(|current| {
        roost_core::is_newer_discovery_key(&candidate, &ContactDiscoveryKey::from(&current))
    }))
}

/// A contact's published keys as the app fetched them from the relay, to start a session with.
#[derive(Clone, uniffi::Record)]
pub struct PreKeyBundle {
    /// The contact's identity.
    pub identity: Identity,
    /// The contact's discovery key.
    pub discovery_key: PublicDiscoveryKey,
    /// [`Self::discovery_key`]'s signature over the contact's identity. Always 64 bytes.
    pub discovery_to_identity: Vec<u8>,
    /// The contact's signed prekey.
    pub signed_prekey: PublicSignedPreKey,
    /// The one-time prekey the relay handed out, absent once the contact's pool ran out.
    pub one_time_prekey: Option<PublicOneTimePreKey>,
}

impl PreKeyBundle {
    pub(crate) fn to_core(&self) -> Result<roost_core::PeerPreKeyBundle, RoostError> {
        Ok(roost_core::PeerPreKeyBundle {
            identity_key: self.identity.to_core()?,
            discovery_to_identity: Signature::from_bytes(&fixed_64(
                &self.discovery_to_identity,
                "discovery_to_identity",
            )?),
            bundle: CorePreKeyBundle {
                discovery_key: self.discovery_key.to_core()?,
                signed_prekey: self.signed_prekey.to_core()?,
                one_time_prekey: self
                    .one_time_prekey
                    .as_ref()
                    .map(PublicOneTimePreKey::to_core)
                    .transpose()?,
            },
        })
    }
}
