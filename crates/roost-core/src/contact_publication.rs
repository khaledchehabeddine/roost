use crate::stored_data::{
    SignatureWire, StoredDataError, decode_versioned, encode_versioned, signature_from_wire,
    signature_to_wire,
};
use roost_crypto::{
    PublicDiscoveryKey, PublicIdentityKey, PublicKeyError, Signature,
    verify_discovery_to_identity_binding, verify_public_discovery_key, verify_public_identity_key,
};
use roost_protocol::PUBLIC_KEY_LEN;
use serde::{Deserialize, Serialize};

const CONTACT_PUBLICATION_VERSION: u8 = 1;

/// An identity's public identity key and current discovery key, with the signatures that bind the
/// two, as a contact link carries them.
#[derive(Clone, Debug)]
pub struct ContactPublication {
    /// The identity key, whose binding signature ties its agreement key to its signing key.
    pub identity: PublicIdentityKey,
    /// The current discovery key, whose signature is the identity key's half of the binding
    /// between the two keys.
    pub discovery_key: PublicDiscoveryKey,
    /// [`Self::discovery_key`]'s signature over [`Self::identity`], the other half of that
    /// binding.
    pub(crate) discovery_to_identity: Signature,
}

/// A reason a [`ContactPublication`] doesn't encode, or bytes don't decode into one.
#[derive(Debug, thiserror::Error)]
pub enum ContactPublicationError {
    /// The bytes don't decode as a contact publication, or the publication failed to encode.
    #[error("contact publication format is invalid")]
    Format(#[from] StoredDataError),
    /// A key or signature is malformed, or a signature doesn't verify.
    #[error("contact publication key is invalid")]
    Key(#[from] PublicKeyError),
    /// The bytes decode, but Roost encodes the same publication differently, such as with a
    /// number written in more bytes than it needs.
    #[error("contact publication isn't in its one encoding")]
    NotCanonical,
    /// The bytes start with a version older than the first one, so no Roost wrote them.
    #[error("contact publication version {0} predates the first version")]
    VersionBeforeFirst(u8),
}

impl ContactPublication {
    /// Returns the publication's bytes, starting with their format version.
    pub fn encode(&self) -> Result<Vec<u8>, ContactPublicationError> {
        let wire = ContactPublicationWire {
            identity_x25519_public_key: *self.identity.public_key.as_bytes(),
            identity_ed25519_verifying_key: self.identity.verifying_key.to_bytes(),
            identity_binding_signature: signature_to_wire(
                &self.identity.binding_signature.to_bytes(),
            ),
            discovery_x25519_public_key: *self.discovery_key.public_key.as_bytes(),
            discovery_ed25519_verifying_key: self.discovery_key.verifying_key.to_bytes(),
            epoch: self.discovery_key.epoch,
            created_at_secs: self.discovery_key.created_at_secs,
            identity_signature: signature_to_wire(&self.discovery_key.signature.to_bytes()),
            discovery_to_identity: signature_to_wire(&self.discovery_to_identity.to_bytes()),
        };
        Ok(encode_versioned(CONTACT_PUBLICATION_VERSION, &wire)?.to_vec())
    }

    /// Decodes a publication from `bytes` and verifies the identity key's own binding and both
    /// halves of its binding with the discovery key.
    ///
    /// Only the bytes [`Self::encode`] writes decode, so two links that differ in their bytes
    /// never hold the same publication.
    pub fn decode(bytes: &[u8]) -> Result<Self, ContactPublicationError> {
        if let Some(&version) = bytes.first()
            && version < CONTACT_PUBLICATION_VERSION
        {
            return Err(ContactPublicationError::VersionBeforeFirst(version));
        }
        let wire: ContactPublicationWire = decode_versioned(CONTACT_PUBLICATION_VERSION, bytes)?;
        if *encode_versioned(CONTACT_PUBLICATION_VERSION, &wire)? != bytes {
            return Err(ContactPublicationError::NotCanonical);
        }
        let identity = PublicIdentityKey::from_bytes(
            &wire.identity_x25519_public_key,
            &wire.identity_ed25519_verifying_key,
            &signature_from_wire(&wire.identity_binding_signature),
        )?;
        let discovery_key = PublicDiscoveryKey::from_bytes(
            &wire.discovery_x25519_public_key,
            &wire.discovery_ed25519_verifying_key,
            wire.epoch,
            wire.created_at_secs,
            &signature_from_wire(&wire.identity_signature),
        )?;
        let discovery_to_identity =
            Signature::from_bytes(&signature_from_wire(&wire.discovery_to_identity));
        verify_public_identity_key(&identity)?;
        verify_public_discovery_key(&discovery_key, &identity.verifying_key)?;
        verify_discovery_to_identity_binding(
            &identity,
            &discovery_key.verifying_key,
            &discovery_to_identity,
        )?;
        Ok(Self {
            identity,
            discovery_key,
            discovery_to_identity,
        })
    }
}

#[derive(Deserialize, Serialize)]
struct ContactPublicationWire {
    identity_x25519_public_key: [u8; PUBLIC_KEY_LEN],
    identity_ed25519_verifying_key: [u8; PUBLIC_KEY_LEN],
    identity_binding_signature: SignatureWire,
    discovery_x25519_public_key: [u8; PUBLIC_KEY_LEN],
    discovery_ed25519_verifying_key: [u8; PUBLIC_KEY_LEN],
    epoch: u32,
    created_at_secs: u64,
    identity_signature: SignatureWire,
    discovery_to_identity: SignatureWire,
}
