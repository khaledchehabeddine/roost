use crate::protocol_state::StateChanges;
use roost_crypto::{PublicDiscoveryKey, Signature};
use roost_protocol::IdentityKey;
use roost_protocol::PUBLIC_KEY_LEN;
use serde::{Deserialize, Serialize};

/// A peer identity key that owns contact, trust, and blocking state.
pub type ContactIdentityKey = IdentityKey;

/// Current discovery key material for a contact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContactDiscoveryKey {
    /// Canonical X25519 public key bytes used to look up the contact prekey bundle.
    pub x25519_public_key: [u8; PUBLIC_KEY_LEN],
    /// Canonical Ed25519 verifying-key bytes used to validate signed prekeys.
    pub ed25519_verifying_key: [u8; PUBLIC_KEY_LEN],
    /// Discovery key epoch, monotonic within one storage lineage.
    pub epoch: u32,
    /// Signed creation timestamp used to compare restored storage lineages.
    pub created_at_secs: u64,
    /// Identity-key signature over the public discovery key.
    pub identity_signature: [u8; Signature::BYTE_SIZE],
}

impl From<&PublicDiscoveryKey> for ContactDiscoveryKey {
    fn from(value: &PublicDiscoveryKey) -> Self {
        Self {
            x25519_public_key: *value.public_key.as_bytes(),
            ed25519_verifying_key: value.verifying_key.to_bytes(),
            epoch: value.epoch,
            created_at_secs: value.created_at_secs,
            identity_signature: value.identity_signature.to_bytes(),
        }
    }
}

/// The trust level the app records for one contact identity key.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ContactTrustState {
    /// A contact request is open in either direction.
    Pending,
    /// Both sides consented, but the safety number has not been confirmed out of band.
    Unverified,
    /// The accepted contact's safety number was confirmed out of band.
    Verified,
}

/// A contact as the app shows it, decoded from its record after the app commits.
///
/// The peer's delivery capability is not part of it: that leaves Roost only in the destination of
/// an established message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContactState {
    /// Permanent identity key that owns trust and blocking decisions.
    pub identity_key: ContactIdentityKey,
    /// Current discovery key, absent for a stranger blocked before they sent anything.
    pub discovery_key: Option<ContactDiscoveryKey>,
    /// Identity-key-bound trust state.
    pub trust_state: ContactTrustState,
    /// Local-only block flag for this contact.
    pub blocked: bool,
}

/// Result of out-of-band safety number confirmation.
pub enum ContactSafetyNumberConfirmation {
    /// The presented safety number matched, and the changes verify the contact.
    Matched(StateChanges),
    /// The presented safety number did not match, and nothing changed.
    Mismatched,
}
