//! Contact identity and trust-state records.

use crate::protocol_state::StateChanges;
use crate::safety_number::IdentityKey;
use roost_crypto::PublicDiscoveryKey;
use roost_protocol::PUBLIC_KEY_LEN;
use serde::{Deserialize, Serialize};

const SIGNATURE_LEN: usize = 64;

/// A peer Identity Key that owns contact, trust, and blocking state.
pub type ContactIdentityKey = IdentityKey;

/// Current Discovery Key material for a Contact Identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContactDiscoveryKey {
    /// Canonical X25519 public key bytes used to look up the contact prekey bundle.
    pub x25519_public_key: [u8; PUBLIC_KEY_LEN],
    /// Canonical Ed25519 verifying-key bytes used to validate signed pre-keys.
    pub ed25519_verifying_key: [u8; PUBLIC_KEY_LEN],
    /// Discovery Key epoch, monotonic within one storage lineage.
    pub epoch: u32,
    /// Signed creation timestamp used to compare restored storage lineages.
    pub created_at_secs: u64,
    /// Identity-key signature over the public Discovery Key.
    pub identity_signature: [u8; SIGNATURE_LEN],
}

impl From<&PublicDiscoveryKey> for ContactDiscoveryKey {
    fn from(value: &PublicDiscoveryKey) -> Self {
        Self {
            x25519_public_key: *value.public_key.as_bytes(),
            ed25519_verifying_key: value.verifying_key.to_bytes(),
            epoch: value.epoch,
            created_at_secs: value.created_at_secs,
            identity_signature: value.signature.to_bytes(),
        }
    }
}

/// The trust level the app records for one contact Identity Key.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ContactTrustState {
    /// A Contact Request is open in either direction.
    Pending,
    /// Both sides consented, but the Safety Number has not been confirmed out of band.
    Unverified,
    /// The accepted contact's Safety Number was confirmed out of band.
    Verified,
}

/// A contact as the app shows it, decoded from its record after the app commits.
///
/// The peer's Delivery Capability is not part of it: that leaves Roost only in the destination of
/// an established Message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContactState {
    /// Permanent Identity Key that owns trust and blocking decisions.
    pub identity_key: ContactIdentityKey,
    /// Current Discovery Key, absent for a stranger blocked before they sent anything.
    pub discovery_key: Option<ContactDiscoveryKey>,
    /// Identity-key-bound trust state.
    pub trust_state: ContactTrustState,
    /// Local-only block flag for this Contact Identity Key.
    pub blocked: bool,
}

/// Result of out-of-band Safety Number confirmation.
pub enum ContactSafetyNumberConfirmation {
    /// The presented Safety Number matched, and the changes verify the contact.
    Matched(StateChanges),
    /// The presented Safety Number did not match, and nothing changed.
    Mismatched,
}
