//! Contact identity and trust-state records.

use crate::safety_number::IdentityKey;
use roost_crypto::{DiscoveryKeyBundle, RecipientDeliveryCapability};
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
    pub created_at: u64,
    /// Identity-key signature over the Discovery Key bundle.
    pub identity_signature: [u8; SIGNATURE_LEN],
}

impl ContactDiscoveryKey {
    /// Returns the Discovery Key lookup key used by consumers to fetch the contact prekey bundle.
    #[must_use]
    pub fn prekey_bundle_lookup_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.x25519_public_key
    }
}

impl From<&DiscoveryKeyBundle> for ContactDiscoveryKey {
    fn from(value: &DiscoveryKeyBundle) -> Self {
        Self {
            x25519_public_key: *value.public_key.as_bytes(),
            ed25519_verifying_key: value.verifying_key.to_bytes(),
            epoch: value.epoch,
            created_at: value.created_at,
            identity_signature: value.signature.to_bytes(),
        }
    }
}

/// A known peer contact identity: permanent Identity Key plus current Discovery Key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContactIdentity {
    /// Permanent Identity Key that owns trust and blocking decisions.
    pub identity_key: ContactIdentityKey,
    /// Current Discovery Key used for prekey-bundle lookup.
    pub discovery_key: ContactDiscoveryKey,
}

/// Consumer-recorded local trust verdict for one contact Identity Key.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ContactTrustState {
    /// The contact exists but has not been accepted by the consumer.
    Pending,
    /// The contact was accepted but its Safety Number has not been confirmed out of band.
    Unverified,
    /// The accepted contact's Safety Number was confirmed out of band.
    Verified,
}

/// Public contact state stored by Core and mirrored through events/current-state snapshots.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContactState {
    /// Contact identity material.
    pub identity: ContactIdentity,
    /// Identity-key-bound trust state.
    pub trust_state: ContactTrustState,
    /// Local-only block flag for this Contact Identity Key.
    pub blocked: bool,
}

/// Contact state-change event emitted after the consumer durably commits returned updates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContactEvent {
    /// A contact was created, accepted, verified, blocked, unblocked, or had its Discovery Key updated.
    Changed {
        /// Complete public snapshot of the changed contact.
        contact: ContactState,
    },
}

/// State updates and public event data produced by one contact-state operation.
pub struct ContactStateChange {
    /// Complete public snapshot after the operation.
    pub contact: ContactState,
    /// Protocol-state updates to commit durably before emitting `event`.
    pub state_updates: Vec<crate::protocol_state::ProtocolStateUpdate>,
    /// Event to emit after durable commit, if this operation changed state.
    pub event: Option<ContactEvent>,
}

/// Result of out-of-band Safety Number confirmation.
pub enum ContactSafetyNumberConfirmation {
    /// The presented Safety Number matched.
    Matched(ContactStateChange),
    /// The presented Safety Number did not match and no state update or event was produced.
    Mismatched(ContactStateChange),
}

/// A peer's current inbox authorization: what a caller needs to submit an established Message.
///
/// Held per contact and supplied by that contact inside an encrypted Message (AE-CON-05). The
/// capability is the peer's bearer secret, so this deliberately does not live in [`ContactState`],
/// which is available through public contact queries.
///
/// `generation` is the peer's inbox generation the capability belongs to. It exists so a replayed
/// older authorization can be recognized and refused rather than silently rolling a contact back to
/// a capability they have already rotated away from.
pub struct PeerInboxAuthorization {
    /// The peer inbox generation this authorization belongs to.
    pub generation: u32,
    /// The peer's recipient delivery capability for that generation.
    pub capability: RecipientDeliveryCapability,
}
