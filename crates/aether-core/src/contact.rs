//! Contact identity and trust-state records.

use crate::events::EventStream;
use aether_crypto::DiscoveryKeyBundle;
use serde::{Deserialize, Serialize};

const CONTACT_IDENTITY_KEY_DOMAIN_TAG: &[u8] = b"AetherIK-v1:";
const PUBLIC_KEY_LEN: usize = 32;
const SIGNATURE_LEN: usize = 64;
const CONTACT_IDENTITY_KEY_ENCODING_LEN: usize =
    CONTACT_IDENTITY_KEY_DOMAIN_TAG.len() + PUBLIC_KEY_LEN * 2;

/// A peer Identity Key that owns contact, trust, and blocking state.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ContactIdentityKey {
    /// Canonical X25519 public key bytes.
    pub x25519_public_key: [u8; PUBLIC_KEY_LEN],
    /// Canonical Ed25519 verifying-key bytes.
    pub ed25519_verifying_key: [u8; PUBLIC_KEY_LEN],
}

impl ContactIdentityKey {
    /// Returns the canonical Identity Key encoding used as the contact Protocol State Key.
    #[must_use]
    pub fn canonical_encoding(&self) -> [u8; CONTACT_IDENTITY_KEY_ENCODING_LEN] {
        let mut encoding = [0u8; CONTACT_IDENTITY_KEY_ENCODING_LEN];
        let mut offset = 0;
        encoding[offset..offset + CONTACT_IDENTITY_KEY_DOMAIN_TAG.len()]
            .copy_from_slice(CONTACT_IDENTITY_KEY_DOMAIN_TAG);
        offset += CONTACT_IDENTITY_KEY_DOMAIN_TAG.len();
        encoding[offset..offset + PUBLIC_KEY_LEN].copy_from_slice(&self.x25519_public_key);
        offset += PUBLIC_KEY_LEN;
        encoding[offset..offset + PUBLIC_KEY_LEN].copy_from_slice(&self.ed25519_verifying_key);
        encoding
    }
}

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
}

/// Contact state-change event emitted after the consumer durably commits returned updates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContactEvent {
    /// A contact was created, accepted, verified, or had its Discovery Key updated.
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

/// Per-instance Contact Event Stream.
pub type ContactEventStream = EventStream<ContactEvent, Vec<ContactState>>;
