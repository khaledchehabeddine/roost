//! UniFFI protocol-state objects, records, and host persistence boundary.

use crate::context::{Contacts, Messaging};
use crate::error::RoostError;
use crate::message::{Message, PayloadKind, SenderIdentityMaterial};
use crate::records::{fixed_32, fixed_64};
use crate::time::{millis_from_secs, time_from_millis, whole_secs_from_millis};
use rand::rngs::OsRng;
use roost_core::RecipientDeliveryCapability as CoreRecipientDeliveryCapability;
use roost_core::{
    ContactSafetyNumberConfirmation as CoreSafetyNumberConfirmation,
    ContactStateChange as CoreContactStateChange, ProtocolStateAddress as CoreProtocolStateAddress,
    ProtocolStateBlob as CoreProtocolStateBlob, ProtocolStateKey as CoreProtocolStateKey,
    ProtocolStateSnapshot as CoreProtocolStateSnapshot,
    ProtocolStateUpdate as CoreProtocolStateUpdate,
};
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

/// Stable category for an opaque protocol-state blob.
#[derive(Clone, Copy, Eq, PartialEq, uniffi::Enum)]
pub enum ProtocolStateKind {
    /// Double Ratchet session state.
    RatchetSession,
    /// Deduplication-set state.
    DeduplicationSet,
    /// Pending-acknowledgment state.
    PendingAcknowledgments,
    /// Identity-key-addressed contact state.
    ContactState,
    /// Identity-key-addressed peer inbox-authorization state.
    ///
    /// Separate from [`Self::ContactState`] because it holds the peer's delivery capability, a
    /// bearer secret that must not ride along with the public contact snapshot.
    PeerInboxAuthorization,
    /// Identity-key-addressed record of which local inbox generation a contact has been given.
    LocalInboxAuthorization,
}

/// Host-side compare-and-set precondition for one protocol-state update.
///
/// Core derives this value from the input snapshot. Check it against current durable storage inside
/// the same per-identity transaction that writes all returned updates and effects. Compare digests
/// in constant time; on failure reload and process again.
#[derive(Clone, Eq, PartialEq, uniffi::Enum)]
pub enum ProtocolStateCommitCheck {
    /// The host must apply the update only when no blob exists at the address.
    Absent,
    /// The host must apply the update only when the current blob digest matches.
    Digest {
        /// Expected digest of the current opaque blob. Always 32 bytes.
        expected_blob_digest: Vec<u8>,
    },
}

/// Opaque protocol-state address and blob loaded by a host.
///
/// Loaded blob bytes are wrapped and zeroized when converted into a Rust snapshot.
#[derive(uniffi::Record)]
pub struct ProtocolStateEntry {
    /// State kind.
    pub kind: ProtocolStateKind,
    /// State key bytes.
    pub key: Vec<u8>,
    /// Opaque blob bytes.
    pub blob: Vec<u8>,
}

/// Opaque protocol-state update returned by Rust for host commit.
///
/// Returned blob bytes are host-owned FFI values; hosts must commit or discard them promptly.
#[derive(uniffi::Record)]
pub struct ProtocolStateUpdate {
    /// State kind.
    pub kind: ProtocolStateKind,
    /// State key bytes.
    pub key: Vec<u8>,
    /// Previous-blob check the host must enforce before applying this update.
    pub commit_check: ProtocolStateCommitCheck,
    /// Replacement blob, or `None` to delete the address.
    pub blob: Option<Vec<u8>>,
}

/// Protocol hardening limits exposed to bindings.
#[derive(uniffi::Record)]
pub struct ProtocolHardeningLimits {
    /// Maximum encoded Message bytes accepted before parsing.
    pub max_encoded_message_len: u64,
    /// Maximum Message ciphertext bytes accepted after frame decode.
    pub max_message_payload_len: u64,
    /// Maximum general Protocol State Blob bytes accepted before body decode.
    pub max_protocol_state_blob_len: u64,
    /// Maximum sender certificate bytes accepted after sealed-sender decrypt.
    pub max_sender_certificate_len: u64,
    /// Maximum sender signature bytes accepted after sealed-sender decrypt.
    pub max_sender_signature_len: u64,
    /// Received-message digest window capacity.
    pub deduplication_capacity: u64,
    /// Maximum pending outbound Messages retained for acknowledgment processing.
    pub max_pending_acknowledgments: u64,
    /// Maximum processed acknowledgment digests retained for duplicate detection.
    pub max_acknowledgment_digests: u64,
}

/// An identity's permanent public key, used for trust, certificates, and contacts.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct IdentityKey {
    /// The X25519 key that peers agree on shared secrets with. Always 32 bytes.
    pub agreement_key: Vec<u8>,
    /// The Ed25519 key that verifies the identity's signatures. Always 32 bytes.
    pub signing_key: Vec<u8>,
}

/// Current Discovery Key material for a Contact Identity.
#[derive(Clone, uniffi::Record)]
pub struct ContactDiscoveryKey {
    /// X25519 public key used to fetch the contact prekey bundle.
    pub x25519_public_key: Vec<u8>,
    /// Ed25519 verifying key used to validate signed prekeys.
    pub ed25519_verifying_key: Vec<u8>,
    /// Discovery Key epoch.
    pub epoch: u32,
    /// Signed creation time in Unix milliseconds, always a whole number of seconds.
    pub created_at_millis: u64,
    /// Identity-key signature over the public Discovery Key. Always 64 bytes.
    pub identity_signature: Vec<u8>,
}

/// Known peer identity and current Discovery Key.
#[derive(Clone, uniffi::Record)]
pub struct ContactIdentity {
    /// Permanent peer Identity Key.
    pub identity_key: IdentityKey,
    /// Current peer Discovery Key.
    pub discovery_key: ContactDiscoveryKey,
}

/// Consumer-recorded trust state for a contact.
#[derive(Clone, Copy, uniffi::Enum)]
pub enum ContactTrustState {
    /// Contact exists but has not been accepted.
    Pending,
    /// Contact was accepted but not verified out of band.
    Unverified,
    /// Contact Safety Number was verified out of band.
    Verified,
}

/// Public contact state snapshot.
#[derive(Clone, uniffi::Record)]
pub struct ContactState {
    /// Contact identity material.
    pub identity: ContactIdentity,
    /// Trust state.
    pub trust_state: ContactTrustState,
    /// Local block flag.
    pub blocked: bool,
}

/// Contact event kind.
#[derive(Clone, Copy, uniffi::Enum)]
pub enum ContactEventKind {
    /// Contact state changed.
    Changed,
}

/// Immutable contact event snapshot.
#[derive(Clone, uniffi::Record)]
pub struct ContactEvent {
    /// Event kind.
    pub kind: ContactEventKind,
    /// Complete changed contact snapshot.
    pub contact: ContactState,
}

/// A peer's recipient delivery capability for one of its inbox generations.
///
/// Deliberately not [`Clone`]: [`Self::capability`] is a bearer secret, and every clone is another
/// heap copy nothing scrubs. Hand it straight to the relay submission that needs it.
#[derive(uniffi::Record)]
pub struct PeerInboxAuthorization {
    /// The peer inbox generation this authorization belongs to.
    pub generation: u32,
    /// The peer's recipient delivery capability for that generation. Always 32 bytes, and secret.
    pub capability: Vec<u8>,
}

/// Contact mutation result.
#[derive(uniffi::Record)]
pub struct ContactStateChange {
    /// Complete contact snapshot after the operation.
    pub contact: ContactState,
    /// Opaque state updates to commit.
    pub state_updates: Vec<ProtocolStateUpdate>,
    /// Event to emit after durable commit, when state changed.
    pub event: Option<ContactEvent>,
}

/// Safety-number confirmation outcome kind.
#[derive(uniffi::Enum)]
pub enum ContactSafetyNumberConfirmationKind {
    /// Presented Safety Number matched.
    Matched,
    /// Presented Safety Number did not match.
    Mismatched,
}

/// Safety-number confirmation outcome.
#[derive(uniffi::Record)]
pub struct ContactSafetyNumberConfirmation {
    /// Match result.
    pub kind: ContactSafetyNumberConfirmationKind,
    /// Contact state change.
    pub change: ContactStateChange,
}

/// Derived Safety Number.
#[derive(uniffi::Record)]
pub struct SafetyNumber {
    /// Raw derivation bytes.
    pub raw_bytes: Vec<u8>,
    /// Grouped decimal display string.
    pub grouped_decimal: String,
}

/// Pending acknowledgment visible to hosts without plaintext.
#[derive(uniffi::Record)]
pub struct PendingAcknowledgment {
    /// Original outbound Message ID. Always 16 bytes.
    pub message_id: Vec<u8>,
    /// Original outbound Message waiting for acknowledgment.
    pub message: Message,
    /// First-send Unix timestamp in milliseconds.
    pub first_sent_at_millis: u64,
    /// Last retry-instruction timestamp in milliseconds.
    pub last_retried_at_millis: Option<u64>,
}

/// Retry instruction for an unacknowledged Message.
#[derive(uniffi::Record)]
pub struct RetryInstruction {
    /// Original outbound Message ID. Always 16 bytes.
    pub message_id: Vec<u8>,
    /// Message the host may retransmit.
    pub message: Message,
    /// First-send Unix timestamp in milliseconds.
    pub first_sent_at_millis: u64,
    /// Previous retry-instruction timestamp in milliseconds.
    pub last_retried_at_millis: Option<u64>,
}

/// Retry instructions plus pending-state updates.
#[derive(uniffi::Record)]
pub struct RetryInstructionResult {
    /// Messages whose retry window elapsed.
    pub instructions: Vec<RetryInstruction>,
    /// Opaque state updates to commit.
    pub state_updates: Vec<ProtocolStateUpdate>,
}

/// Outbound Message plus state updates from one encrypt operation.
#[derive(uniffi::Record)]
pub struct OutboundMessageResult {
    /// Stable outbound Message ID. Always 16 bytes.
    pub message_id: Vec<u8>,
    /// Sender-observed Unix timestamp in milliseconds.
    pub sent_at_millis: u64,
    /// Payload kind sealed in the Message.
    pub payload_kind: PayloadKind,
    /// Message to send after durable commit.
    pub message: Message,
    /// Opaque state updates to commit atomically with the Message.
    pub state_updates: Vec<ProtocolStateUpdate>,
}

/// Terminal Session reason.
#[derive(uniffi::Enum)]
pub enum SessionUnrecoverableReason {
    /// The skipped-message-key retention cap was exceeded.
    SkippedKeyLimitExceeded,
}

/// Session event emitted after committing returned updates.
#[derive(uniffi::Record)]
pub struct SessionEvent {
    /// Session-scoped protocol-state key.
    pub session_key: Vec<u8>,
    /// Terminal reason.
    pub reason: SessionUnrecoverableReason,
}

/// A provisional receive result. Commit its updates and effects atomically before use.
///
/// Switch on the outcome to obtain only the fields that case permits. The host transaction must
/// enforce every returned condition and persist effects before plaintext is displayed, an
/// acknowledgment is sent, or recovery is scheduled.
#[derive(uniffi::Enum)]
pub enum InboundMessageOutcome {
    /// Authenticated plaintext and acknowledgment for a unique Message.
    Accepted {
        /// Payload for this outcome.
        result: InboundMessageResult,
    },
    /// A blocked Message with state changes and the configured acknowledgment policy.
    Blocked {
        /// Payload for this outcome.
        result: BlockedInboundMessageResult,
    },
    /// An already accepted encrypted Message. No effects are produced.
    Duplicate,
    /// A dead Session and its once-only durable recovery signal.
    SessionUnrecoverable {
        /// Payload for this outcome.
        result: SessionUnrecoverableResult,
    },
}

/// Authenticated Message data that remains provisional until the host transaction commits.
///
/// The host commits the Message, acknowledgment, and conditional updates in one transaction.
/// Plaintext is host-owned secret bytes; clear discarded copies promptly.
#[derive(uniffi::Record)]
pub struct InboundMessageResult {
    /// Authenticated Message identifier. Always 16 bytes.
    pub message_id: Vec<u8>,
    /// Authenticated sender timestamp in milliseconds.
    pub sent_at_millis: u64,
    /// Authenticated payload kind.
    pub payload_kind: PayloadKind,
    /// Plaintext for the host to protect and clear after use.
    pub plaintext: Vec<u8>,
    /// Authenticated sender material.
    pub sender_identity: SenderIdentityMaterial,
    /// Encrypted acknowledgment to commit with its exact caller-supplied Transport Binding.
    pub acknowledgment: Message,
    /// Conditional opaque updates to commit with the accepted Message and acknowledgment.
    pub state_updates: Vec<ProtocolStateUpdate>,
}

/// A blocked receive with no plaintext available to the caller.
///
/// The acknowledgment is present only under the silent-receipt policy. Commit it with the updates
/// before sending; under the default policy the host persists only the processed state.
#[derive(uniffi::Record)]
pub struct BlockedInboundMessageResult {
    /// Acknowledgment when the configured policy permits one.
    pub acknowledgment: Option<Message>,
    /// Conditional updates to commit before treating the Message as processed.
    pub state_updates: Vec<ProtocolStateUpdate>,
}

/// A terminal Session and the recovery work required after durable commit.
///
/// An event accompanies the first durable observation. Persist it with the conditional updates so
/// restarts can resume recovery without reporting it twice. Replacement requires an explicit host
/// wipe and a fresh handshake; this result never resets the Session.
#[derive(uniffi::Record)]
pub struct SessionUnrecoverableResult {
    /// Session to replace through a fresh handshake.
    pub session_key: Vec<u8>,
    /// Typed terminal reason.
    pub reason: SessionUnrecoverableReason,
    /// Once-only recovery signal to persist atomically with the returned updates.
    pub event: Option<SessionEvent>,
    /// Conditional updates that record delivery of the recovery signal.
    pub state_updates: Vec<ProtocolStateUpdate>,
}

/// A provisional result of processing an encrypted acknowledgment.
///
/// Cleared and missed acknowledgments both advance authenticated protocol state. Commit that state
/// and the matching host delivery decision together. Duplicates have no effects; terminal Sessions
/// carry the same durable recovery contract as Message receives.
#[derive(uniffi::Enum)]
pub enum AcknowledgmentOutcome {
    /// A pending outbound Message was cleared.
    Cleared {
        /// Payload for this outcome.
        result: AcknowledgmentResult,
    },
    /// An authenticated acknowledgment did not match a pending Message.
    Missed {
        /// Payload for this outcome.
        result: AcknowledgmentResult,
    },
    /// An already processed acknowledgment. No effects are produced.
    Duplicate,
    /// A terminal Session with durable recovery work.
    SessionUnrecoverable {
        /// Payload for this outcome.
        result: SessionUnrecoverableResult,
    },
}

/// Authenticated acknowledgment data and its conditional state updates.
///
/// The named outbound Message may have already left host pending state. A missed acknowledgment
/// still needs its protocol updates committed so retries are recognized as duplicates.
#[derive(uniffi::Record)]
pub struct AcknowledgmentResult {
    /// Acknowledgment Message identifier. Always 16 bytes.
    pub message_id: Vec<u8>,
    /// Authenticated sender timestamp in milliseconds.
    pub sent_at_millis: u64,
    /// Outbound Message identifier named by the acknowledgment. Always 16 bytes.
    pub acknowledged_message_id: Vec<u8>,
    /// Authenticated sender material.
    pub sender_identity: SenderIdentityMaterial,
    /// Conditional updates to commit before clearing host pending state.
    pub state_updates: Vec<ProtocolStateUpdate>,
}

/// Blocked-contact acknowledgment policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum BlockedContactAcknowledgmentPolicy {
    /// Suppress acknowledgments so blocks look like unreachable recipients.
    Unreachable,
    /// Return normal acknowledgments while hiding plaintext.
    SilentReceipt,
}

#[uniffi::export]
impl Messaging {
    /// Returns the engine hardening limits.
    ///
    /// The values come from this context's immutable configuration and describe the limits applied to its operations.
    pub fn hardening_limits(&self) -> ProtocolHardeningLimits {
        ProtocolHardeningLimits::from_core(self.inner.protocol_engine().hardening_limits())
    }

    /// Returns an update that initializes a deduplication set.
    ///
    /// Persist the update with the first application effects using this set. Its absent precondition refuses replacement of an existing set.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if the key exceeds the protocol address limit.
    /// - [`RoostError::InternalError`] if the new state cannot be encoded.
    pub fn initialize_deduplication_set(
        &self,
        key: Vec<u8>,
    ) -> Result<ProtocolStateUpdate, RoostError> {
        Ok(ProtocolStateUpdate::from_core(
            self.inner
                .protocol_engine()
                .initialize_deduplication_set(&mut OsRng, protocol_key(key)?)?,
        ))
    }

    /// Returns an update that initializes pending-acknowledgment state.
    ///
    /// Persist the returned absent-checked update before using a separately initialized Session. Session initiation creates its own acknowledgment state.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if the key exceeds the protocol address limit.
    /// - [`RoostError::InternalError`] if the new state cannot be encoded.
    pub fn initialize_pending_acknowledgments(
        &self,
        key: Vec<u8>,
    ) -> Result<ProtocolStateUpdate, RoostError> {
        Ok(ProtocolStateUpdate::from_core(
            self.inner
                .protocol_engine()
                .initialize_pending_acknowledgments(protocol_key(key)?)?,
        ))
    }

    /// Returns deletion updates for all protocol-state kinds at the key.
    ///
    /// Deletion remains conditional on the supplied snapshot. Commit the returned updates atomically with the host effects that require the wipe.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if a key or snapshot exceeds its bounds or repeats an address.
    pub fn wipe(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        key: Vec<u8>,
    ) -> Result<Vec<ProtocolStateUpdate>, RoostError> {
        Ok(self
            .inner
            .protocol_engine()
            .wipe(&snapshot_input_from_entries(snapshot)?, protocol_key(key)?)
            .into_iter()
            .map(ProtocolStateUpdate::from_core)
            .collect())
    }

    /// Returns all pending acknowledgments for a Session.
    ///
    /// Load the Session's pending-acknowledgment blob from the committed host store. This query does not change retry state.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if a key or snapshot exceeds its bounds or repeats an address.
    /// - [`RoostError::ProtocolStateFault`] if the pending-acknowledgment blob is missing or malformed.
    /// - [`RoostError::UnsupportedVersion`] if the stored blob has an unsupported version.
    pub fn pending_acknowledgments(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        key: Vec<u8>,
    ) -> Result<Vec<PendingAcknowledgment>, RoostError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        Ok(self
            .inner
            .protocol_engine()
            .pending_acknowledgments(&snapshot, protocol_key(key)?)?
            .into_iter()
            .map(PendingAcknowledgment::from_core)
            .collect())
    }

    /// Returns retry instructions whose retry window elapsed.
    ///
    /// Commit the returned updates with the host retry work. Preserve each Message's originally supplied Transport Binding when submitting it again.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if a key or snapshot exceeds its bounds or repeats an address.
    /// - [`RoostError::InternalError`] if updated retry state cannot be encoded.
    /// - [`RoostError::ProtocolStateFault`] if pending-acknowledgment state is missing or malformed.
    /// - [`RoostError::UnsupportedVersion`] if a stored blob has an unsupported version.
    pub fn retry_instructions(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        key: Vec<u8>,
        now_millis: u64,
        retry_window_millis: u64,
    ) -> Result<RetryInstructionResult, RoostError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        Ok(RetryInstructionResult::from_core(
            self.inner.protocol_engine().retry_instructions(
                &snapshot,
                protocol_key(key)?,
                time_from_millis(now_millis, "now_millis")?,
                Duration::from_millis(retry_window_millis),
            )?,
        ))
    }
}

#[uniffi::export]
impl Contacts {
    /// Creates or updates a Contact State blob.
    ///
    /// Roost verifies the Contact Identity and Discovery Key binding. Commit the returned updates with the host contact record; an unchanged contact may produce no updates.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if peer key lengths or snapshot bounds are invalid.
    /// - [`RoostError::InternalError`] if the updated contact cannot be encoded.
    /// - [`RoostError::ProtocolStateFault`] if peer keys or their binding fail validation, or stored state is malformed.
    /// - [`RoostError::UnsupportedVersion`] if stored contact state has an unsupported version.
    pub fn record_contact(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        contact_identity: ContactIdentity,
    ) -> Result<ContactStateChange, RoostError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        ContactStateChange::from_core(
            self.inner
                .protocol_engine()
                .record_contact(&snapshot, contact_identity.to_core()?)?,
        )
    }

    /// Returns one Contact State, if present.
    ///
    /// An absent contact returns `None`. Corrupt stored state is an error and must not be treated as absence.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if peer key lengths or snapshot bounds are invalid.
    /// - [`RoostError::ProtocolStateFault`] if peer keys are not canonical or stored contact state is malformed.
    /// - [`RoostError::UnsupportedVersion`] if stored contact state has an unsupported version.
    pub fn contact_state(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        identity_key: IdentityKey,
    ) -> Result<Option<ContactState>, RoostError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        self.inner
            .protocol_engine()
            .contact_state(&snapshot, identity_key.to_core()?)?
            .map(ContactState::from_core)
            .transpose()
    }

    /// Returns all Contact State snapshots.
    ///
    /// Project contacts from a snapshot freshly loaded from the committed host store. Platform observation can coalesce refreshes without retaining Rust subscriptions or cursors.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if the snapshot exceeds its bounds or repeats an address.
    /// - [`RoostError::ProtocolStateFault`] if stored contact state is malformed.
    /// - [`RoostError::UnsupportedVersion`] if stored contact state has an unsupported version.
    pub fn contact_states(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
    ) -> Result<Vec<ContactState>, RoostError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        self.inner
            .protocol_engine()
            .contact_states(&snapshot)?
            .into_iter()
            .map(ContactState::from_core)
            .collect()
    }

    /// Accepts a pending contact.
    ///
    /// Accepting a pending peer changes its trust to unverified. Commit the returned contact changes before sending application messages to that peer.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if peer key lengths or snapshot bounds are invalid.
    /// - [`RoostError::InternalError`] if the updated contact cannot be encoded.
    /// - [`RoostError::ProtocolStateFault`] if peer keys are not canonical, or the contact is missing or malformed.
    /// - [`RoostError::UnsupportedVersion`] if stored contact state has an unsupported version.
    pub fn accept_contact(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        identity_key: IdentityKey,
    ) -> Result<ContactStateChange, RoostError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        ContactStateChange::from_core(
            self.inner
                .protocol_engine()
                .accept_contact(&snapshot, identity_key.to_core()?)?,
        )
    }

    /// Records a peer's inbox authorization for a generation.
    ///
    /// Returns no updates when `generation` is not newer than what is stored. That refusal is
    /// load-bearing: an old authorization replayed at a contact would restore a capability the
    /// peer has already rotated away from, which is exactly the state a blocked sender wants to
    /// reach.
    ///
    /// # Errors
    /// - [`RoostError::InternalError`] if the new authorization cannot be encoded.
    /// - [`RoostError::InvalidData`] if keys, capability length, or snapshot bounds are invalid.
    /// - [`RoostError::ProtocolStateFault`] if the peer key is not canonical or stored authorization is malformed.
    /// - [`RoostError::UnsupportedVersion`] if stored authorization has an unsupported version.
    pub fn record_peer_inbox_authorization(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        identity_key: IdentityKey,
        generation: u32,
        capability: Vec<u8>,
    ) -> Result<Vec<ProtocolStateUpdate>, RoostError> {
        let capability = Zeroizing::new(capability);
        let snapshot = snapshot_input_from_entries(snapshot)?;
        let capability = CoreRecipientDeliveryCapability::from_bytes(fixed_32(
            &capability,
            "recipient delivery capability",
        )?);
        Ok(updates_from_core(
            self.inner
                .protocol_engine()
                .record_peer_inbox_authorization(
                    &snapshot,
                    identity_key.to_core()?,
                    generation,
                    &capability,
                )?,
        ))
    }

    /// Returns the stored inbox authorization for a peer, if one has been recorded.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if key lengths or snapshot bounds are invalid.
    /// - [`RoostError::ProtocolStateFault`] if the peer key is not canonical or stored authorization is malformed.
    /// - [`RoostError::UnsupportedVersion`] if stored authorization has an unsupported version.
    pub fn peer_inbox_authorization(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        identity_key: IdentityKey,
    ) -> Result<Option<PeerInboxAuthorization>, RoostError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        Ok(self
            .inner
            .protocol_engine()
            .peer_inbox_authorization(&snapshot, identity_key.to_core()?)?
            .map(|stored| PeerInboxAuthorization {
                generation: stored.generation,
                capability: stored.capability.to_bytes().to_vec(),
            }))
    }

    /// Records that a contact has been given local inbox generation `generation`.
    ///
    /// Call this only once the authorization update has actually reached transport. Recording it
    /// earlier would let an app killed mid-re-key resume past a contact that never received
    /// anything, leaving that contact unable to deliver until the next rotation.
    ///
    /// # Errors
    /// - [`RoostError::InternalError`] if the new record cannot be encoded.
    /// - [`RoostError::InvalidData`] if key lengths or snapshot bounds are invalid.
    /// - [`RoostError::ProtocolStateFault`] if the peer key is not canonical or the stored record is malformed.
    /// - [`RoostError::UnsupportedVersion`] if the stored record has an unsupported version.
    pub fn record_inbox_authorization_delivered(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        identity_key: IdentityKey,
        generation: u32,
    ) -> Result<Vec<ProtocolStateUpdate>, RoostError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        Ok(updates_from_core(
            self.inner
                .protocol_engine()
                .record_inbox_authorization_delivered(
                    &snapshot,
                    identity_key.to_core()?,
                    generation,
                )?,
        ))
    }

    /// Returns which of `candidates` still need the current inbox generation.
    ///
    /// A contact qualifies when it has never been given an authorization or was last given an
    /// older one. Blocked contacts are always excluded — re-supplying one would hand back the very
    /// capability the rotation revoked and silently undo the block. Contacts with no
    /// stored contact record are skipped.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if candidate key lengths or snapshot bounds are invalid.
    /// - [`RoostError::ProtocolStateFault`] if a candidate key is not canonical or a stored record is malformed.
    /// - [`RoostError::UnsupportedVersion`] if a stored record has an unsupported version.
    pub fn contacts_needing_inbox_authorization(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        current_generation: u32,
        candidates: Vec<IdentityKey>,
    ) -> Result<Vec<IdentityKey>, RoostError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        let candidates = candidates
            .iter()
            .map(IdentityKey::to_core)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(self
            .inner
            .protocol_engine()
            .contacts_needing_inbox_authorization(&snapshot, current_generation, &candidates)?
            .into_iter()
            .map(IdentityKey::from_core)
            .collect())
    }

    /// Confirms a Safety Number using this context's local Identity.
    ///
    /// The peer must already be accepted. A mismatch, including malformed presented text, returns
    /// no updates. The local Identity comes from this context's storage and cannot be supplied by
    /// the caller. Commit a matching confirmation's updates before showing the peer as verified.
    ///
    /// # Errors
    /// - [`RoostError::Corrupt`] if stored local Identity material is incomplete or malformed.
    /// - [`RoostError::InternalError`] if a storage lock is poisoned or a state update cannot encode.
    /// - [`RoostError::InvalidData`] if peer key lengths or snapshot bounds are invalid.
    /// - [`RoostError::NotFound`] if the context has no local Identity.
    /// - [`RoostError::OperationRecoveryRequired`] if a committed secure operation needs recovery.
    /// - [`RoostError::ProtocolStateFault`] if peer keys are not canonical, or the contact is missing, unaccepted, or corrupt.
    /// - [`RoostError::Storage`] if platform storage fails.
    /// - [`RoostError::UnsupportedVersion`] if stored Identity or contact state has an unsupported version.
    pub fn confirm_contact_safety_number(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        contact_identity_key: IdentityKey,
        presented_grouped_decimal: String,
    ) -> Result<ContactSafetyNumberConfirmation, RoostError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        let local = self.inner.load_identity()?;
        ContactSafetyNumberConfirmation::from_core(
            self.inner.protocol_engine().confirm_contact_safety_number(
                &snapshot,
                roost_core::ContactIdentityKey {
                    x25519_public_key: *local.public_key().as_bytes(),
                    ed25519_verifying_key: *local.verifying_key().as_bytes(),
                },
                contact_identity_key.to_core()?,
                &presented_grouped_decimal,
            )?,
        )
    }

    /// Unblocks a contact locally.
    ///
    /// Commit the returned state change before resuming local delivery. Unblocking does not restore a delivery capability invalidated by a prior inbox rotation.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if peer key lengths or snapshot bounds are invalid.
    /// - [`RoostError::InternalError`] if the updated contact cannot be encoded.
    /// - [`RoostError::ProtocolStateFault`] if peer keys are not canonical, or the contact is missing or malformed.
    /// - [`RoostError::UnsupportedVersion`] if stored contact state has an unsupported version.
    pub fn unblock_contact(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        identity_key: IdentityKey,
    ) -> Result<ContactStateChange, RoostError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        ContactStateChange::from_core(
            self.inner
                .protocol_engine()
                .unblock_contact(&snapshot, identity_key.to_core()?)?,
        )
    }
}

/// Protocol-state address requested from a host store.
#[derive(uniffi::Record)]
pub struct ProtocolStateAddress {
    /// State kind.
    pub kind: ProtocolStateKind,
    /// State key bytes.
    pub key: Vec<u8>,
}

/// Derives a Safety Number for two permanent Identity Keys.
#[uniffi::export]
pub fn derive_safety_number(
    first: IdentityKey,
    second: IdentityKey,
) -> Result<SafetyNumber, RoostError> {
    let safety_number = roost_core::derive_safety_number(first.to_core()?, second.to_core()?)?;
    Ok(SafetyNumber {
        raw_bytes: safety_number.raw_bytes.to_vec(),
        grouped_decimal: safety_number.grouped_decimal,
    })
}

/// Computes the Core-owned digest used by `ProtocolStateUpdate` commit checks.
#[uniffi::export]
pub fn protocol_state_blob_digest(blob: Vec<u8>) -> Vec<u8> {
    let blob = Zeroizing::new(blob);
    roost_core::protocol_state_blob_digest(&blob).to_vec()
}

pub(crate) fn protocol_key(key: Vec<u8>) -> Result<CoreProtocolStateKey, RoostError> {
    CoreProtocolStateKey::from_bytes(key).map_err(RoostError::from)
}

pub(crate) fn snapshot_input_from_entries(
    mut entries: Vec<ProtocolStateEntry>,
) -> Result<CoreProtocolStateSnapshot, RoostError> {
    if entries.len() > roost_core::MAX_PROTOCOL_STATE_ENTRIES {
        for entry in &mut entries {
            entry.blob.zeroize();
        }
        return Err(RoostError::InvalidData {
            reason: "too many protocol-state entries".into(),
        });
    }
    // Wrap every entry before validation, including entries after a malformed one.
    let entries: Vec<_> = entries
        .into_iter()
        .map(|entry| {
            (
                entry.kind,
                entry.key,
                CoreProtocolStateBlob::from_bytes(entry.blob),
            )
        })
        .collect();

    let mut snapshot = CoreProtocolStateSnapshot::new();
    for (kind, key, blob) in entries {
        let address = CoreProtocolStateAddress::new(kind.to_core(), protocol_key(key)?);
        if snapshot.get(&address).is_some() {
            return Err(RoostError::InvalidData {
                reason: "duplicate protocol-state address".into(),
            });
        }
        snapshot.set(address, blob)?;
    }
    Ok(snapshot)
}

impl ProtocolStateUpdate {
    pub(crate) fn from_core(update: CoreProtocolStateUpdate) -> Self {
        Self {
            kind: ProtocolStateKind::from_core(update.address().kind()),
            key: update.address().key().as_bytes().to_vec(),
            commit_check: match update.commit_condition() {
                roost_core::ProtocolStateCommitCondition::Absent => {
                    ProtocolStateCommitCheck::Absent
                }
                roost_core::ProtocolStateCommitCondition::Digest(digest) => {
                    ProtocolStateCommitCheck::Digest {
                        expected_blob_digest: digest.to_vec(),
                    }
                }
            },
            blob: update.blob().map(|blob| blob.as_bytes().to_vec()),
        }
    }
}

pub(crate) fn updates_from_core(updates: Vec<CoreProtocolStateUpdate>) -> Vec<ProtocolStateUpdate> {
    updates
        .into_iter()
        .map(ProtocolStateUpdate::from_core)
        .collect()
}

impl ProtocolHardeningLimits {
    fn from_core(value: roost_core::ProtocolHardeningLimits) -> Self {
        Self {
            max_encoded_message_len: value.max_encoded_message_len as u64,
            max_message_payload_len: value.max_message_payload_len as u64,
            max_protocol_state_blob_len: value.max_protocol_state_blob_len as u64,
            max_sender_certificate_len: value.max_sender_certificate_len as u64,
            max_sender_signature_len: value.max_sender_signature_len as u64,
            deduplication_capacity: value.deduplication_capacity as u64,
            max_pending_acknowledgments: value.max_pending_acknowledgments as u64,
            max_acknowledgment_digests: value.max_acknowledgment_digests as u64,
        }
    }
}

impl BlockedContactAcknowledgmentPolicy {
    pub(crate) fn from_core(policy: roost_core::BlockedContactAcknowledgmentPolicy) -> Self {
        match policy {
            roost_core::BlockedContactAcknowledgmentPolicy::Unreachable => Self::Unreachable,
            roost_core::BlockedContactAcknowledgmentPolicy::SilentReceipt => Self::SilentReceipt,
        }
    }

    pub(crate) fn to_core(self) -> roost_core::BlockedContactAcknowledgmentPolicy {
        match self {
            Self::Unreachable => roost_core::BlockedContactAcknowledgmentPolicy::Unreachable,
            Self::SilentReceipt => roost_core::BlockedContactAcknowledgmentPolicy::SilentReceipt,
        }
    }
}

impl IdentityKey {
    pub(crate) fn from_core(value: roost_core::IdentityKey) -> Self {
        Self {
            agreement_key: value.x25519_public_key.to_vec(),
            signing_key: value.ed25519_verifying_key.to_vec(),
        }
    }

    pub(crate) fn to_core(&self) -> Result<roost_core::IdentityKey, RoostError> {
        Ok(roost_core::IdentityKey {
            x25519_public_key: fixed_32(&self.agreement_key, "identity agreement key")?,
            ed25519_verifying_key: fixed_32(&self.signing_key, "identity signing key")?,
        })
    }
}

impl ContactDiscoveryKey {
    fn from_core(value: roost_core::ContactDiscoveryKey) -> Result<Self, RoostError> {
        Ok(Self {
            x25519_public_key: value.x25519_public_key.to_vec(),
            ed25519_verifying_key: value.ed25519_verifying_key.to_vec(),
            epoch: value.epoch,
            created_at_millis: millis_from_secs(
                value.created_at_secs,
                "contact discovery-key creation time",
            )?,
            identity_signature: value.identity_signature.to_vec(),
        })
    }

    fn to_core(&self) -> Result<roost_core::ContactDiscoveryKey, RoostError> {
        Ok(roost_core::ContactDiscoveryKey {
            x25519_public_key: fixed_32(
                &self.x25519_public_key,
                "contact discovery x25519 public key",
            )?,
            ed25519_verifying_key: fixed_32(
                &self.ed25519_verifying_key,
                "contact discovery ed25519 verifying key",
            )?,
            epoch: self.epoch,
            created_at_secs: whole_secs_from_millis(
                self.created_at_millis,
                "contact discovery-key created_at_millis",
            )?,
            identity_signature: fixed_64(
                &self.identity_signature,
                "contact discovery identity signature",
            )?,
        })
    }
}

impl ContactIdentity {
    fn from_core(value: roost_core::ContactIdentity) -> Result<Self, RoostError> {
        Ok(Self {
            identity_key: IdentityKey::from_core(value.identity_key),
            discovery_key: ContactDiscoveryKey::from_core(value.discovery_key)?,
        })
    }

    fn to_core(&self) -> Result<roost_core::ContactIdentity, RoostError> {
        Ok(roost_core::ContactIdentity {
            identity_key: self.identity_key.to_core()?,
            discovery_key: self.discovery_key.to_core()?,
        })
    }
}

impl ContactTrustState {
    fn from_core(value: roost_core::ContactTrustState) -> Self {
        match value {
            roost_core::ContactTrustState::Pending => Self::Pending,
            roost_core::ContactTrustState::Unverified => Self::Unverified,
            roost_core::ContactTrustState::Verified => Self::Verified,
        }
    }
}

impl ContactState {
    pub(crate) fn from_core(value: roost_core::ContactState) -> Result<Self, RoostError> {
        Ok(Self {
            identity: ContactIdentity::from_core(value.identity)?,
            trust_state: ContactTrustState::from_core(value.trust_state),
            blocked: value.blocked,
        })
    }
}

impl ContactEvent {
    pub(crate) fn from_core(value: roost_core::ContactEvent) -> Result<Self, RoostError> {
        match value {
            roost_core::ContactEvent::Changed { contact } => Ok(Self {
                kind: ContactEventKind::Changed,
                contact: ContactState::from_core(contact)?,
            }),
        }
    }
}

impl ContactStateChange {
    pub(crate) fn from_core(value: CoreContactStateChange) -> Result<Self, RoostError> {
        Ok(Self {
            contact: ContactState::from_core(value.contact)?,
            state_updates: updates_from_core(value.state_updates),
            event: value.event.map(ContactEvent::from_core).transpose()?,
        })
    }
}

impl ContactSafetyNumberConfirmation {
    fn from_core(value: CoreSafetyNumberConfirmation) -> Result<Self, RoostError> {
        match value {
            CoreSafetyNumberConfirmation::Matched(change) => Ok(Self {
                kind: ContactSafetyNumberConfirmationKind::Matched,
                change: ContactStateChange::from_core(change)?,
            }),
            CoreSafetyNumberConfirmation::Mismatched(change) => Ok(Self {
                kind: ContactSafetyNumberConfirmationKind::Mismatched,
                change: ContactStateChange::from_core(change)?,
            }),
        }
    }
}

impl PendingAcknowledgment {
    fn from_core(value: roost_core::PendingAcknowledgment) -> Self {
        Self {
            message_id: value.message_id.as_bytes().to_vec(),
            message: Message::from_core(value.message),
            first_sent_at_millis: value.first_sent_at_millis,
            last_retried_at_millis: value.last_retried_at_millis,
        }
    }
}

impl RetryInstruction {
    fn from_core(value: roost_core::RetryInstruction) -> Self {
        Self {
            message_id: value.message_id.as_bytes().to_vec(),
            message: Message::from_core(value.message),
            first_sent_at_millis: value.first_sent_at_millis,
            last_retried_at_millis: value.last_retried_at_millis,
        }
    }
}

impl RetryInstructionResult {
    fn from_core(value: roost_core::RetryInstructionResult) -> Self {
        Self {
            instructions: value
                .instructions
                .into_iter()
                .map(RetryInstruction::from_core)
                .collect(),
            state_updates: updates_from_core(value.state_updates),
        }
    }
}

impl OutboundMessageResult {
    pub(crate) fn from_core(value: roost_core::OutboundMessageResult) -> Self {
        Self {
            message_id: value.message_id.as_bytes().to_vec(),
            sent_at_millis: value.sent_at_millis,
            payload_kind: PayloadKind::from_protocol(value.payload_kind),
            message: Message::from_core(value.message),
            state_updates: updates_from_core(value.state_updates),
        }
    }
}

impl InboundMessageOutcome {
    pub(crate) fn from_core(value: roost_core::InboundMessageOutcome) -> Self {
        match value {
            roost_core::InboundMessageOutcome::Accepted(result) => {
                let state_updates = updates_from_core(result.state_updates);
                Self::Accepted {
                    result: InboundMessageResult {
                        message_id: result.message_id.as_bytes().to_vec(),
                        sent_at_millis: result.sent_at_millis,
                        payload_kind: PayloadKind::from_protocol(result.payload_kind),
                        plaintext: result.plaintext.to_vec(),
                        sender_identity: SenderIdentityMaterial::from_core(result.sender_identity),
                        acknowledgment: Message::from_core(result.acknowledgment),
                        state_updates,
                    },
                }
            }
            roost_core::InboundMessageOutcome::Blocked(result) => Self::Blocked {
                result: BlockedInboundMessageResult {
                    acknowledgment: result.acknowledgment.map(Message::from_core),
                    state_updates: updates_from_core(result.state_updates),
                },
            },
            roost_core::InboundMessageOutcome::Duplicate => Self::Duplicate,
            roost_core::InboundMessageOutcome::SessionUnrecoverable(result) => {
                Self::SessionUnrecoverable {
                    result: SessionUnrecoverableResult::from_core(*result),
                }
            }
        }
    }
}

impl SessionUnrecoverableResult {
    fn from_core(result: roost_core::SessionUnrecoverableResult) -> Self {
        Self {
            session_key: result.session_key.as_bytes().to_vec(),
            reason: SessionUnrecoverableReason::from_core(result.reason),
            event: result.event.map(SessionEvent::from_core),
            state_updates: updates_from_core(result.state_updates),
        }
    }
}

impl AcknowledgmentOutcome {
    pub(crate) fn from_core(value: roost_core::AcknowledgmentOutcome) -> Self {
        match value {
            roost_core::AcknowledgmentOutcome::Cleared(result) => Self::Cleared {
                result: AcknowledgmentResult {
                    message_id: result.message_id.as_bytes().to_vec(),
                    sent_at_millis: result.sent_at_millis,
                    acknowledged_message_id: result.acknowledged_message_id.as_bytes().to_vec(),
                    sender_identity: SenderIdentityMaterial::from_core(result.sender_identity),
                    state_updates: updates_from_core(result.state_updates),
                },
            },
            roost_core::AcknowledgmentOutcome::Missed {
                message_id,
                sent_at_millis,
                acknowledged_message_id,
                sender_identity,
                state_updates,
            } => Self::Missed {
                result: AcknowledgmentResult {
                    message_id: message_id.as_bytes().to_vec(),
                    sent_at_millis,
                    acknowledged_message_id: acknowledged_message_id.as_bytes().to_vec(),
                    sender_identity: SenderIdentityMaterial::from_core(sender_identity),
                    state_updates: updates_from_core(state_updates),
                },
            },
            roost_core::AcknowledgmentOutcome::Duplicate => Self::Duplicate,
            roost_core::AcknowledgmentOutcome::SessionUnrecoverable(result) => {
                Self::SessionUnrecoverable {
                    result: SessionUnrecoverableResult::from_core(*result),
                }
            }
        }
    }
}

impl SessionEvent {
    fn from_core(value: roost_core::SessionEvent) -> Self {
        match value {
            roost_core::SessionEvent::Unrecoverable {
                session_key,
                reason,
            } => Self {
                session_key: session_key.as_bytes().to_vec(),
                reason: SessionUnrecoverableReason::from_core(reason),
            },
        }
    }
}

impl SessionUnrecoverableReason {
    fn from_core(value: roost_core::SessionUnrecoverableReason) -> Self {
        match value {
            roost_core::SessionUnrecoverableReason::SkippedKeyLimitExceeded => {
                Self::SkippedKeyLimitExceeded
            }
        }
    }
}

impl ProtocolStateKind {
    fn from_core(value: roost_core::ProtocolStateKind) -> Self {
        match value {
            roost_core::ProtocolStateKind::RatchetSession => Self::RatchetSession,
            roost_core::ProtocolStateKind::DeduplicationSet => Self::DeduplicationSet,
            roost_core::ProtocolStateKind::PendingAcknowledgments => Self::PendingAcknowledgments,
            roost_core::ProtocolStateKind::ContactState => Self::ContactState,
            roost_core::ProtocolStateKind::PeerInboxAuthorization => Self::PeerInboxAuthorization,
            roost_core::ProtocolStateKind::LocalInboxAuthorization => Self::LocalInboxAuthorization,
        }
    }

    fn to_core(self) -> roost_core::ProtocolStateKind {
        match self {
            Self::RatchetSession => roost_core::ProtocolStateKind::RatchetSession,
            Self::DeduplicationSet => roost_core::ProtocolStateKind::DeduplicationSet,
            Self::PendingAcknowledgments => roost_core::ProtocolStateKind::PendingAcknowledgments,
            Self::ContactState => roost_core::ProtocolStateKind::ContactState,
            Self::PeerInboxAuthorization => roost_core::ProtocolStateKind::PeerInboxAuthorization,
            Self::LocalInboxAuthorization => roost_core::ProtocolStateKind::LocalInboxAuthorization,
        }
    }
}
