//! UniFFI protocol-state objects, records, and host persistence boundary.

use crate::context::{Contacts, Messaging};
use crate::error::RoostError;
use crate::message::{Message, MessageId, PayloadKind, SenderIdentityMaterial};
use crate::records::{SessionId, fixed_32, fixed_64, hex_bytes, hex_text};
use crate::time::{millis_from_secs, time_from_millis, whole_secs_from_millis};
use roost_core::RecipientDeliveryCapability as CoreRecipientDeliveryCapability;
use roost_core::{
    ContactSafetyNumberConfirmation as CoreSafetyNumberConfirmation,
    ContactStateChange as CoreContactStateChange, ProtocolStateAddress as CoreProtocolStateAddress,
    ProtocolStateBlob as CoreProtocolStateBlob, ProtocolStateCommitCondition,
    ProtocolStateKey as CoreProtocolStateKey, ProtocolStateSnapshot as CoreProtocolStateSnapshot,
    ProtocolStateUpdate as CoreProtocolStateUpdate, StateChanges as CoreStateChanges,
};
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

/// Stable category for an opaque protocol-state blob.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, uniffi::Enum)]
pub enum ProtocolStateKind {
    /// A Session's encryption state, stored under its SessionID.
    RatchetSession,
    /// Deduplication-set state.
    DeduplicationSet,
    /// SessionID-addressed pending-acknowledgment state.
    PendingAcknowledgments,
    /// Identity-key-addressed contact state.
    ContactState,
    /// Identity-key-addressed peer inbox-authorization state.
    ///
    /// Separate from [`Self::ContactState`] because it holds the peer's delivery capability, a
    /// bearer secret that must not ride along with the public contact snapshot.
    PeerInboxAuthorization,
    /// Identity-key-addressed record of the latest local epoch whose capability a contact holds.
    LocalInboxAuthorization,
    /// Identity-key-addressed record of the Sessions kept with one peer and the one Roost sends
    /// on.
    PeerSessions,
}

/// The name of one record the host stores: its kind and its ID.
///
/// The ID is lowercase hexadecimal. For a contact's records it encodes the contact's Identity
/// Key, so the host can find every record of one contact without decoding a blob.
#[derive(Clone, Debug, Eq, Hash, PartialEq, uniffi::Record)]
pub struct StateKey {
    /// The record's kind.
    pub kind: ProtocolStateKind,
    /// The record's ID within its kind, in lowercase hexadecimal.
    pub id: String,
}

/// One record as the host holds it, or its absence.
///
/// Roost wraps the bytes and erases its copy once it's done with them.
#[derive(uniffi::Record)]
pub struct StateEntry {
    /// The record's name.
    pub key: StateKey,
    /// The record's bytes, or `None` when the host holds no record under this key.
    pub blob: Option<Vec<u8>>,
}

/// One record to write when the host commits.
#[derive(uniffi::Record)]
pub struct StateUpdate {
    /// The record's name.
    pub key: StateKey,
    /// The record's new bytes, or `None` to delete it.
    pub blob: Option<Vec<u8>>,
}

/// What one record must still be when the host commits: unchanged since Roost read it, or still
/// absent.
#[derive(Clone, uniffi::Record)]
pub struct CommitCondition {
    /// The record's name.
    pub key: StateKey,
    /// Roost's fingerprint of the record it read, or `None` when the record must still be absent.
    /// Pass it back unchanged.
    pub digest: Option<Vec<u8>>,
}

/// The records an operation's result relies on, and the records it writes.
///
/// Inside one transaction, read the record under each condition's key, call [`Self::matches`],
/// and only when it returns `true` write every update together with the result's effects, such as
/// a Message to send. When it returns `false`, another operation changed a record first: roll
/// back, then start the operation again from fresh reads.
#[derive(uniffi::Record)]
pub struct StateChanges {
    /// Every record the result relies on, including ones it read but doesn't write.
    pub conditions: Vec<CommitCondition>,
    /// The records to write.
    pub updates: Vec<StateUpdate>,
}

/// Roost's fixed limits on what one Message or record may cost, and the Deduplication Set's range.
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
    /// Maximum pending outbound Messages retained for acknowledgment processing.
    pub max_pending_acknowledgments: u64,
    /// Maximum processed acknowledgment digests retained for duplicate detection.
    pub max_acknowledgment_digests: u64,
    /// Smallest Deduplication Set size a receive may pass.
    pub min_deduplication_capacity: u32,
    /// Deduplication Set size for apps without a reason to choose another.
    pub default_deduplication_capacity: u32,
    /// Largest Deduplication Set size a receive may pass.
    pub max_deduplication_capacity: u32,
}

/// The settings the app passes with each receive.
///
/// Roost holds no settings, so the app and its extensions apply whatever each receive passes.
/// Read the value the app should use from one place, such as its own settings or its Relay.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Record)]
pub struct ReceiveSettings {
    /// How many received-Message digests the Deduplication Set keeps, within
    /// [`ProtocolHardeningLimits`]'s range. Roost resizes the set when this changes, dropping the
    /// oldest digests first.
    pub deduplication_capacity: u32,
    /// Whether a blocked contact's Messages get an acknowledgment.
    pub blocked_contact_acknowledgment_policy: BlockedContactAcknowledgmentPolicy,
    /// How long after expiry a sender certificate still validates, in milliseconds, at most
    /// 300,000.
    ///
    /// A grace covers clock differences between devices, at the cost of accepting a certificate
    /// the relay has stopped vouching for.
    pub certificate_grace_millis: u64,
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

/// A peer's recipient delivery capability for one of its Discovery Key epochs.
///
/// Deliberately not [`Clone`]: [`Self::capability`] is a bearer secret, and every clone is another
/// heap copy nothing scrubs. Hand it straight to the relay submission that needs it.
#[derive(uniffi::Record)]
pub struct PeerInboxAuthorization {
    /// The peer's Discovery Key epoch this authorization belongs to.
    pub epoch: u32,
    /// The peer's recipient delivery capability for that epoch. Always 32 bytes, and secret.
    pub capability: Vec<u8>,
}

/// Contact mutation result.
#[derive(uniffi::Record)]
pub struct ContactStateChange {
    /// Complete contact snapshot after the operation.
    pub contact: ContactState,
    /// State changes to commit.
    pub changes: StateChanges,
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
    /// Original outbound Message ID.
    pub message_id: MessageId,
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
    /// Original outbound Message ID.
    pub message_id: MessageId,
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
    /// State changes to commit.
    pub changes: StateChanges,
}

/// An outbound Message and the state changes from one Message Operation.
#[derive(uniffi::Record)]
pub struct OutboundMessageResult {
    /// The Session Roost selected for the Message.
    pub session_id: SessionId,
    /// The draft's MessageID, sealed inside the Message.
    pub message_id: MessageId,
    /// Sender-observed Unix timestamp in milliseconds.
    pub sent_at_millis: u64,
    /// Payload kind sealed in the Message.
    pub payload_kind: PayloadKind,
    /// Message to send after durable commit.
    pub message: Message,
    /// State changes to commit atomically with the Message.
    pub changes: StateChanges,
}

/// Terminal Session reason.
#[derive(uniffi::Enum)]
pub enum SessionUnrecoverableReason {
    /// The skipped-message-key retention cap was exceeded.
    SkippedKeyLimitExceeded,
}

/// Session event emitted after committing the returned changes.
#[derive(uniffi::Record)]
pub struct SessionEvent {
    /// The Dead Session.
    pub session_id: SessionId,
    /// Terminal reason.
    pub reason: SessionUnrecoverableReason,
}

/// A provisional receive result. Commit its changes and effects atomically before use.
///
/// Switch on the outcome to obtain only the fields that case permits. The host transaction must
/// check the changes with [`StateChanges::matches`] and persist effects before plaintext is
/// displayed, an acknowledgment is sent, or recovery is scheduled.
#[derive(uniffi::Enum)]
pub enum InboundMessageOutcome {
    /// Authenticated plaintext and acknowledgment for a unique Message.
    Accepted {
        /// Payload for this outcome.
        result: InboundMessageResult,
    },
    /// A blocked Message with state changes and the acknowledgment its receive allows.
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
    /// The Message names a Session this identity doesn't have. No effects are produced.
    ///
    /// A Message whose `prekey_reference` is set may still start that Session through
    /// [`Messaging::prepare_accept_session`].
    UnknownSession,
    /// An acknowledgment cleared one of this identity's Pending Acknowledgments. Commit it before
    /// treating the acknowledged Message as delivered. Roost sends no reply to an acknowledgment.
    AcknowledgmentMatched {
        /// Payload for this outcome.
        result: AcknowledgmentResult,
    },
    /// An authenticated acknowledgment named no Pending Acknowledgment, such as one already
    /// cleared. Commit it anyway, so the advanced state recognizes a retry as a duplicate.
    AcknowledgmentUnmatched {
        /// Payload for this outcome.
        result: AcknowledgmentResult,
    },
}

/// Authenticated Message data that remains provisional until the host transaction commits.
///
/// The host commits the Message, acknowledgment, and state changes in one transaction.
/// Plaintext is host-owned secret bytes; clear discarded copies promptly.
#[derive(uniffi::Record)]
pub struct InboundMessageResult {
    /// The Session the Message arrived on.
    pub session_id: SessionId,
    /// Authenticated MessageID.
    pub message_id: MessageId,
    /// Authenticated sender timestamp in milliseconds.
    pub sent_at_millis: u64,
    /// Authenticated payload kind.
    pub payload_kind: PayloadKind,
    /// Plaintext for the host to protect and clear after use.
    pub plaintext: Vec<u8>,
    /// Authenticated sender material.
    pub sender_identity: SenderIdentityMaterial,
    /// Encrypted acknowledgment to commit with the Transport Binding the host supplied for it.
    pub acknowledgment: Message,
    /// State changes to commit with the accepted Message and acknowledgment.
    pub changes: StateChanges,
}

/// A blocked receive with no plaintext available to the caller.
///
/// The acknowledgment is present only under the silent-receipt policy. Commit it with the changes
/// before sending; under the default policy the host persists only the processed state.
#[derive(uniffi::Record)]
pub struct BlockedInboundMessageResult {
    /// Acknowledgment when the receive's policy permits one.
    pub acknowledgment: Option<Message>,
    /// State changes to commit before treating the Message as processed.
    pub changes: StateChanges,
}

/// A terminal Session and the recovery work required after durable commit.
///
/// An event accompanies the first durable observation. Persist it with the state changes so
/// restarts can resume recovery without reporting it twice. Only a fresh handshake, which gets its
/// own SessionID, replaces the Session; this result never resets it.
#[derive(uniffi::Record)]
pub struct SessionUnrecoverableResult {
    /// Session to replace through a fresh handshake.
    pub session_id: SessionId,
    /// Typed terminal reason.
    pub reason: SessionUnrecoverableReason,
    /// Once-only recovery signal to persist atomically with the state changes.
    pub event: Option<SessionEvent>,
    /// State changes that record delivery of the recovery signal.
    pub changes: StateChanges,
}

/// An authenticated acknowledgment and the state it advanced.
#[derive(uniffi::Record)]
pub struct AcknowledgmentResult {
    /// The Session the acknowledgment arrived on.
    pub session_id: SessionId,
    /// The acknowledgment's own MessageID.
    pub message_id: MessageId,
    /// Authenticated sender timestamp in milliseconds.
    pub sent_at_millis: u64,
    /// The outbound MessageID the acknowledgment names.
    pub acknowledged_message_id: MessageId,
    /// Authenticated sender material.
    pub sender_identity: SenderIdentityMaterial,
    /// State changes to commit before clearing the host's own delivery state.
    pub changes: StateChanges,
}

/// Blocked-contact acknowledgment policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum BlockedContactAcknowledgmentPolicy {
    /// Suppress acknowledgments so blocks look like unreachable recipients.
    Unreachable,
    /// Return normal acknowledgments while hiding plaintext.
    SilentReceipt,
}

/// Returns Roost's fixed limits and the Deduplication Set's range.
#[uniffi::export]
pub fn protocol_hardening_limits() -> ProtocolHardeningLimits {
    ProtocolHardeningLimits::from_core(roost_core::ProtocolHardeningLimits::default())
}

#[uniffi::export]
impl Messaging {
    /// Returns changes that delete every kind of record stored under `id`, such as a SessionID.
    ///
    /// Commit the changes atomically with the host effects that require the wipe.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if `id` isn't lowercase hexadecimal of a valid length, or the
    ///   snapshot exceeds its bounds or repeats a key.
    pub fn wipe(&self, snapshot: Vec<StateEntry>, id: String) -> Result<StateChanges, RoostError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        Ok(StateChanges::from_updates(
            self.inner
                .protocol_engine()
                .wipe(&snapshot, protocol_key(&id)?),
        ))
    }

    /// Returns all pending acknowledgments for a Session.
    ///
    /// Load the Session's pending-acknowledgment blob from the committed host store. This query does not change retry state.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if the SessionID isn't canonical or the snapshot exceeds its
    ///   bounds or repeats an address.
    /// - [`RoostError::ProtocolStateFault`] if the pending-acknowledgment blob is missing or malformed.
    /// - [`RoostError::UnsupportedVersion`] if the stored blob has an unsupported version.
    pub fn pending_acknowledgments(
        &self,
        snapshot: Vec<StateEntry>,
        session_id: SessionId,
    ) -> Result<Vec<PendingAcknowledgment>, RoostError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        Ok(self
            .inner
            .protocol_engine()
            .pending_acknowledgments(&snapshot, session_id.to_core()?)?
            .into_iter()
            .map(PendingAcknowledgment::from_core)
            .collect())
    }

    /// Returns retry instructions whose retry window elapsed.
    ///
    /// Commit the returned changes with the host retry work. Preserve each Message's originally supplied Transport Binding when submitting it again.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if the SessionID isn't canonical or the snapshot exceeds its
    ///   bounds or repeats an address.
    /// - [`RoostError::InternalError`] if updated retry state cannot be encoded.
    /// - [`RoostError::ProtocolStateFault`] if pending-acknowledgment state is missing or malformed.
    /// - [`RoostError::UnsupportedVersion`] if a stored blob has an unsupported version.
    pub fn retry_instructions(
        &self,
        snapshot: Vec<StateEntry>,
        session_id: SessionId,
        now_millis: u64,
        retry_window_millis: u64,
    ) -> Result<RetryInstructionResult, RoostError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        Ok(RetryInstructionResult::from_core(
            self.inner.protocol_engine().retry_instructions(
                &snapshot,
                session_id.to_core()?,
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
    /// Roost verifies the Contact Identity and Discovery Key binding. Commit the returned changes with the host contact record; an unchanged contact may produce no updates.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if peer key lengths or snapshot bounds are invalid.
    /// - [`RoostError::InternalError`] if the updated contact cannot be encoded.
    /// - [`RoostError::ProtocolStateFault`] if peer keys or their binding fail validation, or stored state is malformed.
    /// - [`RoostError::UnsupportedVersion`] if stored contact state has an unsupported version.
    pub fn record_contact(
        &self,
        snapshot: Vec<StateEntry>,
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
        snapshot: Vec<StateEntry>,
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
        snapshot: Vec<StateEntry>,
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
        snapshot: Vec<StateEntry>,
        identity_key: IdentityKey,
    ) -> Result<ContactStateChange, RoostError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        ContactStateChange::from_core(
            self.inner
                .protocol_engine()
                .accept_contact(&snapshot, identity_key.to_core()?)?,
        )
    }

    /// Records a peer's inbox authorization for an epoch.
    ///
    /// Returns no updates when `epoch` is not newer than what is stored. That refusal is
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
        snapshot: Vec<StateEntry>,
        identity_key: IdentityKey,
        epoch: u32,
        capability: Vec<u8>,
    ) -> Result<StateChanges, RoostError> {
        let capability = Zeroizing::new(capability);
        let snapshot = snapshot_input_from_entries(snapshot)?;
        let capability = CoreRecipientDeliveryCapability::from_bytes(fixed_32(
            &capability,
            "recipient delivery capability",
        )?);
        Ok(StateChanges::from_updates(
            self.inner
                .protocol_engine()
                .record_peer_inbox_authorization(
                    &snapshot,
                    identity_key.to_core()?,
                    epoch,
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
        snapshot: Vec<StateEntry>,
        identity_key: IdentityKey,
    ) -> Result<Option<PeerInboxAuthorization>, RoostError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        Ok(self
            .inner
            .protocol_engine()
            .peer_inbox_authorization(&snapshot, identity_key.to_core()?)?
            .map(|stored| PeerInboxAuthorization {
                epoch: stored.epoch,
                capability: stored.capability.to_bytes().to_vec(),
            }))
    }

    /// Records that a contact has been given the delivery capability for local epoch `epoch`.
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
        snapshot: Vec<StateEntry>,
        identity_key: IdentityKey,
        epoch: u32,
    ) -> Result<StateChanges, RoostError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        Ok(StateChanges::from_updates(
            self.inner
                .protocol_engine()
                .record_inbox_authorization_delivered(&snapshot, identity_key.to_core()?, epoch)?,
        ))
    }

    /// Returns which of `candidates` still need the current epoch's delivery capability.
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
        snapshot: Vec<StateEntry>,
        current_epoch: u32,
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
            .contacts_needing_inbox_authorization(&snapshot, current_epoch, &candidates)?
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
    /// - [`RoostError::InternalError`] if a storage lock is poisoned or a state update cannot encode.
    /// - [`RoostError::InvalidData`] if the stored local Identity is malformed, or peer key lengths
    ///   or snapshot bounds are invalid.
    /// - [`RoostError::NotFound`] if the context has no local Identity.
    /// - [`RoostError::OperationRecoveryRequired`] if a committed secure operation needs recovery.
    /// - [`RoostError::ProtocolStateFault`] if peer keys are not canonical, or the contact is missing, unaccepted, or corrupt.
    /// - [`RoostError::Storage`] if platform storage fails.
    /// - [`RoostError::UnsupportedVersion`] if stored Identity or contact state has an unsupported version.
    pub fn confirm_contact_safety_number(
        &self,
        snapshot: Vec<StateEntry>,
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
        snapshot: Vec<StateEntry>,
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

#[uniffi::export]
impl StateChanges {
    /// Returns whether every condition still holds for `current`, the host's entry for each
    /// condition's key, read inside the commit's transaction.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if `current` misses a condition's key, repeats one, names one
    ///   no condition has, or a key or digest is malformed.
    pub fn matches(&self, current: Vec<StateEntry>) -> Result<bool, RoostError> {
        let current = entries_to_core(current)?;
        let conditions = self
            .conditions
            .iter()
            .map(CommitCondition::to_core)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(roost_core::commit_conditions_match(&conditions, &current)?)
    }
}

impl StateChanges {
    pub(crate) fn from_core(changes: CoreStateChanges) -> Self {
        let conditions = changes
            .conditions()
            .iter()
            .map(|(address, condition)| CommitCondition::from_core(address, *condition))
            .collect();
        Self {
            conditions,
            updates: changes
                .into_updates()
                .into_iter()
                .map(StateUpdate::from_core)
                .collect(),
        }
    }

    // Conditions come from each update, for operations that read only what they write.
    pub(crate) fn from_updates(updates: Vec<CoreProtocolStateUpdate>) -> Self {
        Self::from_core(CoreStateChanges::from(updates))
    }
}

impl CommitCondition {
    fn from_core(
        address: &CoreProtocolStateAddress,
        condition: ProtocolStateCommitCondition,
    ) -> Self {
        Self {
            key: StateKey::from_core(address),
            digest: match condition {
                ProtocolStateCommitCondition::Absent => None,
                ProtocolStateCommitCondition::Digest(digest) => Some(digest.to_vec()),
            },
        }
    }

    fn to_core(
        &self,
    ) -> Result<(CoreProtocolStateAddress, ProtocolStateCommitCondition), RoostError> {
        let condition = match &self.digest {
            None => ProtocolStateCommitCondition::Absent,
            Some(digest) => {
                ProtocolStateCommitCondition::Digest(fixed_32(digest, "commit condition digest")?)
            }
        };
        Ok((self.key.to_core()?, condition))
    }
}

impl StateUpdate {
    fn from_core(update: CoreProtocolStateUpdate) -> Self {
        Self {
            key: StateKey::from_core(update.address()),
            blob: update.blob().map(|blob| blob.as_bytes().to_vec()),
        }
    }
}

impl StateKey {
    pub(crate) fn from_core(address: &CoreProtocolStateAddress) -> Self {
        Self {
            kind: ProtocolStateKind::from_core(address.kind()),
            id: hex_text(address.key().as_bytes()),
        }
    }

    pub(crate) fn to_core(&self) -> Result<CoreProtocolStateAddress, RoostError> {
        Ok(CoreProtocolStateAddress::new(
            self.kind.to_core(),
            protocol_key(&self.id)?,
        ))
    }
}

fn protocol_key(id: &str) -> Result<CoreProtocolStateKey, RoostError> {
    CoreProtocolStateKey::from_bytes(hex_bytes(id, "state id")?).map_err(RoostError::from)
}

// Wraps every entry's bytes before checking any key, so a malformed entry leaves no copy behind.
pub(crate) fn entries_to_core(
    mut entries: Vec<StateEntry>,
) -> Result<Vec<(CoreProtocolStateAddress, Option<CoreProtocolStateBlob>)>, RoostError> {
    if entries.len() > roost_core::MAX_PROTOCOL_STATE_ENTRIES {
        for entry in &mut entries {
            if let Some(blob) = &mut entry.blob {
                blob.zeroize();
            }
        }
        return Err(RoostError::InvalidData {
            reason: "too many protocol-state entries".into(),
        });
    }
    let wrapped: Vec<_> = entries
        .into_iter()
        .map(|entry| (entry.key, entry.blob.map(CoreProtocolStateBlob::from_bytes)))
        .collect();
    wrapped
        .into_iter()
        .map(|(key, blob)| Ok((key.to_core()?, blob)))
        .collect()
}

// Builds a snapshot from the host's present records; an entry without bytes adds nothing.
pub(crate) fn snapshot_input_from_entries(
    entries: Vec<StateEntry>,
) -> Result<CoreProtocolStateSnapshot, RoostError> {
    let mut snapshot = CoreProtocolStateSnapshot::new();
    for (address, blob) in entries_to_core(entries)? {
        if snapshot.get(&address).is_some() {
            return Err(RoostError::InvalidData {
                reason: "duplicate protocol-state address".into(),
            });
        }
        if let Some(blob) = blob {
            snapshot.set(address, blob)?;
        }
    }
    Ok(snapshot)
}

impl ProtocolHardeningLimits {
    fn from_core(value: roost_core::ProtocolHardeningLimits) -> Self {
        // Every limit is a fixed constant well inside both target types.
        Self {
            max_encoded_message_len: value.max_encoded_message_len as u64,
            max_message_payload_len: value.max_message_payload_len as u64,
            max_protocol_state_blob_len: value.max_protocol_state_blob_len as u64,
            max_sender_certificate_len: value.max_sender_certificate_len as u64,
            max_sender_signature_len: value.max_sender_signature_len as u64,
            max_pending_acknowledgments: value.max_pending_acknowledgments as u64,
            max_acknowledgment_digests: value.max_acknowledgment_digests as u64,
            min_deduplication_capacity: value.min_deduplication_capacity as u32,
            default_deduplication_capacity: value.default_deduplication_capacity as u32,
            max_deduplication_capacity: value.max_deduplication_capacity as u32,
        }
    }
}

impl ReceiveSettings {
    pub(crate) fn to_core(self) -> Result<roost_core::ReceiveSettings, RoostError> {
        let deduplication_capacity =
            usize::try_from(self.deduplication_capacity).map_err(|_| RoostError::InvalidData {
                reason: "deduplication capacity exceeds platform range".into(),
            })?;
        Ok(roost_core::ReceiveSettings::new(
            deduplication_capacity,
            self.blocked_contact_acknowledgment_policy.to_core(),
            Duration::from_millis(self.certificate_grace_millis),
        )?)
    }
}

impl BlockedContactAcknowledgmentPolicy {
    fn to_core(self) -> roost_core::BlockedContactAcknowledgmentPolicy {
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
    pub(crate) fn from_core(value: roost_core::ContactIdentity) -> Result<Self, RoostError> {
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
            changes: StateChanges::from_updates(value.state_updates),
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
            message_id: MessageId::from_core(value.message_id),
            message: Message::from_core(value.message),
            first_sent_at_millis: value.first_sent_at_millis,
            last_retried_at_millis: value.last_retried_at_millis,
        }
    }
}

impl RetryInstruction {
    fn from_core(value: roost_core::RetryInstruction) -> Self {
        Self {
            message_id: MessageId::from_core(value.message_id),
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
            changes: StateChanges::from_updates(value.state_updates),
        }
    }
}

impl OutboundMessageResult {
    pub(crate) fn from_core(value: roost_core::OutboundMessageResult) -> Self {
        Self {
            session_id: SessionId::from_core(value.session_id),
            message_id: MessageId::from_core(value.message_id),
            sent_at_millis: value.sent_at_millis,
            payload_kind: PayloadKind::from_protocol(value.payload_kind),
            message: Message::from_core(value.message),
            changes: StateChanges::from_core(value.changes),
        }
    }
}

impl InboundMessageOutcome {
    pub(crate) fn from_core(value: roost_core::InboundMessageOutcome) -> Self {
        match value {
            roost_core::InboundMessageOutcome::Accepted(result) => Self::Accepted {
                result: InboundMessageResult {
                    session_id: SessionId::from_core(result.session_id),
                    message_id: MessageId::from_core(result.message_id),
                    sent_at_millis: result.sent_at_millis,
                    payload_kind: PayloadKind::from_protocol(result.payload_kind),
                    plaintext: result.plaintext.to_vec(),
                    sender_identity: SenderIdentityMaterial::from_core(result.sender_identity),
                    acknowledgment: Message::from_core(result.acknowledgment),
                    changes: StateChanges::from_core(result.changes),
                },
            },
            roost_core::InboundMessageOutcome::Blocked(result) => Self::Blocked {
                result: BlockedInboundMessageResult {
                    acknowledgment: result.acknowledgment.map(Message::from_core),
                    changes: StateChanges::from_core(result.changes),
                },
            },
            roost_core::InboundMessageOutcome::Duplicate => Self::Duplicate,
            roost_core::InboundMessageOutcome::SessionUnrecoverable(result) => {
                Self::SessionUnrecoverable {
                    result: SessionUnrecoverableResult::from_core(*result),
                }
            }
            roost_core::InboundMessageOutcome::UnknownSession => Self::UnknownSession,
            roost_core::InboundMessageOutcome::AcknowledgmentMatched(result) => {
                Self::AcknowledgmentMatched {
                    result: AcknowledgmentResult::from_core(*result),
                }
            }
            roost_core::InboundMessageOutcome::AcknowledgmentUnmatched(result) => {
                Self::AcknowledgmentUnmatched {
                    result: AcknowledgmentResult::from_core(*result),
                }
            }
        }
    }
}

impl SessionUnrecoverableResult {
    fn from_core(result: roost_core::SessionUnrecoverableResult) -> Self {
        Self {
            session_id: SessionId::from_core(result.session_id),
            reason: SessionUnrecoverableReason::from_core(result.reason),
            event: result.event.map(SessionEvent::from_core),
            changes: StateChanges::from_core(result.changes),
        }
    }
}

impl AcknowledgmentResult {
    fn from_core(result: roost_core::AcknowledgmentResult) -> Self {
        Self {
            session_id: SessionId::from_core(result.session_id),
            message_id: MessageId::from_core(result.message_id),
            sent_at_millis: result.sent_at_millis,
            acknowledged_message_id: MessageId::from_core(result.acknowledged_message_id),
            sender_identity: SenderIdentityMaterial::from_core(result.sender_identity),
            changes: StateChanges::from_core(result.changes),
        }
    }
}

impl SessionEvent {
    fn from_core(value: roost_core::SessionEvent) -> Self {
        match value {
            roost_core::SessionEvent::Unrecoverable { session_id, reason } => Self {
                session_id: SessionId::from_core(session_id),
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
            roost_core::ProtocolStateKind::PeerSessions => Self::PeerSessions,
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
            Self::PeerSessions => roost_core::ProtocolStateKind::PeerSessions,
        }
    }
}
