//! UniFFI protocol-state objects, records, and host persistence boundary.

use crate::client::{Contacts, Messaging};
use crate::error::ClientError;
use crate::message::{Message, PayloadKind, SenderIdentityMaterial};
use crate::records::{fixed_32, fixed_64};
use rand::rngs::OsRng;
use roost_core::RecipientDeliveryCapability as CoreRecipientDeliveryCapability;
use roost_core::{
    ContactSafetyNumberConfirmation as CoreSafetyNumberConfirmation,
    ContactStateChange as CoreContactStateChange, ProtocolStateAddress as CoreProtocolStateAddress,
    ProtocolStateBlob as CoreProtocolStateBlob, ProtocolStateKey as CoreProtocolStateKey,
    ProtocolStateSnapshot as CoreProtocolStateSnapshot,
    ProtocolStateUpdate as CoreProtocolStateUpdate,
};
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
///
/// # Examples
/// ```
/// use roost_client::{ProtocolStateCommitCheck, ProtocolStateUpdate};
///
/// fn requires_absent_blob(update: &ProtocolStateUpdate) -> bool {
///     matches!(update.commit_check, ProtocolStateCommitCheck::Absent)
/// }
/// ```
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

/// Permanent Identity Key bytes used for trust, certificates, and contacts.
#[derive(Clone, uniffi::Record)]
pub struct IdentityKey {
    /// Canonical X25519 public key bytes. Always 32 bytes.
    pub x25519_public_key: Vec<u8>,
    /// Canonical Ed25519 verifying-key bytes. Always 32 bytes.
    pub ed25519_verifying_key: Vec<u8>,
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
    /// Signed creation timestamp in Unix seconds.
    pub created_at: u64,
    /// Identity-key signature over the Discovery Key bundle. Always 64 bytes.
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
    pub first_sent_millis: u64,
    /// Last retry-instruction timestamp in milliseconds.
    pub last_retry_millis: Option<u64>,
}

/// Retry instruction for an unacknowledged Message.
#[derive(uniffi::Record)]
pub struct RetryInstruction {
    /// Original outbound Message ID. Always 16 bytes.
    pub message_id: Vec<u8>,
    /// Message the host may retransmit.
    pub message: Message,
    /// First-send Unix timestamp in milliseconds.
    pub first_sent_millis: u64,
    /// Previous retry-instruction timestamp in milliseconds.
    pub last_retry_millis: Option<u64>,
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
    pub timestamp_millis: u64,
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
///
/// # Examples
/// ```
/// use roost_client::{ClientError, InboundMessageOutcome};
///
/// fn receive(
///     outcome: InboundMessageOutcome,
///     commit_atomically: impl FnOnce(&InboundMessageOutcome) -> Result<(), ClientError>,
/// ) -> Result<Option<Vec<u8>>, ClientError> {
///     commit_atomically(&outcome)?;
///     Ok(match outcome {
///         InboundMessageOutcome::Accepted { result } => Some(result.plaintext),
///         _ => None,
///     })
/// }
/// ```
#[derive(uniffi::Enum)]
#[expect(
    clippy::large_enum_variant,
    reason = "UniFFI enum variants carry outcome records by value"
)]
pub enum InboundMessageOutcome {
    /// Authenticated plaintext, evidence, and acknowledgment for a unique Message.
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
/// Plaintext and evidence are host-owned secret bytes; clear discarded copies promptly.
///
/// # Examples
/// ```
/// use roost_client::{ClientError, InboundMessageResult};
///
/// fn accept(
///     result: InboundMessageResult,
///     commit_atomically: impl FnOnce(&InboundMessageResult) -> Result<(), ClientError>,
/// ) -> Result<Vec<u8>, ClientError> {
///     commit_atomically(&result)?;
///     Ok(result.plaintext)
/// }
/// ```
#[derive(uniffi::Record)]
pub struct InboundMessageResult {
    /// Authenticated Message identifier. Always 16 bytes.
    pub message_id: Vec<u8>,
    /// Authenticated sender timestamp in milliseconds.
    pub timestamp_millis: u64,
    /// Authenticated payload kind.
    pub payload_kind: PayloadKind,
    /// Plaintext for the host to protect and clear after use.
    pub plaintext: Vec<u8>,
    /// Authenticated sender material.
    pub sender_identity: SenderIdentityMaterial,
    /// Authenticity evidence containing plaintext. Retain only when reporting policy requires.
    pub evidence_bundle: Vec<u8>,
    /// Encrypted acknowledgment to commit with its exact caller-supplied Transport Binding.
    pub acknowledgment: Message,
    /// Conditional opaque updates to commit with the accepted Message and acknowledgment.
    pub state_updates: Vec<ProtocolStateUpdate>,
}

/// A blocked receive with no plaintext or evidence available to the caller.
///
/// The acknowledgment is present only under the silent-receipt policy. Commit it with the updates
/// before sending; under the default policy the host persists only the processed state.
///
/// # Examples
/// ```
/// use roost_client::{BlockedInboundMessageResult, ClientError, Message};
///
/// fn process_blocked(
///     result: BlockedInboundMessageResult,
///     commit_atomically: impl FnOnce(&BlockedInboundMessageResult) -> Result<(), ClientError>,
/// ) -> Result<Option<Message>, ClientError> {
///     commit_atomically(&result)?;
///     Ok(result.acknowledgment)
/// }
/// ```
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
///
/// # Examples
/// ```
/// use roost_client::{ClientError, SessionEvent, SessionUnrecoverableResult};
///
/// fn record_recovery(
///     result: SessionUnrecoverableResult,
///     commit_atomically: impl FnOnce(&SessionUnrecoverableResult) -> Result<(), ClientError>,
/// ) -> Result<Option<SessionEvent>, ClientError> {
///     commit_atomically(&result)?;
///     Ok(result.event)
/// }
/// ```
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
///
/// # Examples
/// ```
/// use roost_client::{AcknowledgmentOutcome, ClientError};
///
/// fn acknowledge(
///     outcome: AcknowledgmentOutcome,
///     commit_atomically: impl FnOnce(&AcknowledgmentOutcome) -> Result<(), ClientError>,
/// ) -> Result<Option<Vec<u8>>, ClientError> {
///     commit_atomically(&outcome)?;
///     Ok(match outcome {
///         AcknowledgmentOutcome::Cleared { result } => Some(result.acknowledged_message_id),
///         _ => None,
///     })
/// }
/// ```
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
///
/// # Examples
/// ```
/// use roost_client::{AcknowledgmentResult, ClientError};
///
/// fn commit_acknowledgment(
///     result: AcknowledgmentResult,
///     commit_atomically: impl FnOnce(&AcknowledgmentResult) -> Result<(), ClientError>,
/// ) -> Result<Vec<u8>, ClientError> {
///     commit_atomically(&result)?;
///     Ok(result.acknowledged_message_id)
/// }
/// ```
#[derive(uniffi::Record)]
pub struct AcknowledgmentResult {
    /// Acknowledgment Message identifier. Always 16 bytes.
    pub message_id: Vec<u8>,
    /// Authenticated sender timestamp in milliseconds.
    pub timestamp_millis: u64,
    /// Outbound Message identifier named by the acknowledgment. Always 16 bytes.
    pub acknowledged_message_id: Vec<u8>,
    /// Authenticated sender material.
    pub sender_identity: SenderIdentityMaterial,
    /// Conditional updates to commit before clearing host pending state.
    pub state_updates: Vec<ProtocolStateUpdate>,
}

/// Blocked-contact acknowledgment policy.
#[derive(Clone, Copy, uniffi::Enum)]
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
    /// The values come from this Client's immutable configuration and describe the limits applied to its operations.
    ///
    /// # Examples
    /// ```
    /// # use roost_client::{ClientError, Messaging, ProtocolStateEntry};
    /// fn example(messaging: &Messaging) -> Result<(), ClientError> {
    ///     let limits = messaging.hardening_limits();
    ///     assert!(limits.deduplication_capacity > 0);
    ///     Ok(())
    /// }
    /// ```
    pub fn hardening_limits(&self) -> ProtocolHardeningLimits {
        self.inner.protocol_engine().hardening_limits().into()
    }

    /// Returns an update that initializes a deduplication set.
    ///
    /// Persist the update with the first application effects using this set. Its absent precondition refuses replacement of an existing set.
    ///
    /// # Examples
    /// ```
    /// # use roost_client::{ClientError, Messaging, ProtocolStateEntry};
    /// fn example(messaging: &Messaging) -> Result<(), ClientError> {
    ///     let update = messaging.initialize_deduplication_set(b"deduplication".to_vec())?;
    ///     assert!(matches!(update.commit_check, roost_client::ProtocolStateCommitCheck::Absent));
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::InvalidData`] if the key exceeds the protocol address limit.
    /// - [`ClientError::InternalError`] if the new state cannot be encoded.
    pub fn initialize_deduplication_set(
        &self,
        key: Vec<u8>,
    ) -> Result<ProtocolStateUpdate, ClientError> {
        ProtocolStateUpdate::from_core(
            self.inner
                .protocol_engine()
                .initialize_deduplication_set(&mut OsRng, protocol_key(key)?)?,
        )
    }

    /// Returns an update that initializes pending-acknowledgment state.
    ///
    /// Persist the returned absent-checked update before using a separately initialized Session. Session initiation creates its own acknowledgment state.
    ///
    /// # Examples
    /// ```
    /// # use roost_client::{ClientError, Messaging, ProtocolStateEntry};
    /// fn example(messaging: &Messaging) -> Result<(), ClientError> {
    ///     let update = messaging.initialize_pending_acknowledgments(vec![1; 16])?;
    ///     assert!(update.blob.is_some());
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::InvalidData`] if the key exceeds the protocol address limit.
    /// - [`ClientError::InternalError`] if the new state cannot be encoded.
    pub fn initialize_pending_acknowledgments(
        &self,
        key: Vec<u8>,
    ) -> Result<ProtocolStateUpdate, ClientError> {
        ProtocolStateUpdate::from_core(
            self.inner
                .protocol_engine()
                .initialize_pending_acknowledgments(protocol_key(key)?)?,
        )
    }

    /// Returns deletion updates for all protocol-state kinds at the key.
    ///
    /// Deletion remains conditional on the supplied snapshot. Commit the returned updates atomically with the host effects that require the wipe.
    ///
    /// # Examples
    /// ```
    /// # use roost_client::{ClientError, Messaging, ProtocolStateEntry};
    /// fn example(messaging: &Messaging, snapshot: Vec<ProtocolStateEntry>) -> Result<(), ClientError> {
    ///     let updates = messaging.wipe(snapshot, vec![1; 16])?;
    ///     assert!(updates.iter().all(|update| update.blob.is_none()));
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::InvalidData`] if a key or snapshot exceeds its bounds or repeats an address.
    pub fn wipe(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        key: Vec<u8>,
    ) -> Result<Vec<ProtocolStateUpdate>, ClientError> {
        self.inner
            .protocol_engine()
            .wipe(&snapshot_input_from_entries(snapshot)?, protocol_key(key)?)
            .into_iter()
            .map(ProtocolStateUpdate::from_core)
            .collect()
    }

    /// Returns all pending acknowledgments for a Session.
    ///
    /// Load the Session's pending-acknowledgment blob from the committed host store. This query does not change retry state.
    ///
    /// # Examples
    /// ```
    /// # use roost_client::{ClientError, Messaging, ProtocolStateEntry};
    /// fn example(messaging: &Messaging, snapshot: Vec<ProtocolStateEntry>) -> Result<(), ClientError> {
    ///     let pending = messaging.pending_acknowledgments(snapshot, vec![1; 16])?;
    ///     let _ = pending;
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::InvalidData`] if a key or snapshot exceeds its bounds or repeats an address.
    /// - [`ClientError::ProtocolStateFault`] if the pending-acknowledgment blob is missing or malformed.
    /// - [`ClientError::UnsupportedVersion`] if the stored blob has an unsupported version.
    pub fn pending_acknowledgments(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        key: Vec<u8>,
    ) -> Result<Vec<PendingAcknowledgment>, ClientError> {
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
    /// # Examples
    /// ```
    /// # use roost_client::{ClientError, Messaging, ProtocolStateEntry};
    /// fn example(messaging: &Messaging, snapshot: Vec<ProtocolStateEntry>) -> Result<(), ClientError> {
    ///     let retry = messaging.retry_instructions(snapshot, vec![1; 16], 2_000, 1_000)?;
    ///     let _ = retry.state_updates;
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::InvalidData`] if a key or snapshot exceeds its bounds or repeats an address.
    /// - [`ClientError::InternalError`] if updated retry state cannot be encoded.
    /// - [`ClientError::ProtocolStateFault`] if pending-acknowledgment state is missing or malformed.
    /// - [`ClientError::UnsupportedVersion`] if a stored blob has an unsupported version.
    pub fn retry_instructions(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        key: Vec<u8>,
        now_millis: u64,
        retry_window_millis: u64,
    ) -> Result<RetryInstructionResult, ClientError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        RetryInstructionResult::from_core(self.inner.protocol_engine().retry_instructions(
            &snapshot,
            protocol_key(key)?,
            now_millis,
            retry_window_millis,
        )?)
    }
}

#[uniffi::export]
impl Contacts {
    /// Creates or updates a Contact State blob.
    ///
    /// Roost verifies the Contact Identity and Discovery Key binding. Commit the returned updates with the host contact record; an unchanged contact may produce no updates.
    ///
    /// # Examples
    /// ```
    /// # use roost_client::{ClientError, Contacts, ProtocolStateEntry};
    /// fn example(contacts: &Contacts, snapshot: Vec<ProtocolStateEntry>, peer: roost_client::ContactIdentity) -> Result<(), ClientError> {
    ///     let change = contacts.record_contact(snapshot, peer)?;
    ///     let _ = change.state_updates;
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::InvalidData`] if peer key lengths or snapshot bounds are invalid.
    /// - [`ClientError::InternalError`] if the updated contact cannot be encoded.
    /// - [`ClientError::ProtocolStateFault`] if peer keys or their binding fail validation, or stored state is malformed.
    /// - [`ClientError::UnsupportedVersion`] if stored contact state has an unsupported version.
    pub fn record_contact(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        contact_identity: ContactIdentity,
    ) -> Result<ContactStateChange, ClientError> {
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
    /// # Examples
    /// ```
    /// # use roost_client::{ClientError, Contacts, ProtocolStateEntry};
    /// fn example(contacts: &Contacts, snapshot: Vec<ProtocolStateEntry>, peer: roost_client::IdentityKey) -> Result<(), ClientError> {
    ///     let contact = contacts.contact_state(snapshot, peer)?;
    ///     let _ = contact;
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::InvalidData`] if peer key lengths or snapshot bounds are invalid.
    /// - [`ClientError::ProtocolStateFault`] if peer keys are not canonical or stored contact state is malformed.
    /// - [`ClientError::UnsupportedVersion`] if stored contact state has an unsupported version.
    pub fn contact_state(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        identity_key: IdentityKey,
    ) -> Result<Option<ContactState>, ClientError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        Ok(self
            .inner
            .protocol_engine()
            .contact_state(&snapshot, identity_key.to_core()?)?
            .map(ContactState::from_core))
    }

    /// Returns all Contact State snapshots.
    ///
    /// Project contacts from a snapshot freshly loaded from the committed host store. Platform observation can coalesce refreshes without retaining Rust subscriptions or cursors.
    ///
    /// # Examples
    /// ```
    /// # use roost_client::{ClientError, Contacts, ProtocolStateEntry};
    /// fn example(contacts: &Contacts, snapshot: Vec<ProtocolStateEntry>) -> Result<(), ClientError> {
    ///     let current = contacts.contact_states(snapshot)?;
    ///     let _ = current;
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::InvalidData`] if the snapshot exceeds its bounds or repeats an address.
    /// - [`ClientError::ProtocolStateFault`] if stored contact state is malformed.
    /// - [`ClientError::UnsupportedVersion`] if stored contact state has an unsupported version.
    pub fn contact_states(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
    ) -> Result<Vec<ContactState>, ClientError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        Ok(self
            .inner
            .protocol_engine()
            .contact_states(&snapshot)?
            .into_iter()
            .map(ContactState::from_core)
            .collect())
    }

    /// Accepts a pending contact.
    ///
    /// Accepting a pending peer changes its trust to unverified. Commit the returned contact changes before sending application messages to that peer.
    ///
    /// # Examples
    /// ```
    /// # use roost_client::{ClientError, Contacts, ProtocolStateEntry};
    /// fn example(contacts: &Contacts, snapshot: Vec<ProtocolStateEntry>, peer: roost_client::IdentityKey) -> Result<(), ClientError> {
    ///     let change = contacts.accept_contact(snapshot, peer)?;
    ///     let _ = change.state_updates;
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::InvalidData`] if peer key lengths or snapshot bounds are invalid.
    /// - [`ClientError::InternalError`] if the updated contact cannot be encoded.
    /// - [`ClientError::ProtocolStateFault`] if peer keys are not canonical, or the contact is missing or malformed.
    /// - [`ClientError::UnsupportedVersion`] if stored contact state has an unsupported version.
    pub fn accept_contact(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        identity_key: IdentityKey,
    ) -> Result<ContactStateChange, ClientError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        ContactStateChange::from_core(
            self.inner
                .protocol_engine()
                .accept_contact(&snapshot, identity_key.to_core()?)?,
        )
    }

    /// Records a peer's inbox authorization for a generation (AE-CON-05).
    ///
    /// Returns no updates when `generation` is not newer than what is stored. That refusal is
    /// load-bearing: an old authorization replayed at a contact would restore a capability the
    /// peer has already rotated away from, which is exactly the state a blocked sender wants to
    /// reach (AE-BLK-08).
    ///
    /// # Examples
    /// ```
    /// # use roost_client::{ClientError, Contacts, IdentityKey, ProtocolStateEntry};
    /// fn example(contacts: &Contacts, snapshot: Vec<ProtocolStateEntry>, peer: IdentityKey, capability: Vec<u8>) -> Result<(), ClientError> {
    ///     let result = contacts.record_peer_inbox_authorization(snapshot, peer, 2, capability)?;
    ///     # let _ = result;
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::InternalError`] if the new authorization cannot be encoded.
    /// - [`ClientError::InvalidData`] if keys, capability length, or snapshot bounds are invalid.
    /// - [`ClientError::ProtocolStateFault`] if the peer key is not canonical or stored authorization is malformed.
    /// - [`ClientError::UnsupportedVersion`] if stored authorization has an unsupported version.
    pub fn record_peer_inbox_authorization(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        identity_key: IdentityKey,
        generation: u32,
        capability: Vec<u8>,
    ) -> Result<Vec<ProtocolStateUpdate>, ClientError> {
        let capability = Zeroizing::new(capability);
        let snapshot = snapshot_input_from_entries(snapshot)?;
        let capability = CoreRecipientDeliveryCapability::from_bytes(fixed_32(
            &capability,
            "recipient delivery capability",
        )?);
        updates_from_core(
            self.inner
                .protocol_engine()
                .record_peer_inbox_authorization(
                    &snapshot,
                    identity_key.to_core()?,
                    generation,
                    &capability,
                )?,
        )
    }

    /// Returns the stored inbox authorization for a peer, if one has been recorded.
    ///
    /// # Examples
    /// ```
    /// # use roost_client::{ClientError, Contacts, IdentityKey, ProtocolStateEntry};
    /// fn example(contacts: &Contacts, snapshot: Vec<ProtocolStateEntry>, peer: IdentityKey) -> Result<(), ClientError> {
    ///     let result = contacts.peer_inbox_authorization(snapshot, peer)?;
    ///     # let _ = result;
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::InvalidData`] if key lengths or snapshot bounds are invalid.
    /// - [`ClientError::ProtocolStateFault`] if the peer key is not canonical or stored authorization is malformed.
    /// - [`ClientError::UnsupportedVersion`] if stored authorization has an unsupported version.
    pub fn peer_inbox_authorization(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        identity_key: IdentityKey,
    ) -> Result<Option<PeerInboxAuthorization>, ClientError> {
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
    /// # Examples
    /// ```
    /// # use roost_client::{ClientError, Contacts, IdentityKey, ProtocolStateEntry};
    /// fn example(contacts: &Contacts, snapshot: Vec<ProtocolStateEntry>, peer: IdentityKey) -> Result<(), ClientError> {
    ///     let result = contacts.record_inbox_authorization_delivered(snapshot, peer, 2)?;
    ///     # let _ = result;
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::InternalError`] if the new record cannot be encoded.
    /// - [`ClientError::InvalidData`] if key lengths or snapshot bounds are invalid.
    /// - [`ClientError::ProtocolStateFault`] if the peer key is not canonical or the stored record is malformed.
    /// - [`ClientError::UnsupportedVersion`] if the stored record has an unsupported version.
    pub fn record_inbox_authorization_delivered(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        identity_key: IdentityKey,
        generation: u32,
    ) -> Result<Vec<ProtocolStateUpdate>, ClientError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        updates_from_core(
            self.inner
                .protocol_engine()
                .record_inbox_authorization_delivered(
                    &snapshot,
                    identity_key.to_core()?,
                    generation,
                )?,
        )
    }

    /// Returns which of `candidates` still need the current inbox generation.
    ///
    /// A contact qualifies when it has never been given an authorization or was last given an
    /// older one. Blocked contacts are always excluded — re-supplying one would hand back the very
    /// capability the rotation revoked and silently undo the block (AE-BLK-08). Contacts with no
    /// stored contact record are skipped.
    ///
    /// # Examples
    /// ```
    /// # use roost_client::{ClientError, Contacts, IdentityKey, ProtocolStateEntry};
    /// fn example(contacts: &Contacts, snapshot: Vec<ProtocolStateEntry>, peer: IdentityKey) -> Result<(), ClientError> {
    ///     let result = contacts.contacts_needing_inbox_authorization(snapshot, 2, vec![peer])?;
    ///     # let _ = result;
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::InvalidData`] if candidate key lengths or snapshot bounds are invalid.
    /// - [`ClientError::ProtocolStateFault`] if a candidate key is not canonical or a stored record is malformed.
    /// - [`ClientError::UnsupportedVersion`] if a stored record has an unsupported version.
    pub fn contacts_needing_inbox_authorization(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        current_generation: u32,
        candidates: Vec<IdentityKey>,
    ) -> Result<Vec<IdentityKey>, ClientError> {
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

    /// Confirms a Safety Number using this Client's local Identity.
    ///
    /// The peer must already be accepted. A mismatch, including malformed presented text, returns
    /// no updates. The local Identity comes from this Client's storage and cannot be supplied by
    /// the caller. Commit a matching confirmation's updates before showing the peer as verified.
    ///
    /// # Examples
    /// ```
    /// # use roost_client::{ClientError, Contacts, IdentityKey, ProtocolStateEntry};
    /// fn confirm(
    ///     contacts: &Contacts,
    ///     snapshot: Vec<ProtocolStateEntry>,
    ///     peer: IdentityKey,
    ///     presented: String,
    /// ) -> Result<(), ClientError> {
    ///     let confirmation = contacts.confirm_contact_safety_number(snapshot, peer, presented)?;
    ///     // Commit `confirmation.change.state_updates` in the host store.
    ///     # let _ = confirmation;
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::Corrupt`] if stored local Identity material is incomplete or malformed.
    /// - [`ClientError::InternalError`] if a storage lock is poisoned or a state update cannot encode.
    /// - [`ClientError::InvalidData`] if peer key lengths or snapshot bounds are invalid.
    /// - [`ClientError::NotFound`] if the Client has no local Identity.
    /// - [`ClientError::OperationRecoveryRequired`] if a committed secure operation needs recovery.
    /// - [`ClientError::ProtocolStateFault`] if peer keys are not canonical, or the contact is missing, unaccepted, or corrupt.
    /// - [`ClientError::Storage`] if platform storage fails.
    /// - [`ClientError::UnsupportedVersion`] if stored Identity or contact state has an unsupported version.
    pub fn confirm_contact_safety_number(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        contact_identity_key: IdentityKey,
        presented_grouped_decimal: String,
    ) -> Result<ContactSafetyNumberConfirmation, ClientError> {
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
    /// # Examples
    /// ```
    /// # use roost_client::{ClientError, Contacts, ProtocolStateEntry};
    /// fn example(contacts: &Contacts, snapshot: Vec<ProtocolStateEntry>, peer: roost_client::IdentityKey) -> Result<(), ClientError> {
    ///     let change = contacts.unblock_contact(snapshot, peer)?;
    ///     let _ = change.state_updates;
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::InvalidData`] if peer key lengths or snapshot bounds are invalid.
    /// - [`ClientError::InternalError`] if the updated contact cannot be encoded.
    /// - [`ClientError::ProtocolStateFault`] if peer keys are not canonical, or the contact is missing or malformed.
    /// - [`ClientError::UnsupportedVersion`] if stored contact state has an unsupported version.
    pub fn unblock_contact(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        identity_key: IdentityKey,
    ) -> Result<ContactStateChange, ClientError> {
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
) -> Result<SafetyNumber, ClientError> {
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

pub(crate) fn protocol_key(key: Vec<u8>) -> Result<CoreProtocolStateKey, ClientError> {
    CoreProtocolStateKey::from_bytes(key).map_err(ClientError::from)
}

pub(crate) fn snapshot_input_from_entries(
    mut entries: Vec<ProtocolStateEntry>,
) -> Result<CoreProtocolStateSnapshot, ClientError> {
    if entries.len() > roost_core::MAX_PROTOCOL_STATE_ENTRIES {
        for entry in &mut entries {
            entry.blob.zeroize();
        }
        return Err(ClientError::InvalidData {
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
        let address = CoreProtocolStateAddress::new(kind.into(), protocol_key(key)?);
        if snapshot.get(&address).is_some() {
            return Err(ClientError::InvalidData {
                reason: "duplicate protocol-state address".into(),
            });
        }
        snapshot.set(address, blob)?;
    }
    Ok(snapshot)
}

impl ProtocolStateUpdate {
    pub(crate) fn from_core(update: CoreProtocolStateUpdate) -> Result<Self, ClientError> {
        Ok(Self {
            kind: ProtocolStateKind::from_core(update.address().kind())?,
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
        })
    }
}

pub(crate) fn updates_from_core(
    updates: Vec<CoreProtocolStateUpdate>,
) -> Result<Vec<ProtocolStateUpdate>, ClientError> {
    updates
        .into_iter()
        .map(ProtocolStateUpdate::from_core)
        .collect()
}

impl From<ProtocolStateKind> for roost_core::ProtocolStateKind {
    fn from(value: ProtocolStateKind) -> Self {
        match value {
            ProtocolStateKind::RatchetSession => Self::RatchetSession,
            ProtocolStateKind::DeduplicationSet => Self::DeduplicationSet,
            ProtocolStateKind::PendingAcknowledgments => Self::PendingAcknowledgments,
            ProtocolStateKind::ContactState => Self::ContactState,
            ProtocolStateKind::PeerInboxAuthorization => Self::PeerInboxAuthorization,
            ProtocolStateKind::LocalInboxAuthorization => Self::LocalInboxAuthorization,
        }
    }
}

impl From<roost_core::ProtocolHardeningLimits> for ProtocolHardeningLimits {
    fn from(value: roost_core::ProtocolHardeningLimits) -> Self {
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

impl From<BlockedContactAcknowledgmentPolicy> for roost_core::BlockedContactAcknowledgmentPolicy {
    fn from(value: BlockedContactAcknowledgmentPolicy) -> Self {
        match value {
            BlockedContactAcknowledgmentPolicy::Unreachable => Self::Unreachable,
            BlockedContactAcknowledgmentPolicy::SilentReceipt => Self::SilentReceipt,
        }
    }
}

impl IdentityKey {
    pub(crate) fn from_core(value: roost_core::IdentityKey) -> Self {
        Self {
            x25519_public_key: value.x25519_public_key.to_vec(),
            ed25519_verifying_key: value.ed25519_verifying_key.to_vec(),
        }
    }

    pub(crate) fn to_core(&self) -> Result<roost_core::IdentityKey, ClientError> {
        Ok(roost_core::IdentityKey {
            x25519_public_key: fixed_32(&self.x25519_public_key, "identity x25519 public key")?,
            ed25519_verifying_key: fixed_32(
                &self.ed25519_verifying_key,
                "identity ed25519 verifying key",
            )?,
        })
    }
}

impl ContactDiscoveryKey {
    fn from_core(value: roost_core::ContactDiscoveryKey) -> Self {
        Self {
            x25519_public_key: value.x25519_public_key.to_vec(),
            ed25519_verifying_key: value.ed25519_verifying_key.to_vec(),
            epoch: value.epoch,
            created_at: value.created_at,
            identity_signature: value.identity_signature.to_vec(),
        }
    }

    fn to_core(&self) -> Result<roost_core::ContactDiscoveryKey, ClientError> {
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
            created_at: self.created_at,
            identity_signature: fixed_64(
                &self.identity_signature,
                "contact discovery identity signature",
            )?,
        })
    }
}

impl ContactIdentity {
    fn from_core(value: roost_core::ContactIdentity) -> Self {
        Self {
            identity_key: IdentityKey::from_core(value.identity_key),
            discovery_key: ContactDiscoveryKey::from_core(value.discovery_key),
        }
    }

    fn to_core(&self) -> Result<roost_core::ContactIdentity, ClientError> {
        Ok(roost_core::ContactIdentity {
            identity_key: self.identity_key.to_core()?,
            discovery_key: self.discovery_key.to_core()?,
        })
    }
}

impl From<roost_core::ContactTrustState> for ContactTrustState {
    fn from(value: roost_core::ContactTrustState) -> Self {
        match value {
            roost_core::ContactTrustState::Pending => Self::Pending,
            roost_core::ContactTrustState::Unverified => Self::Unverified,
            roost_core::ContactTrustState::Verified => Self::Verified,
        }
    }
}

impl From<ContactTrustState> for roost_core::ContactTrustState {
    fn from(value: ContactTrustState) -> Self {
        match value {
            ContactTrustState::Pending => Self::Pending,
            ContactTrustState::Unverified => Self::Unverified,
            ContactTrustState::Verified => Self::Verified,
        }
    }
}

impl ContactState {
    pub(crate) fn from_core(value: roost_core::ContactState) -> Self {
        Self {
            identity: ContactIdentity::from_core(value.identity),
            trust_state: value.trust_state.into(),
            blocked: value.blocked,
        }
    }
}

impl ContactEvent {
    pub(crate) fn from_core(value: roost_core::ContactEvent) -> Self {
        match value {
            roost_core::ContactEvent::Changed { contact } => Self {
                kind: ContactEventKind::Changed,
                contact: ContactState::from_core(contact),
            },
        }
    }
}

impl ContactStateChange {
    pub(crate) fn from_core(value: CoreContactStateChange) -> Result<Self, ClientError> {
        Ok(Self {
            contact: ContactState::from_core(value.contact),
            state_updates: updates_from_core(value.state_updates)?,
            event: value.event.map(ContactEvent::from_core),
        })
    }
}

impl ContactSafetyNumberConfirmation {
    fn from_core(value: CoreSafetyNumberConfirmation) -> Result<Self, ClientError> {
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
            first_sent_millis: value.first_sent_millis,
            last_retry_millis: value.last_retry_millis,
        }
    }
}

impl RetryInstruction {
    fn from_core(value: roost_core::RetryInstruction) -> Self {
        Self {
            message_id: value.message_id.as_bytes().to_vec(),
            message: Message::from_core(value.message),
            first_sent_millis: value.first_sent_millis,
            last_retry_millis: value.last_retry_millis,
        }
    }
}

impl RetryInstructionResult {
    fn from_core(value: roost_core::RetryInstructionResult) -> Result<Self, ClientError> {
        Ok(Self {
            instructions: value
                .instructions
                .into_iter()
                .map(RetryInstruction::from_core)
                .collect(),
            state_updates: updates_from_core(value.state_updates)?,
        })
    }
}

impl OutboundMessageResult {
    pub(crate) fn from_core(value: roost_core::OutboundMessageResult) -> Result<Self, ClientError> {
        Ok(Self {
            message_id: value.message_id.as_bytes().to_vec(),
            timestamp_millis: value.timestamp_millis,
            payload_kind: value.payload_kind.into(),
            message: Message::from_core(value.message),
            state_updates: updates_from_core(value.state_updates)?,
        })
    }
}

impl InboundMessageOutcome {
    pub(crate) fn from_core(value: roost_core::InboundMessageOutcome) -> Result<Self, ClientError> {
        Ok(match value {
            roost_core::InboundMessageOutcome::Accepted(result) => {
                let state_updates = updates_from_core(result.state_updates)?;
                Self::Accepted {
                    result: InboundMessageResult {
                        message_id: result.message_id.as_bytes().to_vec(),
                        timestamp_millis: result.timestamp_millis,
                        payload_kind: result.payload_kind.into(),
                        plaintext: result.plaintext.to_vec(),
                        sender_identity: SenderIdentityMaterial::from_core(result.sender_identity),
                        evidence_bundle: result.evidence_bundle.as_bytes().to_vec(),
                        acknowledgment: Message::from_core(result.acknowledgment),
                        state_updates,
                    },
                }
            }
            roost_core::InboundMessageOutcome::Blocked(result) => Self::Blocked {
                result: BlockedInboundMessageResult {
                    acknowledgment: result.acknowledgment.map(Message::from_core),
                    state_updates: updates_from_core(result.state_updates)?,
                },
            },
            roost_core::InboundMessageOutcome::Duplicate => Self::Duplicate,
            roost_core::InboundMessageOutcome::SessionUnrecoverable(result) => {
                Self::SessionUnrecoverable {
                    result: SessionUnrecoverableResult::from_core(*result)?,
                }
            }
        })
    }
}

impl SessionUnrecoverableResult {
    fn from_core(result: roost_core::SessionUnrecoverableResult) -> Result<Self, ClientError> {
        Ok(Self {
            session_key: result.session_key.as_bytes().to_vec(),
            reason: SessionUnrecoverableReason::from_core(result.reason),
            event: result.event.map(SessionEvent::from_core),
            state_updates: updates_from_core(result.state_updates)?,
        })
    }
}

impl AcknowledgmentOutcome {
    pub(crate) fn from_core(value: roost_core::AcknowledgmentOutcome) -> Result<Self, ClientError> {
        Ok(match value {
            roost_core::AcknowledgmentOutcome::Cleared(result) => Self::Cleared {
                result: AcknowledgmentResult {
                    message_id: result.message_id.as_bytes().to_vec(),
                    timestamp_millis: result.timestamp_millis,
                    acknowledged_message_id: result.acknowledged_message_id.as_bytes().to_vec(),
                    sender_identity: SenderIdentityMaterial::from_core(result.sender_identity),
                    state_updates: updates_from_core(result.state_updates)?,
                },
            },
            roost_core::AcknowledgmentOutcome::Missed {
                message_id,
                timestamp_millis,
                acknowledged_message_id,
                sender_identity,
                state_updates,
            } => Self::Missed {
                result: AcknowledgmentResult {
                    message_id: message_id.as_bytes().to_vec(),
                    timestamp_millis,
                    acknowledged_message_id: acknowledged_message_id.as_bytes().to_vec(),
                    sender_identity: SenderIdentityMaterial::from_core(sender_identity),
                    state_updates: updates_from_core(state_updates)?,
                },
            },
            roost_core::AcknowledgmentOutcome::Duplicate => Self::Duplicate,
            roost_core::AcknowledgmentOutcome::SessionUnrecoverable(result) => {
                Self::SessionUnrecoverable {
                    result: SessionUnrecoverableResult::from_core(*result)?,
                }
            }
        })
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
    fn from_core(value: roost_core::ProtocolStateKind) -> Result<Self, ClientError> {
        match value {
            roost_core::ProtocolStateKind::RatchetSession => Ok(Self::RatchetSession),
            roost_core::ProtocolStateKind::DeduplicationSet => Ok(Self::DeduplicationSet),
            roost_core::ProtocolStateKind::PendingAcknowledgments => {
                Ok(Self::PendingAcknowledgments)
            }
            roost_core::ProtocolStateKind::ContactState => Ok(Self::ContactState),
            roost_core::ProtocolStateKind::PeerInboxAuthorization => {
                Ok(Self::PeerInboxAuthorization)
            }
            roost_core::ProtocolStateKind::LocalInboxAuthorization => {
                Ok(Self::LocalInboxAuthorization)
            }
            _ => Err(ClientError::UnsupportedVersion {
                reason: "unknown protocol-state kind".into(),
            }),
        }
    }
}
