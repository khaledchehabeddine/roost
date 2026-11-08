mod contact_record;
mod deduplication;
mod envelope;
mod grant;
mod message_operation;
mod pending_acknowledgment;
mod session;

use crate::contact::{
    ContactDiscoveryKey, ContactSafetyNumberConfirmation, ContactState, ContactTrustState,
};
use crate::hardening::{
    DEFAULT_DEDUPLICATION_CAPACITY, ProtocolHardeningLimits, validate_deduplication_capacity,
};
use crate::key_store::KeyStoreOperationId;
use crate::safety_number::{SafetyNumberError, derive_safety_number};
use crate::stored_data::{
    SignatureWire, StoredDataError, decode_exact, deserialize_bounded, encode_zeroizing,
};
use contact_record::{ContactRecord, contact_address};
pub use envelope::SenderIdentityMaterial;
pub use grant::is_newer_discovery_key;
pub use message_operation::{
    AdmissionRequest, DeliveryCheck, DeliveryCheckResult, DeliveryCheckStep, IncomingMessage,
    MessageDecryption, MessageDecryptionStep, MessageDestination, MessageEncryption,
    MessageEncryptionStep, MessageOperationError, MessageRecovery, MessageRecoveryStep,
    OutgoingGrantUpdate, OutgoingMessage, OutgoingRecovery, PeerPreKeyBundle,
    SignedSenderCertificate,
};
pub(crate) use message_operation::{LocalIdentityKeys, SendIntent};
pub use pending_acknowledgment::PendingAcknowledgment;
use roost_crypto::SealedFrame;
use roost_protocol::{
    IdentityKey, MAX_CERTIFICATE_GRACE_WINDOW, MessageId, MessageTranscriptError, PUBLIC_KEY_LEN,
    PayloadKind, SealedPayloadError, SenderCertificateValidationError, SessionId, SignatureError,
};
use serde::{Deserialize, Serialize};
use session::{
    encode_peer_sessions, load_peer_sessions, load_session, peer_sessions_address, session_address,
};
use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroizing;

const PROTOCOL_STATE_BLOB_VERSION: u8 = 1;
const PROTOCOL_STATE_BLOB_HEADER_LEN: usize = 1;
const MAX_PROTOCOL_STATE_KEY_LEN: usize = 96;
// Deduplication and acknowledgment digests keep this many bytes of their hash.
const DIGEST_LEN: usize = 16;

/// The key part of a protocol-state address, such as a session ID or an identity key.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProtocolStateKey(Vec<u8>);

impl ProtocolStateKey {
    /// Creates a protocol-state key from bounded bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, ProtocolStateError> {
        if bytes.is_empty() {
            return Err(ProtocolStateError::EmptyStateKey);
        }
        if bytes.len() > MAX_PROTOCOL_STATE_KEY_LEN {
            return Err(ProtocolStateError::StateKeyTooLong {
                len: bytes.len(),
                max: MAX_PROTOCOL_STATE_KEY_LEN,
            });
        }
        Ok(Self(bytes))
    }

    /// Returns the key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<IdentityKey> for ProtocolStateKey {
    fn from(value: IdentityKey) -> Self {
        Self(value.canonical_encoding().to_vec())
    }
}

/// The stable category for an opaque protocol-state blob.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProtocolStateKind {
    /// Session-ID-addressed Double Ratchet session state.
    RatchetSession,
    /// Deduplication-set state.
    DeduplicationSet,
    /// Session-ID-addressed pending-acknowledgment state.
    PendingAcknowledgments,
    /// Identity-key-addressed contact state, including the peer's delivery capability.
    ContactState,
    /// Identity-key-addressed record of the sessions kept with one peer and the one Roost sends on.
    PeerSessions,
}

impl fmt::Display for ProtocolStateKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RatchetSession => write!(f, "ratchet/session state"),
            Self::DeduplicationSet => write!(f, "deduplication-set state"),
            Self::PendingAcknowledgments => write!(f, "pending-acknowledgment state"),
            Self::ContactState => write!(f, "contact state"),
            Self::PeerSessions => write!(f, "peer sessions"),
        }
    }
}

/// A protocol-state blob address made of kind and key.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProtocolStateAddress {
    kind: ProtocolStateKind,
    key: ProtocolStateKey,
}

impl ProtocolStateAddress {
    /// Creates a protocol-state address.
    #[must_use]
    pub fn new(kind: ProtocolStateKind, key: ProtocolStateKey) -> Self {
        Self { kind, key }
    }

    /// Returns the state kind.
    #[must_use]
    pub fn kind(&self) -> ProtocolStateKind {
        self.kind
    }

    /// Returns the state key.
    #[must_use]
    pub fn key(&self) -> &ProtocolStateKey {
        &self.key
    }
}

impl fmt::Display for ProtocolStateAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:", self.kind)?;
        write_hex(f, self.key.as_bytes())
    }
}

/// An opaque protocol-state byte value.
///
/// The bytes may contain ratchet or other protocol secrets and are zeroized on drop.
pub struct ProtocolStateBlob {
    bytes: Zeroizing<Vec<u8>>,
}

impl ProtocolStateBlob {
    /// Wraps opaque protocol-state bytes.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    fn from_zeroizing(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self { bytes }
    }

    /// Returns the opaque blob bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// A condition Roost computes, which the app checks inside its state transaction.
///
/// A failed condition requires reloading state and processing the operation again.
#[derive(Clone, Copy, Debug)]
pub enum ProtocolStateCommitCondition {
    /// No blob may exist at this address.
    Absent,
    /// The current opaque blob must have this digest.
    Digest([u8; 32]),
}

impl ProtocolStateCommitCondition {
    fn is_satisfied_by(&self, blob: Option<&ProtocolStateBlob>) -> bool {
        match (self, blob) {
            (Self::Absent, None) => true,
            (Self::Digest(expected), Some(blob)) => {
                bool::from(expected.ct_eq(&protocol_state_blob_digest(blob.as_bytes())))
            }
            _ => false,
        }
    }

    fn from_blob(blob: Option<&ProtocolStateBlob>) -> Self {
        match blob {
            Some(blob) => Self::Digest(protocol_state_blob_digest(blob.as_bytes())),
            None => Self::Absent,
        }
    }
}

/// A state update the app must commit durably.
pub struct ProtocolStateUpdate {
    address: ProtocolStateAddress,
    blob: Option<ProtocolStateBlob>,
    condition: ProtocolStateCommitCondition,
}

impl ProtocolStateUpdate {
    #[must_use]
    fn set(address: ProtocolStateAddress, blob: ProtocolStateBlob) -> Self {
        Self {
            address,
            blob: Some(blob),
            condition: ProtocolStateCommitCondition::Absent,
        }
    }

    #[must_use]
    fn delete(address: ProtocolStateAddress) -> Self {
        Self {
            address,
            blob: None,
            condition: ProtocolStateCommitCondition::Absent,
        }
    }

    // Creates an update that replaces `current`, the record the app passed for `address`.
    fn replacing(
        address: ProtocolStateAddress,
        blob: Option<ProtocolStateBlob>,
        current: Option<&ProtocolStateBlob>,
    ) -> Self {
        Self {
            address,
            blob,
            condition: ProtocolStateCommitCondition::from_blob(current),
        }
    }

    fn with_snapshot(mut self, snapshot: &ProtocolStateSnapshot) -> Self {
        self.condition = ProtocolStateCommitCondition::from_blob(snapshot.get(&self.address));
        self
    }

    /// Returns the addressed blob location.
    #[must_use]
    pub fn address(&self) -> &ProtocolStateAddress {
        &self.address
    }

    /// Returns the blob to store, or `None` for deletion.
    #[must_use]
    pub fn blob(&self) -> Option<&ProtocolStateBlob> {
        self.blob.as_ref()
    }
}

/// The records an operation's result relies on, the records it writes, the prepared KeyStore
/// operation that commits with them, if any, and the sent messages Roost stops waiting for.
///
/// Message operations, delivery checks, and contact changes return these beside their result.
/// They're empty for a duplicate.
///
/// The app reads the record at each commit condition's address inside its transaction, and commits
/// the updates with the result's effects only when [`commit_conditions_match`] holds for them. The
/// app marks each of [`Self::undelivered`] not delivered in the same transaction. When
/// [`Self::operation`] is present, the app reserves it before the transaction, commits its ID with
/// the updates, and finalizes it before using the result.
pub struct StateChanges {
    conditions: Vec<(ProtocolStateAddress, ProtocolStateCommitCondition)>,
    updates: Vec<ProtocolStateUpdate>,
    operation: Option<KeyStoreOperationId>,
    undelivered: Vec<MessageId>,
}

impl StateChanges {
    fn empty() -> Self {
        Self {
            conditions: Vec::new(),
            updates: Vec::new(),
            operation: None,
            undelivered: Vec::new(),
        }
    }

    // Returns changes that rely on one record a call took directly and write at most that record.
    fn for_record(
        address: ProtocolStateAddress,
        current: Option<&ProtocolStateBlob>,
        update: Option<ProtocolStateUpdate>,
    ) -> Self {
        Self {
            conditions: vec![(address, ProtocolStateCommitCondition::from_blob(current))],
            updates: update.into_iter().collect(),
            operation: None,
            undelivered: Vec::new(),
        }
    }

    pub(crate) fn with_operation(mut self, operation: KeyStoreOperationId) -> Self {
        self.operation = Some(operation);
        self
    }

    fn with_undelivered(mut self, undelivered: Vec<MessageId>) -> Self {
        self.undelivered = undelivered;
        self
    }

    /// Returns the prepared KeyStore operation that commits with these changes, if any.
    #[must_use]
    pub fn operation(&self) -> Option<KeyStoreOperationId> {
        self.operation
    }

    /// Returns each commit condition with the address it applies to, in address order.
    #[must_use]
    pub fn conditions(&self) -> &[(ProtocolStateAddress, ProtocolStateCommitCondition)] {
        &self.conditions
    }

    /// Returns the sent messages Roost stops waiting for, oldest first, because the relay would
    /// have dropped them by now or their session is deleted.
    #[must_use]
    pub fn undelivered(&self) -> &[MessageId] {
        &self.undelivered
    }

    /// Returns the updates to commit.
    #[must_use]
    pub fn into_updates(self) -> Vec<ProtocolStateUpdate> {
        self.updates
    }
}

/// Returns whether every condition holds for `current`, which must hold exactly one record for
/// each condition's address, in any order.
pub fn commit_conditions_match(
    conditions: &[(ProtocolStateAddress, ProtocolStateCommitCondition)],
    current: &[(ProtocolStateAddress, Option<ProtocolStateBlob>)],
) -> Result<bool, StateEntryError> {
    let expected: Vec<&ProtocolStateAddress> =
        conditions.iter().map(|(address, _)| address).collect();
    let found = match_state_entries(&expected, current)?;
    Ok(conditions.iter().all(|(address, condition)| {
        found
            .get(address)
            .is_some_and(|blob| condition.is_satisfied_by(*blob))
    }))
}

// Checks that `entries` holds exactly one entry for each expected address, and returns them by
// address.
fn match_state_entries<'a>(
    expected: &[&ProtocolStateAddress],
    entries: &'a [(ProtocolStateAddress, Option<ProtocolStateBlob>)],
) -> Result<BTreeMap<&'a ProtocolStateAddress, Option<&'a ProtocolStateBlob>>, StateEntryError> {
    let mut found = BTreeMap::new();
    for (address, blob) in entries {
        if !expected.contains(&address) {
            return Err(StateEntryError::Unexpected {
                address: address.clone(),
            });
        }
        if found.insert(address, blob.as_ref()).is_some() {
            return Err(StateEntryError::Repeated {
                address: address.clone(),
            });
        }
    }
    if let Some(missing) = expected
        .iter()
        .find(|address| !found.contains_key(**address))
    {
        return Err(StateEntryError::Missing {
            address: (*missing).clone(),
        });
    }
    Ok(found)
}

/// Why the records the app returned don't line up with the ones Roost asked for.
#[derive(Debug, thiserror::Error)]
pub enum StateEntryError {
    /// No entry was returned for a requested record.
    #[error("no entry for {address}")]
    Missing {
        /// The requested record's address.
        address: ProtocolStateAddress,
    },
    /// More than one entry was returned for one record.
    #[error("more than one entry for {address}")]
    Repeated {
        /// The repeated record's address.
        address: ProtocolStateAddress,
    },
    /// An entry was returned for a record nobody asked for.
    #[error("unrequested entry for {address}")]
    Unexpected {
        /// The unrequested record's address.
        address: ProtocolStateAddress,
    },
}

// The records an operation read, by address.
#[derive(Default)]
pub(crate) struct ProtocolStateSnapshot {
    blobs: BTreeMap<ProtocolStateAddress, ProtocolStateBlob>,
}

impl ProtocolStateSnapshot {
    pub(crate) fn get(&self, address: &ProtocolStateAddress) -> Option<&ProtocolStateBlob> {
        self.blobs.get(address)
    }

    fn insert(&mut self, address: ProtocolStateAddress, blob: ProtocolStateBlob) {
        self.blobs.insert(address, blob);
    }
}

/// An outbound message from one message operation.
pub struct OutboundMessageResult {
    /// The session Roost selected for the message.
    pub session_id: SessionId,
    /// Stable identifier sealed inside the produced message.
    pub message_id: MessageId,
    /// Sender-observed Unix timestamp sealed inside the produced message.
    pub sent_at_millis: u64,
    /// Payload kind sealed inside the produced message.
    pub payload_kind: PayloadKind,
    /// Message for the app to send once it commits the state changes.
    pub message: SealedFrame,
}

/// Inbound plaintext from one message operation.
///
/// A sender's recovery resends a message under its original message ID with new bytes, so the app
/// shows one message per sender and message ID, and still commits and acknowledges each copy.
pub struct InboundMessageResult {
    /// The session the message arrived on.
    pub session_id: SessionId,
    /// The sender's message ID.
    pub message_id: MessageId,
    /// The sender's Unix timestamp, in milliseconds.
    pub sent_at_millis: u64,
    /// The payload kind.
    pub payload_kind: PayloadKind,
    /// Decrypted plaintext bytes.
    pub plaintext: Zeroizing<Vec<u8>>,
    /// Sender identity material decoded from the sealed sender envelope.
    pub sender_identity: SenderIdentityMaterial,
    /// Encrypted acknowledgment artifact to durably queue with the state changes, absent while
    /// the contact isn't accepted and this side doesn't acknowledge yet, or while no inbox grant
    /// has supplied the contact's current delivery capability.
    pub acknowledgment: Option<SealedFrame>,
}

/// A message from a contact who isn't accepted, past the limit on messages before acceptance.
///
/// Roost withholds its plaintext and sends no acknowledgment.
pub struct WithheldInboundMessageResult {
    /// The session the message arrived on.
    pub session_id: SessionId,
    /// The sender's message ID.
    pub message_id: MessageId,
}

/// A grant update, which has nothing to show.
pub struct GrantUpdateResult {
    /// The session the grant update arrived on.
    pub session_id: SessionId,
    /// The sender's message ID.
    pub message_id: MessageId,
    /// Encrypted acknowledgment artifact to durably queue with the state changes, absent while
    /// this side doesn't acknowledge the contact yet.
    pub acknowledgment: Option<SealedFrame>,
}

/// A blocked contact's message, which Roost accepted and whose plaintext it withholds.
pub struct BlockedInboundMessageResult {
    /// Encrypted acknowledgment artifact to durably queue with the state changes, or `None` when
    /// the blocked-contact acknowledgment policy suppresses it or no inbox grant has supplied the
    /// contact's current delivery capability.
    pub acknowledgment: Option<SealedFrame>,
}

/// An authenticated acknowledgment.
///
/// Its state changes commit whether it matched or not, so a retried acknowledgment is a
/// duplicate.
pub struct AcknowledgmentResult {
    /// The session the acknowledgment arrived on.
    pub session_id: SessionId,
    /// The acknowledgment's own message ID.
    pub message_id: MessageId,
    /// The sender's Unix timestamp for the acknowledgment.
    pub sent_at_millis: u64,
    /// The outbound message ID the acknowledgment names.
    pub acknowledged_message_id: MessageId,
    /// Sender identity material decoded from the acknowledgment.
    pub sender_identity: SenderIdentityMaterial,
}

/// The result of receiving an inbound encrypted message.
pub enum InboundMessageOutcome {
    /// A unique message decrypted and advanced protocol state.
    Accepted(Box<InboundMessageResult>),
    /// A first message from an identity with no contact record, which creates a pending one.
    ContactRequest(Box<InboundMessageResult>),
    /// A unique blocked message decrypted and advanced protocol state.
    Blocked(Box<BlockedInboundMessageResult>),
    /// A message past the limit before acceptance decrypted, and its plaintext is withheld.
    Withheld(Box<WithheldInboundMessageResult>),
    /// A grant update from a contact who isn't blocked.
    GrantUpdate(Box<GrantUpdateResult>),
    /// The message's bytes and transport binding match one already received.
    Duplicate,
    /// The message names a session this identity doesn't keep and carries no handshake, such as
    /// one whose records it lost, and nothing changed.
    UnknownSession,
    /// The first message names a session this identity deleted, so nothing was created.
    DeletedSession,
    /// An acknowledgment cleared one of this identity's pending acknowledgments.
    AcknowledgmentMatched(Box<AcknowledgmentResult>),
    /// An authenticated acknowledgment named no pending acknowledgment, such as one already
    /// cleared, or a message already reported as not delivered whose later copy arrived.
    AcknowledgmentUnmatched(Box<AcknowledgmentResult>),
}

/// Whether a blocked sender receives an acknowledgment for an accepted-but-hidden message.
///
/// The default is [`Self::Unreachable`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum BlockedContactAcknowledgmentPolicy {
    /// Return no acknowledgment and do not advance the sending chain, so a blocked sender can't
    /// tell the block from a recipient who is offline.
    #[default]
    Unreachable,
    /// Return the acknowledgment an unblocked sender would get, which reveals delivery. The
    /// plaintext stays hidden.
    Acknowledge,
}

/// The settings an app passes with each receive, checked against Roost's limits.
///
/// Roost holds no settings, so every library instance serving one identity, in the app or its
/// extensions, applies the values the app passes at that moment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiveSettings {
    deduplication_capacity: usize,
    blocked_contact_acknowledgment_policy: BlockedContactAcknowledgmentPolicy,
    certificate_grace: Duration,
}

impl ReceiveSettings {
    /// Returns settings after checking the deduplication set's size and the certificate grace.
    pub fn new(
        deduplication_capacity: usize,
        blocked_contact_acknowledgment_policy: BlockedContactAcknowledgmentPolicy,
        certificate_grace: Duration,
    ) -> Result<Self, ProtocolStateError> {
        validate_deduplication_capacity(deduplication_capacity)?;
        if certificate_grace > MAX_CERTIFICATE_GRACE_WINDOW {
            return Err(ProtocolStateError::SenderCertificateValidation(
                SenderCertificateValidationError::GraceWindowTooLarge {
                    grace_window: certificate_grace,
                    max: MAX_CERTIFICATE_GRACE_WINDOW,
                },
            ));
        }
        Ok(Self {
            deduplication_capacity,
            blocked_contact_acknowledgment_policy,
            certificate_grace,
        })
    }
}

impl Default for ReceiveSettings {
    /// Returns the default deduplication set size, no acknowledgments to blocked senders, and no
    /// grace.
    fn default() -> Self {
        Self {
            deduplication_capacity: DEFAULT_DEDUPLICATION_CAPACITY,
            blocked_contact_acknowledgment_policy: BlockedContactAcknowledgmentPolicy::Unreachable,
            certificate_grace: Duration::ZERO,
        }
    }
}

/// Stateless protocol-state operations over blobs the app holds.
///
/// The app must read required blobs from an atomic, durable, crash-consistent, and
/// integrity-preserving store before each operation, then commit returned updates atomically with
/// any produced message.
///
/// Received-message deduplication is scoped to one local identity through the
/// [`ProtocolStateKind::DeduplicationSet`] blob. It drops byte-identical encrypted message retries
/// before decryption, and the Double Ratchet's replay check rejects the replays it misses.
#[derive(Clone, Copy)]
pub struct ProtocolStateEngine {
    limits: ProtocolHardeningLimits,
}

impl ProtocolStateEngine {
    pub(crate) fn new() -> Self {
        Self {
            limits: ProtocolHardeningLimits::default(),
        }
    }

    /// Returns the contact a contact state record holds.
    pub fn decode_contact(
        &self,
        address: &ProtocolStateAddress,
        blob: &ProtocolStateBlob,
    ) -> Result<ContactState, ProtocolStateError> {
        if address.kind != ProtocolStateKind::ContactState {
            return Err(ProtocolStateError::InvalidStateBinding {
                address: address.clone(),
                reason: "record is not a contact".into(),
            });
        }
        Ok(ContactRecord::decode(address, blob, self.limits)?.to_contact_state())
    }

    /// Unblocks a contact, given its record or the record's absence.
    ///
    /// Existing sessions remain usable, and the next message carries the current inbox grant over
    /// them. The contact may have rotated its own inbox during the block, so the first send after
    /// an unblock asks for its prekey bundle, and a bundle whose discovery key is newer starts a
    /// new session. Unblocking a stranger blocked before they sent anything deletes their record,
    /// since nobody asked.
    pub fn unblock_contact(
        &self,
        identity_key: IdentityKey,
        record: Option<&ProtocolStateBlob>,
    ) -> Result<StateChanges, ProtocolStateError> {
        let address = contact_address(identity_key);
        validate_contact_identity_key(&address, &identity_key)?;
        let Some(blob) = record else {
            return Ok(StateChanges::for_record(address, None, None));
        };
        let mut contact = ContactRecord::decode(&address, blob, self.limits)?;
        if !contact.blocked {
            return Ok(StateChanges::for_record(address, record, None));
        }
        let blob = if contact.discovery_key.is_none() {
            None
        } else {
            contact.unblock();
            Some(contact.encode(&address, self.limits)?)
        };
        let update = ProtocolStateUpdate::replacing(address.clone(), blob, record);
        Ok(StateChanges::for_record(address, record, Some(update)))
    }

    /// Records out-of-band safety number confirmation for an accepted contact, given its record.
    ///
    /// The presented value must match the safety number derived from `local_identity_key` and
    /// `contact_identity_key`.
    pub fn confirm_contact_safety_number(
        &self,
        local_identity_key: IdentityKey,
        contact_identity_key: IdentityKey,
        record: Option<&ProtocolStateBlob>,
        presented_grouped_decimal: &str,
    ) -> Result<ContactSafetyNumberConfirmation, ProtocolStateError> {
        let address = contact_address(contact_identity_key);
        validate_contact_identity_key(&address, &contact_identity_key)?;
        let safety_number = derive_safety_number(local_identity_key, contact_identity_key)?;
        let blob = record.ok_or_else(|| ProtocolStateError::MissingRequiredState {
            address: address.clone(),
        })?;
        let mut contact = ContactRecord::decode(&address, blob, self.limits)?;
        if contact.trust_state == ContactTrustState::Pending {
            return Err(ProtocolStateError::InvalidStateBinding {
                address,
                reason: "pending contact cannot be verified".into(),
            });
        }
        if safety_number.grouped_decimal != presented_grouped_decimal {
            return Ok(ContactSafetyNumberConfirmation::Mismatched);
        }
        if contact.trust_state == ContactTrustState::Verified {
            return Ok(ContactSafetyNumberConfirmation::Matched(
                StateChanges::for_record(address, record, None),
            ));
        }
        contact.trust_state = ContactTrustState::Verified;
        let update = ProtocolStateUpdate::replacing(
            address.clone(),
            Some(contact.encode(&address, self.limits)?),
            record,
        );
        Ok(ContactSafetyNumberConfirmation::Matched(
            StateChanges::for_record(address, record, Some(update)),
        ))
    }

    // Returns the changes that block a contact, given its record or its absence, and whether they
    // block anyone new. A stranger with no record gets one that holds only the block.
    pub(crate) fn block_contact(
        &self,
        identity_key: IdentityKey,
        record: Option<&ProtocolStateBlob>,
    ) -> Result<(StateChanges, bool), ProtocolStateError> {
        let address = contact_address(identity_key);
        validate_contact_identity_key(&address, &identity_key)?;
        let mut contact = match record {
            Some(blob) => ContactRecord::decode(&address, blob, self.limits)?,
            None => ContactRecord::pending(identity_key),
        };
        if contact.blocked {
            return Ok((StateChanges::for_record(address, record, None), false));
        }
        contact.blocked = true;
        let update = ProtocolStateUpdate::replacing(
            address.clone(),
            Some(contact.encode(&address, self.limits)?),
            record,
        );
        Ok((
            StateChanges::for_record(address, record, Some(update)),
            true,
        ))
    }

    // Returns the update that makes `session_id` the session Roost sends on, if it isn't already.
    fn delivery_update(
        &self,
        snapshot: &ProtocolStateSnapshot,
        session_id: SessionId,
        peer_identity_key: IdentityKey,
    ) -> Result<Option<ProtocolStateUpdate>, ProtocolStateError> {
        let peer_address = peer_sessions_address(peer_identity_key);
        let mut peer_sessions = load_peer_sessions(snapshot, &peer_address, self.limits)?
            .ok_or_else(|| ProtocolStateError::MissingRequiredState {
                address: peer_address.clone(),
            })?;
        if !peer_sessions.record_delivery(&peer_address, session_id)? {
            return Ok(None);
        }
        Ok(Some(
            ProtocolStateUpdate::set(
                peer_address.clone(),
                encode_peer_sessions(&peer_address, &peer_sessions, self.limits)?,
            )
            .with_snapshot(snapshot),
        ))
    }

    // Returns whether this side started `session_id` and hasn't heard back on it yet, from a peer
    // whose current discovery key is `peer_discovery_key`. A session the app wiped, or one started
    // on prekeys the peer's rotation since deleted, awaits nothing, so the peer's new handshake
    // can replace it.
    fn awaits_reply(
        &self,
        snapshot: &ProtocolStateSnapshot,
        session_id: SessionId,
        peer_discovery_key: &ContactDiscoveryKey,
    ) -> Result<bool, ProtocolStateError> {
        let Some(session) = load_session(snapshot, &session_address(session_id), self.limits)?
        else {
            return Ok(false);
        };
        Ok(session.pending_handshake.is_some_and(|pending| {
            pending.handshake.responder_discovery_key.as_bytes()
                == &peer_discovery_key.x25519_public_key
        }))
    }
}

/// Errors returned by protocol-state operations.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolStateError {
    /// The contact is locally blocked.
    #[error("contact is blocked")]
    BlockedContact,
    /// The contact isn't accepted, so Roost refuses the send, since a grant update would give a
    /// requester the inbox grant, or no session exists to send on.
    #[error("contact is not accepted")]
    ContactNotAccepted,
    /// A received contact inbox grant's signatures don't verify against its sender's identity
    /// key, so the whole message is rejected.
    #[error("inbox grant does not verify")]
    InvalidInboxGrant,
    /// The contact has no open contact request for this side to accept.
    #[error("no contact request to accept")]
    NoContactRequest,
    /// An established message needs the peer's delivery capability, and no grant has supplied one
    /// for its current discovery key.
    #[error("no delivery capability for this contact")]
    NoDeliveryCapability,
    /// This side already sent the most messages allowed before the contact accepts.
    #[error("contact is not accepted and the limit of {limit} messages is reached")]
    PendingLimitReached {
        /// Distinct messages each side may send before acceptance.
        limit: usize,
    },
    /// The time a delivery check was given has no Unix timestamp in milliseconds.
    #[error("time is out of range")]
    TimeOutOfRange,
    /// A contact acceptance arrived on a session this side didn't start with a contact request.
    #[error("contact acceptance answers no request")]
    UnsolicitedAcceptance,
    /// The most messages allowed already wait for the contact's acknowledgment on the session.
    #[error("{limit} messages already wait for an acknowledgment on this session")]
    PendingAcknowledgmentLimitReached {
        /// Most messages that wait for an acknowledgment on one session.
        limit: usize,
    },
    /// A stored blob failed to decode or holds an invalid record.
    #[error("protocol-state blob failed to decode at {address}: {reason}")]
    BlobDecode {
        /// Address whose blob failed to decode.
        address: ProtocolStateAddress,
        /// Diagnostic decode context for logs only.
        reason: String,
    },
    /// A protocol-state blob failed encoding.
    #[error("protocol-state blob failed to encode at {address}: {reason}")]
    BlobEncode {
        /// Address whose blob failed to encode.
        address: ProtocolStateAddress,
        /// Diagnostic encode context for logs only.
        reason: String,
    },
    /// Starting or accepting a handshake, or checking its proof, failed.
    #[error("protocol-state handshake failed")]
    Handshake(#[from] roost_crypto::HandshakeError),
    /// Double Ratchet encryption or decryption failed.
    #[error("protocol-state ratchet operation failed")]
    Ratchet(#[from] roost_crypto::RatchetError),
    /// A ratchet state failed to encode or decode.
    #[error("protocol-state ratchet state failed")]
    RatchetState(#[from] roost_crypto::RatchetStateError),
    /// Sealing or opening a sealed sender frame failed.
    #[error("protocol-state sealed frame failed")]
    SealedFrame(#[from] roost_crypto::SealedFrameError),
    /// Deriving the safety number failed, because the local identity key is invalid.
    #[error("safety number derivation failed")]
    SafetyNumber(#[from] SafetyNumberError),
    /// A message transcript signature failed context framing or verification.
    #[error("protocol-state signature failed")]
    Signature(#[from] SignatureError),
    /// A message's fields are too long for its transcript.
    #[error("message transcript failed")]
    MessageTranscript(#[from] MessageTranscriptError),
    /// A plaintext doesn't fit the padding, or a received message's padding is malformed.
    #[error("sealed payload padding failed")]
    SealedPayload(#[from] SealedPayloadError),
    /// A message's content is longer than Roost accepts.
    #[error("message content is {len} bytes, longer than {max}")]
    ContentTooLong {
        /// Length of the content.
        len: usize,
        /// Longest content Roost accepts.
        max: usize,
    },
    /// A sender certificate failed validation, or the certificate grace is too long.
    #[error("sender certificate validation failed")]
    SenderCertificateValidation(#[source] SenderCertificateValidationError),
    /// A message is malformed or doesn't authenticate, or a prekey bundle or sender certificate it
    /// uses is invalid.
    #[error("invalid message: {reason}")]
    InvalidMessage {
        /// Diagnostic failure context for logs only.
        reason: String,
    },
    /// Received-message deduplication capacity is outside supported bounds.
    #[error("invalid deduplication capacity: {capacity} outside {minimum}..={maximum}")]
    InvalidDeduplicationCapacity {
        /// Requested capacity.
        capacity: usize,
        /// Minimum supported capacity.
        minimum: usize,
        /// Maximum supported capacity.
        maximum: usize,
    },
    /// The records the app supplied don't line up with the ones Roost asked for.
    #[error("protocol-state entries don't match the request")]
    StateEntry(#[from] StateEntryError),
    /// The random number generator failed.
    #[error("randomness failed")]
    Randomness(#[source] rand::Error),
    /// A state binding operation would violate an existing protocol-state invariant.
    #[error("invalid protocol-state binding at {address}: {reason}")]
    InvalidStateBinding {
        /// Address whose binding invariant would be violated.
        address: ProtocolStateAddress,
        /// Diagnostic failure context for logs only.
        reason: String,
    },
    /// A protocol-state key is empty.
    #[error("protocol-state key is empty")]
    EmptyStateKey,
    /// A protocol-state key is longer than Roost accepts.
    #[error("protocol-state key is {len} bytes, longer than {max}")]
    StateKeyTooLong {
        /// Length of the key.
        len: usize,
        /// Longest key Roost accepts.
        max: usize,
    },
    /// A required protocol-state blob was absent from the records the app supplied.
    #[error("missing required protocol-state blob at {address}")]
    MissingRequiredState {
        /// Address that must be present before the operation.
        address: ProtocolStateAddress,
    },
    /// A persisted blob used a version this build does not support.
    #[error("unsupported protocol-state blob version at {address}: {version}")]
    UnsupportedBlobVersion {
        /// Address whose blob version is unsupported.
        address: ProtocolStateAddress,
        /// Version read from the blob's first byte.
        version: u8,
    },
}

// Computes the digest a commit condition holds for a record that must stay unchanged.
fn protocol_state_blob_digest(blob: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"RoostProtocolStateCommit-v1:");
    // A blob is far shorter than `u32::MAX` bytes.
    hasher.update(&(blob.len() as u32).to_be_bytes());
    hasher.update(blob);
    *hasher.finalize().as_bytes()
}

// Prefixes `body` with the version that covers the whole blob.
fn encode_blob(
    address: &ProtocolStateAddress,
    body: &[u8],
    max_len: usize,
) -> Result<ProtocolStateBlob, ProtocolStateError> {
    let len = body.len() + PROTOCOL_STATE_BLOB_HEADER_LEN;
    if len > max_len {
        return Err(ProtocolStateError::BlobEncode {
            address: address.clone(),
            reason: format!(
                "{} blob length {len} exceeds limit {max_len}",
                address.kind()
            ),
        });
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(len));
    bytes.push(PROTOCOL_STATE_BLOB_VERSION);
    bytes.extend_from_slice(body);
    Ok(ProtocolStateBlob::from_zeroizing(bytes))
}

// Checks a blob's length and version, then decodes its body as one `T`.
fn decode_blob<'a, T: Deserialize<'a>>(
    address: &ProtocolStateAddress,
    blob: &'a ProtocolStateBlob,
    max_len: usize,
) -> Result<T, ProtocolStateError> {
    let body = blob_body(address, blob, max_len)?;
    decode_exact(body).map_err(|error| ProtocolStateError::BlobDecode {
        address: address.clone(),
        reason: decode_failure(address.kind(), &error),
    })
}

// Says why `part` didn't decode as one value.
fn decode_failure(part: impl fmt::Display, error: &StoredDataError) -> String {
    match error {
        StoredDataError::TrailingBytes { len } => format!("{part} has {len} bytes left over"),
        StoredDataError::Decode(_)
        | StoredDataError::Encode(_)
        | StoredDataError::UnsupportedVersion { .. } => format!("{part} failed to decode"),
    }
}

fn decode_error(address: &ProtocolStateAddress, reason: &str) -> ProtocolStateError {
    ProtocolStateError::BlobDecode {
        address: address.clone(),
        reason: reason.into(),
    }
}

// Checks a blob's length and version before anything decodes its body.
fn blob_body<'a>(
    address: &ProtocolStateAddress,
    blob: &'a ProtocolStateBlob,
    max_len: usize,
) -> Result<&'a [u8], ProtocolStateError> {
    let bytes = blob.as_bytes();
    if bytes.len() > max_len {
        return Err(ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: format!(
                "{} blob length {} exceeds limit {max_len}",
                address.kind(),
                bytes.len()
            ),
        });
    }
    let (&version, body) = bytes
        .split_first()
        .ok_or_else(|| ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: format!("{} blob is empty", address.kind()),
        })?;
    if version != PROTOCOL_STATE_BLOB_VERSION {
        return Err(ProtocolStateError::UnsupportedBlobVersion {
            address: address.clone(),
            version,
        });
    }
    Ok(body)
}

#[derive(Deserialize, Serialize)]
struct DiscoveryKeyWire {
    x25519_public_key: [u8; PUBLIC_KEY_LEN],
    ed25519_verifying_key: [u8; PUBLIC_KEY_LEN],
    epoch: u32,
    created_at_secs: u64,
    identity_signature: SignatureWire,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
struct IdentityKeyWire {
    x25519_public_key: [u8; PUBLIC_KEY_LEN],
    ed25519_verifying_key: [u8; PUBLIC_KEY_LEN],
}

impl From<IdentityKey> for IdentityKeyWire {
    fn from(value: IdentityKey) -> Self {
        Self {
            x25519_public_key: value.x25519_public_key,
            ed25519_verifying_key: value.ed25519_verifying_key,
        }
    }
}

impl From<IdentityKeyWire> for IdentityKey {
    fn from(value: IdentityKeyWire) -> Self {
        Self {
            x25519_public_key: value.x25519_public_key,
            ed25519_verifying_key: value.ed25519_verifying_key,
        }
    }
}

fn validate_contact_identity_key(
    address: &ProtocolStateAddress,
    identity_key: &IdentityKey,
) -> Result<(), ProtocolStateError> {
    if !identity_key.is_valid() {
        return Err(ProtocolStateError::InvalidStateBinding {
            address: address.clone(),
            reason: "contact identity key is invalid".into(),
        });
    }
    Ok(())
}

// Hashes `label`, then `transport_binding` and `encoded_message` each after its length, into a
// deduplication or acknowledgment digest. Both inputs are far shorter than `u32::MAX` bytes.
fn digest_of(
    mut hasher: blake3::Hasher,
    label: &[u8],
    transport_binding: &[u8],
    encoded_message: &[u8],
) -> [u8; DIGEST_LEN] {
    hasher.update(label);
    for field in [transport_binding, encoded_message] {
        hasher.update(&(field.len() as u32).to_be_bytes());
        hasher.update(field);
    }
    let mut digest = [0u8; DIGEST_LEN];
    digest.copy_from_slice(&hasher.finalize().as_bytes()[..DIGEST_LEN]);
    digest
}

// Returns whether `digests` holds `digest`, comparing every candidate in constant time.
fn contains_digest(digests: &[[u8; DIGEST_LEN]], digest: &[u8; DIGEST_LEN]) -> bool {
    let mut found = Choice::from(0);
    for candidate in digests {
        found |= candidate.ct_eq(digest);
    }
    bool::from(found)
}

fn push_bounded(digests: &mut Vec<[u8; DIGEST_LEN]>, digest: [u8; DIGEST_LEN], capacity: usize) {
    digests.push(digest);
    keep_newest(digests, capacity);
}

fn keep_newest(digests: &mut Vec<[u8; DIGEST_LEN]>, capacity: usize) {
    let excess = digests.len().saturating_sub(capacity);
    digests.drain(..excess);
}

fn write_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(f, "{byte:02x}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_versions_other_than_the_current_one_are_faults() {
        let address = ProtocolStateAddress::new(
            ProtocolStateKind::RatchetSession,
            ProtocolStateKey::from_bytes(vec![9; 16]).unwrap(),
        );
        for version in [0, PROTOCOL_STATE_BLOB_VERSION + 1, u8::MAX] {
            let blob = ProtocolStateBlob::from_bytes(vec![version, 0xaa]);
            assert!(matches!(
                blob_body(&address, &blob, 64),
                Err(ProtocolStateError::UnsupportedBlobVersion { address: actual, version: actual_version })
                    if actual == address && actual_version == version
            ));
        }
    }

    #[test]
    fn a_protocol_state_key_holds_at_most_96_bytes() {
        ProtocolStateKey::from_bytes(vec![1; 96]).unwrap();
        assert!(matches!(
            ProtocolStateKey::from_bytes(vec![1; 97]),
            Err(ProtocolStateError::StateKeyTooLong { len: 97, max: 96 })
        ));
    }
}
