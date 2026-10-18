mod contact_record;
mod deduplication;
mod envelope;
mod grant;
mod message_operation;
mod pending_acknowledgment;
mod session;

use crate::contact::{
    ContactDiscoveryKey, ContactIdentityKey, ContactSafetyNumberConfirmation, ContactState,
    ContactTrustState,
};
use crate::hardening::{
    DEFAULT_DEDUPLICATION_CAPACITY, ProtocolHardeningLimits, validate_deduplication_capacity,
};
use crate::key_store::KeyStoreOperationId;
use crate::safety_number::{IdentityKey, derive_safety_number, identity_key_is_valid};
use crate::{MessageId, PayloadKind};
use contact_record::{ContactRecord, contact_address};
pub use envelope::SenderIdentityMaterial;
pub use message_operation::{
    AdmissionRequest, DeliveryCheck, DeliveryCheckResult, DeliveryCheckStep, IncomingMessage,
    MessageDecryption, MessageDecryptionStep, MessageDestination, MessageEncryption,
    MessageEncryptionStep, MessageOperationError, MessageRecovery, MessageRecoveryStep,
    OutgoingGrantUpdate, OutgoingMessage, OutgoingRecovery, PeerPreKeyBundle, RetryInstruction,
    SignedSenderCertificate,
};
pub(crate) use message_operation::{LocalIdentityKeys, SendIntent};
pub use pending_acknowledgment::PendingAcknowledgment;
use roost_crypto::SealedFrame;
use roost_protocol::{
    DomainSigningKey, DomainSigningKeyStatus, MAX_CERTIFICATE_GRACE_WINDOW, MessageTranscriptError,
    PUBLIC_KEY_LEN, RevocationState, SealedPayloadError, SenderCertificateIdentityKey,
    SenderCertificateValidationError, SenderCertificateValidationInput, SessionId, SignatureError,
    ValidatedSenderCertificate, validate_sender_certificate,
};
use serde::de::{Error as DeError, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use session::{
    encode_peer_sessions, load_peer_sessions, load_session, peer_sessions_address, session_address,
};
use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;
use std::time::{Duration, SystemTime};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const PROTOCOL_STATE_BLOB_VERSION: u8 = 3;
const PROTOCOL_STATE_BLOB_HEADER_LEN: usize = 1;
const MAX_PROTOCOL_STATE_KEY_LEN: usize = 96;
// Deduplication and acknowledgment digests keep this many bytes of their hash.
const DIGEST_LEN: usize = 16;

/// The key part of a protocol-state address: a SessionID, an Identity Key, or a host-chosen key.
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

impl From<ContactIdentityKey> for ProtocolStateKey {
    fn from(value: ContactIdentityKey) -> Self {
        Self(value.canonical_encoding().to_vec())
    }
}

/// The stable category for an opaque protocol-state blob.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProtocolStateKind {
    /// SessionID-addressed Double Ratchet session state.
    RatchetSession,
    /// Deduplication-set state.
    DeduplicationSet,
    /// SessionID-addressed pending-acknowledgment state.
    PendingAcknowledgments,
    /// Identity-key-addressed contact state, including the peer's Delivery Capability.
    ContactState,
    /// Identity-key-addressed record of the Sessions kept with one peer and the one Roost sends on.
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
#[derive(Zeroize, ZeroizeOnDrop)]
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

/// A Core-computed condition the host must enforce inside its state transaction.
///
/// All updates and associated effects must commit atomically under the host's per-identity
/// serializer. A failed condition requires reloading state and processing the operation again.
#[derive(Clone, Copy, Debug)]
pub enum ProtocolStateCommitCondition {
    /// No blob may exist at this address.
    Absent,
    /// The current opaque blob must have this digest.
    Digest([u8; 32]),
}

impl ProtocolStateCommitCondition {
    // Checks the condition against the blob read inside the host transaction.
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

/// A state update the consumer must commit durably.
pub struct ProtocolStateUpdate {
    address: ProtocolStateAddress,
    blob: Option<ProtocolStateBlob>,
    condition: ProtocolStateCommitCondition,
}

impl ProtocolStateUpdate {
    /// Creates an update that stores `blob` at `address`.
    #[must_use]
    fn set(address: ProtocolStateAddress, blob: ProtocolStateBlob) -> Self {
        Self {
            address,
            blob: Some(blob),
            condition: ProtocolStateCommitCondition::Absent,
        }
    }

    /// Creates an update that removes `address`.
    #[must_use]
    fn delete(address: ProtocolStateAddress) -> Self {
        Self {
            address,
            blob: None,
            condition: ProtocolStateCommitCondition::Absent,
        }
    }

    // Creates an update that replaces `current`, the record the caller passed for `address`.
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

/// The records an operation's result relies on, the records it writes, the Prepared KeyStore
/// Operation that commits with them, if any, and the sent Messages Roost stops waiting for.
///
/// Message Operations and delivery checks return these beside their result, so the host commits
/// them through [`Self::conditions`] and [`Self::into_updates`] and keeps the rest of the result.
/// They're empty when the result changes nothing, such as a duplicate.
///
/// The host reads the record at each Commit Condition's address inside its transaction, and
/// commits the updates with the result's effects only when [`commit_conditions_match`] holds for
/// them. The host marks each of [`Self::undelivered`] not delivered in the same transaction. When
/// [`Self::operation`] is present, the host reserves it before the transaction, commits its ID
/// with the updates, and finalizes it before using the result.
pub struct StateChanges {
    conditions: Vec<(ProtocolStateAddress, ProtocolStateCommitCondition)>,
    updates: Vec<ProtocolStateUpdate>,
    operation: Option<KeyStoreOperationId>,
    undelivered: Vec<MessageId>,
}

impl StateChanges {
    // Returns changes for a result that relies on no record and writes none.
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

    /// Returns the Prepared KeyStore Operation that commits with these changes, if any.
    #[must_use]
    pub fn operation(&self) -> Option<KeyStoreOperationId> {
        self.operation
    }

    /// Returns each Commit Condition with the address it applies to, in address order.
    #[must_use]
    pub fn conditions(&self) -> &[(ProtocolStateAddress, ProtocolStateCommitCondition)] {
        &self.conditions
    }

    /// Returns the sent Messages Roost stops waiting for, oldest first, because the Relay would
    /// have dropped them by now or their Session is deleted.
    #[must_use]
    pub fn undelivered(&self) -> &[MessageId] {
        &self.undelivered
    }

    /// Returns the updates to commit, consuming the changes.
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

/// Why the records a host returned don't line up with the ones Roost asked for.
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

/// Maximum number of opaque entries accepted in one operation snapshot.
pub const MAX_PROTOCOL_STATE_ENTRIES: usize = 4096;

/// A consumer-held snapshot of protocol-state blobs.
#[derive(Default)]
pub struct ProtocolStateSnapshot {
    blobs: BTreeMap<ProtocolStateAddress, ProtocolStateBlob>,
}

impl ProtocolStateSnapshot {
    /// Creates an empty protocol-state snapshot.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the blob stored at `address`, if present.
    #[must_use]
    pub fn get(&self, address: &ProtocolStateAddress) -> Option<&ProtocolStateBlob> {
        self.blobs.get(address)
    }

    /// Stores `blob` at `address` in the caller-supplied operation snapshot.
    pub fn set(
        &mut self,
        address: ProtocolStateAddress,
        blob: ProtocolStateBlob,
    ) -> Result<(), ProtocolStateError> {
        if self.blobs.len() >= MAX_PROTOCOL_STATE_ENTRIES && !self.blobs.contains_key(&address) {
            return Err(ProtocolStateError::SnapshotCapacityExceeded {
                max: MAX_PROTOCOL_STATE_ENTRIES,
            });
        }
        self.blobs.insert(address, blob);
        Ok(())
    }
}

/// An outbound Message from one Message Operation.
pub struct OutboundMessageResult {
    /// The Session Roost selected for the Message.
    pub session_id: SessionId,
    /// Stable identifier sealed inside the produced Message.
    pub message_id: MessageId,
    /// Sender-observed Unix timestamp sealed inside the produced Message.
    pub sent_at_millis: u64,
    /// Payload kind sealed inside the produced Message.
    pub payload_kind: PayloadKind,
    /// Message to hand to the consumer transport after state commit.
    pub message: SealedFrame,
}

/// Sender-certificate validation inputs for receive-time Identity-keyed decisions.
///
/// Core validates the sealed sender certificate after decrypting a unique Message, rejects revoked
/// Identity Keys before local blocking, and uses the validated sender Identity Key to suppress
/// blocked inbound plaintext. An unavailable revocation source fails validation closed, so no
/// plaintext is surfaced without a revocation verdict.
pub struct InboundSenderCertificateValidation {
    /// Known domain-signing keys indexed by certificate signing-key identifier.
    pub domain_signing_keys: Vec<KnownDomainSigningKey>,
    /// Relay domain the recipient expects incoming certificates to name.
    pub expected_relay_domain: Vec<u8>,
    /// Revoked Identity Keys, or `None` when the revocation source failed to load.
    pub revoked_identity_keys: Option<Vec<SenderCertificateIdentityKey>>,
    /// Caller-supplied time used for expiry evaluation.
    pub reference_time: SystemTime,
}

impl InboundSenderCertificateValidation {
    /// Validates a sender certificate, accepting one that expired at most `grace` ago.
    pub fn validate(
        &self,
        certificate: &[u8],
        signature: &[u8],
        grace: Duration,
    ) -> Result<ValidatedSenderCertificate, SenderCertificateValidationError> {
        let domain_signing_keys: Vec<DomainSigningKey<'_>> = self
            .domain_signing_keys
            .iter()
            .map(|key| DomainSigningKey {
                id: &key.id,
                verifying_key: &key.verifying_key,
                status: key.status,
            })
            .collect();
        validate_sender_certificate(SenderCertificateValidationInput {
            certificate,
            signature,
            domain_signing_keys: &domain_signing_keys,
            expected_relay_domain: &self.expected_relay_domain,
            revocation_state: match &self.revoked_identity_keys {
                Some(revoked) => RevocationState::Available(revoked),
                None => RevocationState::Unavailable,
            },
            reference_time: self.reference_time,
            grace_window: grace,
        })
    }
}

/// A domain-signing key the app knows, trusted or not.
pub struct KnownDomainSigningKey {
    /// Identifier matched exactly against the certificate signing-key identifier.
    pub id: Vec<u8>,
    /// Canonical Ed25519 verifying-key bytes.
    pub verifying_key: [u8; PUBLIC_KEY_LEN],
    /// Whether certificates signed by this key may validate.
    pub status: DomainSigningKeyStatus,
}

/// Inbound plaintext from one Message Operation.
///
/// A sender's recovery resends a Message under its original MessageID with new bytes, so the app
/// shows one Message per sender and MessageID, and still commits and acknowledges each copy.
pub struct InboundMessageResult {
    /// The Session the Message arrived on.
    pub session_id: SessionId,
    /// Message ID recovered after decrypt.
    pub message_id: MessageId,
    /// Sender-observed Unix timestamp recovered after decrypt.
    pub sent_at_millis: u64,
    /// Payload kind recovered after decrypt.
    pub payload_kind: PayloadKind,
    /// Decrypted plaintext bytes.
    pub plaintext: Zeroizing<Vec<u8>>,
    /// Sender identity material decoded from the sealed-sender envelope.
    pub sender_identity: SenderIdentityMaterial,
    /// Encrypted acknowledgment artifact to durably queue with the state changes, absent while
    /// the contact isn't accepted and this side doesn't acknowledge yet.
    pub acknowledgment: Option<SealedFrame>,
}

/// A Message from a contact who isn't accepted, past the limit on Messages before acceptance.
///
/// Roost withholds its plaintext and sends no acknowledgment.
pub struct WithheldInboundMessageResult {
    /// The Session the Message arrived on.
    pub session_id: SessionId,
    /// Message ID recovered after decrypt.
    pub message_id: MessageId,
}

/// A Grant Update whose Inbox Grant Roost kept, which has nothing to show.
pub struct GrantUpdateResult {
    /// The Session the Grant Update arrived on.
    pub session_id: SessionId,
    /// Message ID recovered after decrypt.
    pub message_id: MessageId,
    /// Encrypted acknowledgment artifact to durably queue with the state changes, absent while
    /// this side doesn't acknowledge the contact yet.
    pub acknowledgment: Option<SealedFrame>,
}

/// Accepted blocked inbound Message result without consumer-visible plaintext.
pub struct BlockedInboundMessageResult {
    /// Encrypted acknowledgment artifact to durably queue with the state changes, or `None` when
    /// the blocked-contact acknowledgment policy suppresses it.
    pub acknowledgment: Option<SealedFrame>,
}

/// An authenticated acknowledgment.
///
/// Its state changes commit whether it matched or not, so a retried acknowledgment is a
/// duplicate.
pub struct AcknowledgmentResult {
    /// The Session the acknowledgment arrived on.
    pub session_id: SessionId,
    /// Acknowledgment Message ID recovered after decrypt.
    pub message_id: MessageId,
    /// Acknowledgment timestamp recovered after decrypt.
    pub sent_at_millis: u64,
    /// The outbound Message ID the acknowledgment names.
    pub acknowledged_message_id: MessageId,
    /// Sender identity material decoded from the acknowledgment.
    pub sender_identity: SenderIdentityMaterial,
}

/// The result of receiving an inbound encrypted Message.
pub enum InboundMessageOutcome {
    /// A unique Message decrypted and advanced protocol state.
    Accepted(Box<InboundMessageResult>),
    /// A first Message from an Identity with no contact record, which creates a Pending one.
    ContactRequest(Box<InboundMessageResult>),
    /// A unique blocked Message decrypted and advanced protocol state.
    Blocked(Box<BlockedInboundMessageResult>),
    /// A Message past the limit before acceptance decrypted, and its plaintext is withheld.
    Withheld(Box<WithheldInboundMessageResult>),
    /// A Grant Update from a contact who isn't blocked, whose Inbox Grant Roost kept.
    GrantUpdate(Box<GrantUpdateResult>),
    /// The Message matched an already-accepted encrypted byte sequence.
    Duplicate,
    /// The Message names a Session this identity doesn't have and carries no handshake, such as
    /// one it lost, and nothing changed.
    UnknownSession,
    /// The first Message names a Session this identity deleted, so nothing was created.
    DeletedSession,
    /// An acknowledgment cleared one of this identity's Pending Acknowledgments.
    AcknowledgmentMatched(Box<AcknowledgmentResult>),
    /// An authenticated acknowledgment named no Pending Acknowledgment, such as one already
    /// cleared.
    AcknowledgmentUnmatched(Box<AcknowledgmentResult>),
}

/// Whether a blocked sender receives an acknowledgment for an accepted-but-hidden Message.
///
/// The default preserves privacy: a blocked sender cannot distinguish a block from an unreachable
/// recipient. Opting in to [`Self::SilentReceipt`] trades that away for delivery confirmation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum BlockedContactAcknowledgmentPolicy {
    /// Return no acknowledgment and do not advance the sending chain, so a blocked sender can't
    /// tell the block from a recipient who is offline.
    #[default]
    Unreachable,
    /// Return the acknowledgment an unblocked sender would get, revealing delivery; local plaintext
    /// is still hidden.
    SilentReceipt,
}

/// The settings an app passes with each receive, checked against Roost's limits.
///
/// Roost holds no settings, so every Library Instance serving one identity, in the app or its
/// extensions, applies the values the app passes at that moment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiveSettings {
    deduplication_capacity: usize,
    blocked_contact_acknowledgment_policy: BlockedContactAcknowledgmentPolicy,
    certificate_grace: Duration,
}

impl ReceiveSettings {
    /// Returns settings after checking the Deduplication Set's size and the certificate grace.
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
    /// Returns the default Deduplication Set size, no receipts to blocked senders, and no grace.
    fn default() -> Self {
        Self {
            deduplication_capacity: DEFAULT_DEDUPLICATION_CAPACITY,
            blocked_contact_acknowledgment_policy: BlockedContactAcknowledgmentPolicy::Unreachable,
            certificate_grace: Duration::ZERO,
        }
    }
}

/// Stateless protocol-state operations over consumer-held blobs.
///
/// Consumers must read required blobs from an atomic, durable, crash-consistent, and
/// integrity-preserving store before each operation, then commit returned updates atomically with
/// any produced Message. At most one library instance may mutate a given Identity's protocol
/// state at a time.
///
/// Received-message deduplication is scoped to one local Identity through the
/// [`ProtocolStateKind::DeduplicationSet`] blob. It drops byte-identical encrypted Message retries
/// before decryption; Double Ratchet replay rejection still handles cryptographic replays after
/// decryption starts.
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

    /// Returns the contact a Contact State record holds.
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
    /// Existing Sessions remain usable, and the next Message carries the current Inbox Grant over
    /// them. The contact may have rotated its own inbox during the block, so the first send after
    /// an unblock asks for its prekey bundle, and a bundle whose Discovery Key is newer starts a
    /// new Session. Unblocking a stranger blocked before they sent anything deletes their record,
    /// since nobody asked.
    pub fn unblock_contact(
        &self,
        identity_key: ContactIdentityKey,
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

    /// Records out-of-band Safety Number confirmation for an accepted contact, given its record.
    ///
    /// The presented value must match the Safety Number derived from `local_identity_key` and
    /// `contact_identity_key`. In-band Messages and acknowledgments never call this transition.
    pub fn confirm_contact_safety_number(
        &self,
        local_identity_key: IdentityKey,
        contact_identity_key: ContactIdentityKey,
        record: Option<&ProtocolStateBlob>,
        presented_grouped_decimal: &str,
    ) -> Result<ContactSafetyNumberConfirmation, ProtocolStateError> {
        let address = contact_address(contact_identity_key);
        validate_contact_identity_key(&address, &contact_identity_key)?;
        let safety_number = derive_safety_number(local_identity_key, contact_identity_key)
            .map_err(|_| ProtocolStateError::InvalidStateBinding {
                address: address.clone(),
                reason: "identity key is invalid".into(),
            })?;
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
        identity_key: ContactIdentityKey,
        record: Option<&ProtocolStateBlob>,
    ) -> Result<(StateChanges, bool), ProtocolStateError> {
        let address = contact_address(identity_key);
        validate_contact_identity_key(&address, &identity_key)?;
        let mut contact = match record {
            Some(blob) => ContactRecord::decode(&address, blob, self.limits)?,
            None => ContactRecord::pending(identity_key, None),
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

    // Returns the update that makes `session_id` the Session Roost sends on, if it isn't already.
    fn delivery_update(
        &self,
        snapshot: &ProtocolStateSnapshot,
        session_id: SessionId,
        peer_identity_key: ContactIdentityKey,
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
    // whose current Discovery Key is `peer_discovery_key`. A Session the host wiped, or one started
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
    /// The contact isn't accepted, so Roost refuses the send: a Grant Update would give a
    /// requester the Inbox Grant, or no Session exists to send on.
    #[error("contact is not accepted")]
    ContactNotAccepted,
    /// A received Contact Inbox Grant's signatures don't verify against its sender's Identity
    /// Key, so the whole Message is rejected.
    #[error("inbox grant does not verify")]
    InvalidInboxGrant,
    /// The contact has no open Contact Request for this side to accept.
    #[error("no contact request to accept")]
    NoContactRequest,
    /// An established Message needs the peer's Delivery Capability, and no grant has supplied one
    /// for its current Discovery Key.
    #[error("no delivery capability for this contact")]
    NoDeliveryCapability,
    /// This side already sent the most Messages allowed before the contact accepts.
    #[error("contact is not accepted and the limit of {limit} messages is reached")]
    PendingLimitReached {
        /// Distinct Messages each side may send before acceptance.
        limit: usize,
    },
    /// The time a delivery check was given has no Unix timestamp in milliseconds.
    #[error("time is out of range")]
    TimeOutOfRange,
    /// A Contact Acceptance arrived on a Session this side didn't start with a Contact Request.
    #[error("contact acceptance answers no request")]
    UnsolicitedAcceptance,
    /// The operation snapshot would hold more entries than its cap.
    #[error("protocol-state snapshot holds more than {max} entries")]
    SnapshotCapacityExceeded {
        /// Most entries one snapshot holds.
        max: usize,
    },
    /// The most Messages allowed already wait for the contact's acknowledgment on the Session.
    #[error("{limit} messages already wait for an acknowledgment on this session")]
    PendingAcknowledgmentLimitReached {
        /// Most Messages that wait for an acknowledgment on one Session.
        limit: usize,
    },
    /// A persisted blob failed structural decoding.
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
    /// Sealing or opening a sealed-sender frame failed.
    #[error("protocol-state sealed frame failed")]
    SealedFrame(#[from] roost_crypto::SealedFrameError),
    /// A Message transcript signature failed context framing or verification.
    #[error("protocol-state signature failed")]
    Signature(#[from] SignatureError),
    /// A Message's fields are too long for its transcript.
    #[error("message transcript failed")]
    MessageTranscript(#[from] MessageTranscriptError),
    /// A plaintext doesn't fit the padding, or a received Message's padding is malformed.
    #[error("sealed payload padding failed")]
    SealedPayload(#[from] SealedPayloadError),
    /// Sender-certificate validation failed during receive.
    #[error("sender certificate validation failed")]
    SenderCertificateValidation(#[source] SenderCertificateValidationError),
    /// A Message did not carry the expected ratcheted payload.
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
    /// The records a host supplied don't line up with the ones Roost asked for.
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
    /// A required protocol-state blob was absent from the consumer snapshot.
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

// Computes the digest a Commit Condition holds for a record that must stay unchanged.
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

// Encodes `wire` into a buffer sized up front, so secret bytes are never left behind in memory a
// growing `Vec` freed.
fn encode_zeroizing<T: Serialize>(wire: &T) -> Result<Zeroizing<Vec<u8>>, postcard::Error> {
    let len = postcard::experimental::serialized_size(wire)?;
    let mut bytes = Zeroizing::new(vec![0; len]);
    let written = postcard::to_slice(wire, &mut bytes)?.len();
    if written != len {
        return Err(postcard::Error::SerializeBufferFull);
    }
    Ok(bytes)
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

#[derive(Clone, Copy, Deserialize, Serialize)]
struct ContactIdentityKeyWire {
    x25519_public_key: [u8; PUBLIC_KEY_LEN],
    ed25519_verifying_key: [u8; PUBLIC_KEY_LEN],
}

impl From<ContactIdentityKey> for ContactIdentityKeyWire {
    fn from(value: ContactIdentityKey) -> Self {
        Self {
            x25519_public_key: value.x25519_public_key,
            ed25519_verifying_key: value.ed25519_verifying_key,
        }
    }
}

impl From<ContactIdentityKeyWire> for ContactIdentityKey {
    fn from(value: ContactIdentityKeyWire) -> Self {
        Self {
            x25519_public_key: value.x25519_public_key,
            ed25519_verifying_key: value.ed25519_verifying_key,
        }
    }
}

fn validate_contact_identity_key(
    address: &ProtocolStateAddress,
    identity_key: &ContactIdentityKey,
) -> Result<(), ProtocolStateError> {
    if !identity_key_is_valid(identity_key) {
        return Err(ProtocolStateError::InvalidStateBinding {
            address: address.clone(),
            reason: "contact identity key is invalid".into(),
        });
    }
    Ok(())
}

fn contact_identity_keys_match(left: &ContactIdentityKey, right: &ContactIdentityKey) -> bool {
    left.x25519_public_key
        .ct_eq(&right.x25519_public_key)
        .unwrap_u8()
        == 1
        && left
            .ed25519_verifying_key
            .ct_eq(&right.ed25519_verifying_key)
            .unwrap_u8()
            == 1
}

// Hashes `label`, then `transport_binding` and `encoded_message` each after its length, into a
// Deduplication or acknowledgment digest. Both inputs are far shorter than `u32::MAX` bytes.
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

// Appends `digest`, dropping the oldest digests beyond `capacity`.
fn push_bounded(digests: &mut Vec<[u8; DIGEST_LEN]>, digest: [u8; DIGEST_LEN], capacity: usize) {
    digests.push(digest);
    keep_newest(digests, capacity);
}

// Drops the oldest digests beyond `capacity`.
fn keep_newest(digests: &mut Vec<[u8; DIGEST_LEN]>, capacity: usize) {
    let excess = digests.len().saturating_sub(capacity);
    digests.drain(..excess);
}

// Decodes a list, refusing one longer than `MAX` before it allocates for more.
fn deserialize_bounded<'de, D, T, const MAX: usize>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct BoundedVisitor<T, const MAX: usize>(PhantomData<T>);

    impl<'de, T: Deserialize<'de>, const MAX: usize> Visitor<'de> for BoundedVisitor<T, MAX> {
        type Value = Vec<T>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "at most {MAX} entries")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let too_many = || A::Error::custom(format_args!("more than {MAX} entries"));
            if seq.size_hint().is_some_and(|len| len > MAX) {
                return Err(too_many());
            }
            let mut entries = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(MAX));
            while let Some(entry) = seq.next_element()? {
                if entries.len() == MAX {
                    return Err(too_many());
                }
                entries.push(entry);
            }
            Ok(entries)
        }
    }

    deserializer.deserialize_seq(BoundedVisitor::<T, MAX>(PhantomData))
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
    fn protocol_state_blob_digest_changes_with_the_blob() {
        assert_ne!(
            protocol_state_blob_digest(b"first blob"),
            protocol_state_blob_digest(b"second blob")
        );
    }
}
