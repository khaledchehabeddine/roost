//! Public protocol-state blob addressing and stateless operation results.

use crate::contact::{
    ContactDiscoveryKey, ContactEvent, ContactIdentity, ContactIdentityKey,
    ContactSafetyNumberConfirmation, ContactState, ContactStateChange, ContactTrustState,
    PeerInboxAuthorization,
};
use crate::hardening::{
    DEFAULT_MAX_ACKNOWLEDGMENT_DIGESTS, DEFAULT_MAX_PENDING_ACKNOWLEDGMENTS,
    MAX_DEDUPLICATION_CAPACITY, MIN_DEDUPLICATION_CAPACITY, ProtocolHardeningLimits,
    validate_hardening_limits,
};
use crate::safety_number::{IdentityKey, derive_safety_number, identity_key_is_valid};
use crate::{Message, MessageError, MessageId, PayloadKind, TransportBinding};
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use roost_crypto::{
    DiscoveryKey, Header, PublicDiscoveryKey, PublicIdentityKey, PublicKey, RatchetState,
    RecipientDeliveryCapability, SenderIdentityMaterial, Signature, SigningKeyPair,
    open_frame_for_discovery_key_with_associated_data, seal_frame_with_associated_data,
    verify_public_discovery_key, verify_public_identity_key,
};
use roost_protocol::{
    DomainSigningKey, MAX_CERTIFICATE_GRACE_WINDOW, RevocationState,
    SenderCertificateValidationError, SenderCertificateValidationInput,
    validate_sender_certificate,
};
use roost_protocol::{
    MESSAGE_TRANSCRIPT_CONTEXT, MessageTranscriptInput, message_transcript,
    pad_sealed_payload as pad_message_payload, unpad_sealed_payload as unpad_message_payload,
};
use roost_protocol::{
    PUBLIC_KEY_LEN, is_valid_x25519_public_key, parse_ed25519_verifying_key_bytes,
};
#[cfg(test)]
use roost_protocol::{SEALED_PAYLOAD_BUCKETS, SEALED_PAYLOAD_LEN_PREFIX_LEN};
use roost_protocol::{SignatureError, verify_with_context};
use roost_protocol::{from_unix_millis, to_unix_millis};
use serde::de::{Error as DeError, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::time::{Duration, SystemTime};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const CURRENT_PROTOCOL_STATE_BLOB_MAJOR: u8 = 1;
const CURRENT_PROTOCOL_STATE_BLOB_MINOR: u8 = 0;
const PROTOCOL_STATE_BLOB_HEADER_LEN: usize = 2;
const SESSION_STATE_WIRE_VERSION: u8 = 4;
const DEDUPLICATION_SET_WIRE_VERSION: u8 = 1;
const PENDING_ACKNOWLEDGMENTS_WIRE_VERSION: u8 = 1;
const PEER_INBOX_AUTHORIZATION_VERSION: u8 = 1;
const LOCAL_INBOX_AUTHORIZATION_VERSION: u8 = 1;
const CONTACT_STATE_WIRE_VERSION: u8 = 2;
const ACKNOWLEDGMENT_PLAINTEXT_WIRE_VERSION: u8 = 1;
const MESSAGE_FRAME_PLAINTEXT_WIRE_VERSION: u8 = 1;
const DEDUPLICATION_DIGEST_LEN: usize = 16;
const DEDUPLICATION_KEY_LEN: usize = 32;
const ACKNOWLEDGMENT_DIGEST_LEN: usize = 16;
const RATCHET_PAYLOAD_VERSION: u8 = 1;
const RATCHET_PAYLOAD_HEADER_LEN: usize = 1 + 32 + 4 + 4;
const RATCHET_AEAD_TAG_LEN: usize = 16;
const SEALED_SENDER_ENVELOPE_VERSION: u8 = 1;
const SEALED_SENDER_ENCODING_OVERHEAD_CAP: usize = 64;
const TRANSCRIPT_SIGNATURE_LEN: usize = 64;
const MAX_PROTOCOL_STATE_KEY_LEN: usize = 96;
const PENDING_ACKNOWLEDGMENT_ENTRY_OVERHEAD_CAP: usize = 64;
const PENDING_ACKNOWLEDGMENTS_WIRE_OVERHEAD_CAP: usize = 64;

/// The UUID-shaped identifier for a cryptographic Session.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SessionId([u8; 16]);

impl SessionId {
    /// Creates a session identifier from UUID bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the UUID bytes for this identifier.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// The consumer-defined key portion of a protocol-state address.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProtocolStateKey(Vec<u8>);

impl ProtocolStateKey {
    /// Creates a protocol-state key from bounded bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, ProtocolStateError> {
        if bytes.is_empty() {
            return Err(ProtocolStateError::InvalidStateKey {
                reason: "protocol-state key is empty".into(),
            });
        }
        if bytes.len() > MAX_PROTOCOL_STATE_KEY_LEN {
            return Err(ProtocolStateError::InvalidStateKey {
                reason: format!("protocol-state key length exceeds limit: {}", bytes.len()),
            });
        }
        Ok(Self(bytes))
    }

    /// Creates a protocol-state key for a Session.
    #[must_use]
    pub fn session(session_id: SessionId) -> Self {
        Self(session_id.as_bytes().to_vec())
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
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProtocolStateKind {
    /// Double Ratchet session state.
    RatchetSession = 0,
    /// Deduplication-set state.
    DeduplicationSet = 3,
    /// Pending-acknowledgment state.
    PendingAcknowledgments = 4,
    /// Identity-key-addressed contact state.
    ContactState = 5,
    /// Identity-key-addressed peer inbox authorization.
    ///
    /// Kept separate from [`Self::ContactState`] because a peer's delivery capability is a bearer
    /// secret, while contact queries return public state for host-owned views and observation.
    PeerInboxAuthorization = 6,
    /// Identity-key-addressed record of which local inbox generation a contact has been given.
    ///
    /// Distribution bookkeeping, not key material: the local capability itself lives in secure
    /// storage. This answers "who still holds a superseded capability and must be re-supplied",
    /// which is what makes a post-rotation re-key both complete and resumable.
    LocalInboxAuthorization = 7,
}

impl ProtocolStateKind {
    /// Returns every protocol-state kind known to this build.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::RatchetSession,
            Self::DeduplicationSet,
            Self::PendingAcknowledgments,
            Self::ContactState,
            Self::PeerInboxAuthorization,
            Self::LocalInboxAuthorization,
        ]
    }
}

impl fmt::Display for ProtocolStateKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RatchetSession => write!(f, "ratchet/session state"),
            Self::DeduplicationSet => write!(f, "deduplication-set state"),
            Self::PendingAcknowledgments => write!(f, "pending-acknowledgment state"),
            Self::ContactState => write!(f, "contact state"),
            Self::PeerInboxAuthorization => write!(f, "peer inbox-authorization state"),
            Self::LocalInboxAuthorization => write!(f, "local inbox-authorization state"),
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
    /// Checks the condition against the blob read inside the host transaction.
    #[must_use]
    pub fn is_satisfied_by(&self, blob: Option<&ProtocolStateBlob>) -> bool {
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

    fn with_snapshot(mut self, snapshot: &ProtocolStateSnapshot) -> Self {
        self.condition = ProtocolStateCommitCondition::from_blob(snapshot.get(&self.address));
        self
    }

    /// Returns the condition the host must enforce before committing this update.
    #[must_use]
    pub fn commit_condition(&self) -> ProtocolStateCommitCondition {
        self.condition
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
            return Err(ProtocolStateError::SnapshotCapacityExceeded);
        }
        self.blobs.insert(address, blob);
        Ok(())
    }

    /// Removes the blob stored at `address`.
    pub fn remove(&mut self, address: &ProtocolStateAddress) -> Option<ProtocolStateBlob> {
        self.blobs.remove(address)
    }

    /// Applies one update to this in-memory snapshot after host commit.
    ///
    /// The host must enforce the update's condition inside its own durable transaction first.
    pub fn apply(&mut self, update: ProtocolStateUpdate) -> Result<(), ProtocolStateError> {
        match update.blob {
            Some(blob) => self.set(update.address, blob),
            None => {
                self.remove(&update.address);
                Ok(())
            }
        }
    }

    /// Applies committed updates to this in-memory snapshot in order.
    ///
    /// This operation is not a durable transaction. Earlier snapshot updates remain if a later
    /// update exceeds the entry cap.
    pub fn apply_all<I>(&mut self, updates: I) -> Result<(), ProtocolStateError>
    where
        I: IntoIterator<Item = ProtocolStateUpdate>,
    {
        for update in updates {
            self.apply(update)?;
        }
        Ok(())
    }
}

/// Plaintext and transport metadata for an outbound encrypted Message.
pub struct OutboundPlaintext<'a> {
    /// Stable identifier for the produced Message.
    pub id: MessageId,
    /// Sender identity material sealed inside the encrypted payload.
    pub sender_identity: &'a SenderIdentityMaterial,
    /// Sender Identity Key signing half used to authenticate the sealed message transcript.
    pub sender_identity_signing_key: &'a SigningKeyPair,
    /// Recipient contact Identity Key used to enforce local trust-state gates.
    pub contact_identity_key: ContactIdentityKey,
    /// Recipient X25519 public key bytes. Always 32 bytes.
    pub recipient_public_key: [u8; 32],
    /// Sender-observed Unix timestamp in milliseconds.
    pub sent_at_millis: u64,
    /// Plaintext bytes to encrypt.
    pub plaintext: &'a [u8],
}

/// Metadata used to encrypt an acknowledgment artifact for an accepted inbound Message.
pub struct OutboundAcknowledgment<'a> {
    /// Stable identifier for the produced acknowledgment Message.
    pub id: MessageId,
    /// Receiver identity material sealed inside the encrypted acknowledgment payload.
    pub sender_identity: &'a SenderIdentityMaterial,
    /// Receiver Identity Key signing half used to authenticate the sealed acknowledgment transcript.
    pub sender_identity_signing_key: &'a SigningKeyPair,
    /// Recipient X25519 public key bytes. Always 32 bytes.
    pub recipient_public_key: [u8; 32],
    /// Receiver-observed Unix timestamp in milliseconds.
    pub sent_at_millis: u64,
}

/// An outbound Message and all advanced protocol-state updates from one operation.
pub struct OutboundMessageResult {
    /// Stable identifier sealed inside the produced Message.
    pub message_id: MessageId,
    /// Sender-observed Unix timestamp sealed inside the produced Message.
    pub sent_at_millis: u64,
    /// Payload kind sealed inside the produced Message.
    pub payload_kind: PayloadKind,
    /// Message to hand to the consumer transport after state commit.
    pub message: Message,
    /// Protocol-state updates to commit atomically with the outbound Message.
    pub state_updates: Vec<ProtocolStateUpdate>,
}

/// An inbound encrypted Message plus the protocol-state keys needed to receive it.
pub struct InboundEncryptedMessage<'a> {
    /// Session-scoped key for the ratchet/session Protocol State Blob.
    pub session_key: ProtocolStateKey,
    /// Identity-scoped key for the deduplication-set Protocol State Blob.
    pub deduplication_key: ProtocolStateKey,
    /// Encrypted Message to deduplicate and decrypt.
    pub message: &'a Message,
    /// Local recipient Discovery Key used to open the sealed-sender frame.
    pub recipient_discovery_key: &'a DiscoveryKey,
    /// Local recipient Ed25519 Identity Key verifying half authenticated by the transcript.
    ///
    /// This must be the Identity Key paired with `recipient_discovery_key`, not a key inferred
    /// from the acknowledgment sender material.
    pub recipient_identity_verifying_key: [u8; 32],
    /// Metadata for the encrypted acknowledgment returned when the Message is accepted.
    pub acknowledgment: OutboundAcknowledgment<'a>,
    /// Sender-certificate validation inputs required for unique encrypted receives.
    ///
    /// Duplicate receives may return [`InboundMessageOutcome::Duplicate`] before validation because
    /// no plaintext or sender identity is surfaced.
    pub sender_certificate_validation: Option<InboundSenderCertificateValidation<'a>>,
}

/// Sender-certificate validation inputs for receive-time Identity-keyed decisions.
///
/// Core validates the sealed sender certificate after decrypting a unique Message, rejects revoked
/// Identity Keys before local blocking, and uses the validated sender Identity Key to suppress
/// blocked inbound plaintext. An unavailable revocation source fails validation closed, so no
/// plaintext is surfaced without a revocation verdict.
#[derive(Clone, Copy)]
pub struct InboundSenderCertificateValidation<'a> {
    /// Known domain-signing keys indexed by certificate signing-key identifier.
    pub domain_signing_keys: &'a [DomainSigningKey<'a>],
    /// Relay domain the recipient expects incoming certificates to name.
    pub expected_relay_domain: &'a [u8],
    /// Caller-supplied revocation input for the sender Identity Key check.
    pub revocation_state: RevocationState<'a>,
    /// Caller-supplied time used for expiry evaluation.
    pub reference_time: SystemTime,
}

/// Inbound plaintext and all advanced protocol-state updates from one operation.
pub struct InboundMessageResult {
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
    /// Encrypted acknowledgment artifact to durably queue with the returned state updates.
    pub acknowledgment: Message,
    /// Protocol-state updates to commit before treating the inbound Message as processed.
    pub state_updates: Vec<ProtocolStateUpdate>,
}

/// Accepted blocked inbound Message result without consumer-visible plaintext.
pub struct BlockedInboundMessageResult {
    /// Encrypted acknowledgment artifact to durably queue with the returned state updates, or
    /// `None` when the blocked-contact acknowledgment policy suppresses it.
    pub acknowledgment: Option<Message>,
    /// Protocol-state updates to commit before treating the blocked inbound Message as processed.
    pub state_updates: Vec<ProtocolStateUpdate>,
}

/// Reason a Session was marked permanently unrecoverable.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum SessionUnrecoverableReason {
    /// The skipped-message-key retention cap was exceeded.
    SkippedKeyLimitExceeded,
}

/// Public event produced when a Session becomes unrecoverable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionEvent {
    /// A Session is now dead and must be replaced through a fresh X3DH exchange.
    Unrecoverable {
        /// Session-scoped protocol-state key.
        session_key: ProtocolStateKey,
        /// Terminal reason.
        reason: SessionUnrecoverableReason,
    },
}

/// Outcome returned for Messages addressed to a Dead Session.
pub struct SessionUnrecoverableResult {
    /// Session-scoped protocol-state key.
    pub session_key: ProtocolStateKey,
    /// Terminal reason.
    pub reason: SessionUnrecoverableReason,
    /// Event to emit after committing `state_updates`, present at most once per Dead Session.
    pub event: Option<SessionEvent>,
    /// Protocol-state updates to commit before surfacing the event.
    pub state_updates: Vec<ProtocolStateUpdate>,
}

/// The result of receiving an inbound encrypted Message.
pub enum InboundMessageOutcome {
    /// A unique Message decrypted and advanced protocol state.
    Accepted(Box<InboundMessageResult>),
    /// A unique blocked Message decrypted, acknowledged, and advanced protocol state.
    Blocked(Box<BlockedInboundMessageResult>),
    /// The Message matched an already-accepted encrypted byte sequence.
    Duplicate,
    /// The Session is permanently unrecoverable and no plaintext was produced.
    SessionUnrecoverable(Box<SessionUnrecoverableResult>),
}

/// An inbound encrypted acknowledgment Message.
pub struct InboundAcknowledgmentMessage<'a> {
    /// Session-scoped key for the ratchet/session and pending-acknowledgment blobs.
    pub session_key: ProtocolStateKey,
    /// Encrypted acknowledgment Message to process.
    pub message: &'a Message,
    /// Local recipient Discovery Key used to open the sealed-sender frame.
    pub recipient_discovery_key: &'a DiscoveryKey,
    /// Local recipient Ed25519 Identity Key verifying half authenticated by the transcript.
    ///
    /// This must be the Identity Key that signed `recipient_discovery_key`.
    pub recipient_identity_verifying_key: [u8; 32],
}

/// Pending acknowledgment state exposed to the consumer for durable flushing.
pub struct PendingAcknowledgment {
    /// Original outbound Message ID.
    pub message_id: MessageId,
    /// Original outbound Message waiting for an acknowledgment.
    pub message: Message,
    /// First-send Unix timestamp in milliseconds.
    pub first_sent_at_millis: u64,
    /// Last retry-instruction timestamp in milliseconds, if any.
    pub last_retried_at_millis: Option<u64>,
}

/// A retry instruction for one still-unacknowledged outbound Message.
pub struct RetryInstruction {
    /// Original outbound Message ID.
    pub message_id: MessageId,
    /// Message the consumer may retransmit.
    pub message: Message,
    /// First-send Unix timestamp in milliseconds.
    pub first_sent_at_millis: u64,
    /// Previous retry-instruction timestamp in milliseconds, if any.
    pub last_retried_at_millis: Option<u64>,
}

/// Retry instructions and any pending-state updates produced by one retry query.
pub struct RetryInstructionResult {
    /// Messages whose retry window has elapsed.
    pub instructions: Vec<RetryInstruction>,
    /// Protocol-state updates to commit after acting on the retry query.
    pub state_updates: Vec<ProtocolStateUpdate>,
}

/// State updates and decrypted metadata for a matched acknowledgment.
pub struct ClearedAcknowledgment {
    /// Acknowledgment Message ID recovered after decrypt.
    pub message_id: MessageId,
    /// Acknowledgment timestamp recovered after decrypt.
    pub sent_at_millis: u64,
    /// Outbound Message ID cleared from pending state.
    pub acknowledged_message_id: MessageId,
    /// Sender identity material decoded from the acknowledgment.
    pub sender_identity: SenderIdentityMaterial,
    /// Protocol-state updates to commit before treating the acknowledgment as processed.
    pub state_updates: Vec<ProtocolStateUpdate>,
}

/// The result of processing an encrypted acknowledgment.
pub enum AcknowledgmentOutcome {
    /// A matching pending acknowledgment was cleared.
    Cleared(ClearedAcknowledgment),
    /// The acknowledgment decrypted but did not match current pending state.
    Missed {
        /// Acknowledgment Message ID recovered after decrypt.
        message_id: MessageId,
        /// Acknowledgment timestamp recovered after decrypt.
        sent_at_millis: u64,
        /// Acknowledged Message ID carried inside the encrypted acknowledgment.
        acknowledged_message_id: MessageId,
        /// Sender identity material decoded from the acknowledgment.
        sender_identity: SenderIdentityMaterial,
        /// Protocol-state updates to commit before treating the miss as processed.
        state_updates: Vec<ProtocolStateUpdate>,
    },
    /// The exact acknowledgment Message was already processed.
    Duplicate,
    /// The Session is permanently unrecoverable and the acknowledgment was not decrypted.
    SessionUnrecoverable(Box<SessionUnrecoverableResult>),
}

/// Whether a blocked sender receives an acknowledgment for an accepted-but-hidden Message.
///
/// The default preserves privacy: a blocked sender cannot distinguish a block from an unreachable
/// recipient. Opting in to [`Self::SilentReceipt`] trades that away for delivery confirmation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum BlockedContactAcknowledgmentPolicy {
    /// Return no acknowledgment and do not advance the sending chain, so a blocked sender keeps
    /// retrying as if the recipient were offline.
    #[default]
    Unreachable,
    /// Return a normal acknowledgment, revealing delivery; local plaintext is still hidden.
    SilentReceipt,
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
    blocked_contact_acknowledgment_policy: BlockedContactAcknowledgmentPolicy,
    certificate_grace: Duration,
}

impl ProtocolStateEngine {
    /// Creates a stateless protocol-state engine.
    #[must_use]
    pub fn new() -> Self {
        let limits = ProtocolHardeningLimits::default();
        Self {
            limits,
            blocked_contact_acknowledgment_policy: BlockedContactAcknowledgmentPolicy::default(),
            certificate_grace: Duration::ZERO,
        }
    }

    /// Creates a stateless protocol-state engine with caller-selected hardening limits.
    pub fn with_hardening_limits(
        limits: ProtocolHardeningLimits,
    ) -> Result<Self, ProtocolStateError> {
        validate_hardening_limits(limits)?;
        Ok(Self {
            limits,
            blocked_contact_acknowledgment_policy: BlockedContactAcknowledgmentPolicy::default(),
            certificate_grace: Duration::ZERO,
        })
    }

    /// Returns the hardening limits used by this engine.
    #[must_use]
    pub fn hardening_limits(&self) -> ProtocolHardeningLimits {
        self.limits
    }

    /// Creates a stateless protocol-state engine with a received-message deduplication capacity.
    pub fn with_deduplication_capacity(capacity: usize) -> Result<Self, ProtocolStateError> {
        let limits = ProtocolHardeningLimits {
            deduplication_capacity: capacity,
            ..Default::default()
        };
        Self::with_hardening_limits(limits)
    }

    /// Returns the acknowledgment policy applied to Messages from blocked senders.
    #[must_use]
    pub fn blocked_contact_acknowledgment_policy(&self) -> BlockedContactAcknowledgmentPolicy {
        self.blocked_contact_acknowledgment_policy
    }

    /// Sets the acknowledgment policy applied to Messages from blocked senders.
    #[must_use]
    pub fn with_blocked_contact_acknowledgment_policy(
        mut self,
        policy: BlockedContactAcknowledgmentPolicy,
    ) -> Self {
        self.blocked_contact_acknowledgment_policy = policy;
        self
    }

    /// Returns how long after expiry an inbound sender certificate still validates.
    #[must_use]
    pub fn certificate_grace(&self) -> Duration {
        self.certificate_grace
    }

    /// Sets how long after expiry an inbound sender certificate still validates.
    ///
    /// The grace defaults to zero. It covers clock skew between devices, at the cost of accepting
    /// a certificate the relay has already stopped vouching for.
    pub fn with_certificate_grace(mut self, grace: Duration) -> Result<Self, ProtocolStateError> {
        if grace > MAX_CERTIFICATE_GRACE_WINDOW {
            return Err(ProtocolStateError::SenderCertificateValidation(
                SenderCertificateValidationError::GraceWindowTooLarge {
                    grace_window: grace,
                    max: MAX_CERTIFICATE_GRACE_WINDOW,
                },
            ));
        }
        self.certificate_grace = grace;
        Ok(self)
    }

    /// Returns an update that initializes an empty deduplication set for a local Identity.
    ///
    /// The consumer must commit the returned blob before receiving encrypted Messages for that
    /// Identity and must keep using the same Protocol State Blob across library restarts.
    pub fn initialize_deduplication_set<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        key: ProtocolStateKey,
    ) -> Result<ProtocolStateUpdate, ProtocolStateError> {
        let address = deduplication_address(key);
        let mut digest_key = Zeroizing::new([0u8; DEDUPLICATION_KEY_LEN]);
        rng.fill_bytes(&mut digest_key[..]);
        let state = LoadedDeduplicationSet {
            capacity: self.limits.deduplication_capacity,
            digest_key,
            digests: Vec::new(),
        };
        Ok(ProtocolStateUpdate::set(
            address.clone(),
            encode_deduplication_set(&address, &state, self.limits)?,
        ))
    }

    /// Returns an update that initializes empty pending-acknowledgment state for a Session.
    ///
    /// The consumer must commit the returned blob before sending encrypted Messages for that
    /// Session. Core reloads this blob for every send, acknowledgment, pending-list, and retry
    /// operation.
    pub fn initialize_pending_acknowledgments(
        &self,
        key: ProtocolStateKey,
    ) -> Result<ProtocolStateUpdate, ProtocolStateError> {
        let address = pending_acknowledgment_address(key);
        let state = LoadedPendingAcknowledgments {
            pending: BTreeMap::new(),
            acknowledgment_digests: Vec::new(),
        };
        Ok(ProtocolStateUpdate::set(
            address.clone(),
            encode_pending_acknowledgments(&address, &state, self.limits)?,
        ))
    }

    /// Returns an update that stores the supplied Ratchet session state without peer sender
    /// identity.
    ///
    /// Inbound decryption requires peer sender identity to be bound with
    /// [`Self::set_session_state_with_peer_identity`] or
    /// [`Self::bind_session_state_peer_identity_key`].
    pub fn set_session_state(
        &self,
        key: ProtocolStateKey,
        state: &RatchetState,
    ) -> Result<ProtocolStateUpdate, ProtocolStateError> {
        let address = ratchet_address(key);
        Ok(ProtocolStateUpdate::set(
            address.clone(),
            encode_session_state(&address, state, None, None, self.limits)?,
        ))
    }

    /// Returns an update that stores a Ratchet session state bound to the expected peer sender
    /// identity material.
    ///
    /// Responders should pass the sender identity returned by X3DH `accept` when installing the
    /// accepted ratchet state for inbound Messages from that peer.
    pub fn set_session_state_with_peer_identity(
        &self,
        key: ProtocolStateKey,
        state: &RatchetState,
        peer_sender_identity: &SenderIdentityMaterial,
    ) -> Result<ProtocolStateUpdate, ProtocolStateError> {
        self.set_session_state_with_peer_identity_key(key, state, peer_sender_identity.identity_key)
    }

    /// Returns an update that stores a Ratchet session state bound to the expected peer sender
    /// identity key.
    ///
    /// Use this when installing a session for a peer whose discovery public key is known without
    /// full sender certificate material.
    pub fn set_session_state_with_peer_identity_key(
        &self,
        key: ProtocolStateKey,
        state: &RatchetState,
        peer_sender_identity_key: [u8; 32],
    ) -> Result<ProtocolStateUpdate, ProtocolStateError> {
        let address = ratchet_address(key);
        Ok(ProtocolStateUpdate::set(
            address.clone(),
            encode_session_state(
                &address,
                state,
                Some(peer_sender_identity_key),
                None,
                self.limits,
            )?,
        ))
    }

    /// Returns an update that binds an existing Ratchet session blob to the expected peer sender
    /// identity key.
    ///
    /// Use this when restoring an existing opaque session blob and the peer identity key is known
    /// without full sender certificate material.
    pub fn bind_session_state_peer_identity_key(
        &self,
        snapshot: &ProtocolStateSnapshot,
        key: ProtocolStateKey,
        peer_sender_identity_key: [u8; 32],
    ) -> Result<ProtocolStateUpdate, ProtocolStateError> {
        let address = ratchet_address(key);
        let loaded = load_session_state(snapshot, &address, self.limits)?;
        let state = active_session_state(loaded.status)?;
        let peer_sender_identity_key = match loaded.peer_sender_identity_key {
            Some(existing)
                if !sender_identity_key_matches(&existing, &peer_sender_identity_key) =>
            {
                return Err(ProtocolStateError::InvalidStateBinding {
                    address,
                    reason: "session sender identity key is already bound".into(),
                });
            }
            Some(existing) => existing,
            None => peer_sender_identity_key,
        };
        Ok(ProtocolStateUpdate::set(
            address.clone(),
            encode_session_state(
                &address,
                &state,
                Some(peer_sender_identity_key),
                loaded.contact_identity_key,
                self.limits,
            )?,
        )
        .with_snapshot(snapshot))
    }

    /// Creates or updates an Identity-key-addressed Contact State blob.
    ///
    /// New contacts start [`ContactTrustState::Pending`]. Updating an existing contact may replace
    /// the current Discovery Key, but never resets the Identity-key-bound trust state.
    /// Consumers must build `contact_identity` from authenticated identity material; this method
    /// validates canonical key encodings and the Discovery Key signature, but it cannot prove where
    /// the Identity Key bytes came from.
    pub fn record_contact(
        &self,
        snapshot: &ProtocolStateSnapshot,
        contact_identity: ContactIdentity,
    ) -> Result<ContactStateChange, ProtocolStateError> {
        let address = contact_address(contact_identity.identity_key);
        validate_contact_identity(&address, &contact_identity)?;
        let contact = match snapshot.get(&address) {
            Some(blob) => {
                let current = decode_contact_state(&address, blob, self.limits)?;
                if contact_discovery_key_is_newer(
                    &current.identity.discovery_key,
                    &contact_identity.discovery_key,
                ) {
                    ContactState {
                        identity: contact_identity,
                        trust_state: current.trust_state,
                        blocked: current.blocked,
                    }
                } else {
                    return Ok(ContactStateChange {
                        contact: current,
                        state_updates: Vec::new(),
                        event: None,
                    });
                }
            }
            None => ContactState {
                identity: contact_identity,
                trust_state: ContactTrustState::Pending,
                blocked: false,
            },
        };
        changed_contact_state(snapshot, address, contact, self.limits)
    }

    /// Returns the Contact State for one peer Identity Key, if present.
    pub fn contact_state(
        &self,
        snapshot: &ProtocolStateSnapshot,
        identity_key: ContactIdentityKey,
    ) -> Result<Option<ContactState>, ProtocolStateError> {
        let address = contact_address(identity_key);
        validate_contact_identity_key(&address, &identity_key)?;
        snapshot
            .get(&address)
            .map(|blob| decode_contact_state(&address, blob, self.limits))
            .transpose()
    }

    /// Returns all current Contact State snapshots in address order.
    pub fn contact_states(
        &self,
        snapshot: &ProtocolStateSnapshot,
    ) -> Result<Vec<ContactState>, ProtocolStateError> {
        snapshot
            .blobs
            .iter()
            .filter(|(address, _)| address.kind == ProtocolStateKind::ContactState)
            .map(|(address, blob)| decode_contact_state(address, blob, self.limits))
            .collect()
    }

    /// Records consumer acceptance for a Pending contact.
    ///
    /// Acceptance moves Pending to Unverified. Calling this for an already accepted contact is an
    /// idempotent no-op.
    pub fn accept_contact(
        &self,
        snapshot: &ProtocolStateSnapshot,
        identity_key: ContactIdentityKey,
    ) -> Result<ContactStateChange, ProtocolStateError> {
        let address = contact_address(identity_key);
        validate_contact_identity_key(&address, &identity_key)?;
        let mut contact = load_contact_state(snapshot, &address, self.limits)?;
        match contact.trust_state {
            ContactTrustState::Pending => {
                contact.trust_state = ContactTrustState::Unverified;
                changed_contact_state(snapshot, address, contact, self.limits)
            }
            ContactTrustState::Unverified | ContactTrustState::Verified => Ok(ContactStateChange {
                contact,
                state_updates: Vec::new(),
                event: None,
            }),
        }
    }

    /// Locally blocks a contact without changing its Trust State.
    ///
    /// Blocking is keyed by the contact Identity Key. It refuses new outgoing user Messages and
    /// suppresses consumer-visible inbound plaintext after mandatory sender-certificate validation,
    /// while still accepting the protocol Message.
    pub fn block_contact(
        &self,
        snapshot: &ProtocolStateSnapshot,
        identity_key: ContactIdentityKey,
    ) -> Result<ContactStateChange, ProtocolStateError> {
        self.set_contact_blocked(snapshot, identity_key, true)
    }

    /// Locally unblocks a contact without changing its Trust State.
    ///
    /// Existing Sessions remain usable after unblock; no handshake is required solely because of
    /// the block/unblock cycle.
    pub fn unblock_contact(
        &self,
        snapshot: &ProtocolStateSnapshot,
        identity_key: ContactIdentityKey,
    ) -> Result<ContactStateChange, ProtocolStateError> {
        self.set_contact_blocked(snapshot, identity_key, false)
    }

    /// Records out-of-band Safety Number confirmation for an accepted contact.
    ///
    /// The presented value must match the Safety Number derived from `local_identity_key` and
    /// `contact_identity_key`. A mismatch is reported explicitly, leaves the stored Trust State
    /// unchanged, and returns no update or event. In-band Messages and acknowledgments never call
    /// this transition.
    pub fn confirm_contact_safety_number(
        &self,
        snapshot: &ProtocolStateSnapshot,
        local_identity_key: IdentityKey,
        contact_identity_key: ContactIdentityKey,
        presented_grouped_decimal: &str,
    ) -> Result<ContactSafetyNumberConfirmation, ProtocolStateError> {
        let address = contact_address(contact_identity_key);
        validate_contact_identity_key(&address, &contact_identity_key)?;
        let safety_number = derive_safety_number(local_identity_key, contact_identity_key)
            .map_err(|_| ProtocolStateError::InvalidStateBinding {
                address: address.clone(),
                reason: "identity key is invalid".into(),
            })?;
        let mut contact = load_contact_state(snapshot, &address, self.limits)?;
        match contact.trust_state {
            ContactTrustState::Pending => {
                return Err(ProtocolStateError::InvalidStateBinding {
                    address,
                    reason: "pending contact cannot be verified".into(),
                });
            }
            ContactTrustState::Verified => {}
            ContactTrustState::Unverified => {}
        }
        if safety_number.grouped_decimal != presented_grouped_decimal {
            return Ok(ContactSafetyNumberConfirmation::Mismatched(
                ContactStateChange {
                    contact,
                    state_updates: Vec::new(),
                    event: None,
                },
            ));
        }
        if contact.trust_state == ContactTrustState::Verified {
            return Ok(ContactSafetyNumberConfirmation::Matched(
                ContactStateChange {
                    contact,
                    state_updates: Vec::new(),
                    event: None,
                },
            ));
        }
        contact.trust_state = ContactTrustState::Verified;
        changed_contact_state(snapshot, address, contact, self.limits)
            .map(ContactSafetyNumberConfirmation::Matched)
    }

    /// Records a peer's inbox authorization, refusing to move backwards.
    ///
    /// Returns updates to commit, or an empty vector when `generation` is not newer than what is
    /// already stored. Refusing a lower generation matters because an old authorization replayed at
    /// a contact would restore a capability the peer has already rotated away from — the exact
    /// state a blocked sender would want to reach.
    ///
    /// The capability never enters [`ContactState`], so it is not mirrored to event observers.
    pub fn record_peer_inbox_authorization(
        &self,
        snapshot: &ProtocolStateSnapshot,
        identity_key: ContactIdentityKey,
        generation: u32,
        capability: &RecipientDeliveryCapability,
    ) -> Result<Vec<ProtocolStateUpdate>, ProtocolStateError> {
        let address = peer_inbox_authorization_address(identity_key);
        validate_contact_identity_key(&address, &identity_key)?;
        if let Some(stored) = load_peer_inbox_authorization(snapshot, &address)?
            && generation <= stored.generation
        {
            return Ok(Vec::new());
        }
        let wire = PeerInboxAuthorizationWire {
            version: PEER_INBOX_AUTHORIZATION_VERSION,
            generation,
            capability: *capability.to_bytes(),
        };
        let blob = postcard::to_stdvec(&wire).map_err(|e| ProtocolStateError::BlobEncode {
            address: address.clone(),
            reason: e.to_string(),
        })?;
        Ok(vec![
            ProtocolStateUpdate::set(address, ProtocolStateBlob::from_bytes(blob))
                .with_snapshot(snapshot),
        ])
    }

    /// Records that `identity_key` has been given local inbox generation `generation`.
    ///
    /// Call this only after the in-band authorization update has actually been handed to the
    /// transport, so an app killed mid-re-key resumes rather than skipping contacts. Returns no
    /// updates when the contact already holds this generation or a newer one.
    pub fn record_inbox_authorization_delivered(
        &self,
        snapshot: &ProtocolStateSnapshot,
        identity_key: ContactIdentityKey,
        generation: u32,
    ) -> Result<Vec<ProtocolStateUpdate>, ProtocolStateError> {
        let address = local_inbox_authorization_address(identity_key);
        validate_contact_identity_key(&address, &identity_key)?;
        if let Some(delivered) = load_delivered_inbox_authorization(snapshot, &address)?
            && generation <= delivered
        {
            return Ok(Vec::new());
        }
        let wire = LocalInboxAuthorizationWire {
            version: LOCAL_INBOX_AUTHORIZATION_VERSION,
            generation,
        };
        let blob = postcard::to_stdvec(&wire).map_err(|e| ProtocolStateError::BlobEncode {
            address: address.clone(),
            reason: e.to_string(),
        })?;
        Ok(vec![
            ProtocolStateUpdate::set(address, ProtocolStateBlob::from_bytes(blob))
                .with_snapshot(snapshot),
        ])
    }

    /// Returns the local inbox generation `identity_key` was last given, if any.
    pub fn delivered_inbox_authorization(
        &self,
        snapshot: &ProtocolStateSnapshot,
        identity_key: ContactIdentityKey,
    ) -> Result<Option<u32>, ProtocolStateError> {
        let address = local_inbox_authorization_address(identity_key);
        validate_contact_identity_key(&address, &identity_key)?;
        load_delivered_inbox_authorization(snapshot, &address)
    }

    /// Returns which of `candidates` still need the current inbox generation.
    ///
    /// A contact qualifies when it has never been given an authorization, or was last given one
    /// older than `current_generation`. **Blocked contacts are always excluded**: re-supplying a
    /// blocked contact would hand back the very capability the rotation revoked and silently undo
    /// the block. Contacts with no stored contact record are skipped.
    pub fn contacts_needing_inbox_authorization(
        &self,
        snapshot: &ProtocolStateSnapshot,
        current_generation: u32,
        candidates: &[ContactIdentityKey],
    ) -> Result<Vec<ContactIdentityKey>, ProtocolStateError> {
        let mut stale = Vec::new();
        for identity_key in candidates {
            let contact_address = contact_address(*identity_key);
            validate_contact_identity_key(&contact_address, identity_key)?;
            let Some(blob) = snapshot.get(&contact_address) else {
                continue;
            };
            if decode_contact_state(&contact_address, blob, self.limits)?.blocked {
                continue;
            }
            let delivered = load_delivered_inbox_authorization(
                snapshot,
                &local_inbox_authorization_address(*identity_key),
            )?;
            if delivered.is_none_or(|delivered| delivered < current_generation) {
                stale.push(*identity_key);
            }
        }
        Ok(stale)
    }

    /// Returns the stored inbox authorization for a peer, if one has been recorded.
    pub fn peer_inbox_authorization(
        &self,
        snapshot: &ProtocolStateSnapshot,
        identity_key: ContactIdentityKey,
    ) -> Result<Option<PeerInboxAuthorization>, ProtocolStateError> {
        let address = peer_inbox_authorization_address(identity_key);
        validate_contact_identity_key(&address, &identity_key)?;
        load_peer_inbox_authorization(snapshot, &address)
    }

    fn set_contact_blocked(
        &self,
        snapshot: &ProtocolStateSnapshot,
        identity_key: ContactIdentityKey,
        blocked: bool,
    ) -> Result<ContactStateChange, ProtocolStateError> {
        let address = contact_address(identity_key);
        validate_contact_identity_key(&address, &identity_key)?;
        let mut contact = load_contact_state(snapshot, &address, self.limits)?;
        if contact.blocked == blocked {
            return Ok(ContactStateChange {
                contact,
                state_updates: Vec::new(),
                event: None,
            });
        }
        contact.blocked = blocked;
        changed_contact_state(snapshot, address, contact, self.limits)
    }

    /// Returns deletion updates for all protocol-state kinds at `key`.
    #[must_use]
    pub fn wipe(
        &self,
        snapshot: &ProtocolStateSnapshot,
        key: ProtocolStateKey,
    ) -> Vec<ProtocolStateUpdate> {
        ProtocolStateKind::all()
            .iter()
            .map(|kind| {
                ProtocolStateUpdate::delete(ProtocolStateAddress::new(*kind, key.clone()))
                    .with_snapshot(snapshot)
            })
            .collect()
    }

    /// Encrypts plaintext while authenticating a caller-owned Transport Binding.
    /// The caller must retain the exact binding with the returned Message for retransmission.
    pub fn encrypt_message_with_transport_binding(
        &self,
        snapshot: &ProtocolStateSnapshot,
        key: ProtocolStateKey,
        plaintext: OutboundPlaintext<'_>,
        transport_binding: &TransportBinding,
    ) -> Result<OutboundMessageResult, ProtocolStateError> {
        let pending_address = pending_acknowledgment_address(key.clone());
        let address = ratchet_address(key);
        let loaded = load_session_state(snapshot, &address, self.limits)?;
        let contact_identity_key =
            session_contact_identity_key(&address, &loaded, plaintext.contact_identity_key)?;
        let transport_binding_bytes = transport_binding.as_bytes();
        ensure_contact_allows_outbound(
            snapshot,
            contact_identity_key,
            &plaintext.recipient_public_key,
            self.limits,
        )?;
        validate_sender_identity(plaintext.sender_identity, self.limits)?;
        let session_key_bytes = address.key().as_bytes().to_vec();
        let mut pending = load_pending_acknowledgments(snapshot, &pending_address, self.limits)?;
        let mut state = active_session_state(loaded.status)?;
        let padded_plaintext = pad_sealed_payload(plaintext.plaintext)?;
        let transcript_signature = sign_message_transcript(
            plaintext.sender_identity_signing_key,
            MessageTranscriptInput {
                session_key: &session_key_bytes,
                recipient_identity_verifying_key: &contact_identity_key.ed25519_verifying_key,
                id: plaintext.id,
                sent_at_millis: plaintext.sent_at_millis,
                payload_kind: PayloadKind::EncryptedText,
                payload: &padded_plaintext,
                sender_certificate: &plaintext.sender_identity.certificate,
            },
        )?;
        let sealed = encode_validated_sealed_sender_envelope(
            plaintext.sender_identity,
            &transcript_signature.to_bytes(),
            &padded_plaintext,
            self.limits,
        )?;
        let associated_data =
            ratchet_associated_data(&session_key_bytes, &plaintext.recipient_public_key);
        let (header, ciphertext) = state.ratchet_encrypt(&sealed, &associated_data)?;
        let ratcheted_payload = encode_ratcheted_payload(&header, &ciphertext);
        let frame_plaintext = encode_message_frame_plaintext(
            plaintext.id,
            plaintext.sent_at_millis,
            PayloadKind::EncryptedText,
            &ratcheted_payload,
        )?;
        let recipient_public_key = PublicKey::from(plaintext.recipient_public_key);
        let mut frame_rng = OsRng;
        let frame = seal_frame_with_associated_data(
            &mut frame_rng,
            &recipient_public_key,
            None,
            &frame_plaintext,
            transport_binding_bytes,
        )?;
        let message = Message::from_frame(frame);
        message
            .to_bytes_with_hardening_limits(self.limits)
            .map_err(ProtocolStateError::MessageEncode)?;
        record_pending_acknowledgment(
            &pending_address,
            &mut pending,
            plaintext.id,
            plaintext.sent_at_millis,
            &message,
            self.limits,
        )?;
        let update = ProtocolStateUpdate::set(
            address.clone(),
            encode_session_state(
                &address,
                &state,
                loaded.peer_sender_identity_key,
                Some(contact_identity_key),
                self.limits,
            )?,
        )
        .with_snapshot(snapshot);
        let pending_update = ProtocolStateUpdate::set(
            pending_address.clone(),
            encode_pending_acknowledgments(&pending_address, &pending, self.limits)?,
        )
        .with_snapshot(snapshot);

        Ok(OutboundMessageResult {
            message_id: plaintext.id,
            sent_at_millis: plaintext.sent_at_millis,
            payload_kind: PayloadKind::EncryptedText,
            message,
            state_updates: vec![update, pending_update],
        })
    }

    /// Receives a Message while authenticating its Transport Binding and the binding used for the
    /// returned acknowledgment.
    /// The caller must retain `acknowledgment_transport_binding` with the returned acknowledgment.
    pub fn decrypt_message_with_transport_bindings<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        snapshot: &ProtocolStateSnapshot,
        inbound: InboundEncryptedMessage<'_>,
        message_transport_binding: &TransportBinding,
        acknowledgment_transport_binding: &TransportBinding,
    ) -> Result<InboundMessageOutcome, ProtocolStateError> {
        let message_transport_binding_bytes = message_transport_binding.as_bytes();
        let deduplication_address = deduplication_address(inbound.deduplication_key);
        let encoded = inbound
            .message
            .to_bytes_with_hardening_limits(self.limits)
            .map_err(ProtocolStateError::MessageEncode)?;
        let mut deduplication =
            load_deduplication_set(snapshot, &deduplication_address, self.limits)?;
        let digest = deduplication_digest(
            &deduplication.digest_key,
            message_transport_binding_bytes,
            &encoded,
        );
        if contains_digest(&deduplication.digests, &digest) {
            return Ok(InboundMessageOutcome::Duplicate);
        }
        let recipient_identity_verifying_key =
            parse_ed25519_verifying_key_bytes(&inbound.recipient_identity_verifying_key)
                .ok_or_else(|| ProtocolStateError::InvalidMessage {
                    reason: "recipient identity verifying key is not canonical".into(),
                })?;
        verify_public_discovery_key(
            &inbound.recipient_discovery_key.public(),
            &recipient_identity_verifying_key,
        )
        .map_err(|_| ProtocolStateError::InvalidMessage {
            reason: "recipient discovery key does not match recipient identity key".into(),
        })?;

        let address = ratchet_address(inbound.session_key);
        let session_key_bytes = address.key().as_bytes().to_vec();
        let loaded = load_session_state(snapshot, &address, self.limits)?;
        let LoadedSessionState {
            status,
            peer_sender_identity_key,
            contact_identity_key,
        } = loaded;
        let mut state = match status {
            LoadedSessionStatus::Active(state) => *state,
            LoadedSessionStatus::Unrecoverable {
                reason,
                event_emitted,
            } => {
                return Ok(InboundMessageOutcome::SessionUnrecoverable(Box::new(
                    session_unrecoverable_result(
                        snapshot,
                        &address,
                        reason,
                        event_emitted,
                        peer_sender_identity_key,
                        contact_identity_key,
                        self.limits,
                    )?,
                )));
            }
        };
        let message = inbound.message;
        if message.prekey_reference.is_some() {
            return Err(ProtocolStateError::InvalidMessage {
                reason: "session message carries an x3dh prekey reference".into(),
            });
        }
        let expected_sender_identity_key =
            peer_sender_identity_key.ok_or_else(|| ProtocolStateError::InvalidMessage {
                reason: "session sender identity key is not bound".into(),
            })?;

        let frame_plaintext = open_frame_for_discovery_key_with_associated_data(
            inbound.recipient_discovery_key,
            &message.to_frame(),
            message_transport_binding_bytes,
        )?;
        let frame_plaintext = decode_message_frame_plaintext(&frame_plaintext)?;
        if frame_plaintext.payload_kind != PayloadKind::EncryptedText {
            return Err(ProtocolStateError::InvalidMessage {
                reason: "message payload is not ratcheted encrypted text".into(),
            });
        }
        let (header, ciphertext) = decode_ratcheted_payload(&frame_plaintext.ratcheted_payload)?;
        let associated_data =
            ratchet_associated_data(&session_key_bytes, &message.recipient_public_key);
        let sealed = state.ratchet_decrypt(rng, ciphertext, &header, &associated_data)?;
        let decoded = decode_sealed_sender_envelope(&sealed, self.limits)?;
        if !sender_identity_key_matches(
            &expected_sender_identity_key,
            &decoded.sender_identity.identity_key,
        ) {
            return Err(ProtocolStateError::InvalidMessage {
                reason: "sealed sender identity key does not match session".into(),
            });
        }
        verify_message_transcript(
            &decoded.sender_identity,
            MessageTranscriptInput {
                session_key: &session_key_bytes,
                recipient_identity_verifying_key: &inbound.recipient_identity_verifying_key,
                id: frame_plaintext.id,
                sent_at_millis: frame_plaintext.sent_at_millis,
                payload_kind: frame_plaintext.payload_kind,
                payload: &decoded.padded_plaintext,
                sender_certificate: &decoded.sender_identity.certificate,
            },
            &decoded.transcript_signature,
        )?;
        let validation = inbound
            .sender_certificate_validation
            .ok_or(ProtocolStateError::MissingSenderCertificateValidation)?;
        let inbound_contact_identity_key = inbound_contact_identity_key(
            validation,
            self.certificate_grace,
            &decoded.sender_identity,
            contact_identity_key,
            self.limits,
        )?;
        let blocked = contact_is_blocked(snapshot, inbound_contact_identity_key, self.limits)?;
        record_deduplication_digest(&mut deduplication, digest);
        // Unreachable policy suppresses the acknowledgment and leaves the sending chain unadvanced;
        // the receiving-chain advance and recorded digest are still committed below.
        if blocked
            && self.blocked_contact_acknowledgment_policy
                == BlockedContactAcknowledgmentPolicy::Unreachable
        {
            let state_updates = receive_state_updates(
                snapshot,
                &address,
                &state,
                inbound_contact_identity_key,
                &deduplication_address,
                &deduplication,
                self.limits,
            )?;
            return Ok(InboundMessageOutcome::Blocked(Box::new(
                BlockedInboundMessageResult {
                    acknowledgment: None,
                    state_updates,
                },
            )));
        }
        let acknowledgment = encrypt_acknowledgment(
            &mut state,
            &session_key_bytes,
            AcknowledgmentEncryptionInput {
                acknowledgment: &inbound.acknowledgment,
                transport_binding: acknowledgment_transport_binding,
            },
            &decoded.sender_identity.identity_verifying_key,
            frame_plaintext.id,
            rng,
            self.limits,
        )?;
        let state_updates = receive_state_updates(
            snapshot,
            &address,
            &state,
            inbound_contact_identity_key,
            &deduplication_address,
            &deduplication,
            self.limits,
        )?;
        if blocked {
            return Ok(InboundMessageOutcome::Blocked(Box::new(
                BlockedInboundMessageResult {
                    acknowledgment: Some(acknowledgment),
                    state_updates,
                },
            )));
        }
        Ok(InboundMessageOutcome::Accepted(Box::new(
            InboundMessageResult {
                message_id: frame_plaintext.id,
                sent_at_millis: frame_plaintext.sent_at_millis,
                payload_kind: frame_plaintext.payload_kind,
                plaintext: decoded.plaintext,
                sender_identity: decoded.sender_identity,
                acknowledgment,
                state_updates,
            },
        )))
    }

    /// Returns all pending acknowledgments stored for a Session.
    pub fn pending_acknowledgments(
        &self,
        snapshot: &ProtocolStateSnapshot,
        key: ProtocolStateKey,
    ) -> Result<Vec<PendingAcknowledgment>, ProtocolStateError> {
        let address = pending_acknowledgment_address(key);
        let pending = load_pending_acknowledgments(snapshot, &address, self.limits)?;
        Ok(pending
            .pending
            .iter()
            .map(|(message_id, entry)| PendingAcknowledgment {
                message_id: MessageId::from_bytes(*message_id),
                message: copy_message(&entry.message),
                first_sent_at_millis: entry.first_sent_at_millis,
                last_retried_at_millis: entry.last_retried_at_millis,
            })
            .collect())
    }

    /// Returns retry instructions for pending acknowledgments whose retry window has elapsed.
    ///
    /// `now` is caller supplied so retry behavior is deterministic in tests and does not read the
    /// system clock.
    pub fn retry_instructions(
        &self,
        snapshot: &ProtocolStateSnapshot,
        key: ProtocolStateKey,
        now: SystemTime,
        retry_window: Duration,
    ) -> Result<RetryInstructionResult, ProtocolStateError> {
        let address = pending_acknowledgment_address(key);
        let mut pending = load_pending_acknowledgments(snapshot, &address, self.limits)?;
        let mut instructions = Vec::new();
        for (message_id, entry) in pending.pending.iter_mut() {
            let reference_millis = entry
                .last_retried_at_millis
                .unwrap_or(entry.first_sent_at_millis);
            let is_due = from_unix_millis(reference_millis).is_some_and(|reference| {
                now.duration_since(reference)
                    .is_ok_and(|elapsed| elapsed >= retry_window)
            });
            if is_due {
                instructions.push(RetryInstruction {
                    message_id: MessageId::from_bytes(*message_id),
                    message: copy_message(&entry.message),
                    first_sent_at_millis: entry.first_sent_at_millis,
                    last_retried_at_millis: entry.last_retried_at_millis,
                });
                // `now` is at or after a Unix timestamp here, so only a value beyond `u64`
                // milliseconds saturates.
                entry.last_retried_at_millis = Some(to_unix_millis(now).unwrap_or(u64::MAX));
            }
        }

        let state_updates = if instructions.is_empty() {
            Vec::new()
        } else {
            vec![
                ProtocolStateUpdate::set(
                    address.clone(),
                    encode_pending_acknowledgments(&address, &pending, self.limits)?,
                )
                .with_snapshot(snapshot),
            ]
        };
        Ok(RetryInstructionResult {
            instructions,
            state_updates,
        })
    }

    /// Processes an acknowledgment while authenticating its Transport Binding.
    pub fn process_acknowledgment_with_transport_binding<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        snapshot: &ProtocolStateSnapshot,
        inbound: InboundAcknowledgmentMessage<'_>,
        transport_binding: &TransportBinding,
    ) -> Result<AcknowledgmentOutcome, ProtocolStateError> {
        let transport_binding_bytes = transport_binding.as_bytes();
        let pending_address = pending_acknowledgment_address(inbound.session_key.clone());
        let encoded = inbound
            .message
            .to_bytes_with_hardening_limits(self.limits)
            .map_err(ProtocolStateError::MessageEncode)?;
        let digest = acknowledgment_digest(transport_binding_bytes, &encoded);
        if pending_acknowledgment_digest_seen(snapshot, &pending_address, digest, self.limits)? {
            return Ok(AcknowledgmentOutcome::Duplicate);
        }
        let recipient_identity_verifying_key =
            parse_ed25519_verifying_key_bytes(&inbound.recipient_identity_verifying_key)
                .ok_or_else(|| ProtocolStateError::InvalidMessage {
                    reason: "recipient identity verifying key is not canonical".into(),
                })?;
        verify_public_discovery_key(
            &inbound.recipient_discovery_key.public(),
            &recipient_identity_verifying_key,
        )
        .map_err(|_| ProtocolStateError::InvalidMessage {
            reason: "recipient discovery key does not match recipient identity key".into(),
        })?;
        let mut pending = load_pending_acknowledgments(snapshot, &pending_address, self.limits)?;

        let address = ratchet_address(inbound.session_key);
        let session_key_bytes = address.key().as_bytes().to_vec();
        let loaded = load_session_state(snapshot, &address, self.limits)?;
        let LoadedSessionState {
            status,
            peer_sender_identity_key,
            contact_identity_key,
        } = loaded;
        let mut state = match status {
            LoadedSessionStatus::Active(state) => *state,
            LoadedSessionStatus::Unrecoverable {
                reason,
                event_emitted,
            } => {
                return Ok(AcknowledgmentOutcome::SessionUnrecoverable(Box::new(
                    session_unrecoverable_result(
                        snapshot,
                        &address,
                        reason,
                        event_emitted,
                        peer_sender_identity_key,
                        contact_identity_key,
                        self.limits,
                    )?,
                )));
            }
        };
        let message = inbound.message;
        if message.prekey_reference.is_some() {
            return Err(ProtocolStateError::InvalidMessage {
                reason: "acknowledgment carries an x3dh prekey reference".into(),
            });
        }
        let expected_sender_identity_key =
            peer_sender_identity_key.ok_or_else(|| ProtocolStateError::InvalidMessage {
                reason: "session sender identity key is not bound".into(),
            })?;

        let frame_plaintext = open_frame_for_discovery_key_with_associated_data(
            inbound.recipient_discovery_key,
            &message.to_frame(),
            transport_binding_bytes,
        )?;
        let frame_plaintext = decode_message_frame_plaintext(&frame_plaintext)?;
        if frame_plaintext.payload_kind != PayloadKind::Acknowledgment {
            return Err(ProtocolStateError::InvalidMessage {
                reason: "message payload is not an acknowledgment".into(),
            });
        }
        let (header, ciphertext) = decode_ratcheted_payload(&frame_plaintext.ratcheted_payload)?;
        let associated_data =
            ratchet_associated_data(&session_key_bytes, &message.recipient_public_key);
        let sealed = state.ratchet_decrypt(rng, ciphertext, &header, &associated_data)?;
        let decoded = decode_sealed_sender_envelope(&sealed, self.limits)?;
        if !sender_identity_key_matches(
            &expected_sender_identity_key,
            &decoded.sender_identity.identity_key,
        ) {
            return Err(ProtocolStateError::InvalidMessage {
                reason: "sealed sender identity key does not match session".into(),
            });
        }
        verify_message_transcript(
            &decoded.sender_identity,
            MessageTranscriptInput {
                session_key: &session_key_bytes,
                recipient_identity_verifying_key: &inbound.recipient_identity_verifying_key,
                id: frame_plaintext.id,
                sent_at_millis: frame_plaintext.sent_at_millis,
                payload_kind: frame_plaintext.payload_kind,
                payload: &decoded.padded_plaintext,
                sender_certificate: &decoded.sender_identity.certificate,
            },
            &decoded.transcript_signature,
        )?;
        let acknowledged_message_id = decode_acknowledgment_plaintext(&decoded.plaintext)?;
        record_acknowledgment_digest(&mut pending, digest, self.limits);
        let cleared = pending
            .pending
            .remove(acknowledged_message_id.as_bytes())
            .is_some();
        let session_update = ProtocolStateUpdate::set(
            address.clone(),
            encode_session_state(
                &address,
                &state,
                Some(expected_sender_identity_key),
                contact_identity_key,
                self.limits,
            )?,
        )
        .with_snapshot(snapshot);
        let pending_update = ProtocolStateUpdate::set(
            pending_address.clone(),
            encode_pending_acknowledgments(&pending_address, &pending, self.limits)?,
        )
        .with_snapshot(snapshot);
        let state_updates = vec![session_update, pending_update];
        if cleared {
            Ok(AcknowledgmentOutcome::Cleared(ClearedAcknowledgment {
                message_id: frame_plaintext.id,
                sent_at_millis: frame_plaintext.sent_at_millis,
                acknowledged_message_id,
                sender_identity: decoded.sender_identity,
                state_updates,
            }))
        } else {
            Ok(AcknowledgmentOutcome::Missed {
                message_id: frame_plaintext.id,
                sent_at_millis: frame_plaintext.sent_at_millis,
                acknowledged_message_id,
                sender_identity: decoded.sender_identity,
                state_updates,
            })
        }
    }
}

impl Default for ProtocolStateEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors returned by protocol-state operations.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolStateError {
    /// The contact is locally blocked.
    #[error("contact is blocked")]
    BlockedContact,
    /// The contact must be accepted before sending.
    #[error("contact is not accepted")]
    ContactNotAccepted,
    /// A terminal Session must be replaced by a fresh handshake.
    #[error("session is unrecoverable")]
    SessionUnrecoverable,
    /// The operation snapshot exceeds its entry cap.
    #[error("protocol-state snapshot capacity exceeded")]
    SnapshotCapacityExceeded,
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
    /// Sender-certificate validation failed during receive.
    #[error("sender certificate validation failed")]
    SenderCertificateValidation(#[source] SenderCertificateValidationError),
    /// A unique encrypted receive was attempted without sender-certificate validation inputs.
    #[error("missing sender certificate validation input")]
    MissingSenderCertificateValidation,
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
    /// A configured hardening limit is outside supported bounds.
    #[error("invalid hardening limit for {name}: {value} outside {minimum}..={maximum}")]
    InvalidHardeningLimit {
        /// Name of the rejected limit.
        name: &'static str,
        /// Requested limit.
        value: usize,
        /// Minimum supported value.
        minimum: usize,
        /// Maximum supported value.
        maximum: usize,
    },
    /// A Message failed canonical encoding.
    #[error("protocol-state message encoding failed")]
    MessageEncode(#[source] MessageError),
    /// A state binding operation would violate an existing protocol-state invariant.
    #[error("invalid protocol-state binding at {address}: {reason}")]
    InvalidStateBinding {
        /// Address whose binding invariant would be violated.
        address: ProtocolStateAddress,
        /// Diagnostic failure context for logs only.
        reason: String,
    },
    /// A protocol-state key is malformed.
    #[error("invalid protocol-state key: {reason}")]
    InvalidStateKey {
        /// Diagnostic failure context for logs only.
        reason: String,
    },
    /// A required protocol-state blob was absent from the consumer snapshot.
    #[error("missing required protocol-state blob at {address}")]
    MissingRequiredState {
        /// Address that must be present before the operation.
        address: ProtocolStateAddress,
    },
    /// A persisted blob used a version this build does not support.
    #[error("unsupported protocol-state blob version at {address}: {major}.{minor}")]
    UnsupportedBlobVersion {
        /// Address whose blob version is unsupported.
        address: ProtocolStateAddress,
        /// Major version read from the blob envelope.
        major: u8,
        /// Minor version read from the blob envelope.
        minor: u8,
    },
}

/// Computes the digest used by protocol-state commit conditions.
#[must_use]
pub fn protocol_state_blob_digest(blob: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"RoostProtocolStateCommit-v1:");
    hasher.update(blob);
    *hasher.finalize().as_bytes()
}

fn ratchet_address(key: ProtocolStateKey) -> ProtocolStateAddress {
    ProtocolStateAddress::new(ProtocolStateKind::RatchetSession, key)
}

fn deduplication_address(key: ProtocolStateKey) -> ProtocolStateAddress {
    ProtocolStateAddress::new(ProtocolStateKind::DeduplicationSet, key)
}

fn pending_acknowledgment_address(key: ProtocolStateKey) -> ProtocolStateAddress {
    ProtocolStateAddress::new(ProtocolStateKind::PendingAcknowledgments, key)
}

fn contact_address(identity_key: ContactIdentityKey) -> ProtocolStateAddress {
    ProtocolStateAddress::new(ProtocolStateKind::ContactState, identity_key.into())
}

fn peer_inbox_authorization_address(identity_key: ContactIdentityKey) -> ProtocolStateAddress {
    ProtocolStateAddress::new(
        ProtocolStateKind::PeerInboxAuthorization,
        identity_key.into(),
    )
}

fn local_inbox_authorization_address(identity_key: ContactIdentityKey) -> ProtocolStateAddress {
    ProtocolStateAddress::new(
        ProtocolStateKind::LocalInboxAuthorization,
        identity_key.into(),
    )
}

fn load_delivered_inbox_authorization(
    snapshot: &ProtocolStateSnapshot,
    address: &ProtocolStateAddress,
) -> Result<Option<u32>, ProtocolStateError> {
    let Some(blob) = snapshot.get(address) else {
        return Ok(None);
    };
    let wire: LocalInboxAuthorizationWire =
        decode_inbox_authorization(address, blob, LOCAL_INBOX_AUTHORIZATION_VERSION)?;
    Ok(Some(wire.generation))
}

fn load_peer_inbox_authorization(
    snapshot: &ProtocolStateSnapshot,
    address: &ProtocolStateAddress,
) -> Result<Option<PeerInboxAuthorization>, ProtocolStateError> {
    let Some(blob) = snapshot.get(address) else {
        return Ok(None);
    };
    let wire: PeerInboxAuthorizationWire =
        decode_inbox_authorization(address, blob, PEER_INBOX_AUTHORIZATION_VERSION)?;
    Ok(Some(PeerInboxAuthorization {
        generation: wire.generation,
        capability: RecipientDeliveryCapability::from_bytes(wire.capability),
    }))
}

// Checks the leading version byte before decoding the rest, then rejects leftover bytes.
fn decode_inbox_authorization<T: serde::de::DeserializeOwned>(
    address: &ProtocolStateAddress,
    blob: &ProtocolStateBlob,
    version: u8,
) -> Result<T, ProtocolStateError> {
    let bytes = blob.as_bytes();
    if let Some(&stored_version) = bytes.first()
        && stored_version != version
    {
        return Err(ProtocolStateError::UnsupportedBlobVersion {
            address: address.clone(),
            major: stored_version,
            minor: 0,
        });
    }
    let (wire, trailing) =
        postcard::take_from_bytes(bytes).map_err(|e| ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: e.to_string(),
        })?;
    if !trailing.is_empty() {
        return Err(ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: format!("inbox authorization has {} trailing bytes", trailing.len()),
        });
    }
    Ok(wire)
}

fn validate_persisted_deduplication_capacity(
    address: &ProtocolStateAddress,
    capacity: usize,
) -> Result<(), ProtocolStateError> {
    if !(MIN_DEDUPLICATION_CAPACITY..=MAX_DEDUPLICATION_CAPACITY).contains(&capacity) {
        return Err(ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: format!("deduplication-set capacity is outside supported range: {capacity}"),
        });
    }
    Ok(())
}

#[derive(Deserialize, Serialize)]
struct SessionStateWire<'a> {
    version: u8,
    #[serde(borrow)]
    status: SessionStatusWire<'a>,
    peer_sender_identity_key: Option<[u8; 32]>,
}

#[derive(Deserialize, Serialize)]
enum SessionStatusWire<'a> {
    ContactUnbound {
        #[serde(borrow)]
        ratchet_state: &'a [u8],
    },
    ContactBound {
        #[serde(borrow)]
        ratchet_state: &'a [u8],
        contact_identity_key: ContactIdentityKeyWire,
    },
    Unrecoverable {
        reason: SessionUnrecoverableReason,
        recovery_reported: bool,
        contact_identity_key: Option<ContactIdentityKeyWire>,
    },
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

fn encode_session_state(
    address: &ProtocolStateAddress,
    state: &RatchetState,
    peer_sender_identity_key: Option<[u8; 32]>,
    contact_identity_key: Option<ContactIdentityKey>,
    limits: ProtocolHardeningLimits,
) -> Result<ProtocolStateBlob, ProtocolStateError> {
    let state_bytes = state.to_bytes()?;
    let status = match contact_identity_key {
        Some(key) => SessionStatusWire::ContactBound {
            ratchet_state: &state_bytes,
            contact_identity_key: key.into(),
        },
        None => SessionStatusWire::ContactUnbound {
            ratchet_state: &state_bytes,
        },
    };
    encode_session_wire(
        address,
        SessionStateWire {
            version: SESSION_STATE_WIRE_VERSION,
            status,
            peer_sender_identity_key,
        },
        limits,
    )
}

fn encode_unrecoverable_session_state(
    address: &ProtocolStateAddress,
    reason: SessionUnrecoverableReason,
    event_emitted: bool,
    peer_sender_identity_key: Option<[u8; 32]>,
    contact_identity_key: Option<ContactIdentityKey>,
    limits: ProtocolHardeningLimits,
) -> Result<ProtocolStateBlob, ProtocolStateError> {
    encode_session_wire(
        address,
        SessionStateWire {
            version: SESSION_STATE_WIRE_VERSION,
            status: SessionStatusWire::Unrecoverable {
                reason,
                recovery_reported: event_emitted,
                contact_identity_key: contact_identity_key.map(Into::into),
            },
            peer_sender_identity_key,
        },
        limits,
    )
}

fn encode_session_wire(
    address: &ProtocolStateAddress,
    wire: SessionStateWire<'_>,
    limits: ProtocolHardeningLimits,
) -> Result<ProtocolStateBlob, ProtocolStateError> {
    let payload =
        Zeroizing::new(
            postcard::to_stdvec(&wire).map_err(|_| ProtocolStateError::BlobEncode {
                address: address.clone(),
                reason: "ratchet/session state failed to encode".into(),
            })?,
        );
    encode_session_payload(address, payload, limits)
}

fn encode_session_payload(
    address: &ProtocolStateAddress,
    payload: Zeroizing<Vec<u8>>,
    limits: ProtocolHardeningLimits,
) -> Result<ProtocolStateBlob, ProtocolStateError> {
    if payload.len() + PROTOCOL_STATE_BLOB_HEADER_LEN > limits.max_protocol_state_blob_len {
        return Err(ProtocolStateError::BlobEncode {
            address: address.clone(),
            reason: format!(
                "ratchet/session blob length exceeds limit: {}",
                payload.len() + PROTOCOL_STATE_BLOB_HEADER_LEN
            ),
        });
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        PROTOCOL_STATE_BLOB_HEADER_LEN + payload.len(),
    ));
    bytes.push(CURRENT_PROTOCOL_STATE_BLOB_MAJOR);
    bytes.push(CURRENT_PROTOCOL_STATE_BLOB_MINOR);
    bytes.extend_from_slice(&payload);
    Ok(ProtocolStateBlob::from_zeroizing(bytes))
}

struct LoadedSessionState {
    status: LoadedSessionStatus,
    peer_sender_identity_key: Option<[u8; 32]>,
    contact_identity_key: Option<ContactIdentityKey>,
}

enum LoadedSessionStatus {
    Active(Box<RatchetState>),
    Unrecoverable {
        reason: SessionUnrecoverableReason,
        event_emitted: bool,
    },
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct LoadedDeduplicationSet {
    capacity: usize,
    digest_key: Zeroizing<[u8; DEDUPLICATION_KEY_LEN]>,
    digests: Vec<[u8; DEDUPLICATION_DIGEST_LEN]>,
}

struct LoadedPendingAcknowledgments {
    pending: BTreeMap<[u8; 16], LoadedPendingAcknowledgment>,
    acknowledgment_digests: Vec<[u8; ACKNOWLEDGMENT_DIGEST_LEN]>,
}

struct LoadedPendingAcknowledgment {
    message: Message,
    encoded_message: Vec<u8>,
    first_sent_at_millis: u64,
    last_retried_at_millis: Option<u64>,
}

#[derive(Serialize)]
struct DeduplicationSetWire<'a> {
    version: u8,
    capacity: u16,
    digest_key: &'a [u8; DEDUPLICATION_KEY_LEN],
    digests: &'a [[u8; DEDUPLICATION_DIGEST_LEN]],
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct DecodedDeduplicationSetWire {
    version: u8,
    capacity: u16,
    digest_key: [u8; DEDUPLICATION_KEY_LEN],
    digests: Vec<[u8; DEDUPLICATION_DIGEST_LEN]>,
}

#[derive(Serialize)]
struct PendingAcknowledgmentsWire<'a> {
    version: u8,
    pending: Vec<PendingAcknowledgmentWire<'a>>,
    acknowledgment_digests: &'a [[u8; ACKNOWLEDGMENT_DIGEST_LEN]],
}

#[derive(Serialize)]
struct PendingAcknowledgmentWire<'a> {
    message_id: [u8; 16],
    encoded_message: &'a [u8],
    first_sent_at_millis: u64,
    last_retried_at_millis: Option<u64>,
}

#[derive(Deserialize)]
struct DecodedPendingAcknowledgmentsWire {
    version: u8,
    #[serde(deserialize_with = "deserialize_pending_acknowledgment_list")]
    pending: Vec<DecodedPendingAcknowledgmentWire>,
    #[serde(deserialize_with = "deserialize_acknowledgment_digest_list")]
    acknowledgment_digests: Vec<[u8; ACKNOWLEDGMENT_DIGEST_LEN]>,
}

#[derive(Deserialize)]
struct DecodedPendingAcknowledgmentWire {
    message_id: [u8; 16],
    encoded_message: Vec<u8>,
    first_sent_at_millis: u64,
    last_retried_at_millis: Option<u64>,
}

fn deserialize_pending_acknowledgment_list<'de, D>(
    deserializer: D,
) -> Result<Vec<DecodedPendingAcknowledgmentWire>, D::Error>
where
    D: Deserializer<'de>,
{
    struct PendingAcknowledgmentListVisitor;

    impl<'de> Visitor<'de> for PendingAcknowledgmentListVisitor {
        type Value = Vec<DecodedPendingAcknowledgmentWire>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "a bounded pending acknowledgment list")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if seq
                .size_hint()
                .is_some_and(|len| len > DEFAULT_MAX_PENDING_ACKNOWLEDGMENTS)
            {
                return Err(A::Error::custom(
                    "pending acknowledgment count exceeds limit",
                ));
            }
            let capacity = seq
                .size_hint()
                .unwrap_or(0)
                .min(DEFAULT_MAX_PENDING_ACKNOWLEDGMENTS);
            let mut pending = Vec::with_capacity(capacity);
            while let Some(entry) = seq.next_element()? {
                if pending.len() == DEFAULT_MAX_PENDING_ACKNOWLEDGMENTS {
                    return Err(A::Error::custom(
                        "pending acknowledgment count exceeds limit",
                    ));
                }
                pending.push(entry);
            }
            Ok(pending)
        }
    }

    deserializer.deserialize_seq(PendingAcknowledgmentListVisitor)
}

fn deserialize_acknowledgment_digest_list<'de, D>(
    deserializer: D,
) -> Result<Vec<[u8; ACKNOWLEDGMENT_DIGEST_LEN]>, D::Error>
where
    D: Deserializer<'de>,
{
    struct AcknowledgmentDigestListVisitor;

    impl<'de> Visitor<'de> for AcknowledgmentDigestListVisitor {
        type Value = Vec<[u8; ACKNOWLEDGMENT_DIGEST_LEN]>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "a bounded acknowledgment digest list")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if seq
                .size_hint()
                .is_some_and(|len| len > DEFAULT_MAX_ACKNOWLEDGMENT_DIGESTS)
            {
                return Err(A::Error::custom(
                    "acknowledgment digest count exceeds limit",
                ));
            }
            let capacity = seq
                .size_hint()
                .unwrap_or(0)
                .min(DEFAULT_MAX_ACKNOWLEDGMENT_DIGESTS);
            let mut digests = Vec::with_capacity(capacity);
            while let Some(digest) = seq.next_element()? {
                if digests.len() == DEFAULT_MAX_ACKNOWLEDGMENT_DIGESTS {
                    return Err(A::Error::custom(
                        "acknowledgment digest count exceeds limit",
                    ));
                }
                digests.push(digest);
            }
            Ok(digests)
        }
    }

    deserializer.deserialize_seq(AcknowledgmentDigestListVisitor)
}

#[derive(Deserialize, Serialize)]
struct LocalInboxAuthorizationWire {
    version: u8,
    generation: u32,
}

// Persistence requires serialization; `ZeroizeOnDrop` scrubs the temporary bearer-secret copy.
#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
struct PeerInboxAuthorizationWire {
    version: u8,
    generation: u32,
    capability: [u8; 32],
}

#[derive(Serialize)]
struct ContactStateWire<'a> {
    version: u8,
    identity_x25519_public_key: [u8; PUBLIC_KEY_LEN],
    identity_ed25519_verifying_key: [u8; PUBLIC_KEY_LEN],
    discovery_x25519_public_key: [u8; PUBLIC_KEY_LEN],
    discovery_ed25519_verifying_key: [u8; PUBLIC_KEY_LEN],
    discovery_epoch: u32,
    discovery_created_at_secs: u64,
    discovery_identity_signature: &'a [u8],
    trust_state: ContactTrustState,
    blocked: bool,
}

#[derive(Deserialize)]
struct DecodedContactStateWireV2 {
    version: u8,
    identity_x25519_public_key: [u8; PUBLIC_KEY_LEN],
    identity_ed25519_verifying_key: [u8; PUBLIC_KEY_LEN],
    discovery_x25519_public_key: [u8; PUBLIC_KEY_LEN],
    discovery_ed25519_verifying_key: [u8; PUBLIC_KEY_LEN],
    discovery_epoch: u32,
    discovery_created_at_secs: u64,
    discovery_identity_signature: Vec<u8>,
    trust_state: ContactTrustState,
    blocked: bool,
}

#[derive(Serialize)]
struct AcknowledgmentPlaintextWire {
    version: u8,
    acknowledged_message_id: [u8; 16],
}

#[derive(Deserialize)]
struct DecodedAcknowledgmentPlaintextWire {
    version: u8,
    acknowledged_message_id: [u8; 16],
}

#[derive(Serialize)]
struct MessageFramePlaintextWire<'a> {
    version: u8,
    id: [u8; 16],
    sent_at_millis: u64,
    payload_kind: u8,
    ratcheted_payload: &'a [u8],
}

#[derive(Deserialize)]
struct DecodedMessageFramePlaintextWire {
    version: u8,
    id: [u8; 16],
    sent_at_millis: u64,
    payload_kind: u8,
    ratcheted_payload: Vec<u8>,
}

struct DecodedMessageFramePlaintext {
    id: MessageId,
    sent_at_millis: u64,
    payload_kind: PayloadKind,
    ratcheted_payload: Vec<u8>,
}

fn load_session_state(
    snapshot: &ProtocolStateSnapshot,
    address: &ProtocolStateAddress,
    limits: ProtocolHardeningLimits,
) -> Result<LoadedSessionState, ProtocolStateError> {
    let blob = snapshot
        .get(address)
        .ok_or_else(|| ProtocolStateError::MissingRequiredState {
            address: address.clone(),
        })?;
    decode_session_state(address, blob, limits)
}

fn decode_session_state(
    address: &ProtocolStateAddress,
    blob: &ProtocolStateBlob,
    limits: ProtocolHardeningLimits,
) -> Result<LoadedSessionState, ProtocolStateError> {
    let bytes = blob.as_bytes();
    if bytes.len() > limits.max_protocol_state_blob_len {
        return Err(ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: format!("ratchet/session blob length exceeds limit: {}", bytes.len()),
        });
    }
    let (major, minor) =
        read_blob_version(bytes).ok_or_else(|| ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: "ratchet/session blob header is incomplete".into(),
        })?;
    let payload = &bytes[PROTOCOL_STATE_BLOB_HEADER_LEN..];

    if major == CURRENT_PROTOCOL_STATE_BLOB_MAJOR && minor == CURRENT_PROTOCOL_STATE_BLOB_MINOR {
        return decode_session_state_payload(address, payload);
    }

    Err(ProtocolStateError::UnsupportedBlobVersion {
        address: address.clone(),
        major,
        minor,
    })
}

fn read_blob_version(bytes: &[u8]) -> Option<(u8, u8)> {
    let header = bytes.get(..PROTOCOL_STATE_BLOB_HEADER_LEN)?;
    Some((header[0], header[1]))
}

fn decode_session_state_payload(
    address: &ProtocolStateAddress,
    payload: &[u8],
) -> Result<LoadedSessionState, ProtocolStateError> {
    if payload.first() != Some(&SESSION_STATE_WIRE_VERSION) {
        return Err(ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: "ratchet/session payload version is unsupported".into(),
        });
    }
    // Borrow ratchet bytes so a failed decode or key validation leaves no unsanitized heap copy.
    let (wire, trailing): (SessionStateWire<'_>, &[u8]) = postcard::take_from_bytes(payload)
        .map_err(|_| ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: "ratchet/session state failed to decode".into(),
        })?;
    if !trailing.is_empty() {
        return Err(ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: "ratchet/session state has trailing bytes".into(),
        });
    }
    match wire.status {
        SessionStatusWire::ContactUnbound { ratchet_state } => {
            decoded_session_state(address, ratchet_state, wire.peer_sender_identity_key, None)
        }
        SessionStatusWire::ContactBound {
            ratchet_state,
            contact_identity_key,
        } => decoded_session_state(
            address,
            ratchet_state,
            wire.peer_sender_identity_key,
            Some(validate_session_contact_identity_key(
                address,
                contact_identity_key.into(),
            )?),
        ),
        SessionStatusWire::Unrecoverable {
            reason,
            recovery_reported,
            contact_identity_key,
        } => Ok(LoadedSessionState {
            status: LoadedSessionStatus::Unrecoverable {
                reason,
                event_emitted: recovery_reported,
            },
            peer_sender_identity_key: wire.peer_sender_identity_key,
            contact_identity_key: contact_identity_key
                .map(Into::into)
                .map(|key| validate_session_contact_identity_key(address, key))
                .transpose()?,
        }),
    }
}

fn decoded_session_state(
    address: &ProtocolStateAddress,
    ratchet_state: &[u8],
    peer_sender_identity_key: Option<[u8; 32]>,
    contact_identity_key: Option<ContactIdentityKey>,
) -> Result<LoadedSessionState, ProtocolStateError> {
    let state =
        RatchetState::from_bytes(ratchet_state).map_err(|_| ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: "ratchet/session state failed to decode".into(),
        })?;
    Ok(LoadedSessionState {
        status: LoadedSessionStatus::Active(Box::new(state)),
        peer_sender_identity_key,
        contact_identity_key,
    })
}

fn active_session_state(status: LoadedSessionStatus) -> Result<RatchetState, ProtocolStateError> {
    match status {
        LoadedSessionStatus::Active(state) => Ok(*state),
        LoadedSessionStatus::Unrecoverable { .. } => Err(ProtocolStateError::SessionUnrecoverable),
    }
}

fn session_unrecoverable_result(
    snapshot: &ProtocolStateSnapshot,

    address: &ProtocolStateAddress,
    reason: SessionUnrecoverableReason,
    event_emitted: bool,
    peer_sender_identity_key: Option<[u8; 32]>,
    contact_identity_key: Option<ContactIdentityKey>,
    limits: ProtocolHardeningLimits,
) -> Result<SessionUnrecoverableResult, ProtocolStateError> {
    let session_key = address.key().clone();
    let (event, state_updates) = if event_emitted {
        (None, Vec::new())
    } else {
        let event = SessionEvent::Unrecoverable {
            session_key: session_key.clone(),
            reason,
        };
        let update = ProtocolStateUpdate::set(
            address.clone(),
            encode_unrecoverable_session_state(
                address,
                reason,
                true,
                peer_sender_identity_key,
                contact_identity_key,
                limits,
            )?,
        )
        .with_snapshot(snapshot);
        (Some(event), vec![update])
    };
    Ok(SessionUnrecoverableResult {
        session_key,
        reason,
        event,
        state_updates,
    })
}

fn encode_deduplication_set(
    address: &ProtocolStateAddress,
    state: &LoadedDeduplicationSet,
    limits: ProtocolHardeningLimits,
) -> Result<ProtocolStateBlob, ProtocolStateError> {
    validate_persisted_deduplication_capacity(address, state.capacity)?;
    if state.digests.len() > state.capacity {
        return Err(ProtocolStateError::BlobEncode {
            address: address.clone(),
            reason: format!(
                "deduplication-set digest count exceeds capacity: {}",
                state.digests.len()
            ),
        });
    }
    let payload = Zeroizing::new(
        postcard::to_stdvec(&DeduplicationSetWire {
            version: DEDUPLICATION_SET_WIRE_VERSION,
            capacity: state.capacity as u16,
            digest_key: &state.digest_key,
            digests: &state.digests,
        })
        .map_err(|_| ProtocolStateError::BlobEncode {
            address: address.clone(),
            reason: "deduplication set failed to encode".into(),
        })?,
    );
    if payload.len() + PROTOCOL_STATE_BLOB_HEADER_LEN > limits.max_protocol_state_blob_len {
        return Err(ProtocolStateError::BlobEncode {
            address: address.clone(),
            reason: format!(
                "deduplication-set blob length exceeds limit: {}",
                payload.len() + PROTOCOL_STATE_BLOB_HEADER_LEN
            ),
        });
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        PROTOCOL_STATE_BLOB_HEADER_LEN + payload.len(),
    ));
    bytes.push(CURRENT_PROTOCOL_STATE_BLOB_MAJOR);
    bytes.push(CURRENT_PROTOCOL_STATE_BLOB_MINOR);
    bytes.extend_from_slice(&payload);
    Ok(ProtocolStateBlob::from_zeroizing(bytes))
}

fn load_deduplication_set(
    snapshot: &ProtocolStateSnapshot,
    address: &ProtocolStateAddress,
    limits: ProtocolHardeningLimits,
) -> Result<LoadedDeduplicationSet, ProtocolStateError> {
    let blob = snapshot
        .get(address)
        .ok_or_else(|| ProtocolStateError::MissingRequiredState {
            address: address.clone(),
        })?;
    decode_deduplication_set(address, blob, limits)
}

fn decode_deduplication_set(
    address: &ProtocolStateAddress,
    blob: &ProtocolStateBlob,
    limits: ProtocolHardeningLimits,
) -> Result<LoadedDeduplicationSet, ProtocolStateError> {
    let bytes = blob.as_bytes();
    if bytes.len() > limits.max_protocol_state_blob_len {
        return Err(ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: format!(
                "deduplication-set blob length exceeds limit: {}",
                bytes.len()
            ),
        });
    }
    let (major, minor) =
        read_blob_version(bytes).ok_or_else(|| ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: "deduplication-set blob header is incomplete".into(),
        })?;
    let payload = &bytes[PROTOCOL_STATE_BLOB_HEADER_LEN..];

    if major == CURRENT_PROTOCOL_STATE_BLOB_MAJOR && minor == CURRENT_PROTOCOL_STATE_BLOB_MINOR {
        return decode_deduplication_set_payload(address, payload);
    }

    Err(ProtocolStateError::UnsupportedBlobVersion {
        address: address.clone(),
        major,
        minor,
    })
}

fn decode_deduplication_set_payload(
    address: &ProtocolStateAddress,
    payload: &[u8],
) -> Result<LoadedDeduplicationSet, ProtocolStateError> {
    let (mut wire, trailing): (DecodedDeduplicationSetWire, &[u8]) =
        postcard::take_from_bytes(payload).map_err(|e| ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: e.to_string(),
        })?;
    let digest_key = Zeroizing::new(wire.digest_key);
    let capacity = usize::from(wire.capacity);
    if !trailing.is_empty() || wire.version != DEDUPLICATION_SET_WIRE_VERSION {
        return Err(ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: "deduplication-set payload version is unsupported".into(),
        });
    }
    validate_persisted_deduplication_capacity(address, capacity)?;
    let digest_count = wire.digests.len();
    if digest_count > capacity {
        return Err(ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: format!(
                "deduplication-set digest count exceeds capacity: {}",
                digest_count
            ),
        });
    }
    let digests = std::mem::take(&mut wire.digests);
    Ok(LoadedDeduplicationSet {
        capacity,
        digest_key,
        digests,
    })
}

fn encode_pending_acknowledgments(
    address: &ProtocolStateAddress,
    state: &LoadedPendingAcknowledgments,
    limits: ProtocolHardeningLimits,
) -> Result<ProtocolStateBlob, ProtocolStateError> {
    if state.pending.len() > limits.max_pending_acknowledgments {
        return Err(ProtocolStateError::BlobEncode {
            address: address.clone(),
            reason: format!(
                "pending-acknowledgment count exceeds limit: {}",
                state.pending.len()
            ),
        });
    }
    if state.acknowledgment_digests.len() > limits.max_acknowledgment_digests {
        return Err(ProtocolStateError::BlobEncode {
            address: address.clone(),
            reason: format!(
                "acknowledgment digest count exceeds limit: {}",
                state.acknowledgment_digests.len()
            ),
        });
    }
    let pending = state
        .pending
        .iter()
        .map(|(message_id, entry)| PendingAcknowledgmentWire {
            message_id: *message_id,
            encoded_message: &entry.encoded_message,
            first_sent_at_millis: entry.first_sent_at_millis,
            last_retried_at_millis: entry.last_retried_at_millis,
        })
        .collect();
    let payload = Zeroizing::new(
        postcard::to_stdvec(&PendingAcknowledgmentsWire {
            version: PENDING_ACKNOWLEDGMENTS_WIRE_VERSION,
            pending,
            acknowledgment_digests: &state.acknowledgment_digests,
        })
        .map_err(|_| ProtocolStateError::BlobEncode {
            address: address.clone(),
            reason: "pending acknowledgments failed to encode".into(),
        })?,
    );
    if payload.len() + PROTOCOL_STATE_BLOB_HEADER_LEN > max_pending_acknowledgments_blob_len(limits)
    {
        return Err(ProtocolStateError::BlobEncode {
            address: address.clone(),
            reason: format!(
                "pending-acknowledgment blob length exceeds limit: {}",
                payload.len() + PROTOCOL_STATE_BLOB_HEADER_LEN
            ),
        });
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        PROTOCOL_STATE_BLOB_HEADER_LEN + payload.len(),
    ));
    bytes.push(CURRENT_PROTOCOL_STATE_BLOB_MAJOR);
    bytes.push(CURRENT_PROTOCOL_STATE_BLOB_MINOR);
    bytes.extend_from_slice(&payload);
    Ok(ProtocolStateBlob::from_zeroizing(bytes))
}

fn load_pending_acknowledgments(
    snapshot: &ProtocolStateSnapshot,
    address: &ProtocolStateAddress,
    limits: ProtocolHardeningLimits,
) -> Result<LoadedPendingAcknowledgments, ProtocolStateError> {
    let blob = snapshot
        .get(address)
        .ok_or_else(|| ProtocolStateError::MissingRequiredState {
            address: address.clone(),
        })?;
    decode_pending_acknowledgments(address, blob, limits)
}

fn pending_acknowledgment_digest_seen(
    snapshot: &ProtocolStateSnapshot,
    address: &ProtocolStateAddress,
    digest: [u8; ACKNOWLEDGMENT_DIGEST_LEN],
    limits: ProtocolHardeningLimits,
) -> Result<bool, ProtocolStateError> {
    let blob = snapshot
        .get(address)
        .ok_or_else(|| ProtocolStateError::MissingRequiredState {
            address: address.clone(),
        })?;
    let digests = decode_pending_acknowledgment_digests(address, blob, limits)?;
    Ok(contains_acknowledgment_digest(&digests, &digest))
}

fn decode_pending_acknowledgments(
    address: &ProtocolStateAddress,
    blob: &ProtocolStateBlob,
    limits: ProtocolHardeningLimits,
) -> Result<LoadedPendingAcknowledgments, ProtocolStateError> {
    let bytes = blob.as_bytes();
    if bytes.len() > max_pending_acknowledgments_blob_len(limits) {
        return Err(ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: format!(
                "pending-acknowledgment blob length exceeds limit: {}",
                bytes.len()
            ),
        });
    }
    let (major, minor) =
        read_blob_version(bytes).ok_or_else(|| ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: "pending-acknowledgment blob header is incomplete".into(),
        })?;
    let payload = &bytes[PROTOCOL_STATE_BLOB_HEADER_LEN..];

    if major == CURRENT_PROTOCOL_STATE_BLOB_MAJOR && minor == CURRENT_PROTOCOL_STATE_BLOB_MINOR {
        return decode_pending_acknowledgments_payload(address, payload, limits);
    }

    Err(ProtocolStateError::UnsupportedBlobVersion {
        address: address.clone(),
        major,
        minor,
    })
}

fn decode_pending_acknowledgment_digests(
    address: &ProtocolStateAddress,
    blob: &ProtocolStateBlob,
    limits: ProtocolHardeningLimits,
) -> Result<Vec<[u8; ACKNOWLEDGMENT_DIGEST_LEN]>, ProtocolStateError> {
    let bytes = blob.as_bytes();
    if bytes.len() > max_pending_acknowledgments_blob_len(limits) {
        return Err(ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: format!(
                "pending-acknowledgment blob length exceeds limit: {}",
                bytes.len()
            ),
        });
    }
    let (major, minor) =
        read_blob_version(bytes).ok_or_else(|| ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: "pending-acknowledgment blob header is incomplete".into(),
        })?;
    let payload = &bytes[PROTOCOL_STATE_BLOB_HEADER_LEN..];

    if major == CURRENT_PROTOCOL_STATE_BLOB_MAJOR && minor == CURRENT_PROTOCOL_STATE_BLOB_MINOR {
        return decode_pending_acknowledgment_digests_payload(address, payload, limits);
    }

    Err(ProtocolStateError::UnsupportedBlobVersion {
        address: address.clone(),
        major,
        minor,
    })
}

fn decode_pending_acknowledgments_payload(
    address: &ProtocolStateAddress,
    payload: &[u8],
    limits: ProtocolHardeningLimits,
) -> Result<LoadedPendingAcknowledgments, ProtocolStateError> {
    let (wire, trailing): (DecodedPendingAcknowledgmentsWire, &[u8]) =
        postcard::take_from_bytes(payload).map_err(|e| ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: e.to_string(),
        })?;
    if !trailing.is_empty() || wire.version != PENDING_ACKNOWLEDGMENTS_WIRE_VERSION {
        return Err(ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: "pending-acknowledgment payload version is unsupported".into(),
        });
    }
    if wire.pending.len() > limits.max_pending_acknowledgments {
        return Err(ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: format!(
                "pending-acknowledgment count exceeds limit: {}",
                wire.pending.len()
            ),
        });
    }
    if wire.acknowledgment_digests.len() > limits.max_acknowledgment_digests {
        return Err(ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: format!(
                "acknowledgment digest count exceeds limit: {}",
                wire.acknowledgment_digests.len()
            ),
        });
    }

    let mut pending = BTreeMap::new();
    for entry in wire.pending {
        let message = Message::from_bytes_with_hardening_limits(&entry.encoded_message, limits)
            .map_err(|e| ProtocolStateError::BlobDecode {
                address: address.clone(),
                reason: format!("pending acknowledgment message failed to decode: {e}"),
            })?;
        if message.prekey_reference.is_some() {
            return Err(ProtocolStateError::BlobDecode {
                address: address.clone(),
                reason: "pending acknowledgment message carries x3dh prekey reference".into(),
            });
        }
        let replaced = pending.insert(
            entry.message_id,
            LoadedPendingAcknowledgment {
                message,
                encoded_message: entry.encoded_message,
                first_sent_at_millis: entry.first_sent_at_millis,
                last_retried_at_millis: entry.last_retried_at_millis,
            },
        );
        if replaced.is_some() {
            return Err(ProtocolStateError::BlobDecode {
                address: address.clone(),
                reason: "pending acknowledgment message ID is duplicated".into(),
            });
        }
    }
    Ok(LoadedPendingAcknowledgments {
        pending,
        acknowledgment_digests: wire.acknowledgment_digests,
    })
}

fn decode_pending_acknowledgment_digests_payload(
    address: &ProtocolStateAddress,
    payload: &[u8],
    limits: ProtocolHardeningLimits,
) -> Result<Vec<[u8; ACKNOWLEDGMENT_DIGEST_LEN]>, ProtocolStateError> {
    let mut offset = 0;
    let version = read_postcard_u8(payload, &mut offset).ok_or_else(|| {
        pending_acknowledgment_decode_error(address, "pending-acknowledgment version is missing")
    })?;
    if version != PENDING_ACKNOWLEDGMENTS_WIRE_VERSION {
        return Err(ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: "pending-acknowledgment payload version is unsupported".into(),
        });
    }
    let pending_len = read_postcard_varint_usize(payload, &mut offset).ok_or_else(|| {
        pending_acknowledgment_decode_error(address, "pending-acknowledgment count is malformed")
    })?;
    if pending_len > limits.max_pending_acknowledgments {
        return Err(ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: format!(
                "pending-acknowledgment count exceeds limit: {}",
                pending_len
            ),
        });
    }
    for _ in 0..pending_len {
        skip_postcard_bytes(payload, &mut offset, 16).ok_or_else(|| {
            pending_acknowledgment_decode_error(address, "pending message ID is malformed")
        })?;
        let encoded_len = read_postcard_varint_usize(payload, &mut offset).ok_or_else(|| {
            pending_acknowledgment_decode_error(address, "pending message length is malformed")
        })?;
        skip_postcard_bytes(payload, &mut offset, encoded_len).ok_or_else(|| {
            pending_acknowledgment_decode_error(address, "pending message bytes are malformed")
        })?;
        skip_postcard_varint_u64(payload, &mut offset).ok_or_else(|| {
            pending_acknowledgment_decode_error(address, "pending first-sent time is malformed")
        })?;
        match read_postcard_u8(payload, &mut offset).ok_or_else(|| {
            pending_acknowledgment_decode_error(address, "pending retry time option is malformed")
        })? {
            0 => {}
            1 => skip_postcard_varint_u64(payload, &mut offset).ok_or_else(|| {
                pending_acknowledgment_decode_error(address, "pending retry time is malformed")
            })?,
            _ => {
                return Err(pending_acknowledgment_decode_error(
                    address,
                    "pending retry time option is invalid",
                ));
            }
        }
    }
    let digest_len = read_postcard_varint_usize(payload, &mut offset).ok_or_else(|| {
        pending_acknowledgment_decode_error(address, "acknowledgment digest count is malformed")
    })?;
    if digest_len > limits.max_acknowledgment_digests {
        return Err(ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: format!("acknowledgment digest count exceeds limit: {digest_len}"),
        });
    }
    let mut digests = Vec::with_capacity(digest_len);
    for _ in 0..digest_len {
        let bytes = read_postcard_array::<ACKNOWLEDGMENT_DIGEST_LEN>(payload, &mut offset)
            .ok_or_else(|| {
                pending_acknowledgment_decode_error(address, "acknowledgment digest is malformed")
            })?;
        digests.push(bytes);
    }
    if offset != payload.len() {
        return Err(pending_acknowledgment_decode_error(
            address,
            "pending-acknowledgment payload has trailing bytes",
        ));
    }
    Ok(digests)
}

fn read_postcard_u8(bytes: &[u8], offset: &mut usize) -> Option<u8> {
    let byte = *bytes.get(*offset)?;
    *offset += 1;
    Some(byte)
}

fn read_postcard_array<const N: usize>(bytes: &[u8], offset: &mut usize) -> Option<[u8; N]> {
    let range = *offset..(*offset).checked_add(N)?;
    let slice = bytes.get(range)?;
    *offset += N;
    slice.try_into().ok()
}

fn read_postcard_varint_usize(bytes: &[u8], offset: &mut usize) -> Option<usize> {
    let mut value = 0u128;
    for shift in (0..64).step_by(7) {
        let byte = read_postcard_u8(bytes, offset)?;
        value |= u128::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return usize::try_from(value).ok();
        }
    }
    None
}

fn skip_postcard_varint_u64(bytes: &[u8], offset: &mut usize) -> Option<()> {
    for _ in 0..10 {
        let byte = read_postcard_u8(bytes, offset)?;
        if byte & 0x80 == 0 {
            return Some(());
        }
    }
    None
}

fn skip_postcard_bytes(bytes: &[u8], offset: &mut usize, len: usize) -> Option<()> {
    bytes.get(*offset..offset.checked_add(len)?)?;
    *offset += len;
    Some(())
}

fn pending_acknowledgment_decode_error(
    address: &ProtocolStateAddress,
    reason: &str,
) -> ProtocolStateError {
    ProtocolStateError::BlobDecode {
        address: address.clone(),
        reason: reason.into(),
    }
}

fn max_pending_acknowledgments_blob_len(limits: ProtocolHardeningLimits) -> usize {
    PROTOCOL_STATE_BLOB_HEADER_LEN
        + PENDING_ACKNOWLEDGMENTS_WIRE_OVERHEAD_CAP
        + limits.max_pending_acknowledgments
            * (limits.max_encoded_message_len + PENDING_ACKNOWLEDGMENT_ENTRY_OVERHEAD_CAP)
        + limits.max_acknowledgment_digests * ACKNOWLEDGMENT_DIGEST_LEN
}

fn changed_contact_state(
    snapshot: &ProtocolStateSnapshot,

    address: ProtocolStateAddress,
    contact: ContactState,
    limits: ProtocolHardeningLimits,
) -> Result<ContactStateChange, ProtocolStateError> {
    Ok(ContactStateChange {
        contact: contact.clone(),
        state_updates: vec![
            ProtocolStateUpdate::set(
                address.clone(),
                encode_contact_state(&address, &contact, limits)?,
            )
            .with_snapshot(snapshot),
        ],
        event: Some(ContactEvent::Changed { contact }),
    })
}

fn load_contact_state(
    snapshot: &ProtocolStateSnapshot,
    address: &ProtocolStateAddress,
    limits: ProtocolHardeningLimits,
) -> Result<ContactState, ProtocolStateError> {
    let blob = snapshot
        .get(address)
        .ok_or_else(|| ProtocolStateError::MissingRequiredState {
            address: address.clone(),
        })?;
    decode_contact_state(address, blob, limits)
}

fn encode_contact_state(
    address: &ProtocolStateAddress,
    contact: &ContactState,
    limits: ProtocolHardeningLimits,
) -> Result<ProtocolStateBlob, ProtocolStateError> {
    let wire = ContactStateWire {
        version: CONTACT_STATE_WIRE_VERSION,
        identity_x25519_public_key: contact.identity.identity_key.x25519_public_key,
        identity_ed25519_verifying_key: contact.identity.identity_key.ed25519_verifying_key,
        discovery_x25519_public_key: contact.identity.discovery_key.x25519_public_key,
        discovery_ed25519_verifying_key: contact.identity.discovery_key.ed25519_verifying_key,
        discovery_epoch: contact.identity.discovery_key.epoch,
        discovery_created_at_secs: contact.identity.discovery_key.created_at_secs,
        discovery_identity_signature: &contact.identity.discovery_key.identity_signature,
        trust_state: contact.trust_state,
        blocked: contact.blocked,
    };
    let payload =
        Zeroizing::new(
            postcard::to_stdvec(&wire).map_err(|_| ProtocolStateError::BlobEncode {
                address: address.clone(),
                reason: "contact state failed to encode".into(),
            })?,
        );
    if payload.len() + PROTOCOL_STATE_BLOB_HEADER_LEN > limits.max_protocol_state_blob_len {
        return Err(ProtocolStateError::BlobEncode {
            address: address.clone(),
            reason: format!(
                "contact-state blob length {} exceeds limit {}",
                payload.len() + PROTOCOL_STATE_BLOB_HEADER_LEN,
                limits.max_protocol_state_blob_len
            ),
        });
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        PROTOCOL_STATE_BLOB_HEADER_LEN + payload.len(),
    ));
    bytes.push(CURRENT_PROTOCOL_STATE_BLOB_MAJOR);
    bytes.push(CURRENT_PROTOCOL_STATE_BLOB_MINOR);
    bytes.extend_from_slice(&payload);
    Ok(ProtocolStateBlob::from_zeroizing(bytes))
}

fn decode_contact_state(
    address: &ProtocolStateAddress,
    blob: &ProtocolStateBlob,
    limits: ProtocolHardeningLimits,
) -> Result<ContactState, ProtocolStateError> {
    let bytes = blob.as_bytes();
    if bytes.len() > limits.max_protocol_state_blob_len {
        return Err(ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: format!("contact-state blob length exceeds limit: {}", bytes.len()),
        });
    }
    let (major, minor) =
        read_blob_version(bytes).ok_or_else(|| ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: "contact-state blob header is incomplete".into(),
        })?;
    let payload = &bytes[PROTOCOL_STATE_BLOB_HEADER_LEN..];

    if major == CURRENT_PROTOCOL_STATE_BLOB_MAJOR && minor == CURRENT_PROTOCOL_STATE_BLOB_MINOR {
        return decode_contact_state_payload(address, payload);
    }

    Err(ProtocolStateError::UnsupportedBlobVersion {
        address: address.clone(),
        major,
        minor,
    })
}

fn decode_contact_state_payload(
    address: &ProtocolStateAddress,
    payload: &[u8],
) -> Result<ContactState, ProtocolStateError> {
    let (wire, trailing): (DecodedContactStateWireV2, &[u8]) =
        postcard::take_from_bytes(payload).map_err(|_| ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: "contact-state payload failed to decode".into(),
        })?;
    if !trailing.is_empty() || wire.version != CONTACT_STATE_WIRE_VERSION {
        return Err(ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: "contact-state payload version is unsupported".into(),
        });
    }
    decoded_contact_state(address, wire)
}

fn decoded_contact_state(
    address: &ProtocolStateAddress,
    wire: DecodedContactStateWireV2,
) -> Result<ContactState, ProtocolStateError> {
    let contact = ContactState {
        identity: ContactIdentity {
            identity_key: ContactIdentityKey {
                x25519_public_key: wire.identity_x25519_public_key,
                ed25519_verifying_key: wire.identity_ed25519_verifying_key,
            },
            discovery_key: ContactDiscoveryKey {
                x25519_public_key: wire.discovery_x25519_public_key,
                ed25519_verifying_key: wire.discovery_ed25519_verifying_key,
                epoch: wire.discovery_epoch,
                created_at_secs: wire.discovery_created_at_secs,
                identity_signature: wire.discovery_identity_signature.try_into().map_err(|_| {
                    ProtocolStateError::BlobDecode {
                        address: address.clone(),
                        reason: "contact discovery key signature length is invalid".into(),
                    }
                })?,
            },
        },
        trust_state: wire.trust_state,
        blocked: wire.blocked,
    };
    validate_decoded_contact_state(address, &contact)?;
    Ok(contact)
}

fn validate_decoded_contact_state(
    address: &ProtocolStateAddress,
    contact: &ContactState,
) -> Result<(), ProtocolStateError> {
    let expected_key = contact.identity.identity_key.canonical_encoding();
    if address.key().as_bytes().ct_eq(&expected_key).unwrap_u8() != 1 {
        return Err(ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: "contact identity key does not match address".into(),
        });
    }
    validate_contact_identity_for_decode(address, &contact.identity)
}

fn validate_contact_identity_for_decode(
    address: &ProtocolStateAddress,
    contact_identity: &ContactIdentity,
) -> Result<(), ProtocolStateError> {
    if !contact_identity_key_is_valid(&contact_identity.identity_key) {
        return Err(ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: "contact identity key is invalid".into(),
        });
    }
    let Some(bundle) = contact_public_discovery_key(&contact_identity.discovery_key) else {
        return Err(ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: "contact discovery key is invalid".into(),
        });
    };
    let identity_verifying_key =
        parse_ed25519_verifying_key_bytes(&contact_identity.identity_key.ed25519_verifying_key)
            .ok_or_else(|| ProtocolStateError::BlobDecode {
                address: address.clone(),
                reason: "contact identity key is invalid".into(),
            })?;
    verify_public_discovery_key(&bundle, &identity_verifying_key).map_err(|_| {
        ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: "contact discovery key signature failed".into(),
        }
    })
}

fn validate_contact_identity_key(
    address: &ProtocolStateAddress,
    identity_key: &ContactIdentityKey,
) -> Result<(), ProtocolStateError> {
    if contact_identity_key_is_valid(identity_key) {
        Ok(())
    } else {
        Err(ProtocolStateError::InvalidStateBinding {
            address: address.clone(),
            reason: "contact identity key is invalid".into(),
        })
    }
}

fn validate_session_contact_identity_key(
    address: &ProtocolStateAddress,
    identity_key: ContactIdentityKey,
) -> Result<ContactIdentityKey, ProtocolStateError> {
    if contact_identity_key_is_valid(&identity_key) {
        Ok(identity_key)
    } else {
        Err(ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: "session contact identity key is invalid".into(),
        })
    }
}

fn session_contact_identity_key(
    address: &ProtocolStateAddress,
    session: &LoadedSessionState,
    requested: ContactIdentityKey,
) -> Result<ContactIdentityKey, ProtocolStateError> {
    match session.contact_identity_key {
        Some(existing) if !contact_identity_keys_match(&existing, &requested) => {
            Err(ProtocolStateError::InvalidStateBinding {
                address: address.clone(),
                reason: "session contact identity key is already bound".into(),
            })
        }
        Some(existing) => Ok(existing),
        None => Ok(requested),
    }
}

fn validate_contact_identity(
    address: &ProtocolStateAddress,
    contact_identity: &ContactIdentity,
) -> Result<(), ProtocolStateError> {
    validate_contact_identity_key(address, &contact_identity.identity_key)?;
    let Some(bundle) = contact_public_discovery_key(&contact_identity.discovery_key) else {
        return Err(ProtocolStateError::InvalidStateBinding {
            address: address.clone(),
            reason: "contact discovery key is invalid".into(),
        });
    };
    let identity_verifying_key =
        parse_ed25519_verifying_key_bytes(&contact_identity.identity_key.ed25519_verifying_key)
            .ok_or_else(|| ProtocolStateError::InvalidStateBinding {
                address: address.clone(),
                reason: "contact identity key is invalid".into(),
            })?;
    verify_public_discovery_key(&bundle, &identity_verifying_key).map_err(|_| {
        ProtocolStateError::InvalidStateBinding {
            address: address.clone(),
            reason: "contact discovery key signature failed".into(),
        }
    })
}

fn contact_identity_key_is_valid(identity_key: &ContactIdentityKey) -> bool {
    identity_key_is_valid(identity_key)
}

fn contact_public_discovery_key(discovery_key: &ContactDiscoveryKey) -> Option<PublicDiscoveryKey> {
    if !is_valid_x25519_public_key(&discovery_key.x25519_public_key) {
        return None;
    }
    Some(PublicDiscoveryKey {
        public_key: PublicKey::from(discovery_key.x25519_public_key),
        verifying_key: parse_ed25519_verifying_key_bytes(&discovery_key.ed25519_verifying_key)?,
        epoch: discovery_key.epoch,
        created_at_secs: discovery_key.created_at_secs,
        signature: Signature::from_bytes(&discovery_key.identity_signature),
    })
}

fn contact_discovery_key_is_newer(
    current: &ContactDiscoveryKey,
    candidate: &ContactDiscoveryKey,
) -> bool {
    (candidate.created_at_secs, candidate.epoch) > (current.created_at_secs, current.epoch)
}

fn ensure_contact_allows_outbound(
    snapshot: &ProtocolStateSnapshot,
    identity_key: ContactIdentityKey,
    recipient_public_key: &[u8; PUBLIC_KEY_LEN],
    limits: ProtocolHardeningLimits,
) -> Result<(), ProtocolStateError> {
    let address = contact_address(identity_key);
    validate_contact_identity_key(&address, &identity_key)?;
    let contact = load_contact_state(snapshot, &address, limits)?;
    if contact.blocked {
        return Err(ProtocolStateError::BlockedContact);
    }
    if contact.trust_state == ContactTrustState::Pending {
        return Err(ProtocolStateError::ContactNotAccepted);
    }
    if recipient_public_key
        .ct_eq(&contact.identity.discovery_key.prekey_bundle_lookup_key())
        .unwrap_u8()
        != 1
    {
        return Err(ProtocolStateError::InvalidStateBinding {
            address,
            reason: "contact discovery key does not match outbound recipient".into(),
        });
    }
    Ok(())
}

fn inbound_contact_identity_key(
    validation: InboundSenderCertificateValidation<'_>,
    certificate_grace: Duration,
    sender_identity: &SenderIdentityMaterial,
    session_contact_identity_key: Option<ContactIdentityKey>,
    limits: ProtocolHardeningLimits,
) -> Result<ContactIdentityKey, ProtocolStateError> {
    if sender_identity.certificate.len() > limits.max_sender_certificate_len {
        return Err(ProtocolStateError::InvalidMessage {
            reason: format!(
                "sender certificate length exceeds limit: {}",
                sender_identity.certificate.len()
            ),
        });
    }
    if sender_identity.signature.len() > limits.max_sender_signature_len {
        return Err(ProtocolStateError::InvalidMessage {
            reason: format!(
                "sender signature length exceeds limit: {}",
                sender_identity.signature.len()
            ),
        });
    }
    let validated = validate_sender_certificate(SenderCertificateValidationInput {
        certificate: &sender_identity.certificate,
        signature: &sender_identity.signature,
        domain_signing_keys: validation.domain_signing_keys,
        expected_relay_domain: validation.expected_relay_domain,
        revocation_state: validation.revocation_state,
        reference_time: validation.reference_time,
        grace_window: certificate_grace,
    })
    .map_err(ProtocolStateError::SenderCertificateValidation)?;
    if validated
        .identity_key
        .x25519_public_key
        .ct_eq(&sender_identity.identity_key)
        .unwrap_u8()
        != 1
        || validated
            .identity_key
            .ed25519_verifying_key
            .ct_eq(&sender_identity.identity_verifying_key)
            .unwrap_u8()
            != 1
    {
        return Err(ProtocolStateError::InvalidMessage {
            reason: "sender certificate identity key does not match sealed sender".into(),
        });
    }
    let identity_key = ContactIdentityKey {
        x25519_public_key: validated.identity_key.x25519_public_key,
        ed25519_verifying_key: validated.identity_key.ed25519_verifying_key,
    };
    if let Some(bound_identity_key) = session_contact_identity_key
        && !contact_identity_keys_match(&bound_identity_key, &identity_key)
    {
        return Err(ProtocolStateError::InvalidMessage {
            reason: "sender certificate identity key does not match session contact".into(),
        });
    }
    Ok(identity_key)
}

fn contact_is_blocked(
    snapshot: &ProtocolStateSnapshot,
    identity_key: ContactIdentityKey,
    limits: ProtocolHardeningLimits,
) -> Result<bool, ProtocolStateError> {
    let address = contact_address(identity_key);
    validate_contact_identity_key(&address, &identity_key)?;
    snapshot
        .get(&address)
        .map(|blob| decode_contact_state(&address, blob, limits).map(|contact| contact.blocked))
        .transpose()
        .map(|blocked| blocked.unwrap_or(false))
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

fn deduplication_digest(
    digest_key: &[u8; DEDUPLICATION_KEY_LEN],
    transport_binding_bytes: &[u8],
    encoded_message: &[u8],
) -> [u8; DEDUPLICATION_DIGEST_LEN] {
    let mut hasher = blake3::Hasher::new_keyed(digest_key);
    hasher.update(&(transport_binding_bytes.len() as u32).to_be_bytes());
    hasher.update(transport_binding_bytes);
    hasher.update(encoded_message);
    let hash = hasher.finalize();
    let mut digest = [0u8; DEDUPLICATION_DIGEST_LEN];
    digest.copy_from_slice(&hash.as_bytes()[..DEDUPLICATION_DIGEST_LEN]);
    digest
}

fn contains_digest(
    digests: &[[u8; DEDUPLICATION_DIGEST_LEN]],
    digest: &[u8; DEDUPLICATION_DIGEST_LEN],
) -> bool {
    let mut found = Choice::from(0);
    for candidate in digests {
        found |= candidate.ct_eq(digest);
    }
    bool::from(found)
}

fn record_deduplication_digest(
    state: &mut LoadedDeduplicationSet,
    digest: [u8; DEDUPLICATION_DIGEST_LEN],
) {
    if state.digests.len() == state.capacity {
        state.digests.remove(0);
    }
    state.digests.push(digest);
}

fn record_pending_acknowledgment(
    address: &ProtocolStateAddress,
    state: &mut LoadedPendingAcknowledgments,
    message_id: MessageId,
    first_sent_at_millis: u64,
    message: &Message,
    limits: ProtocolHardeningLimits,
) -> Result<(), ProtocolStateError> {
    let message_id_bytes = *message_id.as_bytes();
    if !state.pending.contains_key(&message_id_bytes)
        && state.pending.len() == limits.max_pending_acknowledgments
    {
        return Err(ProtocolStateError::InvalidStateBinding {
            address: address.clone(),
            reason: "pending-acknowledgment count reached limit".into(),
        });
    }
    let encoded_message = message
        .to_bytes_with_hardening_limits(limits)
        .map_err(ProtocolStateError::MessageEncode)?;
    state.pending.insert(
        message_id_bytes,
        LoadedPendingAcknowledgment {
            message: copy_message(message),
            encoded_message,
            first_sent_at_millis,
            last_retried_at_millis: None,
        },
    );
    Ok(())
}

fn acknowledgment_digest(
    transport_binding_bytes: &[u8],
    encoded_message: &[u8],
) -> [u8; ACKNOWLEDGMENT_DIGEST_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(transport_binding_bytes.len() as u32).to_be_bytes());
    hasher.update(transport_binding_bytes);
    hasher.update(encoded_message);
    let hash = hasher.finalize();
    let mut digest = [0u8; ACKNOWLEDGMENT_DIGEST_LEN];
    digest.copy_from_slice(&hash.as_bytes()[..ACKNOWLEDGMENT_DIGEST_LEN]);
    digest
}

fn contains_acknowledgment_digest(
    digests: &[[u8; ACKNOWLEDGMENT_DIGEST_LEN]],
    digest: &[u8; ACKNOWLEDGMENT_DIGEST_LEN],
) -> bool {
    let mut found = Choice::from(0);
    for candidate in digests {
        found |= candidate.ct_eq(digest);
    }
    bool::from(found)
}

fn record_acknowledgment_digest(
    state: &mut LoadedPendingAcknowledgments,
    digest: [u8; ACKNOWLEDGMENT_DIGEST_LEN],
    limits: ProtocolHardeningLimits,
) {
    if state.acknowledgment_digests.len() == limits.max_acknowledgment_digests {
        state.acknowledgment_digests.remove(0);
    }
    state.acknowledgment_digests.push(digest);
}

fn encode_ratcheted_payload(header: &Header, ciphertext: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(RATCHET_PAYLOAD_HEADER_LEN + ciphertext.len());
    payload.push(RATCHET_PAYLOAD_VERSION);
    payload.extend_from_slice(header.public_key.as_bytes());
    payload.extend_from_slice(&header.previous_chain_length.to_be_bytes());
    payload.extend_from_slice(&header.message_number.to_be_bytes());
    payload.extend_from_slice(ciphertext);
    payload
}

fn decode_ratcheted_payload(payload: &[u8]) -> Result<(Header, &[u8]), ProtocolStateError> {
    if payload.len() < RATCHET_PAYLOAD_HEADER_LEN {
        return Err(ProtocolStateError::InvalidMessage {
            reason: "ratcheted payload is too short".into(),
        });
    }
    let version = payload[0];
    if version != RATCHET_PAYLOAD_VERSION {
        return Err(ProtocolStateError::InvalidMessage {
            reason: format!("unsupported ratcheted payload version: {version}"),
        });
    }

    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&payload[1..33]);
    let mut previous_chain_length = [0u8; 4];
    previous_chain_length.copy_from_slice(&payload[33..37]);
    let mut message_number = [0u8; 4];
    message_number.copy_from_slice(&payload[37..41]);

    Ok((
        Header {
            public_key: PublicKey::from(public_key),
            previous_chain_length: u32::from_be_bytes(previous_chain_length),
            message_number: u32::from_be_bytes(message_number),
        },
        &payload[RATCHET_PAYLOAD_HEADER_LEN..],
    ))
}

fn encode_message_frame_plaintext(
    id: MessageId,
    sent_at_millis: u64,
    payload_kind: PayloadKind,
    ratcheted_payload: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ProtocolStateError> {
    Ok(Zeroizing::new(
        postcard::to_stdvec(&MessageFramePlaintextWire {
            version: MESSAGE_FRAME_PLAINTEXT_WIRE_VERSION,
            id: *id.as_bytes(),
            sent_at_millis,
            payload_kind: payload_kind.tag(),
            ratcheted_payload,
        })
        .map_err(|_| ProtocolStateError::InvalidMessage {
            reason: "message frame plaintext failed to encode".into(),
        })?,
    ))
}

fn decode_message_frame_plaintext(
    bytes: &[u8],
) -> Result<DecodedMessageFramePlaintext, ProtocolStateError> {
    let (wire, trailing): (DecodedMessageFramePlaintextWire, &[u8]) =
        postcard::take_from_bytes(bytes).map_err(|_| ProtocolStateError::InvalidMessage {
            reason: "message frame plaintext failed to decode".into(),
        })?;
    if !trailing.is_empty() {
        return Err(ProtocolStateError::InvalidMessage {
            reason: "message frame plaintext has trailing bytes".into(),
        });
    }
    if wire.version != MESSAGE_FRAME_PLAINTEXT_WIRE_VERSION {
        return Err(ProtocolStateError::InvalidMessage {
            reason: format!(
                "unsupported message frame plaintext version: {}",
                wire.version
            ),
        });
    }
    let payload_kind = PayloadKind::from_tag(wire.payload_kind).map_err(|_| {
        ProtocolStateError::InvalidMessage {
            reason: format!("unsupported message payload kind: {}", wire.payload_kind),
        }
    })?;
    Ok(DecodedMessageFramePlaintext {
        id: MessageId::from_bytes(wire.id),
        sent_at_millis: wire.sent_at_millis,
        payload_kind,
        ratcheted_payload: wire.ratcheted_payload,
    })
}

#[derive(Serialize)]
struct SealedSenderEnvelopeWire<'a> {
    version: u8,
    sender_identity_key: [u8; 32],
    sender_identity_verifying_key: [u8; 32],
    sender_identity_binding_signature: &'a [u8],
    sender_certificate: &'a [u8],
    sender_signature: &'a [u8],
    transcript_signature: &'a [u8],
    padded_plaintext: &'a [u8],
}

#[derive(Deserialize)]
struct DecodedSealedSenderEnvelopeWire {
    version: u8,
    sender_identity_key: [u8; 32],
    sender_identity_verifying_key: [u8; 32],
    sender_identity_binding_signature: Vec<u8>,
    sender_certificate: Vec<u8>,
    sender_signature: Vec<u8>,
    transcript_signature: Vec<u8>,
    padded_plaintext: Vec<u8>,
}

struct DecodedSealedSenderEnvelope {
    sender_identity: SenderIdentityMaterial,
    transcript_signature: Vec<u8>,
    padded_plaintext: Zeroizing<Vec<u8>>,
    plaintext: Zeroizing<Vec<u8>>,
}

fn sign_message_transcript(
    signing_key: &SigningKeyPair,
    input: MessageTranscriptInput<'_>,
) -> Result<Signature, ProtocolStateError> {
    let transcript = message_transcript(input).map_err(|_| ProtocolStateError::InvalidMessage {
        reason: "message transcript input exceeds limit".into(),
    })?;
    Ok(signing_key.sign_with_context(MESSAGE_TRANSCRIPT_CONTEXT, &transcript)?)
}

fn verify_message_transcript(
    sender_identity: &SenderIdentityMaterial,
    input: MessageTranscriptInput<'_>,
    signature: &[u8],
) -> Result<(), ProtocolStateError> {
    validate_transcript_signature(signature)?;
    let signature_bytes: [u8; TRANSCRIPT_SIGNATURE_LEN] =
        signature
            .try_into()
            .map_err(|_| ProtocolStateError::InvalidMessage {
                reason: "message transcript signature length is invalid".into(),
            })?;
    let signature = Signature::from_bytes(&signature_bytes);
    let verifying_key = parse_ed25519_verifying_key_bytes(&sender_identity.identity_verifying_key)
        .ok_or_else(|| ProtocolStateError::InvalidMessage {
            reason: "sender identity verifying key is invalid".into(),
        })?;
    let transcript = message_transcript(input).map_err(|_| ProtocolStateError::InvalidMessage {
        reason: "message transcript input exceeds limit".into(),
    })?;
    verify_with_context(
        &verifying_key,
        MESSAGE_TRANSCRIPT_CONTEXT,
        &transcript,
        &signature,
    )
    .map_err(ProtocolStateError::from)
}

fn encode_validated_sealed_sender_envelope(
    sender_identity: &SenderIdentityMaterial,
    transcript_signature: &[u8],
    padded_plaintext: &[u8],
    limits: ProtocolHardeningLimits,
) -> Result<Zeroizing<Vec<u8>>, ProtocolStateError> {
    validate_transcript_signature(transcript_signature)?;
    validate_sealed_sender_content_len(
        sender_identity,
        transcript_signature,
        padded_plaintext,
        limits,
    )?;
    let sealed = Zeroizing::new(
        postcard::to_stdvec(&SealedSenderEnvelopeWire {
            version: SEALED_SENDER_ENVELOPE_VERSION,
            sender_identity_key: sender_identity.identity_key,
            sender_identity_verifying_key: sender_identity.identity_verifying_key,
            sender_identity_binding_signature: &sender_identity.identity_binding_signature,
            sender_certificate: &sender_identity.certificate,
            sender_signature: &sender_identity.signature,
            transcript_signature,
            padded_plaintext,
        })
        .map_err(|_| ProtocolStateError::InvalidMessage {
            reason: "sealed-sender envelope failed to encode".into(),
        })?,
    );
    if sealed.len() > max_sealed_sender_envelope_len(limits) {
        return Err(ProtocolStateError::InvalidMessage {
            reason: format!(
                "sealed-sender envelope length exceeds limit: {}",
                sealed.len()
            ),
        });
    }
    Ok(sealed)
}

fn decode_sealed_sender_envelope(
    bytes: &[u8],
    limits: ProtocolHardeningLimits,
) -> Result<DecodedSealedSenderEnvelope, ProtocolStateError> {
    let (wire, trailing): (DecodedSealedSenderEnvelopeWire, &[u8]) =
        postcard::take_from_bytes(bytes).map_err(|_| ProtocolStateError::InvalidMessage {
            reason: "sealed-sender envelope failed to decode".into(),
        })?;
    let padded_plaintext = Zeroizing::new(wire.padded_plaintext);
    let sender_identity = SenderIdentityMaterial {
        identity_key: wire.sender_identity_key,
        identity_verifying_key: wire.sender_identity_verifying_key,
        identity_binding_signature: wire.sender_identity_binding_signature,
        certificate: wire.sender_certificate,
        signature: wire.sender_signature,
    };
    if !trailing.is_empty() {
        return Err(ProtocolStateError::InvalidMessage {
            reason: "sealed-sender envelope has trailing bytes".into(),
        });
    }
    if wire.version != SEALED_SENDER_ENVELOPE_VERSION {
        return Err(ProtocolStateError::InvalidMessage {
            reason: format!(
                "unsupported sealed-sender envelope version: {}",
                wire.version
            ),
        });
    }
    validate_sender_identity(&sender_identity, limits)?;
    validate_transcript_signature(&wire.transcript_signature)?;
    validate_sealed_sender_content_len(
        &sender_identity,
        &wire.transcript_signature,
        &padded_plaintext,
        limits,
    )?;
    let plaintext = unpad_sealed_payload(&padded_plaintext)?;
    Ok(DecodedSealedSenderEnvelope {
        sender_identity,
        transcript_signature: wire.transcript_signature,
        padded_plaintext,
        plaintext,
    })
}

fn receive_state_updates(
    snapshot: &ProtocolStateSnapshot,
    address: &ProtocolStateAddress,
    state: &RatchetState,
    contact_identity_key: ContactIdentityKey,
    deduplication_address: &ProtocolStateAddress,
    deduplication: &LoadedDeduplicationSet,
    limits: ProtocolHardeningLimits,
) -> Result<Vec<ProtocolStateUpdate>, ProtocolStateError> {
    let session_update = ProtocolStateUpdate::set(
        address.clone(),
        encode_session_state(
            address,
            state,
            Some(contact_identity_key.x25519_public_key),
            Some(contact_identity_key),
            limits,
        )?,
    )
    .with_snapshot(snapshot);
    let deduplication_update = ProtocolStateUpdate::set(
        deduplication_address.clone(),
        encode_deduplication_set(deduplication_address, deduplication, limits)?,
    )
    .with_snapshot(snapshot);
    Ok(vec![session_update, deduplication_update])
}

struct AcknowledgmentEncryptionInput<'input, 'material> {
    acknowledgment: &'input OutboundAcknowledgment<'material>,
    transport_binding: &'input TransportBinding,
}

fn encrypt_acknowledgment(
    state: &mut RatchetState,
    session_key: &[u8],
    input: AcknowledgmentEncryptionInput<'_, '_>,
    recipient_identity_verifying_key: &[u8; 32],
    acknowledged_message_id: MessageId,
    rng: &mut (impl RngCore + CryptoRng),
    limits: ProtocolHardeningLimits,
) -> Result<Message, ProtocolStateError> {
    let acknowledgment = input.acknowledgment;
    let transport_binding_bytes = input.transport_binding.as_bytes();
    validate_sender_identity(acknowledgment.sender_identity, limits)?;
    let plaintext = encode_acknowledgment_plaintext(acknowledged_message_id)?;
    let padded_plaintext = pad_sealed_payload(&plaintext)?;
    let transcript_signature = sign_message_transcript(
        acknowledgment.sender_identity_signing_key,
        MessageTranscriptInput {
            session_key,
            recipient_identity_verifying_key,
            id: acknowledgment.id,
            sent_at_millis: acknowledgment.sent_at_millis,
            payload_kind: PayloadKind::Acknowledgment,
            payload: &padded_plaintext,
            sender_certificate: &acknowledgment.sender_identity.certificate,
        },
    )?;
    let sealed = encode_validated_sealed_sender_envelope(
        acknowledgment.sender_identity,
        &transcript_signature.to_bytes(),
        &padded_plaintext,
        limits,
    )?;
    let associated_data =
        ratchet_associated_data(session_key, &acknowledgment.recipient_public_key);
    let (header, ciphertext) = state.ratchet_encrypt(&sealed, &associated_data)?;
    let ratcheted_payload = encode_ratcheted_payload(&header, &ciphertext);
    let frame_plaintext = encode_message_frame_plaintext(
        acknowledgment.id,
        acknowledgment.sent_at_millis,
        PayloadKind::Acknowledgment,
        &ratcheted_payload,
    )?;
    let recipient_public_key = PublicKey::from(acknowledgment.recipient_public_key);
    let frame = seal_frame_with_associated_data(
        rng,
        &recipient_public_key,
        None,
        &frame_plaintext,
        transport_binding_bytes,
    )?;
    let message = Message::from_frame(frame);
    message
        .to_bytes_with_hardening_limits(limits)
        .map_err(ProtocolStateError::MessageEncode)?;
    Ok(message)
}

fn encode_acknowledgment_plaintext(
    acknowledged_message_id: MessageId,
) -> Result<Zeroizing<Vec<u8>>, ProtocolStateError> {
    Ok(Zeroizing::new(
        postcard::to_stdvec(&AcknowledgmentPlaintextWire {
            version: ACKNOWLEDGMENT_PLAINTEXT_WIRE_VERSION,
            acknowledged_message_id: *acknowledged_message_id.as_bytes(),
        })
        .map_err(|_| ProtocolStateError::InvalidMessage {
            reason: "acknowledgment plaintext failed to encode".into(),
        })?,
    ))
}

fn decode_acknowledgment_plaintext(bytes: &[u8]) -> Result<MessageId, ProtocolStateError> {
    let (wire, trailing): (DecodedAcknowledgmentPlaintextWire, &[u8]) =
        postcard::take_from_bytes(bytes).map_err(|_| ProtocolStateError::InvalidMessage {
            reason: "acknowledgment plaintext failed to decode".into(),
        })?;
    if !trailing.is_empty() {
        return Err(ProtocolStateError::InvalidMessage {
            reason: "acknowledgment plaintext has trailing bytes".into(),
        });
    }
    if wire.version != ACKNOWLEDGMENT_PLAINTEXT_WIRE_VERSION {
        return Err(ProtocolStateError::InvalidMessage {
            reason: format!(
                "unsupported acknowledgment plaintext version: {}",
                wire.version
            ),
        });
    }
    Ok(MessageId::from_bytes(wire.acknowledged_message_id))
}

fn validate_sender_identity(
    sender_identity: &SenderIdentityMaterial,
    limits: ProtocolHardeningLimits,
) -> Result<(), ProtocolStateError> {
    let bundle = PublicIdentityKey::from_bytes(
        &sender_identity.identity_key,
        &sender_identity.identity_verifying_key,
        &sender_identity.identity_binding_signature,
    )
    .map_err(|_| ProtocolStateError::InvalidMessage {
        reason: "sender public identity key encoding is invalid".into(),
    })?;
    verify_public_identity_key(&bundle).map_err(|_| ProtocolStateError::InvalidMessage {
        reason: "sender identity key binding signature failed".into(),
    })?;
    if sender_identity.certificate.len() > limits.max_sender_certificate_len {
        return Err(ProtocolStateError::InvalidMessage {
            reason: format!(
                "sender certificate length exceeds limit: {}",
                sender_identity.certificate.len()
            ),
        });
    }
    if sender_identity.signature.len() > limits.max_sender_signature_len {
        return Err(ProtocolStateError::InvalidMessage {
            reason: format!(
                "sender signature length exceeds limit: {}",
                sender_identity.signature.len()
            ),
        });
    }
    Ok(())
}

fn validate_transcript_signature(signature: &[u8]) -> Result<(), ProtocolStateError> {
    if signature.len() != TRANSCRIPT_SIGNATURE_LEN {
        return Err(ProtocolStateError::InvalidMessage {
            reason: "message transcript signature length is invalid".into(),
        });
    }
    Ok(())
}

fn validate_sealed_sender_content_len(
    sender_identity: &SenderIdentityMaterial,
    transcript_signature: &[u8],
    padded_plaintext: &[u8],
    limits: ProtocolHardeningLimits,
) -> Result<(), ProtocolStateError> {
    let len = sender_identity
        .certificate
        .len()
        .checked_add(sender_identity.identity_binding_signature.len())
        .and_then(|len| len.checked_add(sender_identity.signature.len()))
        .and_then(|len| len.checked_add(transcript_signature.len()))
        .and_then(|len| len.checked_add(padded_plaintext.len()))
        .ok_or_else(|| ProtocolStateError::InvalidMessage {
            reason: "sealed-sender content length overflowed".into(),
        })?;
    if len > max_sealed_sender_content_len(limits) {
        return Err(ProtocolStateError::InvalidMessage {
            reason: format!("sealed-sender content length exceeds limit: {len}"),
        });
    }
    Ok(())
}

fn max_sealed_sender_envelope_len(limits: ProtocolHardeningLimits) -> usize {
    limits
        .max_message_payload_len
        .saturating_sub(RATCHET_PAYLOAD_HEADER_LEN + RATCHET_AEAD_TAG_LEN)
}

fn max_sealed_sender_content_len(limits: ProtocolHardeningLimits) -> usize {
    max_sealed_sender_envelope_len(limits).saturating_sub(32 + SEALED_SENDER_ENCODING_OVERHEAD_CAP)
}

fn pad_sealed_payload(plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>, ProtocolStateError> {
    pad_message_payload(plaintext).map_err(|error| ProtocolStateError::InvalidMessage {
        reason: error.to_string(),
    })
}

pub(crate) fn unpad_sealed_payload(
    padded: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ProtocolStateError> {
    unpad_message_payload(padded).map_err(|error| ProtocolStateError::InvalidMessage {
        reason: error.to_string(),
    })
}

fn sender_identity_key_matches(expected: &[u8; 32], actual: &[u8; 32]) -> bool {
    expected.ct_eq(actual).into()
}

fn copy_message(message: &Message) -> Message {
    Message {
        version: message.version,
        recipient_public_key: message.recipient_public_key,
        prekey_reference: message.prekey_reference,
        ephemeral_public_key: message.ephemeral_public_key,
        ciphertext: message.ciphertext.clone(),
    }
}

fn ratchet_associated_data(session_key: &[u8], recipient_public_key: &[u8; 32]) -> Vec<u8> {
    let mut associated_data = Vec::with_capacity(32 + session_key.len());
    associated_data.extend_from_slice(b"AetherRatchetedPayload-v1:");
    associated_data.extend_from_slice(&(session_key.len() as u32).to_be_bytes());
    associated_data.extend_from_slice(session_key);
    associated_data.extend_from_slice(recipient_public_key);
    associated_data
}

fn write_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(f, "{byte:02x}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        CURRENT_PROTOCOL_STATE_BLOB_MAJOR, CURRENT_PROTOCOL_STATE_BLOB_MINOR,
        DEDUPLICATION_DIGEST_LEN, DEDUPLICATION_KEY_LEN, LoadedDeduplicationSet,
        MIN_DEDUPLICATION_CAPACITY, MessageTranscriptInput, PayloadKind, ProtocolHardeningLimits,
        ProtocolStateError, SEALED_PAYLOAD_BUCKETS, SEALED_PAYLOAD_LEN_PREFIX_LEN,
        SESSION_STATE_WIRE_VERSION, SessionStateWire, SessionStatusWire, acknowledgment_digest,
        contains_digest, decode_session_state, deduplication_digest, pad_sealed_payload,
        protocol_state_blob_digest, record_deduplication_digest, sign_message_transcript,
        unpad_sealed_payload, verify_message_transcript,
    };
    use crate::{
        MessageId, ProtocolStateAddress, ProtocolStateBlob, ProtocolStateKey, ProtocolStateKind,
        SenderIdentityMaterial, SessionId,
    };
    use roost_crypto::{KeyPair, SigningKeyPair, sign_identity_key_binding};
    use roost_protocol::SignatureError;
    use zeroize::Zeroizing;

    #[test]
    fn non_current_session_blob_versions_are_faults() {
        let address = ProtocolStateAddress::new(
            ProtocolStateKind::RatchetSession,
            ProtocolStateKey::session(SessionId::from_bytes([9; 16])),
        );
        for (major, minor) in [(2, 0), (0, 1), (1, 1)] {
            let blob = ProtocolStateBlob::from_bytes(vec![major, minor, 0xaa]);
            assert!(matches!(
                decode_session_state(&address, &blob, ProtocolHardeningLimits::default()),
                Err(ProtocolStateError::UnsupportedBlobVersion {
                    address: actual, major: actual_major, minor: actual_minor,
                }) if actual == address && actual_major == major && actual_minor == minor
            ));
        }
    }

    #[test]
    fn nested_ratchet_decode_failure_does_not_echo_state_bytes() {
        let address = ProtocolStateAddress::new(
            ProtocolStateKind::RatchetSession,
            ProtocolStateKey::session(SessionId::from_bytes([9; 16])),
        );
        let mut bytes = vec![
            CURRENT_PROTOCOL_STATE_BLOB_MAJOR,
            CURRENT_PROTOCOL_STATE_BLOB_MINOR,
        ];
        bytes.extend(
            postcard::to_stdvec(&SessionStateWire {
                version: SESSION_STATE_WIRE_VERSION,
                status: SessionStatusWire::ContactUnbound {
                    ratchet_state: &[0x42],
                },
                peer_sender_identity_key: None,
            })
            .unwrap(),
        );
        let blob = ProtocolStateBlob::from_bytes(bytes);
        let Err(error) = decode_session_state(&address, &blob, ProtocolHardeningLimits::default())
        else {
            panic!("malformed nested ratchet state decoded");
        };
        let rendered = error.to_string();
        assert!(
            matches!(error, ProtocolStateError::BlobDecode { address: actual, reason }
            if actual == address && reason == "ratchet/session state failed to decode")
        );
        assert!(!rendered.contains("66"));
        assert!(!rendered.contains("0x42"));
    }

    #[test]
    fn same_encrypted_bytes_under_different_deduplication_keys_have_different_digests() {
        let encoded_message = b"encoded encrypted message";
        let first_key = [1u8; DEDUPLICATION_KEY_LEN];
        let second_key = [2u8; DEDUPLICATION_KEY_LEN];

        let first = deduplication_digest(&first_key, &[], encoded_message);
        let second = deduplication_digest(&second_key, &[], encoded_message);

        assert_ne!(first, second);
    }

    #[test]
    fn same_encrypted_bytes_under_different_transport_bindings_have_different_digests() {
        let encoded_message = b"encoded encrypted message";
        let digest_key = [1u8; DEDUPLICATION_KEY_LEN];

        let first = deduplication_digest(&digest_key, b"transport-binding:first", encoded_message);
        let second =
            deduplication_digest(&digest_key, b"transport-binding:second", encoded_message);

        assert_ne!(first, second);
    }

    #[test]
    fn different_encrypted_bytes_under_the_same_key_and_binding_have_different_digests() {
        let digest_key = [1u8; DEDUPLICATION_KEY_LEN];

        let first = deduplication_digest(&digest_key, b"transport-binding", b"first message");
        let second = deduplication_digest(&digest_key, b"transport-binding", b"second message");

        assert_ne!(first, second);
    }

    #[test]
    fn acknowledgment_digest_changes_with_each_input() {
        let expected = acknowledgment_digest(b"transport-binding", b"encoded message");

        assert_ne!(
            acknowledgment_digest(b"other-binding", b"encoded message"),
            expected
        );
        assert_ne!(
            acknowledgment_digest(b"transport-binding", b"other message"),
            expected
        );
    }

    #[test]
    fn protocol_state_blob_digest_changes_with_the_blob() {
        assert_ne!(
            protocol_state_blob_digest(b"first blob"),
            protocol_state_blob_digest(b"second blob")
        );
    }

    #[test]
    fn record_deduplication_digest_evicts_oldest_digest_first() {
        let mut state = LoadedDeduplicationSet {
            capacity: MIN_DEDUPLICATION_CAPACITY,
            digest_key: Zeroizing::new([7u8; DEDUPLICATION_KEY_LEN]),
            digests: Vec::new(),
        };
        let oldest = [0u8; DEDUPLICATION_DIGEST_LEN];
        record_deduplication_digest(&mut state, oldest);
        for tag in 1..MIN_DEDUPLICATION_CAPACITY {
            record_deduplication_digest(&mut state, [tag as u8; DEDUPLICATION_DIGEST_LEN]);
        }
        let newest = [0xff; DEDUPLICATION_DIGEST_LEN];

        record_deduplication_digest(&mut state, newest);

        assert_eq!(state.digests.len(), MIN_DEDUPLICATION_CAPACITY);
        assert!(!contains_digest(&state.digests, &oldest));
        assert!(contains_digest(&state.digests, &newest));
    }

    #[test]
    fn contains_digest_reports_membership_without_short_circuit_result_changes() {
        let first = [1u8; DEDUPLICATION_DIGEST_LEN];
        let second = [2u8; DEDUPLICATION_DIGEST_LEN];
        let missing = [3u8; DEDUPLICATION_DIGEST_LEN];
        let digests = vec![first, second];

        assert!(contains_digest(&digests, &first));
        assert!(contains_digest(&digests, &second));
        assert!(!contains_digest(&digests, &missing));
    }

    #[test]
    fn sealed_payload_padding_unpads_each_bucket() {
        for bucket in SEALED_PAYLOAD_BUCKETS {
            let plaintext = vec![0x42; bucket - SEALED_PAYLOAD_LEN_PREFIX_LEN];

            let padded = pad_sealed_payload(&plaintext).unwrap();
            let unpadded = unpad_sealed_payload(&padded).unwrap();

            assert_eq!(padded.len(), bucket);
            assert_eq!(unpadded.as_slice(), plaintext.as_slice());
        }
    }

    #[test]
    fn sealed_payload_padding_accepts_bucket_boundary_lengths() {
        for bucket in SEALED_PAYLOAD_BUCKETS {
            let plaintext_len = bucket - SEALED_PAYLOAD_LEN_PREFIX_LEN;
            let mut padded = vec![0x41; bucket];
            padded[..SEALED_PAYLOAD_LEN_PREFIX_LEN]
                .copy_from_slice(&(plaintext_len as u32).to_be_bytes());

            let plaintext = unpad_sealed_payload(&padded).unwrap();

            assert_eq!(plaintext.len(), plaintext_len);
            assert!(plaintext.iter().all(|byte| *byte == 0x41));
        }
    }

    #[test]
    fn sealed_payload_padding_rejects_invalid_bucket_lengths() {
        for padded in [
            vec![0u8; SEALED_PAYLOAD_BUCKETS[0] - 1],
            vec![0u8; SEALED_PAYLOAD_BUCKETS[0] + 1],
        ] {
            assert!(matches!(
                unpad_sealed_payload(&padded),
                Err(ProtocolStateError::InvalidMessage { .. })
            ));
        }
    }

    #[test]
    fn sealed_payload_padding_rejects_overlarge_length_prefix() {
        let mut padded = vec![0u8; SEALED_PAYLOAD_BUCKETS[0]];
        let plaintext_len = (SEALED_PAYLOAD_BUCKETS[0] + 1) as u32;
        padded[..SEALED_PAYLOAD_LEN_PREFIX_LEN].copy_from_slice(&plaintext_len.to_be_bytes());

        assert!(matches!(
            unpad_sealed_payload(&padded),
            Err(ProtocolStateError::InvalidMessage { .. })
        ));
    }

    #[test]
    fn sealed_payload_padding_rejects_nonzero_fill() {
        let mut padded = vec![0u8; SEALED_PAYLOAD_BUCKETS[0]];
        let plaintext_len = 1u32;
        padded[..SEALED_PAYLOAD_LEN_PREFIX_LEN].copy_from_slice(&plaintext_len.to_be_bytes());
        padded[SEALED_PAYLOAD_LEN_PREFIX_LEN] = 0xaa;
        padded[SEALED_PAYLOAD_LEN_PREFIX_LEN + 1] = 0x01;

        assert!(matches!(
            unpad_sealed_payload(&padded),
            Err(ProtocolStateError::InvalidMessage { .. })
        ));
    }

    #[test]
    fn message_transcript_signature_rejects_field_transplants() {
        let signing_key = SigningKeyPair::from_signing_bytes([1u8; 32]);
        let identity_key = KeyPair::from_secret_bytes([2u8; 32]);
        let binding_signature =
            sign_identity_key_binding(&signing_key, &identity_key.public).unwrap();
        let sender_identity = SenderIdentityMaterial {
            identity_key: *identity_key.public.as_bytes(),
            identity_verifying_key: signing_key.verifying.to_bytes(),
            identity_binding_signature: binding_signature.to_bytes().to_vec(),
            certificate: b"sender certificate".to_vec(),
            signature: Vec::new(),
        };
        let session_key = [3u8; 16];
        let recipient_identity_verifying_key = [4u8; 32];
        let id = MessageId::from_bytes([5u8; 16]);
        let payload = b"payload";
        let signature = sign_message_transcript(
            &signing_key,
            MessageTranscriptInput {
                session_key: &session_key,
                recipient_identity_verifying_key: &recipient_identity_verifying_key,
                id,
                sent_at_millis: 6,
                payload_kind: PayloadKind::EncryptedText,
                payload,
                sender_certificate: &sender_identity.certificate,
            },
        )
        .unwrap();
        let signature_bytes = signature.to_bytes();

        let valid = || MessageTranscriptInput {
            session_key: &session_key,
            recipient_identity_verifying_key: &recipient_identity_verifying_key,
            id,
            sent_at_millis: 6,
            payload_kind: PayloadKind::EncryptedText,
            payload,
            sender_certificate: &sender_identity.certificate,
        };
        assert!(verify_message_transcript(&sender_identity, valid(), &signature_bytes).is_ok());

        let other_session_key = [7u8; 16];
        let other_recipient_identity_verifying_key = [8u8; 32];
        let other_payload = b"other payload";
        let other_sender_certificate = b"other sender certificate";
        let cases = [
            MessageTranscriptInput {
                session_key: &other_session_key,
                ..valid()
            },
            MessageTranscriptInput {
                recipient_identity_verifying_key: &other_recipient_identity_verifying_key,
                ..valid()
            },
            MessageTranscriptInput {
                id: MessageId::from_bytes([9u8; 16]),
                ..valid()
            },
            MessageTranscriptInput {
                sent_at_millis: 10,
                ..valid()
            },
            MessageTranscriptInput {
                payload_kind: PayloadKind::Acknowledgment,
                ..valid()
            },
            MessageTranscriptInput {
                payload: other_payload,
                ..valid()
            },
            MessageTranscriptInput {
                sender_certificate: other_sender_certificate,
                ..valid()
            },
        ];
        for input in cases {
            assert!(matches!(
                verify_message_transcript(&sender_identity, input, &signature_bytes),
                Err(ProtocolStateError::Signature(
                    SignatureError::SignatureInvalid
                ))
            ));
        }
    }
}
