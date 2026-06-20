//! Public protocol-state blob addressing and stateless operation results.

use crate::contact::{
    ContactDiscoveryKey, ContactEvent, ContactIdentity, ContactIdentityKey,
    ContactSafetyNumberConfirmation, ContactState, ContactStateChange, ContactTrustState,
};
use crate::hardening::{
    DEFAULT_MAX_ACKNOWLEDGMENT_DIGESTS, DEFAULT_MAX_PENDING_ACKNOWLEDGMENTS,
    MAX_DEDUPLICATION_CAPACITY, MIN_DEDUPLICATION_CAPACITY, ProtocolHardeningLimits,
    validate_hardening_limits,
};
use crate::key_encoding::{
    PUBLIC_KEY_LEN, parse_ed25519_verifying_key_bytes, validate_x25519_public_key,
};
use crate::safety_number::{IdentityKey, derive_safety_number, identity_key_is_valid};
use crate::sender_certificate::{
    DomainSigningKey, RevocationState, SenderCertificateValidationError,
    SenderCertificateValidationInput, validate_sender_certificate,
};
use crate::{Message, MessageError, MessageId, PayloadKind};
use aether_crypto::{
    DiscoveryKey, DiscoveryKeyBundle, Header, IdentityKeyBundle, PublicKey, RatchetState,
    SenderIdentityMaterial, Signature, SigningKeyPair, open_frame_for_discovery_key, seal_frame,
    verify_discovery_key_bundle, verify_identity_key_bundle, verify_with_context,
};
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use serde::de::{Error as DeError, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const CURRENT_PROTOCOL_STATE_BLOB_MAJOR: u8 = 1;
const CURRENT_PROTOCOL_STATE_BLOB_MINOR: u8 = 0;
const PROTOCOL_STATE_BLOB_HEADER_LEN: usize = 2;
const SESSION_STATE_WIRE_VERSION: u8 = 1;
const SESSION_STATE_WITH_CONTACT_WIRE_VERSION: u8 = 2;
const SESSION_STATE_UNRECOVERABLE_WIRE_VERSION: u8 = 3;
const DEDUPLICATION_SET_WIRE_VERSION: u8 = 1;
const PENDING_ACKNOWLEDGMENTS_WIRE_VERSION: u8 = 1;
const CONTACT_STATE_WIRE_VERSION: u8 = 2;
const CONTACT_STATE_WIRE_VERSION_V1: u8 = 1;
const ACKNOWLEDGMENT_PLAINTEXT_WIRE_VERSION: u8 = 1;
const MESSAGE_FRAME_PLAINTEXT_WIRE_VERSION: u8 = 1;
const SEALED_PAYLOAD_LEN_PREFIX_LEN: usize = 4;
const SEALED_PAYLOAD_BUCKETS: [usize; 12] = [
    32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16_384, 32_768, 65_536,
];
const DEDUPLICATION_DIGEST_LEN: usize = 16;
const DEDUPLICATION_KEY_LEN: usize = 32;
const ACKNOWLEDGMENT_DIGEST_LEN: usize = 16;
const RATCHET_PAYLOAD_VERSION: u8 = 1;
const RATCHET_PAYLOAD_HEADER_LEN: usize = 1 + 32 + 4 + 4;
const RATCHET_AEAD_TAG_LEN: usize = 16;
const SEALED_SENDER_ENVELOPE_VERSION: u8 = 1;
const MESSAGE_TRANSCRIPT_CONTEXT: &[u8] = b"AetherMessageTranscript-v1:";
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
    ///
    /// # Errors
    /// - [`ProtocolStateError::InvalidStateKey`] if the key is empty or exceeds the key length
    ///   cap.
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
#[non_exhaustive]
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

/// A state update the consumer must commit durably.
pub struct ProtocolStateUpdate {
    address: ProtocolStateAddress,
    blob: Option<ProtocolStateBlob>,
}

impl ProtocolStateUpdate {
    /// Creates an update that stores `blob` at `address`.
    #[must_use]
    pub fn set(address: ProtocolStateAddress, blob: ProtocolStateBlob) -> Self {
        Self {
            address,
            blob: Some(blob),
        }
    }

    /// Creates an update that removes `address`.
    #[must_use]
    pub fn delete(address: ProtocolStateAddress) -> Self {
        Self {
            address,
            blob: None,
        }
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

    /// Stores `blob` at `address`.
    pub fn set(&mut self, address: ProtocolStateAddress, blob: ProtocolStateBlob) {
        self.blobs.insert(address, blob);
    }

    /// Removes the blob stored at `address`.
    pub fn remove(&mut self, address: &ProtocolStateAddress) -> Option<ProtocolStateBlob> {
        self.blobs.remove(address)
    }

    /// Applies one state update.
    pub fn apply(&mut self, update: ProtocolStateUpdate) {
        match update.blob {
            Some(blob) => self.set(update.address, blob),
            None => {
                self.remove(&update.address);
            }
        }
    }

    /// Applies all state updates in order.
    pub fn apply_all<I>(&mut self, updates: I)
    where
        I: IntoIterator<Item = ProtocolStateUpdate>,
    {
        for update in updates {
            self.apply(update);
        }
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
    pub timestamp_millis: u64,
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
    pub timestamp_millis: u64,
}

/// An outbound Message and all advanced protocol-state updates from one operation.
pub struct OutboundMessageResult {
    /// Stable identifier sealed inside the produced Message.
    pub message_id: MessageId,
    /// Sender-observed Unix timestamp sealed inside the produced Message.
    pub timestamp_millis: u64,
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
    /// Caller-supplied revocation input for the sender Identity Key check.
    pub revocation_state: RevocationState<'a>,
    /// Caller-supplied Unix timestamp in seconds used for expiry evaluation.
    pub reference_timestamp_secs: u64,
    /// Caller-supplied grace window in seconds, with no library-imposed ceiling; for the
    /// trade-off, see [`SenderCertificateValidationInput::grace_window_secs`].
    pub grace_window_secs: u64,
}

/// Inbound plaintext and all advanced protocol-state updates from one operation.
pub struct InboundMessageResult {
    /// Message ID recovered after decrypt.
    pub message_id: MessageId,
    /// Sender-observed Unix timestamp recovered after decrypt.
    pub timestamp_millis: u64,
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
}

/// Pending acknowledgment state exposed to the consumer for durable flushing.
pub struct PendingAcknowledgment {
    /// Original outbound Message ID.
    pub message_id: MessageId,
    /// Original outbound Message waiting for an acknowledgment.
    pub message: Message,
    /// First-send Unix timestamp in milliseconds.
    pub first_sent_millis: u64,
    /// Last retry-instruction timestamp in milliseconds, if any.
    pub last_retry_millis: Option<u64>,
}

/// A retry instruction for one still-unacknowledged outbound Message.
pub struct RetryInstruction {
    /// Original outbound Message ID.
    pub message_id: MessageId,
    /// Message the consumer may retransmit.
    pub message: Message,
    /// First-send Unix timestamp in milliseconds.
    pub first_sent_millis: u64,
    /// Previous retry-instruction timestamp in milliseconds, if any.
    pub last_retry_millis: Option<u64>,
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
    pub timestamp_millis: u64,
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
        timestamp_millis: u64,
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
}

impl ProtocolStateEngine {
    /// Creates a stateless protocol-state engine.
    #[must_use]
    pub fn new() -> Self {
        let limits = ProtocolHardeningLimits::default();
        Self {
            limits,
            blocked_contact_acknowledgment_policy: BlockedContactAcknowledgmentPolicy::default(),
        }
    }

    /// Creates a stateless protocol-state engine with caller-selected hardening limits.
    ///
    /// # Errors
    /// - [`ProtocolStateError::InvalidDeduplicationCapacity`] if the deduplication capacity is
    ///   outside the supported range.
    /// - [`ProtocolStateError::InvalidHardeningLimit`] if any other limit is zero or above the
    ///   supported ceiling.
    pub fn with_hardening_limits(
        limits: ProtocolHardeningLimits,
    ) -> Result<Self, ProtocolStateError> {
        validate_hardening_limits(limits)?;
        Ok(Self {
            limits,
            blocked_contact_acknowledgment_policy: BlockedContactAcknowledgmentPolicy::default(),
        })
    }

    /// Returns the hardening limits used by this engine.
    #[must_use]
    pub fn hardening_limits(&self) -> ProtocolHardeningLimits {
        self.limits
    }

    /// Creates a stateless protocol-state engine with a received-message deduplication capacity.
    ///
    /// # Errors
    /// - [`ProtocolStateError::InvalidDeduplicationCapacity`] if `capacity` is outside the
    ///   supported range.
    pub fn with_deduplication_capacity(capacity: usize) -> Result<Self, ProtocolStateError> {
        let limits = ProtocolHardeningLimits {
            deduplication_capacity: capacity,
            ..Default::default()
        };
        Self::with_hardening_limits(limits)
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

    /// Returns an update that initializes an empty deduplication set for a local Identity.
    ///
    /// The consumer must commit the returned blob before receiving encrypted Messages for that
    /// Identity and must keep using the same Protocol State Blob across library restarts.
    ///
    /// # Errors
    /// - [`ProtocolStateError::BlobEncode`] if the deduplication-set blob fails to encode or
    ///   exceeds local caps.
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
    ///
    /// # Errors
    /// - [`ProtocolStateError::BlobEncode`] if the pending-acknowledgment blob fails to encode or
    ///   exceeds local caps.
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
    ///
    /// # Errors
    /// - [`ProtocolStateError::BlobEncode`] if the wrapped state fails to encode or exceeds local
    ///   caps.
    /// - [`ProtocolStateError::Crypto`] if ratchet-state encoding fails.
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
    ///
    /// # Errors
    /// - [`ProtocolStateError::BlobEncode`] if the wrapped state fails to encode or exceeds local
    ///   caps.
    /// - [`ProtocolStateError::Crypto`] if ratchet-state encoding fails.
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
    ///
    /// # Errors
    /// - [`ProtocolStateError::BlobEncode`] if the wrapped state fails to encode or exceeds local
    ///   caps.
    /// - [`ProtocolStateError::Crypto`] if ratchet-state encoding fails.
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
    ///
    /// # Errors
    /// - [`ProtocolStateError::BlobDecode`] if the current-format blob or blob envelope fails to
    ///   decode.
    /// - [`ProtocolStateError::BlobEncode`] if the wrapped state fails to encode or exceeds local
    ///   caps.
    /// - [`ProtocolStateError::Crypto`] if ratchet-state encoding fails.
    /// - [`ProtocolStateError::InvalidStateBinding`] if the session is already bound to a
    ///   different peer sender identity key.
    /// - [`ProtocolStateError::MissingRequiredState`] if no ratchet/session blob is present.
    /// - [`ProtocolStateError::UnsupportedBlobVersion`] if the blob version is not supported.
    pub fn bind_session_state_peer_identity_key(
        &self,
        snapshot: &ProtocolStateSnapshot,
        key: ProtocolStateKey,
        peer_sender_identity_key: [u8; 32],
    ) -> Result<ProtocolStateUpdate, ProtocolStateError> {
        let address = ratchet_address(key);
        let loaded = load_session_state(snapshot, &address, self.limits)?;
        let state = active_session_state(&address, loaded.status)?;
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
        ))
    }

    /// Creates or updates an Identity-key-addressed Contact State blob.
    ///
    /// New contacts start [`ContactTrustState::Pending`]. Updating an existing contact may replace
    /// the current Discovery Key, but never resets the Identity-key-bound trust state.
    /// Consumers must build `contact_identity` from authenticated identity material; this method
    /// validates canonical key encodings and the Discovery Key signature, but it cannot prove where
    /// the Identity Key bytes came from.
    ///
    /// # Errors
    /// - [`ProtocolStateError::BlobDecode`] if an existing contact blob fails to decode.
    /// - [`ProtocolStateError::BlobEncode`] if the updated contact blob fails to encode.
    /// - [`ProtocolStateError::InvalidStateBinding`] if the Identity Key or Discovery Key encodings
    ///   are invalid, or the Discovery Key bundle signature does not verify under the contact
    ///   Identity Key.
    /// - [`ProtocolStateError::UnsupportedBlobVersion`] if the blob version is not supported.
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
        changed_contact_state(address, contact, self.limits)
    }

    /// Returns the Contact State for one peer Identity Key, if present.
    ///
    /// # Errors
    /// - [`ProtocolStateError::BlobDecode`] if the contact blob fails to decode.
    /// - [`ProtocolStateError::InvalidStateBinding`] if `identity_key` is not canonical.
    /// - [`ProtocolStateError::UnsupportedBlobVersion`] if the blob version is not supported.
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
    ///
    /// # Errors
    /// - [`ProtocolStateError::BlobDecode`] if any contact blob fails to decode.
    /// - [`ProtocolStateError::UnsupportedBlobVersion`] if any blob version is not supported.
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
    ///
    /// # Errors
    /// - [`ProtocolStateError::BlobDecode`] if the contact blob fails to decode.
    /// - [`ProtocolStateError::BlobEncode`] if the updated contact blob fails to encode.
    /// - [`ProtocolStateError::InvalidStateBinding`] if `identity_key` is not canonical.
    /// - [`ProtocolStateError::MissingRequiredState`] if no contact blob exists for `identity_key`.
    /// - [`ProtocolStateError::UnsupportedBlobVersion`] if the blob version is not supported.
    pub fn accept_contact(
        &self,
        snapshot: &ProtocolStateSnapshot,
        identity_key: ContactIdentityKey,
    ) -> Result<ContactStateChange, ProtocolStateError> {
        let address = contact_address(identity_key);
        validate_contact_identity_key(&address, &identity_key)?;
        let mut contact = load_contact_state(snapshot, &address, self.limits)?;
        if contact.trust_state != ContactTrustState::Pending {
            return Ok(ContactStateChange {
                contact,
                state_updates: Vec::new(),
                event: None,
            });
        }
        contact.trust_state = ContactTrustState::Unverified;
        changed_contact_state(address, contact, self.limits)
    }

    /// Locally blocks a contact without changing its Trust State.
    ///
    /// Blocking is keyed by the contact Identity Key. It refuses new outgoing user Messages and
    /// suppresses consumer-visible inbound plaintext after mandatory sender-certificate validation,
    /// while still accepting the protocol Message.
    ///
    /// # Errors
    /// - [`ProtocolStateError::BlobDecode`] if the contact blob fails to decode.
    /// - [`ProtocolStateError::BlobEncode`] if the updated contact blob fails to encode.
    /// - [`ProtocolStateError::InvalidStateBinding`] if `identity_key` is not canonical.
    /// - [`ProtocolStateError::MissingRequiredState`] if no contact blob exists for
    ///   `identity_key`.
    /// - [`ProtocolStateError::UnsupportedBlobVersion`] if the blob version is not supported.
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
    ///
    /// # Errors
    /// - [`ProtocolStateError::BlobDecode`] if the contact blob fails to decode.
    /// - [`ProtocolStateError::BlobEncode`] if the updated contact blob fails to encode.
    /// - [`ProtocolStateError::InvalidStateBinding`] if `identity_key` is not canonical.
    /// - [`ProtocolStateError::MissingRequiredState`] if no contact blob exists for
    ///   `identity_key`.
    /// - [`ProtocolStateError::UnsupportedBlobVersion`] if the blob version is not supported.
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
    ///
    /// # Errors
    /// - [`ProtocolStateError::BlobDecode`] if the contact blob fails to decode.
    /// - [`ProtocolStateError::BlobEncode`] if the updated contact blob fails to encode.
    /// - [`ProtocolStateError::InvalidStateBinding`] if either Identity Key is not canonical or
    ///   the contact is still Pending.
    /// - [`ProtocolStateError::MissingRequiredState`] if no contact blob exists for
    ///   `contact_identity_key`.
    /// - [`ProtocolStateError::UnsupportedBlobVersion`] if the blob version is not supported.
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
        changed_contact_state(address, contact, self.limits)
            .map(ContactSafetyNumberConfirmation::Matched)
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
        changed_contact_state(address, contact, self.limits)
    }

    /// Returns deletion updates for all protocol-state kinds at `key`.
    #[must_use]
    pub fn wipe(&self, key: ProtocolStateKey) -> Vec<ProtocolStateUpdate> {
        ProtocolStateKind::all()
            .iter()
            .map(|kind| ProtocolStateUpdate::delete(ProtocolStateAddress::new(*kind, key.clone())))
            .collect()
    }

    /// Encrypts plaintext using the required ratchet/session and pending-acknowledgment blobs.
    ///
    /// User messages require an existing accepted Contact State for
    /// [`OutboundPlaintext::contact_identity_key`]. On first send, the session blob is bound to that
    /// contact Identity Key; later sends on the same session must name the same contact. Pending
    /// contacts, blocked contacts, and messages addressed to a key other than the contact's
    /// current Discovery Key are rejected before ratchet state advances.
    ///
    /// # Errors
    /// - [`ProtocolStateError::BlobDecode`] if the ratchet/session or pending-acknowledgment blob
    ///   fails to decode.
    /// - [`ProtocolStateError::BlobEncode`] if the advanced session or pending-acknowledgment
    ///   state fails to encode or exceeds local caps.
    /// - [`ProtocolStateError::Crypto`] if ratchet encryption or state encoding fails.
    /// - [`ProtocolStateError::InvalidMessage`] if sender material or sealed-sender content
    ///   exceeds local caps or fails to encode.
    /// - [`ProtocolStateError::InvalidStateBinding`] if the contact is Pending, malformed, blocked,
    ///   or does not own the outbound recipient public key.
    /// - [`ProtocolStateError::MessageEncode`] if the produced Message fails to encode.
    /// - [`ProtocolStateError::MissingRequiredState`] if no ratchet/session or
    ///   pending-acknowledgment blob is present.
    /// - [`ProtocolStateError::UnsupportedBlobVersion`] if either blob version is not supported.
    pub fn encrypt_message(
        &self,
        snapshot: &ProtocolStateSnapshot,
        key: ProtocolStateKey,
        plaintext: OutboundPlaintext<'_>,
    ) -> Result<OutboundMessageResult, ProtocolStateError> {
        let pending_address = pending_acknowledgment_address(key.clone());
        let address = ratchet_address(key);
        let loaded = load_session_state(snapshot, &address, self.limits)?;
        let contact_identity_key =
            session_contact_identity_key(&address, &loaded, plaintext.contact_identity_key)?;
        ensure_contact_allows_outbound(
            snapshot,
            contact_identity_key,
            &plaintext.recipient_public_key,
            self.limits,
        )?;
        let session_key_bytes = address.key().as_bytes().to_vec();
        let mut pending = load_pending_acknowledgments(snapshot, &pending_address, self.limits)?;
        let mut state = active_session_state(&address, loaded.status)?;
        let transcript_signature = sign_message_transcript(
            plaintext.sender_identity_signing_key,
            MessageTranscriptInput {
                session_key: &session_key_bytes,
                recipient_identity_key: &plaintext.recipient_public_key,
                id: plaintext.id,
                timestamp_millis: plaintext.timestamp_millis,
                payload_kind: PayloadKind::EncryptedText,
                payload: plaintext.plaintext,
            },
        )?;
        let sealed = encode_sealed_sender_envelope(
            plaintext.sender_identity,
            &transcript_signature.to_bytes(),
            plaintext.plaintext,
            self.limits,
        )?;
        let associated_data =
            ratchet_associated_data(&session_key_bytes, &plaintext.recipient_public_key);
        let (header, ciphertext) = state.ratchet_encrypt(&sealed, &associated_data)?;
        let ratcheted_payload = encode_ratcheted_payload(&header, &ciphertext);
        let frame_plaintext = encode_message_frame_plaintext(
            plaintext.id,
            plaintext.timestamp_millis,
            PayloadKind::EncryptedText,
            &ratcheted_payload,
        )?;
        let recipient_public_key = PublicKey::from(plaintext.recipient_public_key);
        let mut frame_rng = OsRng;
        let frame = seal_frame(
            &mut frame_rng,
            &recipient_public_key,
            None,
            &frame_plaintext,
        )?;
        let message = Message::from_frame(frame);
        message
            .to_bytes_with_hardening_limits(self.limits)
            .map_err(ProtocolStateError::MessageEncode)?;
        record_pending_acknowledgment(
            &pending_address,
            &mut pending,
            plaintext.id,
            plaintext.timestamp_millis,
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
        );
        let pending_update = ProtocolStateUpdate::set(
            pending_address.clone(),
            encode_pending_acknowledgments(&pending_address, &pending, self.limits)?,
        );

        Ok(OutboundMessageResult {
            message_id: plaintext.id,
            timestamp_millis: plaintext.timestamp_millis,
            payload_kind: PayloadKind::EncryptedText,
            message,
            state_updates: vec![update, pending_update],
        })
    }

    /// Receives an inbound Message and returns an encrypted acknowledgment artifact on accept.
    ///
    /// Consumers should durably queue the returned acknowledgment with `state_updates` before
    /// treating the inbound Message as processed. Duplicate inbound retries do not regenerate the
    /// acknowledgment artifact. Unique inbound Messages require sender-certificate validation
    /// inputs; receive validates the sealed certificate after decrypting and before surfacing
    /// plaintext or sender identity. Blocked plaintext is suppressed after validation while state
    /// updates still advance; the blocked acknowledgment follows the engine's
    /// [`BlockedContactAcknowledgmentPolicy`], whose default [`BlockedContactAcknowledgmentPolicy::Unreachable`] returns
    /// none so a block is indistinguishable from an unreachable recipient. Duplicate byte-identical
    /// receives may return [`InboundMessageOutcome::Duplicate`] before validation because they
    /// surface no plaintext and do not advance ratchet/session state.
    ///
    /// # Errors
    /// - [`ProtocolStateError::BlobDecode`] if the deduplication-set or ratchet/session blob fails
    ///   to decode.
    /// - [`ProtocolStateError::BlobEncode`] if the advanced deduplication or session state fails
    ///   to encode or exceeds local caps.
    /// - [`ProtocolStateError::Crypto`] if ratchet decryption or state encoding fails.
    /// - [`ProtocolStateError::InvalidMessage`] if the Message does not contain ratcheted text,
    ///   the session is not bound to a peer sender identity key, the decrypted sender identity key
    ///   does not match the session binding, the decrypted sealed-sender envelope is malformed,
    ///   unsupported, or oversized, the validated sender certificate does not match the session
    ///   sender, or the acknowledgment sender material is invalid.
    /// - [`ProtocolStateError::MessageEncode`] if the inbound Message or produced acknowledgment
    ///   fails canonical encoding.
    /// - [`ProtocolStateError::MissingSenderCertificateValidation`] if a unique encrypted Message
    ///   is received without validation inputs.
    /// - [`ProtocolStateError::MissingRequiredState`] if a required deduplication-set or
    ///   ratchet/session blob is absent.
    /// - [`ProtocolStateError::SenderCertificateValidation`] if sender-certificate validation
    ///   rejects the sealed sender certificate.
    /// - [`ProtocolStateError::UnsupportedBlobVersion`] if either blob version is not supported.
    pub fn decrypt_message<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        snapshot: &ProtocolStateSnapshot,
        inbound: InboundEncryptedMessage<'_>,
    ) -> Result<InboundMessageOutcome, ProtocolStateError> {
        let deduplication_address = deduplication_address(inbound.deduplication_key);
        let encoded = inbound
            .message
            .to_bytes_with_hardening_limits(self.limits)
            .map_err(ProtocolStateError::MessageEncode)?;
        let mut deduplication =
            load_deduplication_set(snapshot, &deduplication_address, self.limits)?;
        let digest = deduplication_digest(&deduplication.digest_key, &encoded);
        if contains_digest(&deduplication.digests, &digest) {
            return Ok(InboundMessageOutcome::Duplicate);
        }

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

        let frame_plaintext =
            open_frame_for_discovery_key(inbound.recipient_discovery_key, &message.to_frame())?;
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
                recipient_identity_key: &message.recipient_public_key,
                id: frame_plaintext.id,
                timestamp_millis: frame_plaintext.timestamp_millis,
                payload_kind: frame_plaintext.payload_kind,
                payload: &decoded.plaintext,
            },
            &decoded.transcript_signature,
        )?;
        let validation = inbound
            .sender_certificate_validation
            .ok_or(ProtocolStateError::MissingSenderCertificateValidation)?;
        let inbound_contact_identity_key = inbound_contact_identity_key(
            validation,
            &decoded.sender_identity,
            contact_identity_key,
            self.limits,
        )?;
        record_deduplication_digest(&mut deduplication, digest);
        let blocked = contact_is_blocked(snapshot, inbound_contact_identity_key, self.limits)?;
        // Unreachable policy suppresses the acknowledgment and leaves the sending chain unadvanced;
        // the receiving-chain advance and recorded digest are still committed below.
        if blocked
            && self.blocked_contact_acknowledgment_policy
                == BlockedContactAcknowledgmentPolicy::Unreachable
        {
            let state_updates = receive_state_updates(
                &address,
                &state,
                expected_sender_identity_key,
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
            &inbound.acknowledgment,
            frame_plaintext.id,
            rng,
            self.limits,
        )?;
        let state_updates = receive_state_updates(
            &address,
            &state,
            expected_sender_identity_key,
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
                timestamp_millis: frame_plaintext.timestamp_millis,
                payload_kind: frame_plaintext.payload_kind,
                plaintext: decoded.plaintext,
                sender_identity: decoded.sender_identity,
                acknowledgment,
                state_updates,
            },
        )))
    }

    /// Returns all pending acknowledgments stored for a Session.
    ///
    /// # Errors
    /// - [`ProtocolStateError::BlobDecode`] if the pending-acknowledgment blob fails to decode.
    /// - [`ProtocolStateError::MissingRequiredState`] if no pending-acknowledgment blob is
    ///   present.
    /// - [`ProtocolStateError::UnsupportedBlobVersion`] if the blob version is not supported.
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
                first_sent_millis: entry.first_sent_millis,
                last_retry_millis: entry.last_retry_millis,
            })
            .collect())
    }

    /// Returns retry instructions for pending acknowledgments whose retry window has elapsed.
    ///
    /// `now_millis` is caller supplied so retry behavior is deterministic in tests and does not
    /// read the KeyStore Clock.
    ///
    /// # Errors
    /// - [`ProtocolStateError::BlobDecode`] if the pending-acknowledgment blob fails to decode.
    /// - [`ProtocolStateError::BlobEncode`] if updating retry timestamps fails to encode.
    /// - [`ProtocolStateError::MissingRequiredState`] if no pending-acknowledgment blob is
    ///   present.
    /// - [`ProtocolStateError::UnsupportedBlobVersion`] if the blob version is not supported.
    pub fn retry_instructions(
        &self,
        snapshot: &ProtocolStateSnapshot,
        key: ProtocolStateKey,
        now_millis: u64,
        retry_window_millis: u64,
    ) -> Result<RetryInstructionResult, ProtocolStateError> {
        let address = pending_acknowledgment_address(key);
        let mut pending = load_pending_acknowledgments(snapshot, &address, self.limits)?;
        let mut instructions = Vec::new();
        for (message_id, entry) in pending.pending.iter_mut() {
            let reference = entry.last_retry_millis.unwrap_or(entry.first_sent_millis);
            if now_millis >= reference.saturating_add(retry_window_millis) {
                instructions.push(RetryInstruction {
                    message_id: MessageId::from_bytes(*message_id),
                    message: copy_message(&entry.message),
                    first_sent_millis: entry.first_sent_millis,
                    last_retry_millis: entry.last_retry_millis,
                });
                entry.last_retry_millis = Some(now_millis);
            }
        }

        let state_updates = if instructions.is_empty() {
            Vec::new()
        } else {
            vec![ProtocolStateUpdate::set(
                address.clone(),
                encode_pending_acknowledgments(&address, &pending, self.limits)?,
            )]
        };
        Ok(RetryInstructionResult {
            instructions,
            state_updates,
        })
    }

    /// Processes an encrypted acknowledgment and advances the relevant protocol-state blobs.
    ///
    /// Unknown or already-cleared acknowledgments are non-fatal misses. Exact replayed
    /// acknowledgment Messages retained in the pending state digest window are duplicates and do
    /// not touch ratchet/session state.
    ///
    /// # Errors
    /// - [`ProtocolStateError::BlobDecode`] if the ratchet/session or pending-acknowledgment blob
    ///   fails to decode.
    /// - [`ProtocolStateError::BlobEncode`] if advanced state fails to encode.
    /// - [`ProtocolStateError::Crypto`] if ratchet decryption fails.
    /// - [`ProtocolStateError::InvalidMessage`] if the Message is not an acknowledgment, the
    ///   session is not bound to a peer sender identity key, the decrypted sender identity key
    ///   does not match the session binding, or the encrypted acknowledgment plaintext is
    ///   malformed.
    /// - [`ProtocolStateError::MessageEncode`] if the acknowledgment Message fails canonical
    ///   encoding.
    /// - [`ProtocolStateError::MissingRequiredState`] if required state is absent.
    /// - [`ProtocolStateError::UnsupportedBlobVersion`] if either blob version is not supported.
    pub fn process_acknowledgment<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        snapshot: &ProtocolStateSnapshot,
        inbound: InboundAcknowledgmentMessage<'_>,
    ) -> Result<AcknowledgmentOutcome, ProtocolStateError> {
        let pending_address = pending_acknowledgment_address(inbound.session_key.clone());
        let encoded = inbound
            .message
            .to_bytes_with_hardening_limits(self.limits)
            .map_err(ProtocolStateError::MessageEncode)?;
        let digest = acknowledgment_digest(&encoded);
        if pending_acknowledgment_digest_seen(snapshot, &pending_address, digest, self.limits)? {
            return Ok(AcknowledgmentOutcome::Duplicate);
        }
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

        let frame_plaintext =
            open_frame_for_discovery_key(inbound.recipient_discovery_key, &message.to_frame())?;
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
                recipient_identity_key: &message.recipient_public_key,
                id: frame_plaintext.id,
                timestamp_millis: frame_plaintext.timestamp_millis,
                payload_kind: frame_plaintext.payload_kind,
                payload: &decoded.plaintext,
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
        );
        let pending_update = ProtocolStateUpdate::set(
            pending_address.clone(),
            encode_pending_acknowledgments(&pending_address, &pending, self.limits)?,
        );
        let state_updates = vec![session_update, pending_update];
        if cleared {
            Ok(AcknowledgmentOutcome::Cleared(ClearedAcknowledgment {
                message_id: frame_plaintext.id,
                timestamp_millis: frame_plaintext.timestamp_millis,
                acknowledged_message_id,
                sender_identity: decoded.sender_identity,
                state_updates,
            }))
        } else {
            Ok(AcknowledgmentOutcome::Missed {
                message_id: frame_plaintext.id,
                timestamp_millis: frame_plaintext.timestamp_millis,
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
#[non_exhaustive]
#[derive(Debug)]
pub enum ProtocolStateError {
    /// A persisted blob failed structural decoding.
    BlobDecode {
        /// Address whose blob failed to decode.
        address: ProtocolStateAddress,
        /// Diagnostic decode context for logs only.
        reason: String,
    },
    /// A protocol-state blob failed encoding.
    BlobEncode {
        /// Address whose blob failed to encode.
        address: ProtocolStateAddress,
        /// Diagnostic encode context for logs only.
        reason: String,
    },
    /// A cryptographic operation failed.
    Crypto(aether_crypto::CryptoError),
    /// Sender-certificate validation failed during receive.
    SenderCertificateValidation(SenderCertificateValidationError),
    /// A unique encrypted receive was attempted without sender-certificate validation inputs.
    MissingSenderCertificateValidation,
    /// A Message did not carry the expected ratcheted payload.
    InvalidMessage {
        /// Diagnostic failure context for logs only.
        reason: String,
    },
    /// Received-message deduplication capacity is outside supported bounds.
    InvalidDeduplicationCapacity {
        /// Requested capacity.
        capacity: usize,
        /// Minimum supported capacity.
        minimum: usize,
        /// Maximum supported capacity.
        maximum: usize,
    },
    /// A configured hardening limit is outside supported bounds.
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
    MessageEncode(MessageError),
    /// A state binding operation would violate an existing protocol-state invariant.
    InvalidStateBinding {
        /// Address whose binding invariant would be violated.
        address: ProtocolStateAddress,
        /// Diagnostic failure context for logs only.
        reason: String,
    },
    /// A protocol-state key is malformed.
    InvalidStateKey {
        /// Diagnostic failure context for logs only.
        reason: String,
    },
    /// A required protocol-state blob was absent from the consumer snapshot.
    MissingRequiredState {
        /// Address that must be present before the operation.
        address: ProtocolStateAddress,
    },
    /// A persisted blob used a version this build does not support.
    UnsupportedBlobVersion {
        /// Address whose blob version is unsupported.
        address: ProtocolStateAddress,
        /// Major version read from the blob envelope.
        major: u8,
        /// Minor version read from the blob envelope.
        minor: u8,
    },
}

impl fmt::Display for ProtocolStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BlobDecode { address, reason } => {
                write!(
                    f,
                    "protocol-state blob failed to decode at {address}: {reason}"
                )
            }
            Self::BlobEncode { address, reason } => {
                write!(
                    f,
                    "protocol-state blob failed to encode at {address}: {reason}"
                )
            }
            Self::Crypto(e) => write!(f, "protocol-state crypto operation failed: {e}"),
            Self::SenderCertificateValidation(e) => {
                write!(f, "sender certificate validation failed: {e}")
            }
            Self::MissingSenderCertificateValidation => {
                write!(f, "missing sender certificate validation input")
            }
            Self::InvalidMessage { reason } => write!(f, "invalid message: {reason}"),
            Self::InvalidDeduplicationCapacity {
                capacity,
                minimum,
                maximum,
            } => write!(
                f,
                "invalid deduplication capacity: {capacity} outside {minimum}..={maximum}"
            ),
            Self::InvalidHardeningLimit {
                name,
                value,
                minimum,
                maximum,
            } => write!(
                f,
                "invalid hardening limit for {name}: {value} outside {minimum}..={maximum}"
            ),
            Self::InvalidStateBinding { address, reason } => {
                write!(f, "invalid protocol-state binding at {address}: {reason}")
            }
            Self::InvalidStateKey { reason } => write!(f, "invalid protocol-state key: {reason}"),
            Self::MessageEncode(e) => write!(f, "message failed to encode: {e}"),
            Self::MissingRequiredState { address } => {
                write!(f, "missing required protocol-state blob at {address}")
            }
            Self::UnsupportedBlobVersion {
                address,
                major,
                minor,
            } => {
                write!(
                    f,
                    "unsupported protocol-state blob version at {address}: {major}.{minor}"
                )
            }
        }
    }
}

impl Error for ProtocolStateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Crypto(e) => Some(e),
            Self::SenderCertificateValidation(e) => Some(e),
            Self::MessageEncode(e) => Some(e),
            Self::BlobDecode { .. }
            | Self::BlobEncode { .. }
            | Self::InvalidDeduplicationCapacity { .. }
            | Self::InvalidHardeningLimit { .. }
            | Self::InvalidMessage { .. }
            | Self::InvalidStateBinding { .. }
            | Self::InvalidStateKey { .. }
            | Self::MissingSenderCertificateValidation
            | Self::MissingRequiredState { .. }
            | Self::UnsupportedBlobVersion { .. } => None,
        }
    }
}

impl From<aether_crypto::CryptoError> for ProtocolStateError {
    fn from(e: aether_crypto::CryptoError) -> Self {
        Self::Crypto(e)
    }
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

#[derive(Serialize)]
struct SessionStateWireV1<'a> {
    version: u8,
    ratchet_state: &'a [u8],
    peer_sender_identity_key: Option<[u8; 32]>,
}

#[derive(Deserialize)]
struct DecodedSessionStateWireV1 {
    version: u8,
    ratchet_state: Vec<u8>,
    peer_sender_identity_key: Option<[u8; 32]>,
}

#[derive(Serialize)]
struct SessionStateWireV2<'a> {
    version: u8,
    ratchet_state: &'a [u8],
    peer_sender_identity_key: Option<[u8; 32]>,
    contact_identity_key: Option<ContactIdentityKeyWire>,
}

#[derive(Deserialize)]
struct DecodedSessionStateWireV2 {
    version: u8,
    ratchet_state: Vec<u8>,
    peer_sender_identity_key: Option<[u8; 32]>,
    contact_identity_key: Option<ContactIdentityKeyWire>,
}

#[derive(Deserialize, Serialize)]
struct SessionStateUnrecoverableWire {
    version: u8,
    reason: SessionUnrecoverableReason,
    event_emitted: bool,
    peer_sender_identity_key: Option<[u8; 32]>,
    contact_identity_key: Option<ContactIdentityKeyWire>,
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
    let payload = if let Some(contact_identity_key) = contact_identity_key {
        let wire = SessionStateWireV2 {
            version: SESSION_STATE_WITH_CONTACT_WIRE_VERSION,
            ratchet_state: &state_bytes,
            peer_sender_identity_key,
            contact_identity_key: Some(ContactIdentityKeyWire::from(contact_identity_key)),
        };
        Zeroizing::new(
            postcard::to_stdvec(&wire).map_err(|_| ProtocolStateError::BlobEncode {
                address: address.clone(),
                reason: "ratchet/session state failed to encode".into(),
            })?,
        )
    } else {
        let wire = SessionStateWireV1 {
            version: SESSION_STATE_WIRE_VERSION,
            ratchet_state: &state_bytes,
            peer_sender_identity_key,
        };
        Zeroizing::new(
            postcard::to_stdvec(&wire).map_err(|_| ProtocolStateError::BlobEncode {
                address: address.clone(),
                reason: "ratchet/session state failed to encode".into(),
            })?,
        )
    };
    encode_session_payload(address, payload, limits)
}

fn encode_unrecoverable_session_state(
    address: &ProtocolStateAddress,
    reason: SessionUnrecoverableReason,
    event_emitted: bool,
    peer_sender_identity_key: Option<[u8; 32]>,
    contact_identity_key: Option<ContactIdentityKey>,
    limits: ProtocolHardeningLimits,
) -> Result<ProtocolStateBlob, ProtocolStateError> {
    let wire = SessionStateUnrecoverableWire {
        version: SESSION_STATE_UNRECOVERABLE_WIRE_VERSION,
        reason,
        event_emitted,
        peer_sender_identity_key,
        contact_identity_key: contact_identity_key.map(ContactIdentityKeyWire::from),
    };
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
    first_sent_millis: u64,
    last_retry_millis: Option<u64>,
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
    first_sent_millis: u64,
    last_retry_millis: Option<u64>,
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
    first_sent_millis: u64,
    last_retry_millis: Option<u64>,
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

#[derive(Serialize)]
struct ContactStateWire<'a> {
    version: u8,
    identity_x25519_public_key: [u8; PUBLIC_KEY_LEN],
    identity_ed25519_verifying_key: [u8; PUBLIC_KEY_LEN],
    discovery_x25519_public_key: [u8; PUBLIC_KEY_LEN],
    discovery_ed25519_verifying_key: [u8; PUBLIC_KEY_LEN],
    discovery_epoch: u32,
    discovery_created_at: u64,
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
    discovery_created_at: u64,
    discovery_identity_signature: Vec<u8>,
    trust_state: ContactTrustState,
    blocked: bool,
}

#[derive(Deserialize)]
struct DecodedContactStateWireV1 {
    version: u8,
    identity_x25519_public_key: [u8; PUBLIC_KEY_LEN],
    identity_ed25519_verifying_key: [u8; PUBLIC_KEY_LEN],
    discovery_x25519_public_key: [u8; PUBLIC_KEY_LEN],
    discovery_ed25519_verifying_key: [u8; PUBLIC_KEY_LEN],
    discovery_epoch: u32,
    discovery_created_at: u64,
    discovery_identity_signature: Vec<u8>,
    trust_state: ContactTrustState,
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
    timestamp_millis: u64,
    payload_kind: u8,
    ratcheted_payload: &'a [u8],
}

#[derive(Deserialize)]
struct DecodedMessageFramePlaintextWire {
    version: u8,
    id: [u8; 16],
    timestamp_millis: u64,
    payload_kind: u8,
    ratcheted_payload: Vec<u8>,
}

struct DecodedMessageFramePlaintext {
    id: MessageId,
    timestamp_millis: u64,
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
    if let Ok((wire, trailing)) =
        postcard::take_from_bytes::<SessionStateUnrecoverableWire>(payload)
        && trailing.is_empty()
        && wire.version == SESSION_STATE_UNRECOVERABLE_WIRE_VERSION
    {
        let contact_identity_key = wire
            .contact_identity_key
            .map(ContactIdentityKey::from)
            .map(|identity_key| validate_session_contact_identity_key(address, identity_key))
            .transpose()?;
        return Ok(LoadedSessionState {
            status: LoadedSessionStatus::Unrecoverable {
                reason: wire.reason,
                event_emitted: wire.event_emitted,
            },
            peer_sender_identity_key: wire.peer_sender_identity_key,
            contact_identity_key,
        });
    }

    if let Ok((wire, trailing)) = postcard::take_from_bytes::<DecodedSessionStateWireV2>(payload)
        && trailing.is_empty()
        && wire.version == SESSION_STATE_WITH_CONTACT_WIRE_VERSION
    {
        let contact_identity_key = wire
            .contact_identity_key
            .map(ContactIdentityKey::from)
            .map(|identity_key| validate_session_contact_identity_key(address, identity_key))
            .transpose()?;
        return decoded_session_state(
            address,
            wire.ratchet_state,
            wire.peer_sender_identity_key,
            contact_identity_key,
        );
    }

    let (wire, trailing): (DecodedSessionStateWireV1, &[u8]) =
        postcard::take_from_bytes(payload).map_err(|e| ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: e.to_string(),
        })?;
    if !trailing.is_empty() || wire.version != SESSION_STATE_WIRE_VERSION {
        return Err(ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: "ratchet/session payload version is unsupported".into(),
        });
    }
    decoded_session_state(
        address,
        wire.ratchet_state,
        wire.peer_sender_identity_key,
        None,
    )
}

fn decoded_session_state(
    address: &ProtocolStateAddress,
    ratchet_state: Vec<u8>,
    peer_sender_identity_key: Option<[u8; 32]>,
    contact_identity_key: Option<ContactIdentityKey>,
) -> Result<LoadedSessionState, ProtocolStateError> {
    let ratchet_state = Zeroizing::new(ratchet_state);
    let state =
        RatchetState::from_bytes(&ratchet_state).map_err(|_| ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: "ratchet/session state failed to decode".into(),
        })?;
    Ok(LoadedSessionState {
        status: LoadedSessionStatus::Active(Box::new(state)),
        peer_sender_identity_key,
        contact_identity_key,
    })
}

fn active_session_state(
    address: &ProtocolStateAddress,
    status: LoadedSessionStatus,
) -> Result<RatchetState, ProtocolStateError> {
    match status {
        LoadedSessionStatus::Active(state) => Ok(*state),
        LoadedSessionStatus::Unrecoverable { .. } => Err(ProtocolStateError::InvalidStateBinding {
            address: address.clone(),
            reason: "session is unrecoverable".into(),
        }),
    }
}

fn session_unrecoverable_result(
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
        );
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
            first_sent_millis: entry.first_sent_millis,
            last_retry_millis: entry.last_retry_millis,
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
                first_sent_millis: entry.first_sent_millis,
                last_retry_millis: entry.last_retry_millis,
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
    address: ProtocolStateAddress,
    contact: ContactState,
    limits: ProtocolHardeningLimits,
) -> Result<ContactStateChange, ProtocolStateError> {
    Ok(ContactStateChange {
        contact: contact.clone(),
        state_updates: vec![ProtocolStateUpdate::set(
            address.clone(),
            encode_contact_state(&address, &contact, limits)?,
        )],
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
        discovery_created_at: contact.identity.discovery_key.created_at,
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
                "contact-state blob length exceeds limit: {}",
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
    if let Ok((wire, trailing)) = postcard::take_from_bytes::<DecodedContactStateWireV2>(payload)
        && trailing.is_empty()
        && wire.version == CONTACT_STATE_WIRE_VERSION
    {
        return decoded_contact_state(address, decoded_contact_state_parts_v2(wire));
    }

    let (wire, trailing): (DecodedContactStateWireV1, &[u8]) =
        postcard::take_from_bytes(payload).map_err(|e| ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: e.to_string(),
        })?;
    if !trailing.is_empty() || wire.version != CONTACT_STATE_WIRE_VERSION_V1 {
        return Err(ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: "contact-state payload version is unsupported".into(),
        });
    }
    decoded_contact_state(address, decoded_contact_state_parts_v1(wire))
}

#[cfg(fuzzing)]
#[allow(missing_docs)]
pub fn fuzz_decode_protocol_state_blob(
    kind: ProtocolStateKind,
    key: ProtocolStateKey,
    blob: ProtocolStateBlob,
) -> Result<(), ProtocolStateError> {
    let address = ProtocolStateAddress::new(kind, key);
    let limits = ProtocolHardeningLimits::default();
    match kind {
        ProtocolStateKind::RatchetSession => {
            decode_session_state(&address, &blob, limits).map(|_| ())
        }
        ProtocolStateKind::DeduplicationSet => {
            decode_deduplication_set(&address, &blob, limits).map(|_| ())
        }
        ProtocolStateKind::PendingAcknowledgments => {
            decode_pending_acknowledgments(&address, &blob, limits).map(|_| ())
        }
        ProtocolStateKind::ContactState => {
            decode_contact_state(&address, &blob, limits).map(|_| ())
        }
    }
}

struct DecodedContactStateParts {
    identity_x25519_public_key: [u8; PUBLIC_KEY_LEN],
    identity_ed25519_verifying_key: [u8; PUBLIC_KEY_LEN],
    discovery_x25519_public_key: [u8; PUBLIC_KEY_LEN],
    discovery_ed25519_verifying_key: [u8; PUBLIC_KEY_LEN],
    discovery_epoch: u32,
    discovery_created_at: u64,
    discovery_identity_signature: Vec<u8>,
    trust_state: ContactTrustState,
    blocked: bool,
}

fn decoded_contact_state_parts_v2(wire: DecodedContactStateWireV2) -> DecodedContactStateParts {
    DecodedContactStateParts {
        identity_x25519_public_key: wire.identity_x25519_public_key,
        identity_ed25519_verifying_key: wire.identity_ed25519_verifying_key,
        discovery_x25519_public_key: wire.discovery_x25519_public_key,
        discovery_ed25519_verifying_key: wire.discovery_ed25519_verifying_key,
        discovery_epoch: wire.discovery_epoch,
        discovery_created_at: wire.discovery_created_at,
        discovery_identity_signature: wire.discovery_identity_signature,
        trust_state: wire.trust_state,
        blocked: wire.blocked,
    }
}

fn decoded_contact_state_parts_v1(wire: DecodedContactStateWireV1) -> DecodedContactStateParts {
    DecodedContactStateParts {
        identity_x25519_public_key: wire.identity_x25519_public_key,
        identity_ed25519_verifying_key: wire.identity_ed25519_verifying_key,
        discovery_x25519_public_key: wire.discovery_x25519_public_key,
        discovery_ed25519_verifying_key: wire.discovery_ed25519_verifying_key,
        discovery_epoch: wire.discovery_epoch,
        discovery_created_at: wire.discovery_created_at,
        discovery_identity_signature: wire.discovery_identity_signature,
        trust_state: wire.trust_state,
        blocked: false,
    }
}

fn decoded_contact_state(
    address: &ProtocolStateAddress,
    parts: DecodedContactStateParts,
) -> Result<ContactState, ProtocolStateError> {
    let contact = ContactState {
        identity: ContactIdentity {
            identity_key: ContactIdentityKey {
                x25519_public_key: parts.identity_x25519_public_key,
                ed25519_verifying_key: parts.identity_ed25519_verifying_key,
            },
            discovery_key: ContactDiscoveryKey {
                x25519_public_key: parts.discovery_x25519_public_key,
                ed25519_verifying_key: parts.discovery_ed25519_verifying_key,
                epoch: parts.discovery_epoch,
                created_at: parts.discovery_created_at,
                identity_signature: parts.discovery_identity_signature.try_into().map_err(
                    |_| ProtocolStateError::BlobDecode {
                        address: address.clone(),
                        reason: "contact discovery key signature length is invalid".into(),
                    },
                )?,
            },
        },
        trust_state: parts.trust_state,
        blocked: parts.blocked,
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
    let Some(bundle) = contact_discovery_key_bundle(&contact_identity.discovery_key) else {
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
    verify_discovery_key_bundle(&bundle, &identity_verifying_key).map_err(|_| {
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
    let Some(bundle) = contact_discovery_key_bundle(&contact_identity.discovery_key) else {
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
    verify_discovery_key_bundle(&bundle, &identity_verifying_key).map_err(|_| {
        ProtocolStateError::InvalidStateBinding {
            address: address.clone(),
            reason: "contact discovery key signature failed".into(),
        }
    })
}

fn contact_identity_key_is_valid(identity_key: &ContactIdentityKey) -> bool {
    identity_key_is_valid(identity_key)
}

fn contact_discovery_key_bundle(discovery_key: &ContactDiscoveryKey) -> Option<DiscoveryKeyBundle> {
    if !validate_x25519_public_key(&discovery_key.x25519_public_key) {
        return None;
    }
    Some(DiscoveryKeyBundle {
        public_key: PublicKey::from(discovery_key.x25519_public_key),
        verifying_key: parse_ed25519_verifying_key_bytes(&discovery_key.ed25519_verifying_key)?,
        epoch: discovery_key.epoch,
        created_at: discovery_key.created_at,
        signature: Signature::from_bytes(&discovery_key.identity_signature),
    })
}

fn contact_discovery_key_is_newer(
    current: &ContactDiscoveryKey,
    candidate: &ContactDiscoveryKey,
) -> bool {
    (candidate.created_at, candidate.epoch) > (current.created_at, current.epoch)
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
        return Err(ProtocolStateError::InvalidStateBinding {
            address,
            reason: "blocked contact cannot send user messages".into(),
        });
    }
    if contact.trust_state == ContactTrustState::Pending {
        return Err(ProtocolStateError::InvalidStateBinding {
            address,
            reason: "pending contact cannot send user messages".into(),
        });
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
        revocation_state: validation.revocation_state,
        reference_timestamp_secs: validation.reference_timestamp_secs,
        grace_window_secs: validation.grace_window_secs,
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
    encoded_message: &[u8],
) -> [u8; DEDUPLICATION_DIGEST_LEN] {
    let hash = blake3::keyed_hash(digest_key, encoded_message);
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
    first_sent_millis: u64,
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
            first_sent_millis,
            last_retry_millis: None,
        },
    );
    Ok(())
}

fn acknowledgment_digest(encoded_message: &[u8]) -> [u8; ACKNOWLEDGMENT_DIGEST_LEN] {
    let hash = blake3::hash(encoded_message);
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
    timestamp_millis: u64,
    payload_kind: PayloadKind,
    ratcheted_payload: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ProtocolStateError> {
    Ok(Zeroizing::new(
        postcard::to_stdvec(&MessageFramePlaintextWire {
            version: MESSAGE_FRAME_PLAINTEXT_WIRE_VERSION,
            id: *id.as_bytes(),
            timestamp_millis,
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
        timestamp_millis: wire.timestamp_millis,
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
    plaintext: Zeroizing<Vec<u8>>,
}

struct MessageTranscriptInput<'a> {
    session_key: &'a [u8],
    recipient_identity_key: &'a [u8; 32],
    id: MessageId,
    timestamp_millis: u64,
    payload_kind: PayloadKind,
    payload: &'a [u8],
}

fn sign_message_transcript(
    signing_key: &SigningKeyPair,
    input: MessageTranscriptInput<'_>,
) -> Result<Signature, ProtocolStateError> {
    let transcript = message_transcript(input)?;
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
    let transcript = message_transcript(input)?;
    verify_with_context(
        &verifying_key,
        MESSAGE_TRANSCRIPT_CONTEXT,
        &transcript,
        &signature,
    )?;
    Ok(())
}

fn message_transcript(
    input: MessageTranscriptInput<'_>,
) -> Result<Zeroizing<Vec<u8>>, ProtocolStateError> {
    let session_key_len =
        u32::try_from(input.session_key.len()).map_err(|_| ProtocolStateError::InvalidMessage {
            reason: "message transcript session key length exceeds limit".into(),
        })?;
    let payload_len =
        u32::try_from(input.payload.len()).map_err(|_| ProtocolStateError::InvalidMessage {
            reason: "message transcript payload length exceeds limit".into(),
        })?;
    let mut transcript = Zeroizing::new(Vec::with_capacity(
        4 + input.session_key.len() + 32 + 16 + 8 + 1 + 4 + input.payload.len(),
    ));
    transcript.extend_from_slice(&session_key_len.to_be_bytes());
    transcript.extend_from_slice(input.session_key);
    transcript.extend_from_slice(input.recipient_identity_key);
    transcript.extend_from_slice(input.id.as_bytes());
    transcript.extend_from_slice(&input.timestamp_millis.to_be_bytes());
    transcript.push(input.payload_kind.tag());
    transcript.extend_from_slice(&payload_len.to_be_bytes());
    transcript.extend_from_slice(input.payload);
    Ok(transcript)
}

fn encode_sealed_sender_envelope(
    sender_identity: &SenderIdentityMaterial,
    transcript_signature: &[u8],
    plaintext: &[u8],
    limits: ProtocolHardeningLimits,
) -> Result<Zeroizing<Vec<u8>>, ProtocolStateError> {
    validate_sender_identity(sender_identity, limits)?;
    validate_transcript_signature(transcript_signature)?;
    let padded_plaintext = pad_sealed_payload(plaintext)?;
    validate_sealed_sender_content_len(
        sender_identity,
        transcript_signature,
        &padded_plaintext,
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
            padded_plaintext: &padded_plaintext,
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
        plaintext,
    })
}

#[cfg(fuzzing)]
#[allow(missing_docs)]
pub fn fuzz_decode_sealed_sender_envelope(bytes: &[u8]) -> Result<(), ProtocolStateError> {
    decode_sealed_sender_envelope(bytes, ProtocolHardeningLimits::default()).map(|_| ())
}

fn receive_state_updates(
    address: &ProtocolStateAddress,
    state: &RatchetState,
    peer_sender_identity_key: [u8; 32],
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
            Some(peer_sender_identity_key),
            Some(contact_identity_key),
            limits,
        )?,
    );
    let deduplication_update = ProtocolStateUpdate::set(
        deduplication_address.clone(),
        encode_deduplication_set(deduplication_address, deduplication, limits)?,
    );
    Ok(vec![session_update, deduplication_update])
}

fn encrypt_acknowledgment(
    state: &mut RatchetState,
    session_key: &[u8],
    acknowledgment: &OutboundAcknowledgment<'_>,
    acknowledged_message_id: MessageId,
    rng: &mut (impl RngCore + CryptoRng),
    limits: ProtocolHardeningLimits,
) -> Result<Message, ProtocolStateError> {
    let plaintext = encode_acknowledgment_plaintext(acknowledged_message_id)?;
    let transcript_signature = sign_message_transcript(
        acknowledgment.sender_identity_signing_key,
        MessageTranscriptInput {
            session_key,
            recipient_identity_key: &acknowledgment.recipient_public_key,
            id: acknowledgment.id,
            timestamp_millis: acknowledgment.timestamp_millis,
            payload_kind: PayloadKind::Acknowledgment,
            payload: plaintext.as_slice(),
        },
    )?;
    let sealed = encode_sealed_sender_envelope(
        acknowledgment.sender_identity,
        &transcript_signature.to_bytes(),
        plaintext.as_slice(),
        limits,
    )?;
    let associated_data =
        ratchet_associated_data(session_key, &acknowledgment.recipient_public_key);
    let (header, ciphertext) = state.ratchet_encrypt(&sealed, &associated_data)?;
    let ratcheted_payload = encode_ratcheted_payload(&header, &ciphertext);
    let frame_plaintext = encode_message_frame_plaintext(
        acknowledgment.id,
        acknowledgment.timestamp_millis,
        PayloadKind::Acknowledgment,
        &ratcheted_payload,
    )?;
    let recipient_public_key = PublicKey::from(acknowledgment.recipient_public_key);
    let frame = seal_frame(rng, &recipient_public_key, None, &frame_plaintext)?;
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
    let bundle = IdentityKeyBundle::from_bytes(
        &sender_identity.identity_key,
        &sender_identity.identity_verifying_key,
        &sender_identity.identity_binding_signature,
    )
    .map_err(|_| ProtocolStateError::InvalidMessage {
        reason: "sender identity key bundle encoding is invalid".into(),
    })?;
    verify_identity_key_bundle(&bundle).map_err(|_| ProtocolStateError::InvalidMessage {
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
    let required_len = plaintext
        .len()
        .checked_add(SEALED_PAYLOAD_LEN_PREFIX_LEN)
        .ok_or_else(|| ProtocolStateError::InvalidMessage {
            reason: "sealed payload length overflowed".into(),
        })?;
    let bucket = SEALED_PAYLOAD_BUCKETS
        .iter()
        .copied()
        .find(|bucket| required_len <= *bucket)
        .ok_or_else(|| ProtocolStateError::InvalidMessage {
            reason: format!("sealed payload length exceeds limit: {}", plaintext.len()),
        })?;
    let plaintext_len =
        u32::try_from(plaintext.len()).map_err(|_| ProtocolStateError::InvalidMessage {
            reason: "sealed payload length exceeds u32".into(),
        })?;
    let mut padded = Zeroizing::new(vec![0u8; bucket]);
    padded[..SEALED_PAYLOAD_LEN_PREFIX_LEN].copy_from_slice(&plaintext_len.to_be_bytes());
    padded[SEALED_PAYLOAD_LEN_PREFIX_LEN..required_len].copy_from_slice(plaintext);
    Ok(padded)
}

fn unpad_sealed_payload(padded: &[u8]) -> Result<Zeroizing<Vec<u8>>, ProtocolStateError> {
    if !SEALED_PAYLOAD_BUCKETS.contains(&padded.len()) {
        return Err(ProtocolStateError::InvalidMessage {
            reason: format!("sealed payload padding bucket is invalid: {}", padded.len()),
        });
    }
    let len_bytes: [u8; SEALED_PAYLOAD_LEN_PREFIX_LEN] = padded
        .get(..SEALED_PAYLOAD_LEN_PREFIX_LEN)
        .ok_or_else(|| ProtocolStateError::InvalidMessage {
            reason: "sealed payload padding is too short".into(),
        })?
        .try_into()
        .map_err(|_| ProtocolStateError::InvalidMessage {
            reason: "sealed payload length prefix is invalid".into(),
        })?;
    let plaintext_len = usize::try_from(u32::from_be_bytes(len_bytes)).map_err(|_| {
        ProtocolStateError::InvalidMessage {
            reason: "sealed payload length prefix exceeds platform limit".into(),
        }
    })?;
    let plaintext_end = SEALED_PAYLOAD_LEN_PREFIX_LEN
        .checked_add(plaintext_len)
        .ok_or_else(|| ProtocolStateError::InvalidMessage {
            reason: "sealed payload length overflowed".into(),
        })?;
    if plaintext_end > padded.len() {
        return Err(ProtocolStateError::InvalidMessage {
            reason: "sealed payload length exceeds padding bucket".into(),
        });
    }
    if padded[plaintext_end..].iter().any(|byte| *byte != 0) {
        return Err(ProtocolStateError::InvalidMessage {
            reason: "sealed payload padding is malformed".into(),
        });
    }
    Ok(Zeroizing::new(
        padded[SEALED_PAYLOAD_LEN_PREFIX_LEN..plaintext_end].to_vec(),
    ))
}

#[cfg(fuzzing)]
#[allow(missing_docs)]
pub fn fuzz_unpad_sealed_payload(padded: &[u8]) -> Result<(), ProtocolStateError> {
    unpad_sealed_payload(padded).map(|_| ())
}

#[cfg(fuzzing)]
#[allow(missing_docs)]
pub fn fuzz_deduplication_digest(
    digest_key: [u8; DEDUPLICATION_KEY_LEN],
    encoded_message: &[u8],
) -> [u8; DEDUPLICATION_DIGEST_LEN] {
    deduplication_digest(&digest_key, encoded_message)
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
        DEDUPLICATION_DIGEST_LEN, DEDUPLICATION_KEY_LEN, LoadedDeduplicationSet,
        MIN_DEDUPLICATION_CAPACITY, MessageTranscriptInput, PayloadKind, ProtocolStateError,
        SEALED_PAYLOAD_BUCKETS, SEALED_PAYLOAD_LEN_PREFIX_LEN, contains_digest,
        deduplication_digest, pad_sealed_payload, record_deduplication_digest,
        sign_message_transcript, unpad_sealed_payload, verify_message_transcript,
    };
    use crate::{MessageId, SenderIdentityMaterial};
    use aether_crypto::{KeyPair, SigningKeyPair, sign_identity_key_binding};
    use zeroize::Zeroizing;

    #[test]
    fn same_encrypted_bytes_under_different_deduplication_keys_have_different_digests() {
        let encoded_message = b"encoded encrypted message";
        let first_key = [1u8; DEDUPLICATION_KEY_LEN];
        let second_key = [2u8; DEDUPLICATION_KEY_LEN];

        let first = deduplication_digest(&first_key, encoded_message);
        let second = deduplication_digest(&second_key, encoded_message);

        assert_ne!(first, second);
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
            certificate: Vec::new(),
            signature: Vec::new(),
        };
        let session_key = [3u8; 16];
        let recipient_identity_key = [4u8; 32];
        let id = MessageId::from_bytes([5u8; 16]);
        let payload = b"payload";
        let signature = sign_message_transcript(
            &signing_key,
            MessageTranscriptInput {
                session_key: &session_key,
                recipient_identity_key: &recipient_identity_key,
                id,
                timestamp_millis: 6,
                payload_kind: PayloadKind::EncryptedText,
                payload,
            },
        )
        .unwrap();
        let signature_bytes = signature.to_bytes();

        let valid = || MessageTranscriptInput {
            session_key: &session_key,
            recipient_identity_key: &recipient_identity_key,
            id,
            timestamp_millis: 6,
            payload_kind: PayloadKind::EncryptedText,
            payload,
        };
        assert!(verify_message_transcript(&sender_identity, valid(), &signature_bytes).is_ok());

        let other_session_key = [7u8; 16];
        let other_recipient_identity_key = [8u8; 32];
        let other_payload = b"other payload";
        let cases = [
            MessageTranscriptInput {
                session_key: &other_session_key,
                ..valid()
            },
            MessageTranscriptInput {
                recipient_identity_key: &other_recipient_identity_key,
                ..valid()
            },
            MessageTranscriptInput {
                id: MessageId::from_bytes([9u8; 16]),
                ..valid()
            },
            MessageTranscriptInput {
                timestamp_millis: 10,
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
        ];
        for input in cases {
            assert!(verify_message_transcript(&sender_identity, input, &signature_bytes).is_err());
        }
    }
}
