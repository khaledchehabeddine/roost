//! Public protocol-state blob addressing and stateless operation results.

mod envelope;
mod message_operation;
mod session;

use crate::contact::{
    ContactDiscoveryKey, ContactEvent, ContactIdentity, ContactIdentityKey,
    ContactSafetyNumberConfirmation, ContactState, ContactStateChange, ContactTrustState,
    PeerInboxAuthorization,
};
use crate::hardening::{
    DEFAULT_DEDUPLICATION_CAPACITY, MAX_ACKNOWLEDGMENT_DIGESTS, MAX_DEDUPLICATION_CAPACITY,
    MAX_PENDING_ACKNOWLEDGMENTS, MIN_DEDUPLICATION_CAPACITY, ProtocolHardeningLimits,
    validate_deduplication_capacity,
};
use crate::safety_number::{IdentityKey, derive_safety_number, identity_key_is_valid};
use crate::{Message, MessageError, MessageId, PayloadKind, TransportBinding};
pub use envelope::SenderIdentityMaterial;
use envelope::{
    DecodedSealedSenderEnvelope, MessageMetadata, OpenedMessage, OutboundAuthentication,
    SenderAuthentication, decode_acknowledgment_plaintext, encode_acknowledgment_plaintext,
    encode_sealed_sender_envelope, open_message, seal_message, sign_message_transcript,
    validate_sender_identity, verify_message_transcript,
};
pub(crate) use message_operation::LocalSenderKeys;
pub use message_operation::{
    IncomingMessage, LocalIdentityKeys, MessageDecryption, MessageDecryptionStep,
    MessageDestination, MessageEncryption, MessageEncryptionStep, MessageOperationError,
    OutgoingMessage, SignedSenderCertificate,
};
use rand::{CryptoRng, RngCore};
use roost_crypto::{
    DiscoveryKey, Handshake, KeyPair, OneTimePreKey, PreKeyBundle, PublicDiscoveryKey,
    PublicIdentityKey, PublicKey, PublicSignedPreKey, RatchetState, RecipientDeliveryCapability,
    SenderProofTranscript, Signature, SignedPreKey, SigningKeyPair, accept_handshake,
    initiate_handshake, prove_sender, verify_discovery_to_identity_binding,
    verify_public_discovery_key, verify_sender_proof,
};
use roost_protocol::SignatureError;
use roost_protocol::{
    DomainSigningKey, DomainSigningKeyStatus, MAX_CERTIFICATE_GRACE_WINDOW, RevocationState,
    SenderCertificateIdentityKey, SenderCertificateValidationError,
    SenderCertificateValidationInput, SessionId, ValidatedSenderCertificate,
    validate_sender_certificate,
};
use roost_protocol::{
    MessageTranscriptInput, pad_sealed_payload as pad_message_payload,
    unpad_sealed_payload as unpad_message_payload,
};
use roost_protocol::{
    PUBLIC_KEY_LEN, is_valid_x25519_public_key, parse_ed25519_verifying_key_bytes,
};
#[cfg(test)]
use roost_protocol::{SEALED_PAYLOAD_BUCKETS, SEALED_PAYLOAD_LEN_PREFIX_LEN};
use roost_protocol::{from_unix_millis, to_unix_millis};
use serde::de::{Error as DeError, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use session::{
    LoadedSession, PeerSessions, SessionStatus, SignedPreKeyUse, encode_active_session,
    encode_peer_sessions, load_peer_sessions, load_session, peer_sessions_address,
    pending_acknowledgment_address, session_address,
};
use std::collections::BTreeMap;
use std::fmt;
use std::time::{Duration, SystemTime};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const PROTOCOL_STATE_BLOB_VERSION: u8 = 1;
const PROTOCOL_STATE_BLOB_HEADER_LEN: usize = 1;
const DEDUPLICATION_DIGEST_LEN: usize = 16;
const DEDUPLICATION_KEY_LEN: usize = 32;
const DEDUPLICATION_SET_KEY: &[u8] = &[0];
const ACKNOWLEDGMENT_DIGEST_LEN: usize = 16;
const MAX_PROTOCOL_STATE_KEY_LEN: usize = 96;
const PENDING_ACKNOWLEDGMENT_ENTRY_OVERHEAD_CAP: usize = 64;
const PENDING_ACKNOWLEDGMENTS_WIRE_OVERHEAD_CAP: usize = 64;

/// The key part of a protocol-state address: a SessionID, an Identity Key, or a host-chosen key.
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
    /// SessionID-addressed Double Ratchet session state.
    RatchetSession = 0,
    /// Deduplication-set state.
    DeduplicationSet = 3,
    /// SessionID-addressed pending-acknowledgment state.
    PendingAcknowledgments = 4,
    /// Identity-key-addressed contact state.
    ContactState = 5,
    /// Identity-key-addressed peer inbox authorization.
    ///
    /// Kept separate from [`Self::ContactState`] because a peer's delivery capability is a bearer
    /// secret, while contact queries return public state for host-owned views and observation.
    PeerInboxAuthorization = 6,
    /// Identity-key-addressed record of the latest local epoch whose capability a contact holds.
    ///
    /// Distribution bookkeeping, not key material: the local capability itself lives in secure
    /// storage. This answers "who still holds a superseded capability and must be re-supplied",
    /// which is what makes a post-rotation re-key both complete and resumable.
    LocalInboxAuthorization = 7,
    /// Identity-key-addressed record of the Sessions kept with one peer and the one Roost sends on.
    PeerSessions = 8,
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
            Self::PeerSessions,
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

/// The records an operation's result relies on, and the records it writes.
///
/// The host reads the record at each Commit Condition's address inside its transaction, and
/// commits the updates with the result's effects only when [`Self::matches`] holds for them.
pub struct StateChanges {
    conditions: Vec<(ProtocolStateAddress, ProtocolStateCommitCondition)>,
    updates: Vec<ProtocolStateUpdate>,
}

impl StateChanges {
    /// Returns each Commit Condition with the address it applies to, in address order.
    #[must_use]
    pub fn conditions(&self) -> &[(ProtocolStateAddress, ProtocolStateCommitCondition)] {
        &self.conditions
    }

    /// Returns the updates to commit.
    #[must_use]
    pub fn updates(&self) -> &[ProtocolStateUpdate] {
        &self.updates
    }

    /// Returns the updates to commit, consuming the changes.
    #[must_use]
    pub fn into_updates(self) -> Vec<ProtocolStateUpdate> {
        self.updates
    }

    /// Returns whether every Commit Condition holds for `current`, the host's record at each
    /// condition's address, with `None` for an absent one.
    pub fn matches(
        &self,
        current: &[(ProtocolStateAddress, Option<ProtocolStateBlob>)],
    ) -> Result<bool, StateEntryError> {
        commit_conditions_match(&self.conditions, current)
    }
}

impl From<Vec<ProtocolStateUpdate>> for StateChanges {
    /// Uses each update's own condition, for operations that read only what they write.
    fn from(updates: Vec<ProtocolStateUpdate>) -> Self {
        Self {
            conditions: updates
                .iter()
                .map(|update| (update.address.clone(), update.condition))
                .collect(),
            updates,
        }
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

/// The local Identity's keys and credentials, which authenticate the Messages it sends.
pub struct LocalSender<'a> {
    /// Public identity material and sender certificate sealed into each Message.
    pub identity: &'a SenderIdentityMaterial,
    /// Identity Key signing half, which signs Messages sent after the peer replies.
    pub signing_key: &'a SigningKeyPair,
    /// Identity Key agreement half, which proves Messages that carry a handshake.
    pub agreement_key: &'a KeyPair,
    /// Current Discovery Key, sealed into Messages that carry a handshake so the peer can reply.
    pub discovery_key: &'a PublicDiscoveryKey,
    /// The current Discovery Key's signature over the Identity Key.
    pub discovery_to_identity: &'a Signature,
}

/// Inputs for starting a Session as the X3DH initiator with its first Message.
pub struct OutboundSessionStart<'a> {
    /// Responder permanent public Identity Key.
    pub responder_identity_key: &'a PublicIdentityKey,
    /// The responder Discovery Key's signature over the responder Identity Key.
    pub responder_discovery_to_identity: &'a Signature,
    /// Responder publication bundle containing its Discovery Key and prekeys.
    pub responder_prekey_bundle: &'a PreKeyBundle,
    /// Local keys and credentials that authenticate the first Message.
    pub sender: LocalSender<'a>,
    /// Stable identifier for the first Message.
    pub id: MessageId,
    /// Sender-observed Unix timestamp in milliseconds.
    pub sent_at_millis: u64,
    /// First plaintext bytes.
    pub plaintext: &'a [u8],
}

/// A new Session and the first Message that starts it.
pub struct SessionInitiationResult {
    /// The Session both peers derive from the handshake.
    pub session_id: SessionId,
    /// X3DH first Message to send after committing `state_updates`.
    pub message: Message,
    /// Protocol-state updates for the new Session and the peer's Session list.
    pub state_updates: Vec<ProtocolStateUpdate>,
}

/// A first Message plus the local keys needed to accept the Session it starts.
pub struct InboundSessionStart<'a> {
    /// First Message carrying the handshake.
    pub message: &'a Message,
    /// Local Discovery Key the handshake targets.
    pub recipient_discovery_key: &'a DiscoveryKey,
    /// Local signed prekey the handshake names.
    pub signed_prekey: &'a SignedPreKey,
    /// Local one-time prekey the handshake names, if any.
    pub one_time_prekey: Option<OneTimePreKey>,
    /// Every signed prekey this identity still holds, so Roost can forget deleted SessionIDs that
    /// no handshake can recreate.
    pub held_signed_prekeys: &'a [PublicSignedPreKey],
    /// The app's settings for this receive.
    pub settings: ReceiveSettings,
    /// Sender-certificate validation inputs for the first Message.
    pub sender_certificate_validation: &'a InboundSenderCertificateValidation,
}

/// The result of receiving a first Message that names a Session this identity doesn't have.
pub enum SessionAcceptanceOutcome {
    /// The handshake authenticated and created a Session.
    Accepted(Box<SessionAcceptanceResult>),
    /// The Message matched an already-accepted encrypted byte sequence.
    Duplicate,
    /// The Message names a Session this identity deleted, so nothing was created.
    DeletedSession,
}

/// A Session accepted from an authenticated first Message.
pub struct SessionAcceptanceResult {
    /// The Session both peers derive from the handshake.
    pub session_id: SessionId,
    /// The sender's Identity Key and the Discovery Key it seals for replies.
    pub contact: ContactIdentity,
    /// Message ID recovered after decrypt.
    pub message_id: MessageId,
    /// Sender-observed Unix timestamp recovered after decrypt.
    pub sent_at_millis: u64,
    /// Decrypted first-message plaintext.
    pub plaintext: Zeroizing<Vec<u8>>,
    /// Sender identity material decoded after the first Message authenticated.
    pub sender_identity: SenderIdentityMaterial,
    /// Protocol-state updates to commit before treating the Session as accepted.
    pub state_updates: Vec<ProtocolStateUpdate>,
}

/// An outbound Message and the state changes from one Message Operation.
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
    pub message: Message,
    /// State changes to commit atomically with the outbound Message.
    pub changes: StateChanges,
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
                verifying_key: &key.verifying_key[..],
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

/// Inbound plaintext and the state changes from one Message Operation.
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
    /// Encrypted acknowledgment artifact to durably queue with the state changes.
    pub acknowledgment: Message,
    /// State changes to commit before treating the inbound Message as processed.
    pub changes: StateChanges,
}

/// Accepted blocked inbound Message result without consumer-visible plaintext.
pub struct BlockedInboundMessageResult {
    /// Encrypted acknowledgment artifact to durably queue with the state changes, or `None` when
    /// the blocked-contact acknowledgment policy suppresses it.
    pub acknowledgment: Option<Message>,
    /// State changes to commit before treating the blocked inbound Message as processed.
    pub changes: StateChanges,
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
        /// The Dead Session.
        session_id: SessionId,
        /// Terminal reason.
        reason: SessionUnrecoverableReason,
    },
}

/// Outcome returned for Messages addressed to a Dead Session.
pub struct SessionUnrecoverableResult {
    /// The Dead Session.
    pub session_id: SessionId,
    /// Terminal reason.
    pub reason: SessionUnrecoverableReason,
    /// Event to emit after committing `changes`, present at most once per Dead Session.
    pub event: Option<SessionEvent>,
    /// State changes to commit before surfacing the event.
    pub changes: StateChanges,
}

/// An authenticated acknowledgment and the state it advanced.
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
    /// State changes to commit, matched or not, so a retried acknowledgment is a duplicate.
    pub changes: StateChanges,
}

/// The result of receiving an inbound encrypted Message.
pub enum InboundMessageOutcome {
    /// A unique Message decrypted and advanced protocol state.
    Accepted(Box<InboundMessageResult>),
    /// A unique blocked Message decrypted and advanced protocol state.
    Blocked(Box<BlockedInboundMessageResult>),
    /// The Message matched an already-accepted encrypted byte sequence.
    Duplicate,
    /// The Session is permanently unrecoverable and no plaintext was produced.
    SessionUnrecoverable(Box<SessionUnrecoverableResult>),
    /// The Message names a Session this identity doesn't have, and nothing changed.
    ///
    /// A Message that carries a handshake may still start that Session through acceptance.
    UnknownSession,
    /// An acknowledgment cleared one of this identity's Pending Acknowledgments.
    AcknowledgmentMatched(Box<AcknowledgmentResult>),
    /// An authenticated acknowledgment named no Pending Acknowledgment, such as one already
    /// cleared.
    AcknowledgmentUnmatched(Box<AcknowledgmentResult>),
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

    /// Returns how many received-message digests the Deduplication Set keeps.
    #[must_use]
    pub fn deduplication_capacity(&self) -> usize {
        self.deduplication_capacity
    }

    /// Returns whether a blocked sender receives an acknowledgment.
    #[must_use]
    pub fn blocked_contact_acknowledgment_policy(&self) -> BlockedContactAcknowledgmentPolicy {
        self.blocked_contact_acknowledgment_policy
    }

    /// Returns how long after expiry a sender certificate still validates.
    #[must_use]
    pub fn certificate_grace(&self) -> Duration {
        self.certificate_grace
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
    /// Creates a stateless protocol-state engine.
    #[must_use]
    pub fn new() -> Self {
        Self {
            limits: ProtocolHardeningLimits::default(),
        }
    }

    /// Returns the hardening limits used by this engine.
    #[must_use]
    pub fn hardening_limits(&self) -> ProtocolHardeningLimits {
        self.limits
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
    /// Returns updates to commit, or an empty vector when `epoch` is not newer than what is
    /// already stored. Refusing a lower epoch matters because an old authorization replayed at
    /// a contact would restore a capability the peer has already rotated away from — the exact
    /// state a blocked sender would want to reach.
    ///
    /// The capability never enters [`ContactState`], so it is not mirrored to event observers.
    pub fn record_peer_inbox_authorization(
        &self,
        snapshot: &ProtocolStateSnapshot,
        identity_key: ContactIdentityKey,
        epoch: u32,
        capability: &RecipientDeliveryCapability,
    ) -> Result<Vec<ProtocolStateUpdate>, ProtocolStateError> {
        let address = peer_inbox_authorization_address(identity_key);
        validate_contact_identity_key(&address, &identity_key)?;
        if let Some(stored) = load_peer_inbox_authorization(snapshot, &address, self.limits)?
            && epoch <= stored.epoch
        {
            return Ok(Vec::new());
        }
        let wire = PeerInboxAuthorizationWire {
            epoch,
            capability: *capability.to_bytes(),
        };
        let body = encode_zeroizing(&wire).map_err(|e| ProtocolStateError::BlobEncode {
            address: address.clone(),
            reason: e.to_string(),
        })?;
        let blob = encode_blob(&address, &body, self.limits.max_protocol_state_blob_len)?;
        Ok(vec![
            ProtocolStateUpdate::set(address, blob).with_snapshot(snapshot),
        ])
    }

    /// Records that `identity_key` has been given the delivery capability for local epoch `epoch`.
    ///
    /// Call this only after the in-band authorization update has actually been handed to the
    /// transport, so an app killed mid-re-key resumes rather than skipping contacts. Returns no
    /// updates when the contact already holds this epoch's capability or a newer one.
    pub fn record_inbox_authorization_delivered(
        &self,
        snapshot: &ProtocolStateSnapshot,
        identity_key: ContactIdentityKey,
        epoch: u32,
    ) -> Result<Vec<ProtocolStateUpdate>, ProtocolStateError> {
        let address = local_inbox_authorization_address(identity_key);
        validate_contact_identity_key(&address, &identity_key)?;
        if let Some(delivered) =
            load_delivered_inbox_authorization(snapshot, &address, self.limits)?
            && epoch <= delivered
        {
            return Ok(Vec::new());
        }
        let body = postcard::to_stdvec(&LocalInboxAuthorizationWire { epoch }).map_err(|e| {
            ProtocolStateError::BlobEncode {
                address: address.clone(),
                reason: e.to_string(),
            }
        })?;
        let blob = encode_blob(&address, &body, self.limits.max_protocol_state_blob_len)?;
        Ok(vec![
            ProtocolStateUpdate::set(address, blob).with_snapshot(snapshot),
        ])
    }

    /// Returns the latest local epoch whose capability `identity_key` was given, if any.
    pub fn delivered_inbox_authorization(
        &self,
        snapshot: &ProtocolStateSnapshot,
        identity_key: ContactIdentityKey,
    ) -> Result<Option<u32>, ProtocolStateError> {
        let address = local_inbox_authorization_address(identity_key);
        validate_contact_identity_key(&address, &identity_key)?;
        load_delivered_inbox_authorization(snapshot, &address, self.limits)
    }

    /// Returns which of `candidates` still need the current epoch's delivery capability.
    ///
    /// A contact qualifies when it has never been given an authorization, or was last given one
    /// older than `current_epoch`. **Blocked contacts are always excluded**: re-supplying a
    /// blocked contact would hand back the very capability the rotation revoked and silently undo
    /// the block. Contacts with no stored contact record are skipped.
    pub fn contacts_needing_inbox_authorization(
        &self,
        snapshot: &ProtocolStateSnapshot,
        current_epoch: u32,
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
                self.limits,
            )?;
            if delivered.is_none_or(|delivered| delivered < current_epoch) {
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
        load_peer_inbox_authorization(snapshot, &address, self.limits)
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

    /// Starts a Session with the responder whose bundle the caller fetched, and seals its first
    /// Message.
    ///
    /// The responder's Discovery Key must vouch for its Identity Key, as well as the reverse. Until
    /// the responder replies, every Message on the new Session carries the handshake. The caller
    /// must retain the exact binding with the returned Message for retransmission.
    pub fn initiate_session<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        snapshot: &ProtocolStateSnapshot,
        start: OutboundSessionStart<'_>,
        transport_binding: &TransportBinding,
    ) -> Result<SessionInitiationResult, ProtocolStateError> {
        verify_discovery_to_identity_binding(
            start.responder_identity_key,
            &start.responder_prekey_bundle.discovery_key.verifying_key,
            start.responder_discovery_to_identity,
        )
        .map_err(roost_crypto::HandshakeError::from)?;
        validate_sender_identity(start.sender.identity, self.limits)?;
        let peer_identity_key = ContactIdentityKey {
            x25519_public_key: *start.responder_identity_key.public_key.as_bytes(),
            ed25519_verifying_key: start.responder_identity_key.verifying_key.to_bytes(),
        };
        let (mut state, session_id, handshake) = initiate_handshake(
            rng,
            start.responder_identity_key,
            start.responder_prekey_bundle,
        )?;
        let address = session_address(session_id);
        if snapshot.get(&address).is_some() {
            return Err(ProtocolStateError::InvalidStateBinding {
                address,
                reason: "session already exists".into(),
            });
        }
        let message = seal_proved(
            rng,
            &mut state,
            OutboundContent {
                session_id,
                id: start.id,
                sent_at_millis: start.sent_at_millis,
                plaintext: start.plaintext,
            },
            &handshake,
            &start.sender,
            transport_binding,
            self.limits,
        )?;
        let peer_address = peer_sessions_address(peer_identity_key);
        let (peer_sessions, evicted) =
            match load_peer_sessions(snapshot, &peer_address, self.limits)? {
                Some(mut sessions) => {
                    let evicted = sessions.start(session_id, None);
                    (sessions, evicted)
                }
                None => (PeerSessions::new(session_id, None), Vec::new()),
            };
        let mut state_updates = self.new_session_updates(
            snapshot,
            session_id,
            peer_identity_key,
            &state,
            Some(&handshake),
        )?;
        state_updates.push(
            ProtocolStateUpdate::set(
                peer_address.clone(),
                encode_peer_sessions(&peer_address, &peer_sessions, self.limits)?,
            )
            .with_snapshot(snapshot),
        );
        state_updates.extend(session_deletions(snapshot, &evicted));
        Ok(SessionInitiationResult {
            session_id,
            message,
            state_updates,
        })
    }

    /// Accepts the Session a first Message starts, after authenticating its sender.
    ///
    /// Call this only after a [`MessageDecryption`] returned
    /// [`InboundMessageOutcome::UnknownSession`] for a Message that carries a handshake. The sender
    /// must prove its Identity Key, seal a Discovery Key both bound to it, and present a valid
    /// certificate for it. The new Session becomes the one Roost sends on, except that when this
    /// side's own new Session with the peer still awaits a reply, the lower SessionID wins.
    pub fn accept_session<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        snapshot: &ProtocolStateSnapshot,
        inbound: InboundSessionStart<'_>,
        transport_binding: &TransportBinding,
    ) -> Result<SessionAcceptanceOutcome, ProtocolStateError> {
        let encoded = inbound
            .message
            .to_bytes()
            .map_err(ProtocolStateError::MessageEncode)?;
        let deduplication_address = deduplication_address();
        let mut deduplication =
            receiving_deduplication_set(rng, snapshot, inbound.settings, self.limits)?;
        let digest = deduplication_digest(
            &deduplication.digest_key,
            transport_binding.as_bytes(),
            &encoded,
        );
        if contains_digest(&deduplication.digests, &digest) {
            return Ok(SessionAcceptanceOutcome::Duplicate);
        }
        let prekey_reference =
            inbound
                .message
                .prekey_reference
                .ok_or_else(|| ProtocolStateError::InvalidMessage {
                    reason: "message carries no handshake".into(),
                })?;
        let opened = open_message(
            inbound.message,
            inbound.recipient_discovery_key,
            transport_binding,
        )?;
        let session_id = opened.metadata.session_id;
        let address = session_address(session_id);
        // The host passes a Message here only after decrypting it found no Session.
        if snapshot.get(&address).is_some() {
            return Err(ProtocolStateError::InvalidMessage {
                reason: "message names a session this identity already has".into(),
            });
        }
        ensure_payload_kind(&opened, PayloadKind::EncryptedText)?;
        let base_key =
            opened
                .metadata
                .base_key
                .ok_or_else(|| ProtocolStateError::InvalidMessage {
                    reason: "message carries no handshake".into(),
                })?;
        let handshake = Handshake {
            base_key: PublicKey::from(base_key),
            responder_discovery_key: PublicKey::from(inbound.message.recipient_public_key),
            prekey_reference,
        };
        let (mut state, derived_session_id) = accept_handshake(
            &handshake,
            inbound.recipient_discovery_key,
            inbound.signed_prekey,
            inbound.one_time_prekey,
        )?;
        if !bool::from(derived_session_id.as_bytes().ct_eq(session_id.as_bytes())) {
            return Err(ProtocolStateError::InvalidMessage {
                reason: "session id does not match its handshake".into(),
            });
        }
        let decoded = opened.decrypt(rng, &mut state, self.limits)?;
        let contact = authenticate_first_message(&decoded, &handshake, inbound.signed_prekey)?;
        let peer_identity_key = inbound_contact_identity_key(
            inbound.sender_certificate_validation,
            inbound.settings.certificate_grace(),
            &decoded.sender_identity,
            Some(contact.identity_key),
            self.limits,
        )?;
        let peer_address = peer_sessions_address(peer_identity_key);
        let accepted_with = Some(SignedPreKeyUse {
            epoch: prekey_reference.discovery_epoch,
            public_key: prekey_reference.signed_prekey_public_key,
        });
        let (peer_sessions, evicted) =
            match load_peer_sessions(snapshot, &peer_address, self.limits)? {
                // The Session's blob is gone by now, so one the list still names was wiped by the
                // host.
                Some(sessions)
                    if sessions.was_deleted(session_id) || sessions.contains(session_id) =>
                {
                    return Ok(SessionAcceptanceOutcome::DeletedSession);
                }
                Some(mut sessions) => {
                    sessions.forget_deletions_unless(|signed_prekey| {
                        inbound.held_signed_prekeys.iter().any(|held| {
                            held.epoch == signed_prekey.epoch
                                && held.public_key.as_bytes() == &signed_prekey.public_key
                        })
                    });
                    let evicted = if self.awaits_reply(snapshot, sessions.current())? {
                        sessions.start_alongside(session_id, accepted_with)
                    } else {
                        sessions.start(session_id, accepted_with)
                    };
                    (sessions, evicted)
                }
                None => (PeerSessions::new(session_id, accepted_with), Vec::new()),
            };
        record_deduplication_digest(&mut deduplication, digest);
        let mut state_updates =
            self.new_session_updates(snapshot, session_id, peer_identity_key, &state, None)?;
        state_updates.push(
            ProtocolStateUpdate::set(
                peer_address.clone(),
                encode_peer_sessions(&peer_address, &peer_sessions, self.limits)?,
            )
            .with_snapshot(snapshot),
        );
        state_updates.push(
            ProtocolStateUpdate::set(
                deduplication_address.clone(),
                encode_deduplication_set(&deduplication_address, &deduplication, self.limits)?,
            )
            .with_snapshot(snapshot),
        );
        state_updates.extend(session_deletions(snapshot, &evicted));
        Ok(SessionAcceptanceOutcome::Accepted(Box::new(
            SessionAcceptanceResult {
                session_id,
                contact,
                message_id: opened.metadata.id,
                sent_at_millis: opened.metadata.sent_at_millis,
                plaintext: decoded.plaintext,
                sender_identity: decoded.sender_identity,
                state_updates,
            },
        )))
    }

    /// Returns all pending acknowledgments stored for a Session.
    pub fn pending_acknowledgments(
        &self,
        snapshot: &ProtocolStateSnapshot,
        session_id: SessionId,
    ) -> Result<Vec<PendingAcknowledgment>, ProtocolStateError> {
        let address = pending_acknowledgment_address(session_id);
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

    /// Returns retry instructions for a Session's pending acknowledgments whose retry window has
    /// elapsed.
    ///
    /// `now` is caller supplied so retry behavior is deterministic in tests and does not read the
    /// system clock.
    pub fn retry_instructions(
        &self,
        snapshot: &ProtocolStateSnapshot,
        session_id: SessionId,
        now: SystemTime,
        retry_window: Duration,
    ) -> Result<RetryInstructionResult, ProtocolStateError> {
        let address = pending_acknowledgment_address(session_id);
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

    // Returns the blobs a new Session starts with: its ratchet state and an empty pending list.
    fn new_session_updates(
        &self,
        snapshot: &ProtocolStateSnapshot,
        session_id: SessionId,
        peer_identity_key: ContactIdentityKey,
        state: &RatchetState,
        pending_handshake: Option<&Handshake>,
    ) -> Result<Vec<ProtocolStateUpdate>, ProtocolStateError> {
        let address = session_address(session_id);
        let pending_address = pending_acknowledgment_address(session_id);
        let pending = LoadedPendingAcknowledgments {
            pending: BTreeMap::new(),
            acknowledgment_digests: Vec::new(),
        };
        Ok(vec![
            ProtocolStateUpdate::set(
                address.clone(),
                encode_active_session(
                    &address,
                    peer_identity_key,
                    state,
                    pending_handshake,
                    self.limits,
                )?,
            )
            .with_snapshot(snapshot),
            ProtocolStateUpdate::set(
                pending_address.clone(),
                encode_pending_acknowledgments(&pending_address, &pending, self.limits)?,
            )
            .with_snapshot(snapshot),
        ])
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

    // Returns whether this side started `session_id` and hasn't heard back on it yet. A Session the
    // host wiped awaits nothing, so the peer's new handshake can replace it.
    fn awaits_reply(
        &self,
        snapshot: &ProtocolStateSnapshot,
        session_id: SessionId,
    ) -> Result<bool, ProtocolStateError> {
        let Some(session) = load_session(snapshot, &session_address(session_id), self.limits)?
        else {
            return Ok(false);
        };
        Ok(matches!(
            session.status,
            SessionStatus::Active {
                pending_handshake: Some(_),
                ..
            }
        ))
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
    /// No Session exists with the contact, so a fresh handshake must start one.
    #[error("no session with this contact")]
    NoSession,
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
    hasher.update(blob);
    *hasher.finalize().as_bytes()
}

// The Deduplication Set is the only record of its kind, so its key is fixed.
fn deduplication_address() -> ProtocolStateAddress {
    ProtocolStateAddress::new(
        ProtocolStateKind::DeduplicationSet,
        ProtocolStateKey(DEDUPLICATION_SET_KEY.to_vec()),
    )
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
    limits: ProtocolHardeningLimits,
) -> Result<Option<u32>, ProtocolStateError> {
    let Some(blob) = snapshot.get(address) else {
        return Ok(None);
    };
    let wire: LocalInboxAuthorizationWire = decode_inbox_authorization(address, blob, limits)?;
    Ok(Some(wire.epoch))
}

fn load_peer_inbox_authorization(
    snapshot: &ProtocolStateSnapshot,
    address: &ProtocolStateAddress,
    limits: ProtocolHardeningLimits,
) -> Result<Option<PeerInboxAuthorization>, ProtocolStateError> {
    let Some(blob) = snapshot.get(address) else {
        return Ok(None);
    };
    let wire: PeerInboxAuthorizationWire = decode_inbox_authorization(address, blob, limits)?;
    Ok(Some(PeerInboxAuthorization {
        epoch: wire.epoch,
        capability: RecipientDeliveryCapability::from_bytes(wire.capability),
    }))
}

fn decode_inbox_authorization<T: serde::de::DeserializeOwned>(
    address: &ProtocolStateAddress,
    blob: &ProtocolStateBlob,
    limits: ProtocolHardeningLimits,
) -> Result<T, ProtocolStateError> {
    let body = blob_body(address, blob, limits.max_protocol_state_blob_len)?;
    let (wire, trailing) =
        postcard::take_from_bytes(body).map_err(|e| ProtocolStateError::BlobDecode {
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
    capacity: u16,
    digest_key: &'a [u8; DEDUPLICATION_KEY_LEN],
    digests: &'a [[u8; DEDUPLICATION_DIGEST_LEN]],
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct DecodedDeduplicationSetWire {
    capacity: u16,
    digest_key: [u8; DEDUPLICATION_KEY_LEN],
    digests: Vec<[u8; DEDUPLICATION_DIGEST_LEN]>,
}

#[derive(Serialize)]
struct PendingAcknowledgmentsWire<'a> {
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
                .is_some_and(|len| len > MAX_PENDING_ACKNOWLEDGMENTS)
            {
                return Err(A::Error::custom(
                    "pending acknowledgment count exceeds limit",
                ));
            }
            let capacity = seq
                .size_hint()
                .unwrap_or(0)
                .min(MAX_PENDING_ACKNOWLEDGMENTS);
            let mut pending = Vec::with_capacity(capacity);
            while let Some(entry) = seq.next_element()? {
                if pending.len() == MAX_PENDING_ACKNOWLEDGMENTS {
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
                .is_some_and(|len| len > MAX_ACKNOWLEDGMENT_DIGESTS)
            {
                return Err(A::Error::custom(
                    "acknowledgment digest count exceeds limit",
                ));
            }
            let capacity = seq.size_hint().unwrap_or(0).min(MAX_ACKNOWLEDGMENT_DIGESTS);
            let mut digests = Vec::with_capacity(capacity);
            while let Some(digest) = seq.next_element()? {
                if digests.len() == MAX_ACKNOWLEDGMENT_DIGESTS {
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
    epoch: u32,
}

// Persistence requires serialization; `ZeroizeOnDrop` scrubs the temporary bearer-secret copy.
#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
struct PeerInboxAuthorizationWire {
    epoch: u32,
    capability: [u8; 32],
}

#[derive(Serialize)]
struct ContactStateWire<'a> {
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
struct DecodedContactStateWire {
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
    let body = encode_zeroizing(&DeduplicationSetWire {
        capacity: state.capacity as u16,
        digest_key: &state.digest_key,
        digests: &state.digests,
    })
    .map_err(|_| ProtocolStateError::BlobEncode {
        address: address.clone(),
        reason: "deduplication set failed to encode".into(),
    })?;
    encode_blob(address, &body, limits.max_protocol_state_blob_len)
}

// Returns the Deduplication Set at the size `settings` names, creating it on the first receive and
// evicting the oldest digests when the size shrinks.
fn receiving_deduplication_set<R: RngCore + CryptoRng>(
    rng: &mut R,
    snapshot: &ProtocolStateSnapshot,
    settings: ReceiveSettings,
    limits: ProtocolHardeningLimits,
) -> Result<LoadedDeduplicationSet, ProtocolStateError> {
    let address = deduplication_address();
    let mut set = match snapshot.get(&address) {
        Some(blob) => decode_deduplication_set(&address, blob, limits)?,
        None => {
            let mut digest_key = Zeroizing::new([0u8; DEDUPLICATION_KEY_LEN]);
            rng.try_fill_bytes(&mut digest_key[..])
                .map_err(ProtocolStateError::Randomness)?;
            LoadedDeduplicationSet {
                capacity: settings.deduplication_capacity(),
                digest_key,
                digests: Vec::new(),
            }
        }
    };
    set.capacity = settings.deduplication_capacity();
    let excess = set.digests.len().saturating_sub(set.capacity);
    set.digests.drain(..excess);
    Ok(set)
}

fn decode_deduplication_set(
    address: &ProtocolStateAddress,
    blob: &ProtocolStateBlob,
    limits: ProtocolHardeningLimits,
) -> Result<LoadedDeduplicationSet, ProtocolStateError> {
    let body = blob_body(address, blob, limits.max_protocol_state_blob_len)?;
    let (mut wire, trailing): (DecodedDeduplicationSetWire, &[u8]) =
        postcard::take_from_bytes(body).map_err(|e| ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: e.to_string(),
        })?;
    let digest_key = Zeroizing::new(wire.digest_key);
    let capacity = usize::from(wire.capacity);
    if !trailing.is_empty() {
        return Err(ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: "deduplication set has trailing bytes".into(),
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
    let body = Zeroizing::new(
        postcard::to_stdvec(&PendingAcknowledgmentsWire {
            pending,
            acknowledgment_digests: &state.acknowledgment_digests,
        })
        .map_err(|_| ProtocolStateError::BlobEncode {
            address: address.clone(),
            reason: "pending acknowledgments failed to encode".into(),
        })?,
    );
    encode_blob(address, &body, max_pending_acknowledgments_blob_len(limits))
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
    let body = blob_body(address, blob, max_pending_acknowledgments_blob_len(limits))?;
    decode_pending_acknowledgments_payload(address, body, limits)
}

fn decode_pending_acknowledgment_digests(
    address: &ProtocolStateAddress,
    blob: &ProtocolStateBlob,
    limits: ProtocolHardeningLimits,
) -> Result<Vec<[u8; ACKNOWLEDGMENT_DIGEST_LEN]>, ProtocolStateError> {
    let body = blob_body(address, blob, max_pending_acknowledgments_blob_len(limits))?;
    decode_pending_acknowledgment_digests_payload(address, body, limits)
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
    if !trailing.is_empty() {
        return Err(ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: "pending acknowledgments have trailing bytes".into(),
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
        let message = Message::from_bytes(&entry.encoded_message).map_err(|e| {
            ProtocolStateError::BlobDecode {
                address: address.clone(),
                reason: format!("pending acknowledgment message failed to decode: {e}"),
            }
        })?;
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
    let body = postcard::to_stdvec(&wire).map_err(|_| ProtocolStateError::BlobEncode {
        address: address.clone(),
        reason: "contact state failed to encode".into(),
    })?;
    encode_blob(address, &body, limits.max_protocol_state_blob_len)
}

fn decode_contact_state(
    address: &ProtocolStateAddress,
    blob: &ProtocolStateBlob,
    limits: ProtocolHardeningLimits,
) -> Result<ContactState, ProtocolStateError> {
    let body = blob_body(address, blob, limits.max_protocol_state_blob_len)?;
    let (wire, trailing): (DecodedContactStateWire, &[u8]) = postcard::take_from_bytes(body)
        .map_err(|_| ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: "contact-state payload failed to decode".into(),
        })?;
    if !trailing.is_empty() {
        return Err(ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: "contact state has trailing bytes".into(),
        });
    }
    decoded_contact_state(address, wire)
}

fn decoded_contact_state(
    address: &ProtocolStateAddress,
    wire: DecodedContactStateWire,
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

fn inbound_contact_identity_key(
    validation: &InboundSenderCertificateValidation,
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
    let validated = validation
        .validate(
            &sender_identity.certificate,
            &sender_identity.signature,
            certificate_grace,
        )
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

// What one outbound Message says, before Roost seals it.
struct OutboundContent<'a> {
    session_id: SessionId,
    id: MessageId,
    sent_at_millis: u64,
    plaintext: &'a [u8],
}

// Where a signed Message goes and whose Identity Key its transcript names.
struct SignedRecipient<'a> {
    discovery_key: [u8; PUBLIC_KEY_LEN],
    identity_verifying_key: &'a [u8; PUBLIC_KEY_LEN],
}

// Seals a Message whose sender signs its transcript, as every Message after the handshake does.
#[expect(
    clippy::too_many_arguments,
    reason = "each argument is a separate input to one signed Message"
)]
fn seal_signed<R: RngCore + CryptoRng>(
    rng: &mut R,
    state: &mut RatchetState,
    content: OutboundContent<'_>,
    payload_kind: PayloadKind,
    recipient: SignedRecipient<'_>,
    sender_identity: &SenderIdentityMaterial,
    signing_key: &SigningKeyPair,
    transport_binding: &TransportBinding,
    limits: ProtocolHardeningLimits,
) -> Result<Message, ProtocolStateError> {
    let padded_plaintext = pad_sealed_payload(content.plaintext)?;
    let signature = sign_message_transcript(
        signing_key,
        MessageTranscriptInput {
            session_id: content.session_id,
            recipient_identity_verifying_key: recipient.identity_verifying_key,
            id: content.id,
            sent_at_millis: content.sent_at_millis,
            payload_kind,
            payload: &padded_plaintext,
            sender_certificate: &sender_identity.certificate,
        },
    )?;
    let envelope = encode_sealed_sender_envelope(
        sender_identity,
        OutboundAuthentication::Signature(&signature),
        &padded_plaintext,
        limits,
    )?;
    seal_message(
        rng,
        state,
        MessageMetadata {
            session_id: content.session_id,
            base_key: None,
            id: content.id,
            sent_at_millis: content.sent_at_millis,
            payload_kind,
        },
        recipient.discovery_key,
        None,
        &envelope,
        transport_binding,
    )
}

// Seals a Message that carries the handshake and proves its sender instead of signing.
fn seal_proved<R: RngCore + CryptoRng>(
    rng: &mut R,
    state: &mut RatchetState,
    content: OutboundContent<'_>,
    handshake: &Handshake,
    sender: &LocalSender<'_>,
    transport_binding: &TransportBinding,
    limits: ProtocolHardeningLimits,
) -> Result<Message, ProtocolStateError> {
    let padded_plaintext = pad_sealed_payload(content.plaintext)?;
    let proof = prove_sender(
        sender.agreement_key,
        &SenderProofTranscript {
            handshake,
            sender_identity_key: &sender.identity.public_identity_key()?,
            sender_discovery_key: sender.discovery_key,
            sender_certificate: &sender.identity.certificate,
            sender_certificate_signature: &sender.identity.signature,
        },
    )?;
    let envelope = encode_sealed_sender_envelope(
        sender.identity,
        OutboundAuthentication::Proof {
            discovery_key: sender.discovery_key,
            discovery_to_identity: sender.discovery_to_identity,
            proof: &proof,
        },
        &padded_plaintext,
        limits,
    )?;
    seal_message(
        rng,
        state,
        MessageMetadata {
            session_id: content.session_id,
            base_key: Some(*handshake.base_key.as_bytes()),
            id: content.id,
            sent_at_millis: content.sent_at_millis,
            payload_kind: PayloadKind::EncryptedText,
        },
        *handshake.responder_discovery_key.as_bytes(),
        Some(handshake.prekey_reference),
        &envelope,
        transport_binding,
    )
}

// Checks a first Message's proof and the Discovery Key it seals, and returns the sender they
// authenticate.
fn authenticate_first_message(
    decoded: &DecodedSealedSenderEnvelope,
    handshake: &Handshake,
    signed_prekey: &SignedPreKey,
) -> Result<ContactIdentity, ProtocolStateError> {
    let SenderAuthentication::Proof {
        discovery_key,
        discovery_to_identity,
        proof,
    } = &decoded.authentication
    else {
        return Err(ProtocolStateError::InvalidMessage {
            reason: "first message carries no sender proof".into(),
        });
    };
    let sender_identity_key = decoded.sender_identity.public_identity_key()?;
    verify_public_discovery_key(discovery_key, &sender_identity_key.verifying_key).map_err(
        |_| ProtocolStateError::InvalidMessage {
            reason: "sender discovery key is not signed by its identity key".into(),
        },
    )?;
    verify_discovery_to_identity_binding(
        &sender_identity_key,
        &discovery_key.verifying_key,
        discovery_to_identity,
    )
    .map_err(|_| ProtocolStateError::InvalidMessage {
        reason: "sender discovery key does not sign its identity key".into(),
    })?;
    verify_sender_proof(
        signed_prekey,
        &SenderProofTranscript {
            handshake,
            sender_identity_key: &sender_identity_key,
            sender_discovery_key: discovery_key,
            sender_certificate: &decoded.sender_identity.certificate,
            sender_certificate_signature: &decoded.sender_identity.signature,
        },
        proof,
    )?;
    Ok(ContactIdentity {
        identity_key: decoded.sender_identity.contact_identity_key(),
        discovery_key: ContactDiscoveryKey::from(&**discovery_key),
    })
}

// Checks that a Message on a known Session comes from the Session's peer and, after the handshake,
// that the peer signed it.
//
// A Message that still carries the handshake needs no further check: only the peer holds the
// Session's keys, and the handshake was proved when the Session was created.
fn authenticate_session_message(
    decoded: &DecodedSealedSenderEnvelope,
    opened: &OpenedMessage,
    peer_identity_key: ContactIdentityKey,
    recipient_identity_verifying_key: &[u8; PUBLIC_KEY_LEN],
) -> Result<(), ProtocolStateError> {
    if !contact_identity_keys_match(
        &decoded.sender_identity.contact_identity_key(),
        &peer_identity_key,
    ) {
        return Err(ProtocolStateError::InvalidMessage {
            reason: "sealed sender identity key does not match session".into(),
        });
    }
    match &decoded.authentication {
        SenderAuthentication::Signature(signature) => verify_message_transcript(
            &decoded.sender_identity,
            MessageTranscriptInput {
                session_id: opened.metadata.session_id,
                recipient_identity_verifying_key,
                id: opened.metadata.id,
                sent_at_millis: opened.metadata.sent_at_millis,
                payload_kind: opened.metadata.payload_kind,
                payload: &decoded.padded_plaintext,
                sender_certificate: &decoded.sender_identity.certificate,
            },
            signature,
        ),
        SenderAuthentication::Proof { .. } => Ok(()),
    }
}

fn ensure_payload_kind(
    opened: &OpenedMessage,
    expected: PayloadKind,
) -> Result<(), ProtocolStateError> {
    if opened.metadata.payload_kind != expected {
        return Err(ProtocolStateError::InvalidMessage {
            reason: format!("message payload is not {expected:?}"),
        });
    }
    Ok(())
}

// Checks that the local Discovery Key belongs to the local Identity Key a transcript names.
fn verify_recipient_keys(
    recipient_discovery_key: &DiscoveryKey,
    recipient_identity_verifying_key: &[u8; PUBLIC_KEY_LEN],
) -> Result<(), ProtocolStateError> {
    let recipient_identity_verifying_key =
        parse_ed25519_verifying_key_bytes(recipient_identity_verifying_key).ok_or_else(|| {
            ProtocolStateError::InvalidMessage {
                reason: "recipient identity verifying key is not canonical".into(),
            }
        })?;
    verify_public_discovery_key(
        &recipient_discovery_key.public(),
        &recipient_identity_verifying_key,
    )
    .map_err(|_| ProtocolStateError::InvalidMessage {
        reason: "recipient discovery key does not match recipient identity key".into(),
    })
}

fn load_required_session(
    snapshot: &ProtocolStateSnapshot,
    address: &ProtocolStateAddress,
    limits: ProtocolHardeningLimits,
) -> Result<LoadedSession, ProtocolStateError> {
    load_session(snapshot, address, limits)?.ok_or_else(|| {
        ProtocolStateError::MissingRequiredState {
            address: address.clone(),
        }
    })
}

// Returns the deletions for each evicted Session's blobs.
fn session_deletions(
    snapshot: &ProtocolStateSnapshot,
    evicted: &[SessionId],
) -> Vec<ProtocolStateUpdate> {
    evicted
        .iter()
        .flat_map(|session_id| {
            [
                session_address(*session_id),
                pending_acknowledgment_address(*session_id),
            ]
        })
        .map(|address| ProtocolStateUpdate::delete(address).with_snapshot(snapshot))
        .collect()
}

// Returns an accepted, unblocked contact that new Messages may go to.
fn outbound_contact(
    snapshot: &ProtocolStateSnapshot,
    identity_key: ContactIdentityKey,
    limits: ProtocolHardeningLimits,
) -> Result<ContactState, ProtocolStateError> {
    let address = contact_address(identity_key);
    validate_contact_identity_key(&address, &identity_key)?;
    let contact = load_contact_state(snapshot, &address, limits)?;
    if contact.blocked {
        return Err(ProtocolStateError::BlockedContact);
    }
    if contact.trust_state == ContactTrustState::Pending {
        return Err(ProtocolStateError::ContactNotAccepted);
    }
    Ok(contact)
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
        .to_bytes()
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

fn copy_message(message: &Message) -> Message {
    Message {
        version: message.version,
        recipient_public_key: message.recipient_public_key,
        prekey_reference: message.prekey_reference,
        ephemeral_public_key: message.ephemeral_public_key,
        ciphertext: message.ciphertext.clone(),
    }
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
        MIN_DEDUPLICATION_CAPACITY, PROTOCOL_STATE_BLOB_VERSION, ProtocolStateError,
        SEALED_PAYLOAD_BUCKETS, SEALED_PAYLOAD_LEN_PREFIX_LEN, acknowledgment_digest, blob_body,
        contains_digest, deduplication_digest, pad_sealed_payload, protocol_state_blob_digest,
        record_deduplication_digest, unpad_sealed_payload,
    };
    use crate::{ProtocolStateAddress, ProtocolStateBlob, ProtocolStateKey, ProtocolStateKind};
    use zeroize::Zeroizing;

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
}
