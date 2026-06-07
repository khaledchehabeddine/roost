//! Public protocol-state blob addressing and stateless operation results.

use crate::contact::{
    ContactDiscoveryKey, ContactEvent, ContactIdentity, ContactIdentityKey,
    ContactSafetyNumberConfirmation, ContactState, ContactStateChange, ContactTrustState,
};
use crate::key_encoding::{
    PUBLIC_KEY_LEN, parse_ed25519_verifying_key_bytes, validate_x25519_public_key,
};
use crate::message::{MAX_ENCODED_MESSAGE_LEN, MAX_MESSAGE_PAYLOAD_LEN};
use crate::safety_number::{IdentityKey, derive_safety_number, identity_key_is_valid};
use crate::{Message, MessageError, MessageId, PayloadKind};
use aether_crypto::{
    DiscoveryKeyBundle, Header, PublicKey, RatchetState, SenderIdentityMaterial, Signature,
    verify_discovery_key_bundle,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
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
const DEDUPLICATION_SET_WIRE_VERSION: u8 = 1;
const PENDING_ACKNOWLEDGMENTS_WIRE_VERSION: u8 = 1;
const CONTACT_STATE_WIRE_VERSION: u8 = 1;
const ACKNOWLEDGMENT_PLAINTEXT_WIRE_VERSION: u8 = 1;
const DEDUPLICATION_DIGEST_LEN: usize = 16;
const DEDUPLICATION_KEY_LEN: usize = 32;
const ACKNOWLEDGMENT_DIGEST_LEN: usize = 16;
const RATCHET_PAYLOAD_VERSION: u8 = 1;
const RATCHET_PAYLOAD_HEADER_LEN: usize = 1 + 32 + 4 + 4;
const RATCHET_AEAD_TAG_LEN: usize = 16;
const SEALED_SENDER_ENVELOPE_VERSION: u8 = 1;
const SEALED_SENDER_ENCODING_OVERHEAD_CAP: usize = 64;
const MAX_SEALED_SENDER_ENVELOPE_LEN: usize =
    MAX_MESSAGE_PAYLOAD_LEN - RATCHET_PAYLOAD_HEADER_LEN - RATCHET_AEAD_TAG_LEN;
const MAX_SEALED_SENDER_CONTENT_LEN: usize =
    MAX_SEALED_SENDER_ENVELOPE_LEN - 32 - SEALED_SENDER_ENCODING_OVERHEAD_CAP;
const MAX_SENDER_CERTIFICATE_LEN: usize = 16 * 1024;
const MAX_SENDER_SIGNATURE_LEN: usize = 4 * 1024;
const MAX_PROTOCOL_STATE_BLOB_LEN: usize = 64 * 1024;
const MAX_PROTOCOL_STATE_KEY_LEN: usize = 96;
const MAX_PENDING_ACKNOWLEDGMENTS: usize = 1024;
const MAX_ACKNOWLEDGMENT_DIGESTS: usize = 1024;
const PENDING_ACKNOWLEDGMENT_ENTRY_OVERHEAD_CAP: usize = 64;
const PENDING_ACKNOWLEDGMENTS_WIRE_OVERHEAD_CAP: usize = 64;
const MAX_PENDING_ACKNOWLEDGMENTS_BLOB_LEN: usize = PROTOCOL_STATE_BLOB_HEADER_LEN
    + PENDING_ACKNOWLEDGMENTS_WIRE_OVERHEAD_CAP
    + MAX_PENDING_ACKNOWLEDGMENTS
        * (MAX_ENCODED_MESSAGE_LEN + PENDING_ACKNOWLEDGMENT_ENTRY_OVERHEAD_CAP)
    + MAX_ACKNOWLEDGMENT_DIGESTS * ACKNOWLEDGMENT_DIGEST_LEN;

/// Default number of received-message digests retained per local Identity.
pub const DEFAULT_DEDUPLICATION_CAPACITY: usize = 1024;
/// Minimum supported received-message deduplication capacity.
pub const MIN_DEDUPLICATION_CAPACITY: usize = 64;
/// Maximum supported received-message deduplication capacity.
pub const MAX_DEDUPLICATION_CAPACITY: usize = 2048;

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
    /// Prekey state.
    PreKey = 1,
    /// Sender-certificate state.
    SenderCertificate = 2,
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
            Self::PreKey,
            Self::SenderCertificate,
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
            Self::PreKey => write!(f, "pre-key state"),
            Self::SenderCertificate => write!(f, "sender-certificate state"),
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
    /// Recipient X25519 public key bytes. Always 32 bytes.
    pub recipient_public_key: [u8; 32],
    /// Receiver-observed Unix timestamp in milliseconds.
    pub timestamp_millis: u64,
}

/// An outbound Message and all advanced protocol-state updates from one operation.
pub struct OutboundMessageResult {
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
    /// Metadata for the encrypted acknowledgment returned when the Message is accepted.
    pub acknowledgment: OutboundAcknowledgment<'a>,
}

/// Inbound plaintext and all advanced protocol-state updates from one operation.
pub struct InboundMessageResult {
    /// Decrypted plaintext bytes.
    pub plaintext: Zeroizing<Vec<u8>>,
    /// Sender identity material decoded from the sealed-sender envelope.
    pub sender_identity: SenderIdentityMaterial,
    /// Encrypted acknowledgment artifact to durably queue with the returned state updates.
    pub acknowledgment: Message,
    /// Protocol-state updates to commit before treating the inbound Message as processed.
    pub state_updates: Vec<ProtocolStateUpdate>,
}

/// The result of receiving an inbound encrypted Message.
pub enum InboundMessageOutcome {
    /// A unique Message decrypted and advanced protocol state.
    Accepted(Box<InboundMessageResult>),
    /// The Message matched an already-accepted encrypted byte sequence.
    Duplicate,
}

/// An inbound encrypted acknowledgment Message.
pub struct InboundAcknowledgmentMessage<'a> {
    /// Session-scoped key for the ratchet/session and pending-acknowledgment blobs.
    pub session_key: ProtocolStateKey,
    /// Encrypted acknowledgment Message to process.
    pub message: &'a Message,
}

/// Pending acknowledgment state exposed to the consumer for durable flushing.
pub struct PendingAcknowledgment {
    /// Original outbound Message waiting for an acknowledgment.
    pub message: Message,
    /// First-send Unix timestamp in milliseconds.
    pub first_sent_millis: u64,
    /// Last retry-instruction timestamp in milliseconds, if any.
    pub last_retry_millis: Option<u64>,
}

/// A retry instruction for one still-unacknowledged outbound Message.
pub struct RetryInstruction {
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
        /// Acknowledged Message ID carried inside the encrypted acknowledgment.
        acknowledged_message_id: MessageId,
        /// Sender identity material decoded from the acknowledgment.
        sender_identity: SenderIdentityMaterial,
        /// Protocol-state updates to commit before treating the miss as processed.
        state_updates: Vec<ProtocolStateUpdate>,
    },
    /// The exact acknowledgment Message was already processed.
    Duplicate,
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
    deduplication_capacity: usize,
}

impl ProtocolStateEngine {
    /// Creates a stateless protocol-state engine.
    #[must_use]
    pub fn new() -> Self {
        Self {
            deduplication_capacity: DEFAULT_DEDUPLICATION_CAPACITY,
        }
    }

    /// Creates a stateless protocol-state engine with a received-message deduplication capacity.
    ///
    /// # Errors
    /// - [`ProtocolStateError::InvalidDeduplicationCapacity`] if `capacity` is outside the
    ///   supported range.
    pub fn with_deduplication_capacity(capacity: usize) -> Result<Self, ProtocolStateError> {
        validate_configured_deduplication_capacity(capacity)?;
        Ok(Self {
            deduplication_capacity: capacity,
        })
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
            capacity: self.deduplication_capacity,
            digest_key,
            digests: Vec::new(),
        };
        Ok(ProtocolStateUpdate::set(
            address.clone(),
            encode_deduplication_set(&address, &state)?,
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
            encode_pending_acknowledgments(&address, &state)?,
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
            encode_session_state(&address, state, None, None)?,
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
            encode_session_state(&address, state, Some(peer_sender_identity_key), None)?,
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
        let loaded = load_session_state(snapshot, &address)?;
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
                &loaded.state,
                Some(peer_sender_identity_key),
                loaded.contact_identity_key,
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
                let current = decode_contact_state(&address, blob)?;
                if contact_discovery_key_is_newer(
                    &current.identity.discovery_key,
                    &contact_identity.discovery_key,
                ) {
                    ContactState {
                        identity: contact_identity,
                        trust_state: current.trust_state,
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
            },
        };
        changed_contact_state(address, contact)
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
            .map(|blob| decode_contact_state(&address, blob))
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
            .map(|(address, blob)| decode_contact_state(address, blob))
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
        let mut contact = load_contact_state(snapshot, &address)?;
        if contact.trust_state != ContactTrustState::Pending {
            return Ok(ContactStateChange {
                contact,
                state_updates: Vec::new(),
                event: None,
            });
        }
        contact.trust_state = ContactTrustState::Unverified;
        changed_contact_state(address, contact)
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
        let mut contact = load_contact_state(snapshot, &address)?;
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
        changed_contact_state(address, contact).map(ContactSafetyNumberConfirmation::Matched)
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
    /// contacts and messages addressed to a key other than the contact's current Discovery Key are
    /// rejected before ratchet state advances.
    ///
    /// # Errors
    /// - [`ProtocolStateError::BlobDecode`] if the ratchet/session or pending-acknowledgment blob
    ///   fails to decode.
    /// - [`ProtocolStateError::BlobEncode`] if the advanced session or pending-acknowledgment
    ///   state fails to encode or exceeds local caps.
    /// - [`ProtocolStateError::Crypto`] if ratchet encryption or state encoding fails.
    /// - [`ProtocolStateError::InvalidMessage`] if sender material or sealed-sender content
    ///   exceeds local caps or fails to encode.
    /// - [`ProtocolStateError::InvalidStateBinding`] if the contact is Pending, malformed, or does
    ///   not own the outbound recipient public key.
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
        let loaded = load_session_state(snapshot, &address)?;
        let contact_identity_key =
            session_contact_identity_key(&address, &loaded, plaintext.contact_identity_key)?;
        ensure_contact_allows_outbound(
            snapshot,
            contact_identity_key,
            &plaintext.recipient_public_key,
        )?;
        let mut pending = load_pending_acknowledgments(snapshot, &pending_address)?;
        let mut state = loaded.state;
        let sealed = encode_sealed_sender_envelope(plaintext.sender_identity, plaintext.plaintext)?;
        let associated_data = message_associated_data(
            plaintext.id,
            &plaintext.recipient_public_key,
            plaintext.timestamp_millis,
            PayloadKind::EncryptedText,
        );
        let (header, ciphertext) = state.ratchet_encrypt(&sealed, &associated_data)?;
        let message = Message {
            id: plaintext.id,
            recipient_public_key: plaintext.recipient_public_key,
            timestamp_millis: plaintext.timestamp_millis,
            payload_kind: PayloadKind::EncryptedText,
            payload: encode_ratcheted_payload(&header, &ciphertext),
        };
        message
            .to_bytes()
            .map_err(ProtocolStateError::MessageEncode)?;
        record_pending_acknowledgment(&pending_address, &mut pending, &message)?;
        let update = ProtocolStateUpdate::set(
            address.clone(),
            encode_session_state(
                &address,
                &state,
                loaded.peer_sender_identity_key,
                Some(contact_identity_key),
            )?,
        );
        let pending_update = ProtocolStateUpdate::set(
            pending_address.clone(),
            encode_pending_acknowledgments(&pending_address, &pending)?,
        );

        Ok(OutboundMessageResult {
            message,
            state_updates: vec![update, pending_update],
        })
    }

    /// Receives an inbound Message and returns an encrypted acknowledgment artifact on accept.
    ///
    /// Consumers should durably queue the returned acknowledgment with `state_updates` before
    /// treating the inbound Message as processed. Duplicate inbound retries do not regenerate the
    /// acknowledgment artifact.
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
    ///   unsupported, or oversized, or the acknowledgment sender material is invalid.
    /// - [`ProtocolStateError::MessageEncode`] if the inbound Message or produced acknowledgment
    ///   fails canonical encoding.
    /// - [`ProtocolStateError::MissingRequiredState`] if a required deduplication-set or
    ///   ratchet/session blob is absent.
    /// - [`ProtocolStateError::UnsupportedBlobVersion`] if either blob version is not supported.
    pub fn decrypt_message<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        snapshot: &ProtocolStateSnapshot,
        inbound: InboundEncryptedMessage<'_>,
    ) -> Result<InboundMessageOutcome, ProtocolStateError> {
        let deduplication_address = deduplication_address(inbound.deduplication_key);
        let mut deduplication = load_deduplication_set(snapshot, &deduplication_address)?;
        let encoded = inbound
            .message
            .to_bytes()
            .map_err(ProtocolStateError::MessageEncode)?;
        let digest = deduplication_digest(&deduplication.digest_key, &encoded);
        if contains_digest(&deduplication.digests, &digest) {
            return Ok(InboundMessageOutcome::Duplicate);
        }

        let address = ratchet_address(inbound.session_key);
        let loaded = load_session_state(snapshot, &address)?;
        let message = inbound.message;
        if message.payload_kind != PayloadKind::EncryptedText {
            return Err(ProtocolStateError::InvalidMessage {
                reason: "message payload is not ratcheted encrypted text".into(),
            });
        }
        if message.payload.len() > MAX_MESSAGE_PAYLOAD_LEN {
            return Err(ProtocolStateError::InvalidMessage {
                reason: format!(
                    "message payload length exceeds limit: {}",
                    message.payload.len()
                ),
            });
        }
        let expected_sender_identity_key =
            loaded
                .peer_sender_identity_key
                .ok_or_else(|| ProtocolStateError::InvalidMessage {
                    reason: "session sender identity key is not bound".into(),
                })?;

        let mut state = loaded.state;
        let (header, ciphertext) = decode_ratcheted_payload(&message.payload)?;
        let associated_data = message_associated_data(
            message.id,
            &message.recipient_public_key,
            message.timestamp_millis,
            message.payload_kind,
        );
        let sealed = state.ratchet_decrypt(rng, ciphertext, &header, &associated_data)?;
        let decoded = decode_sealed_sender_envelope(&sealed)?;
        if !sender_identity_key_matches(
            &expected_sender_identity_key,
            &decoded.sender_identity.identity_key,
        ) {
            return Err(ProtocolStateError::InvalidMessage {
                reason: "sealed sender identity key does not match session".into(),
            });
        }
        let acknowledgment =
            encrypt_acknowledgment(&mut state, &inbound.acknowledgment, message.id)?;
        record_deduplication_digest(&mut deduplication, digest);
        let session_update = ProtocolStateUpdate::set(
            address.clone(),
            encode_session_state(
                &address,
                &state,
                Some(expected_sender_identity_key),
                loaded.contact_identity_key,
            )?,
        );
        let deduplication_update = ProtocolStateUpdate::set(
            deduplication_address.clone(),
            encode_deduplication_set(&deduplication_address, &deduplication)?,
        );
        Ok(InboundMessageOutcome::Accepted(Box::new(
            InboundMessageResult {
                plaintext: decoded.plaintext,
                sender_identity: decoded.sender_identity,
                acknowledgment,
                state_updates: vec![session_update, deduplication_update],
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
        let pending = load_pending_acknowledgments(snapshot, &address)?;
        Ok(pending
            .pending
            .values()
            .map(|entry| PendingAcknowledgment {
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
        let mut pending = load_pending_acknowledgments(snapshot, &address)?;
        let mut instructions = Vec::new();
        for entry in pending.pending.values_mut() {
            let reference = entry.last_retry_millis.unwrap_or(entry.first_sent_millis);
            if now_millis >= reference.saturating_add(retry_window_millis) {
                instructions.push(RetryInstruction {
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
                encode_pending_acknowledgments(&address, &pending)?,
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
        let mut pending = load_pending_acknowledgments(snapshot, &pending_address)?;
        let encoded = inbound
            .message
            .to_bytes()
            .map_err(ProtocolStateError::MessageEncode)?;
        let digest = acknowledgment_digest(&encoded);
        if contains_acknowledgment_digest(&pending.acknowledgment_digests, &digest) {
            return Ok(AcknowledgmentOutcome::Duplicate);
        }

        let address = ratchet_address(inbound.session_key);
        let loaded = load_session_state(snapshot, &address)?;
        let message = inbound.message;
        if message.payload_kind != PayloadKind::Acknowledgment {
            return Err(ProtocolStateError::InvalidMessage {
                reason: "message payload is not an acknowledgment".into(),
            });
        }
        if message.payload.len() > MAX_MESSAGE_PAYLOAD_LEN {
            return Err(ProtocolStateError::InvalidMessage {
                reason: format!(
                    "message payload length exceeds limit: {}",
                    message.payload.len()
                ),
            });
        }
        let expected_sender_identity_key =
            loaded
                .peer_sender_identity_key
                .ok_or_else(|| ProtocolStateError::InvalidMessage {
                    reason: "session sender identity key is not bound".into(),
                })?;

        let mut state = loaded.state;
        let (header, ciphertext) = decode_ratcheted_payload(&message.payload)?;
        let associated_data = message_associated_data(
            message.id,
            &message.recipient_public_key,
            message.timestamp_millis,
            message.payload_kind,
        );
        let sealed = state.ratchet_decrypt(rng, ciphertext, &header, &associated_data)?;
        let decoded = decode_sealed_sender_envelope(&sealed)?;
        if !sender_identity_key_matches(
            &expected_sender_identity_key,
            &decoded.sender_identity.identity_key,
        ) {
            return Err(ProtocolStateError::InvalidMessage {
                reason: "sealed sender identity key does not match session".into(),
            });
        }
        let acknowledged_message_id = decode_acknowledgment_plaintext(&decoded.plaintext)?;
        record_acknowledgment_digest(&mut pending, digest);
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
                loaded.contact_identity_key,
            )?,
        );
        let pending_update = ProtocolStateUpdate::set(
            pending_address.clone(),
            encode_pending_acknowledgments(&pending_address, &pending)?,
        );
        let state_updates = vec![session_update, pending_update];
        if cleared {
            Ok(AcknowledgmentOutcome::Cleared(ClearedAcknowledgment {
                acknowledged_message_id,
                sender_identity: decoded.sender_identity,
                state_updates,
            }))
        } else {
            Ok(AcknowledgmentOutcome::Missed {
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
            Self::InvalidMessage { reason } => write!(f, "invalid message: {reason}"),
            Self::InvalidDeduplicationCapacity {
                capacity,
                minimum,
                maximum,
            } => write!(
                f,
                "invalid deduplication capacity: {capacity} outside {minimum}..={maximum}"
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
            Self::MessageEncode(e) => Some(e),
            Self::BlobDecode { .. }
            | Self::BlobEncode { .. }
            | Self::InvalidDeduplicationCapacity { .. }
            | Self::InvalidMessage { .. }
            | Self::InvalidStateBinding { .. }
            | Self::InvalidStateKey { .. }
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

fn validate_configured_deduplication_capacity(capacity: usize) -> Result<(), ProtocolStateError> {
    if !(MIN_DEDUPLICATION_CAPACITY..=MAX_DEDUPLICATION_CAPACITY).contains(&capacity) {
        return Err(ProtocolStateError::InvalidDeduplicationCapacity {
            capacity,
            minimum: MIN_DEDUPLICATION_CAPACITY,
            maximum: MAX_DEDUPLICATION_CAPACITY,
        });
    }
    Ok(())
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
    if payload.len() + PROTOCOL_STATE_BLOB_HEADER_LEN > MAX_PROTOCOL_STATE_BLOB_LEN {
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
    state: RatchetState,
    peer_sender_identity_key: Option<[u8; 32]>,
    contact_identity_key: Option<ContactIdentityKey>,
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
    pending: Vec<DecodedPendingAcknowledgmentWire>,
    acknowledgment_digests: Vec<[u8; ACKNOWLEDGMENT_DIGEST_LEN]>,
}

#[derive(Deserialize)]
struct DecodedPendingAcknowledgmentWire {
    message_id: [u8; 16],
    encoded_message: Vec<u8>,
    first_sent_millis: u64,
    last_retry_millis: Option<u64>,
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
}

#[derive(Deserialize)]
struct DecodedContactStateWire {
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

fn load_session_state(
    snapshot: &ProtocolStateSnapshot,
    address: &ProtocolStateAddress,
) -> Result<LoadedSessionState, ProtocolStateError> {
    let blob = snapshot
        .get(address)
        .ok_or_else(|| ProtocolStateError::MissingRequiredState {
            address: address.clone(),
        })?;
    decode_session_state(address, blob)
}

fn decode_session_state(
    address: &ProtocolStateAddress,
    blob: &ProtocolStateBlob,
) -> Result<LoadedSessionState, ProtocolStateError> {
    let bytes = blob.as_bytes();
    if bytes.len() > MAX_PROTOCOL_STATE_BLOB_LEN {
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
        state,
        peer_sender_identity_key,
        contact_identity_key,
    })
}

fn encode_deduplication_set(
    address: &ProtocolStateAddress,
    state: &LoadedDeduplicationSet,
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
    if payload.len() + PROTOCOL_STATE_BLOB_HEADER_LEN > MAX_PROTOCOL_STATE_BLOB_LEN {
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
) -> Result<LoadedDeduplicationSet, ProtocolStateError> {
    let blob = snapshot
        .get(address)
        .ok_or_else(|| ProtocolStateError::MissingRequiredState {
            address: address.clone(),
        })?;
    decode_deduplication_set(address, blob)
}

fn decode_deduplication_set(
    address: &ProtocolStateAddress,
    blob: &ProtocolStateBlob,
) -> Result<LoadedDeduplicationSet, ProtocolStateError> {
    let bytes = blob.as_bytes();
    if bytes.len() > MAX_PROTOCOL_STATE_BLOB_LEN {
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
) -> Result<ProtocolStateBlob, ProtocolStateError> {
    if state.pending.len() > MAX_PENDING_ACKNOWLEDGMENTS {
        return Err(ProtocolStateError::BlobEncode {
            address: address.clone(),
            reason: format!(
                "pending-acknowledgment count exceeds limit: {}",
                state.pending.len()
            ),
        });
    }
    if state.acknowledgment_digests.len() > MAX_ACKNOWLEDGMENT_DIGESTS {
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
    if payload.len() + PROTOCOL_STATE_BLOB_HEADER_LEN > MAX_PENDING_ACKNOWLEDGMENTS_BLOB_LEN {
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
) -> Result<LoadedPendingAcknowledgments, ProtocolStateError> {
    let blob = snapshot
        .get(address)
        .ok_or_else(|| ProtocolStateError::MissingRequiredState {
            address: address.clone(),
        })?;
    decode_pending_acknowledgments(address, blob)
}

fn decode_pending_acknowledgments(
    address: &ProtocolStateAddress,
    blob: &ProtocolStateBlob,
) -> Result<LoadedPendingAcknowledgments, ProtocolStateError> {
    let bytes = blob.as_bytes();
    if bytes.len() > MAX_PENDING_ACKNOWLEDGMENTS_BLOB_LEN {
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
        return decode_pending_acknowledgments_payload(address, payload);
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
    if wire.pending.len() > MAX_PENDING_ACKNOWLEDGMENTS {
        return Err(ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: format!(
                "pending-acknowledgment count exceeds limit: {}",
                wire.pending.len()
            ),
        });
    }
    if wire.acknowledgment_digests.len() > MAX_ACKNOWLEDGMENT_DIGESTS {
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
        if message.id.as_bytes() != &entry.message_id {
            return Err(ProtocolStateError::BlobDecode {
                address: address.clone(),
                reason: "pending acknowledgment message ID mismatch".into(),
            });
        }
        if message.payload_kind != PayloadKind::EncryptedText {
            return Err(ProtocolStateError::BlobDecode {
                address: address.clone(),
                reason: "pending acknowledgment message is not encrypted text".into(),
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

fn changed_contact_state(
    address: ProtocolStateAddress,
    contact: ContactState,
) -> Result<ContactStateChange, ProtocolStateError> {
    Ok(ContactStateChange {
        contact: contact.clone(),
        state_updates: vec![ProtocolStateUpdate::set(
            address.clone(),
            encode_contact_state(&address, &contact)?,
        )],
        event: Some(ContactEvent::Changed { contact }),
    })
}

fn load_contact_state(
    snapshot: &ProtocolStateSnapshot,
    address: &ProtocolStateAddress,
) -> Result<ContactState, ProtocolStateError> {
    let blob = snapshot
        .get(address)
        .ok_or_else(|| ProtocolStateError::MissingRequiredState {
            address: address.clone(),
        })?;
    decode_contact_state(address, blob)
}

fn encode_contact_state(
    address: &ProtocolStateAddress,
    contact: &ContactState,
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
    };
    let payload =
        Zeroizing::new(
            postcard::to_stdvec(&wire).map_err(|_| ProtocolStateError::BlobEncode {
                address: address.clone(),
                reason: "contact state failed to encode".into(),
            })?,
        );
    if payload.len() + PROTOCOL_STATE_BLOB_HEADER_LEN > MAX_PROTOCOL_STATE_BLOB_LEN {
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
) -> Result<ContactState, ProtocolStateError> {
    let bytes = blob.as_bytes();
    if bytes.len() > MAX_PROTOCOL_STATE_BLOB_LEN {
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
    let (wire, trailing): (DecodedContactStateWire, &[u8]) = postcard::take_from_bytes(payload)
        .map_err(|e| ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: e.to_string(),
        })?;
    if !trailing.is_empty() || wire.version != CONTACT_STATE_WIRE_VERSION {
        return Err(ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: "contact-state payload version is unsupported".into(),
        });
    }
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
                created_at: wire.discovery_created_at,
                identity_signature: wire.discovery_identity_signature.try_into().map_err(|_| {
                    ProtocolStateError::BlobDecode {
                        address: address.clone(),
                        reason: "contact discovery key signature length is invalid".into(),
                    }
                })?,
            },
        },
        trust_state: wire.trust_state,
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
        Some(existing) if existing != requested => Err(ProtocolStateError::InvalidStateBinding {
            address: address.clone(),
            reason: "session contact identity key is already bound".into(),
        }),
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
) -> Result<(), ProtocolStateError> {
    let address = contact_address(identity_key);
    validate_contact_identity_key(&address, &identity_key)?;
    let contact = load_contact_state(snapshot, &address)?;
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
    message: &Message,
) -> Result<(), ProtocolStateError> {
    let message_id = *message.id.as_bytes();
    if !state.pending.contains_key(&message_id)
        && state.pending.len() == MAX_PENDING_ACKNOWLEDGMENTS
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
        message_id,
        LoadedPendingAcknowledgment {
            message: copy_message(message),
            encoded_message,
            first_sent_millis: message.timestamp_millis,
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
) {
    if state.acknowledgment_digests.len() == MAX_ACKNOWLEDGMENT_DIGESTS {
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

#[derive(Serialize)]
struct SealedSenderEnvelopeWire<'a> {
    version: u8,
    sender_identity_key: [u8; 32],
    sender_certificate: &'a [u8],
    sender_signature: &'a [u8],
    plaintext: &'a [u8],
}

#[derive(Deserialize)]
struct DecodedSealedSenderEnvelopeWire {
    version: u8,
    sender_identity_key: [u8; 32],
    sender_certificate: Vec<u8>,
    sender_signature: Vec<u8>,
    plaintext: Vec<u8>,
}

struct DecodedSealedSenderEnvelope {
    sender_identity: SenderIdentityMaterial,
    plaintext: Zeroizing<Vec<u8>>,
}

fn encode_sealed_sender_envelope(
    sender_identity: &SenderIdentityMaterial,
    plaintext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ProtocolStateError> {
    validate_sender_identity(sender_identity)?;
    validate_sealed_sender_content_len(sender_identity, plaintext)?;
    let sealed = Zeroizing::new(
        postcard::to_stdvec(&SealedSenderEnvelopeWire {
            version: SEALED_SENDER_ENVELOPE_VERSION,
            sender_identity_key: sender_identity.identity_key,
            sender_certificate: &sender_identity.certificate,
            sender_signature: &sender_identity.signature,
            plaintext,
        })
        .map_err(|_| ProtocolStateError::InvalidMessage {
            reason: "sealed-sender envelope failed to encode".into(),
        })?,
    );
    if sealed.len() > MAX_SEALED_SENDER_ENVELOPE_LEN {
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
) -> Result<DecodedSealedSenderEnvelope, ProtocolStateError> {
    let (wire, trailing): (DecodedSealedSenderEnvelopeWire, &[u8]) =
        postcard::take_from_bytes(bytes).map_err(|_| ProtocolStateError::InvalidMessage {
            reason: "sealed-sender envelope failed to decode".into(),
        })?;
    let plaintext = Zeroizing::new(wire.plaintext);
    let sender_identity = SenderIdentityMaterial {
        identity_key: wire.sender_identity_key,
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
    validate_sender_identity(&sender_identity)?;
    validate_sealed_sender_content_len(&sender_identity, &plaintext)?;
    Ok(DecodedSealedSenderEnvelope {
        sender_identity,
        plaintext,
    })
}

fn encrypt_acknowledgment(
    state: &mut RatchetState,
    acknowledgment: &OutboundAcknowledgment<'_>,
    acknowledged_message_id: MessageId,
) -> Result<Message, ProtocolStateError> {
    let plaintext = encode_acknowledgment_plaintext(acknowledged_message_id)?;
    let sealed =
        encode_sealed_sender_envelope(acknowledgment.sender_identity, plaintext.as_slice())?;
    let associated_data = message_associated_data(
        acknowledgment.id,
        &acknowledgment.recipient_public_key,
        acknowledgment.timestamp_millis,
        PayloadKind::Acknowledgment,
    );
    let (header, ciphertext) = state.ratchet_encrypt(&sealed, &associated_data)?;
    let message = Message {
        id: acknowledgment.id,
        recipient_public_key: acknowledgment.recipient_public_key,
        timestamp_millis: acknowledgment.timestamp_millis,
        payload_kind: PayloadKind::Acknowledgment,
        payload: encode_ratcheted_payload(&header, &ciphertext),
    };
    message
        .to_bytes()
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
) -> Result<(), ProtocolStateError> {
    if sender_identity.certificate.len() > MAX_SENDER_CERTIFICATE_LEN {
        return Err(ProtocolStateError::InvalidMessage {
            reason: format!(
                "sender certificate length exceeds limit: {}",
                sender_identity.certificate.len()
            ),
        });
    }
    if sender_identity.signature.len() > MAX_SENDER_SIGNATURE_LEN {
        return Err(ProtocolStateError::InvalidMessage {
            reason: format!(
                "sender signature length exceeds limit: {}",
                sender_identity.signature.len()
            ),
        });
    }
    Ok(())
}

fn validate_sealed_sender_content_len(
    sender_identity: &SenderIdentityMaterial,
    plaintext: &[u8],
) -> Result<(), ProtocolStateError> {
    let len = sender_identity
        .certificate
        .len()
        .checked_add(sender_identity.signature.len())
        .and_then(|len| len.checked_add(plaintext.len()))
        .ok_or_else(|| ProtocolStateError::InvalidMessage {
            reason: "sealed-sender content length overflowed".into(),
        })?;
    if len > MAX_SEALED_SENDER_CONTENT_LEN {
        return Err(ProtocolStateError::InvalidMessage {
            reason: format!("sealed-sender content length exceeds limit: {len}"),
        });
    }
    Ok(())
}

fn sender_identity_key_matches(expected: &[u8; 32], actual: &[u8; 32]) -> bool {
    expected.ct_eq(actual).into()
}

fn copy_message(message: &Message) -> Message {
    Message {
        id: message.id,
        recipient_public_key: message.recipient_public_key,
        timestamp_millis: message.timestamp_millis,
        payload_kind: message.payload_kind,
        payload: message.payload.clone(),
    }
}

fn message_associated_data(
    id: MessageId,
    recipient_public_key: &[u8; 32],
    timestamp_millis: u64,
    payload_kind: PayloadKind,
) -> Vec<u8> {
    let mut associated_data = Vec::with_capacity(74);
    associated_data.extend_from_slice(b"AetherMessage-v1:");
    associated_data.extend_from_slice(id.as_bytes());
    associated_data.extend_from_slice(recipient_public_key);
    associated_data.extend_from_slice(&timestamp_millis.to_be_bytes());
    associated_data.push(payload_kind_tag(payload_kind));
    associated_data
}

fn payload_kind_tag(kind: PayloadKind) -> u8 {
    match kind {
        PayloadKind::EncryptedText => 0,
        PayloadKind::Acknowledgment => 1,
        PayloadKind::KeyExchange => 2,
        PayloadKind::RatchetHeader => 3,
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
        MIN_DEDUPLICATION_CAPACITY, contains_digest, deduplication_digest,
        record_deduplication_digest,
    };
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
}
