//! Public protocol-state blob addressing and stateless operation results.

use crate::message::MAX_MESSAGE_PAYLOAD_LEN;
use crate::{Message, MessageError, MessageId, PayloadKind};
use aether_crypto::{Header, PublicKey, RatchetState, SenderIdentityMaterial};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const CURRENT_PROTOCOL_STATE_BLOB_MAJOR: u8 = 1;
const CURRENT_PROTOCOL_STATE_BLOB_MINOR: u8 = 0;
const SUPPORTED_LEGACY_BLOB_MAJOR: u8 = 0;
const SUPPORTED_LEGACY_BLOB_MINOR: u8 = 1;
const PROTOCOL_STATE_BLOB_HEADER_LEN: usize = 2;
const SESSION_STATE_WIRE_VERSION: u8 = 1;
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
const MAX_PROTOCOL_STATE_KEY_LEN: usize = 64;

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
    /// Recipient X25519 public key bytes. Always 32 bytes.
    pub recipient_public_key: [u8; 32],
    /// Sender-observed Unix timestamp in milliseconds.
    pub timestamp_millis: u64,
    /// Plaintext bytes to encrypt.
    pub plaintext: &'a [u8],
}

/// An outbound Message and all advanced protocol-state updates from one operation.
pub struct OutboundMessageResult {
    /// Message to hand to the consumer transport after state commit.
    pub message: Message,
    /// Protocol-state updates to commit atomically with the outbound Message.
    pub state_updates: Vec<ProtocolStateUpdate>,
}

/// Inbound plaintext and all advanced protocol-state updates from one operation.
pub struct InboundMessageResult {
    /// Decrypted plaintext bytes.
    pub plaintext: Zeroizing<Vec<u8>>,
    /// Sender identity material decoded from the sealed-sender envelope.
    pub sender_identity: SenderIdentityMaterial,
    /// Protocol-state updates to commit before treating the inbound Message as processed.
    pub state_updates: Vec<ProtocolStateUpdate>,
}

/// Stateless protocol-state operations over consumer-held blobs.
///
/// Consumers must read required blobs from an atomic, durable, crash-consistent, and
/// integrity-preserving store before each operation, then commit returned updates atomically with
/// any produced Message. At most one library instance may mutate a given Identity's protocol
/// state at a time.
#[derive(Clone, Copy, Default)]
pub struct ProtocolStateEngine;

impl ProtocolStateEngine {
    /// Creates a stateless protocol-state engine.
    #[must_use]
    pub fn new() -> Self {
        Self
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
            encode_session_state(&address, state, None)?,
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
            encode_session_state(&address, state, Some(peer_sender_identity_key))?,
        ))
    }

    /// Returns an update that binds an existing Ratchet session blob to the expected peer sender
    /// identity key.
    ///
    /// Use this when restoring or migrating an existing opaque session blob and the peer identity
    /// key is known without full sender certificate material.
    ///
    /// # Errors
    /// - [`ProtocolStateError::BlobDecode`] if the current-format blob or blob envelope fails to
    ///   decode.
    /// - [`ProtocolStateError::BlobEncode`] if the wrapped state fails to encode or exceeds local
    ///   caps.
    /// - [`ProtocolStateError::Crypto`] if ratchet-state encoding fails.
    /// - [`ProtocolStateError::InvalidStateBinding`] if the session is already bound to a
    ///   different peer sender identity key.
    /// - [`ProtocolStateError::MigrationFailed`] if a supported older blob fails migration.
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
            encode_session_state(&address, &loaded.state, Some(peer_sender_identity_key))?,
        ))
    }

    /// Returns deletion updates for all protocol-state kinds at `key`.
    #[must_use]
    pub fn wipe(&self, key: ProtocolStateKey) -> Vec<ProtocolStateUpdate> {
        ProtocolStateKind::all()
            .iter()
            .map(|kind| ProtocolStateUpdate::delete(ProtocolStateAddress::new(*kind, key.clone())))
            .collect()
    }

    /// Returns a current-format update for an older supported ratchet/session blob.
    ///
    /// Returns `Ok(None)` when the stored blob is already in the current format. Apply a returned
    /// update atomically with the consumer-held blob set before using the migrated state for later
    /// operations.
    ///
    /// # Errors
    /// - [`ProtocolStateError::BlobDecode`] if the current-format blob or blob envelope fails to
    ///   decode.
    /// - [`ProtocolStateError::BlobEncode`] if the current-format writeback fails to encode or
    ///   exceeds local caps.
    /// - [`ProtocolStateError::Crypto`] if migrated state encoding fails.
    /// - [`ProtocolStateError::MigrationFailed`] if a supported older blob fails migration.
    /// - [`ProtocolStateError::MissingRequiredState`] if no ratchet/session blob is present.
    /// - [`ProtocolStateError::UnsupportedBlobVersion`] if the blob version is not supported.
    pub fn migrate_session_state(
        &self,
        snapshot: &ProtocolStateSnapshot,
        key: ProtocolStateKey,
    ) -> Result<Option<ProtocolStateUpdate>, ProtocolStateError> {
        let address = ratchet_address(key);
        let loaded = load_session_state(snapshot, &address)?;
        if loaded.version.is_current() && !loaded.needs_writeback {
            return Ok(None);
        }

        Ok(Some(ProtocolStateUpdate::set(
            address.clone(),
            encode_session_state(&address, &loaded.state, loaded.peer_sender_identity_key)?,
        )))
    }

    /// Encrypts plaintext using the required ratchet/session blob from `snapshot`.
    ///
    /// # Errors
    /// - [`ProtocolStateError::BlobDecode`] if the ratchet/session blob fails to decode.
    /// - [`ProtocolStateError::BlobEncode`] if the current session-state writeback fails to
    ///   encode or exceeds local caps.
    /// - [`ProtocolStateError::Crypto`] if ratchet encryption or state encoding fails.
    /// - [`ProtocolStateError::InvalidMessage`] if sender material or sealed-sender content
    ///   exceeds local caps or fails to encode.
    /// - [`ProtocolStateError::MigrationFailed`] if a supported older blob fails migration.
    /// - [`ProtocolStateError::MessageEncode`] if the produced Message fails to encode.
    /// - [`ProtocolStateError::MissingRequiredState`] if no ratchet/session blob is present.
    /// - [`ProtocolStateError::UnsupportedBlobVersion`] if the blob version is not supported.
    pub fn encrypt_message(
        &self,
        snapshot: &ProtocolStateSnapshot,
        key: ProtocolStateKey,
        plaintext: OutboundPlaintext<'_>,
    ) -> Result<OutboundMessageResult, ProtocolStateError> {
        let address = ratchet_address(key);
        let loaded = load_session_state(snapshot, &address)?;
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
        let update = ProtocolStateUpdate::set(
            address.clone(),
            encode_session_state(&address, &state, loaded.peer_sender_identity_key)?,
        );

        Ok(OutboundMessageResult {
            message,
            state_updates: vec![update],
        })
    }

    /// Decrypts an inbound Message using the required ratchet/session blob from `snapshot`.
    ///
    /// # Errors
    /// - [`ProtocolStateError::BlobDecode`] if the ratchet/session blob fails to decode.
    /// - [`ProtocolStateError::BlobEncode`] if the current session-state writeback fails to
    ///   encode or exceeds local caps.
    /// - [`ProtocolStateError::Crypto`] if ratchet decryption or state encoding fails.
    /// - [`ProtocolStateError::InvalidMessage`] if the Message does not contain ratcheted text,
    ///   the session is not bound to a peer sender identity key, the decrypted sender identity key
    ///   does not match the session binding, or the decrypted sealed-sender envelope is malformed,
    ///   unsupported, or oversized.
    /// - [`ProtocolStateError::MigrationFailed`] if a supported older blob fails migration.
    /// - [`ProtocolStateError::MissingRequiredState`] if no ratchet/session blob is present.
    /// - [`ProtocolStateError::UnsupportedBlobVersion`] if the blob version is not supported.
    pub fn decrypt_message<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        snapshot: &ProtocolStateSnapshot,
        key: ProtocolStateKey,
        message: &Message,
    ) -> Result<InboundMessageResult, ProtocolStateError> {
        let address = ratchet_address(key);
        let loaded = load_session_state(snapshot, &address)?;
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
        let update = ProtocolStateUpdate::set(
            address.clone(),
            encode_session_state(&address, &state, Some(expected_sender_identity_key))?,
        );
        Ok(InboundMessageResult {
            plaintext: decoded.plaintext,
            sender_identity: decoded.sender_identity,
            state_updates: vec![update],
        })
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
    /// A produced Message failed to encode.
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
    /// A supported older blob failed migration.
    MigrationFailed {
        /// Address whose blob failed to migrate.
        address: ProtocolStateAddress,
        /// Diagnostic migration context for logs only.
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
            Self::InvalidStateBinding { address, reason } => {
                write!(f, "invalid protocol-state binding at {address}: {reason}")
            }
            Self::InvalidStateKey { reason } => write!(f, "invalid protocol-state key: {reason}"),
            Self::MigrationFailed { address, reason } => {
                write!(
                    f,
                    "protocol-state blob failed to migrate at {address}: {reason}"
                )
            }
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
            | Self::InvalidMessage { .. }
            | Self::InvalidStateBinding { .. }
            | Self::InvalidStateKey { .. }
            | Self::MigrationFailed { .. }
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

#[derive(Serialize)]
struct SessionStateWire<'a> {
    version: u8,
    ratchet_state: &'a [u8],
    peer_sender_identity_key: Option<[u8; 32]>,
}

#[derive(Deserialize)]
struct DecodedSessionStateWire {
    version: u8,
    ratchet_state: Vec<u8>,
    peer_sender_identity_key: Option<[u8; 32]>,
}

fn encode_session_state(
    address: &ProtocolStateAddress,
    state: &RatchetState,
    peer_sender_identity_key: Option<[u8; 32]>,
) -> Result<ProtocolStateBlob, ProtocolStateError> {
    let state_bytes = state.to_bytes()?;
    let payload = Zeroizing::new(
        postcard::to_stdvec(&SessionStateWire {
            version: SESSION_STATE_WIRE_VERSION,
            ratchet_state: &state_bytes,
            peer_sender_identity_key,
        })
        .map_err(|_| ProtocolStateError::BlobEncode {
            address: address.clone(),
            reason: "ratchet/session state failed to encode".into(),
        })?,
    );
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
    version: ProtocolStateBlobVersion,
    needs_writeback: bool,
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
    let version =
        ProtocolStateBlobVersion::read(bytes).ok_or_else(|| ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: "ratchet/session blob header is incomplete".into(),
        })?;
    let payload = &bytes[PROTOCOL_STATE_BLOB_HEADER_LEN..];

    if version.is_current() {
        return decode_current_session_state(address, payload, version);
    }
    if version.is_supported_legacy() {
        return migrate_legacy_session_state(address, payload, version);
    }

    Err(ProtocolStateError::UnsupportedBlobVersion {
        address: address.clone(),
        major: version.major,
        minor: version.minor,
    })
}

#[derive(Clone, Copy)]
struct ProtocolStateBlobVersion {
    major: u8,
    minor: u8,
}

impl ProtocolStateBlobVersion {
    fn read(bytes: &[u8]) -> Option<Self> {
        let header = bytes.get(..PROTOCOL_STATE_BLOB_HEADER_LEN)?;
        Some(Self {
            major: header[0],
            minor: header[1],
        })
    }

    fn is_current(self) -> bool {
        self.major == CURRENT_PROTOCOL_STATE_BLOB_MAJOR
            && self.minor == CURRENT_PROTOCOL_STATE_BLOB_MINOR
    }

    fn is_supported_legacy(self) -> bool {
        self.major == SUPPORTED_LEGACY_BLOB_MAJOR && self.minor == SUPPORTED_LEGACY_BLOB_MINOR
    }
}

fn decode_current_session_state(
    address: &ProtocolStateAddress,
    payload: &[u8],
    version: ProtocolStateBlobVersion,
) -> Result<LoadedSessionState, ProtocolStateError> {
    match decode_wrapped_session_state(address, payload, version) {
        Ok(loaded) => Ok(loaded),
        Err(wrapped_error) => {
            decode_flat_current_session_state(address, payload, version).map_err(|_| wrapped_error)
        }
    }
}

fn decode_wrapped_session_state(
    address: &ProtocolStateAddress,
    payload: &[u8],
    version: ProtocolStateBlobVersion,
) -> Result<LoadedSessionState, ProtocolStateError> {
    let (wire, trailing): (DecodedSessionStateWire, &[u8]) = postcard::take_from_bytes(payload)
        .map_err(|e| ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: e.to_string(),
        })?;
    let wire_version = wire.version;
    let peer_sender_identity_key = wire.peer_sender_identity_key;
    let ratchet_state = Zeroizing::new(wire.ratchet_state);
    if !trailing.is_empty() || wire_version != SESSION_STATE_WIRE_VERSION {
        return Err(ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: "ratchet/session payload version is unsupported".into(),
        });
    }
    let state =
        RatchetState::from_bytes(&ratchet_state).map_err(|e| ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: e.to_string(),
        })?;
    Ok(LoadedSessionState {
        state,
        peer_sender_identity_key,
        version,
        needs_writeback: false,
    })
}

fn decode_flat_current_session_state(
    address: &ProtocolStateAddress,
    payload: &[u8],
    version: ProtocolStateBlobVersion,
) -> Result<LoadedSessionState, ProtocolStateError> {
    let state = RatchetState::from_bytes(payload).map_err(|e| ProtocolStateError::BlobDecode {
        address: address.clone(),
        reason: e.to_string(),
    })?;
    Ok(LoadedSessionState {
        state,
        peer_sender_identity_key: None,
        version,
        needs_writeback: true,
    })
}

fn migrate_legacy_session_state(
    address: &ProtocolStateAddress,
    payload: &[u8],
    version: ProtocolStateBlobVersion,
) -> Result<LoadedSessionState, ProtocolStateError> {
    let state =
        RatchetState::from_bytes(payload).map_err(|e| ProtocolStateError::MigrationFailed {
            address: address.clone(),
            reason: e.to_string(),
        })?;
    Ok(LoadedSessionState {
        state,
        peer_sender_identity_key: None,
        version,
        needs_writeback: true,
    })
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
