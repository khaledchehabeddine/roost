//! Public protocol-state blob addressing and stateless operation results.

use crate::{Message, MessageError, MessageId, PayloadKind};
use aether_crypto::{Header, PublicKey, RatchetState};
use rand::{CryptoRng, RngCore};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const PROTOCOL_STATE_BLOB_VERSION: u8 = 1;
const RATCHET_PAYLOAD_VERSION: u8 = 1;
const RATCHET_PAYLOAD_HEADER_LEN: usize = 1 + 32 + 4 + 4;
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
    /// Returns every protocol-state kind exposed by v0.5.0.
    #[must_use]
    pub fn v0_5_0_kinds() -> &'static [Self] {
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
    /// Sender X25519 public key bytes. Always 32 bytes.
    pub sender_public_key: [u8; 32],
    /// Recipient X25519 public key bytes. Always 32 bytes.
    pub recipient_public_key: [u8; 32],
    /// Sender-observed Unix timestamp in milliseconds.
    pub timestamp_millis: u64,
    /// Plaintext bytes to encrypt.
    pub plaintext: &'a [u8],
    /// Associated data authenticated with the ratcheted ciphertext.
    pub associated_data: &'a [u8],
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

    /// Returns an update that stores the supplied Ratchet session state.
    ///
    /// # Errors
    /// - [`ProtocolStateError::Crypto`] if ratchet-state encoding fails.
    pub fn set_session_state(
        &self,
        key: ProtocolStateKey,
        state: &RatchetState,
    ) -> Result<ProtocolStateUpdate, ProtocolStateError> {
        Ok(ProtocolStateUpdate::set(
            ratchet_address(key),
            encode_session_state(state)?,
        ))
    }

    /// Returns deletion updates for all v0.5.0 state kinds at `key`.
    #[must_use]
    pub fn wipe(&self, key: ProtocolStateKey) -> Vec<ProtocolStateUpdate> {
        ProtocolStateKind::v0_5_0_kinds()
            .iter()
            .map(|kind| ProtocolStateUpdate::delete(ProtocolStateAddress::new(*kind, key.clone())))
            .collect()
    }

    /// Encrypts plaintext using the required ratchet/session blob from `snapshot`.
    ///
    /// # Errors
    /// - [`ProtocolStateError::BlobDecode`] if the ratchet/session blob fails to decode.
    /// - [`ProtocolStateError::Crypto`] if ratchet encryption or state encoding fails.
    /// - [`ProtocolStateError::MissingRequiredState`] if no ratchet/session blob is present.
    pub fn encrypt_message(
        &self,
        snapshot: &ProtocolStateSnapshot,
        key: ProtocolStateKey,
        plaintext: OutboundPlaintext<'_>,
    ) -> Result<OutboundMessageResult, ProtocolStateError> {
        let address = ratchet_address(key.clone());
        let mut state = load_session_state(snapshot, &address)?;
        let (header, ciphertext) =
            state.ratchet_encrypt(plaintext.plaintext, plaintext.associated_data)?;
        let message = Message {
            id: plaintext.id,
            sender_public_key: plaintext.sender_public_key,
            recipient_public_key: plaintext.recipient_public_key,
            timestamp_millis: plaintext.timestamp_millis,
            payload_kind: PayloadKind::EncryptedText,
            payload: encode_ratcheted_payload(&header, &ciphertext),
        };
        message
            .to_bytes()
            .map_err(ProtocolStateError::MessageEncode)?;
        let update = self.set_session_state(key, &state)?;

        Ok(OutboundMessageResult {
            message,
            state_updates: vec![update],
        })
    }

    /// Decrypts an inbound Message using the required ratchet/session blob from `snapshot`.
    ///
    /// # Errors
    /// - [`ProtocolStateError::BlobDecode`] if the ratchet/session blob fails to decode.
    /// - [`ProtocolStateError::Crypto`] if ratchet decryption or state encoding fails.
    /// - [`ProtocolStateError::InvalidMessage`] if the Message does not contain ratcheted text.
    /// - [`ProtocolStateError::MissingRequiredState`] if no ratchet/session blob is present.
    pub fn decrypt_message<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        snapshot: &ProtocolStateSnapshot,
        key: ProtocolStateKey,
        message: &Message,
        associated_data: &[u8],
    ) -> Result<InboundMessageResult, ProtocolStateError> {
        let address = ratchet_address(key.clone());
        let mut state = load_session_state(snapshot, &address)?;
        if message.payload_kind != PayloadKind::EncryptedText {
            return Err(ProtocolStateError::InvalidMessage {
                reason: "message payload is not ratcheted encrypted text".into(),
            });
        }

        let (header, ciphertext) = decode_ratcheted_payload(&message.payload)?;
        let plaintext = state.ratchet_decrypt(rng, ciphertext, &header, associated_data)?;
        let update = self.set_session_state(key, &state)?;
        Ok(InboundMessageResult {
            plaintext,
            state_updates: vec![update],
        })
    }
}

/// Errors returned by protocol-state operations.
#[derive(Debug)]
pub enum ProtocolStateError {
    /// A persisted blob failed structural decoding.
    BlobDecode {
        /// Address whose blob failed to decode.
        address: ProtocolStateAddress,
        /// Diagnostic decode context for logs only.
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
            Self::Crypto(e) => write!(f, "protocol-state crypto operation failed: {e}"),
            Self::InvalidMessage { reason } => write!(f, "invalid message: {reason}"),
            Self::InvalidStateKey { reason } => write!(f, "invalid protocol-state key: {reason}"),
            Self::MessageEncode(e) => write!(f, "message failed to encode: {e}"),
            Self::MissingRequiredState { address } => {
                write!(f, "missing required protocol-state blob at {address}")
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
            | Self::InvalidMessage { .. }
            | Self::InvalidStateKey { .. }
            | Self::MissingRequiredState { .. } => None,
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

fn encode_session_state(state: &RatchetState) -> Result<ProtocolStateBlob, ProtocolStateError> {
    let state_bytes = state.to_bytes()?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(1 + state_bytes.len()));
    bytes.push(PROTOCOL_STATE_BLOB_VERSION);
    bytes.extend_from_slice(&state_bytes);
    Ok(ProtocolStateBlob::from_zeroizing(bytes))
}

fn load_session_state(
    snapshot: &ProtocolStateSnapshot,
    address: &ProtocolStateAddress,
) -> Result<RatchetState, ProtocolStateError> {
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
) -> Result<RatchetState, ProtocolStateError> {
    let bytes = blob.as_bytes();
    if bytes.len() > MAX_PROTOCOL_STATE_BLOB_LEN {
        return Err(ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: format!("ratchet/session blob length exceeds limit: {}", bytes.len()),
        });
    }
    let version = *bytes
        .first()
        .ok_or_else(|| ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: "empty ratchet/session blob".into(),
        })?;
    if version != PROTOCOL_STATE_BLOB_VERSION {
        return Err(ProtocolStateError::BlobDecode {
            address: address.clone(),
            reason: format!("unsupported protocol-state blob version: {version}"),
        });
    }
    RatchetState::from_bytes(&bytes[1..]).map_err(|e| ProtocolStateError::BlobDecode {
        address: address.clone(),
        reason: e.to_string(),
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

fn write_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(f, "{byte:02x}")?;
    }
    Ok(())
}
