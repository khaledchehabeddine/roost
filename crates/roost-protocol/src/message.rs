//! Authenticated Message metadata, transcript construction, and sealed payload padding.

use zeroize::Zeroizing;

const PUBLIC_KEY_LEN: usize = 32;
const SESSION_ID_LEN: usize = 16;
/// Domain separator for established Message signatures.
pub const MESSAGE_TRANSCRIPT_CONTEXT: &[u8] = b"AetherMessageTranscript-v1:";
/// Length of the original-plaintext size prefix.
pub const SEALED_PAYLOAD_LEN_PREFIX_LEN: usize = 4;
/// Supported padded payload lengths, including the length prefix.
pub const SEALED_PAYLOAD_BUCKETS: [usize; 12] = [
    32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16_384, 32_768, 65_536,
];
// The transcript authenticates the padded payload, so its limit is the largest bucket.
const MAX_TRANSCRIPT_PAYLOAD_LEN: usize = SEALED_PAYLOAD_BUCKETS[SEALED_PAYLOAD_BUCKETS.len() - 1];
// Longest sender certificate a Message transcript accepts.
const MAX_TRANSCRIPT_SENDER_CERTIFICATE_LEN: usize = 16 * 1024;

/// The identifier both peers derive from a Session's handshake.
///
/// It addresses the Session's state and travels sealed in every Message on the Session.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SessionId([u8; SESSION_ID_LEN]);

impl SessionId {
    /// Creates a Session identifier from its bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; SESSION_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the identifier's bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SESSION_ID_LEN] {
        &self.0
    }
}

/// The UUID-shaped identifier for a Message.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MessageId([u8; 16]);

impl MessageId {
    /// Creates a message identifier from UUID bytes.
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

/// The semantic type of a Message payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadKind {
    /// Encrypted application text content.
    EncryptedText,
    /// Delivery or processing acknowledgment.
    Acknowledgment,
    /// Session-establishment key exchange bytes.
    KeyExchange,
    /// Double Ratchet header bytes.
    RatchetHeader,
    /// Encrypted application text content that follows the sender's Inbox Grant.
    EncryptedTextWithGrant,
    /// A Contact Acceptance: the accepter's Inbox Grant, then encrypted application text content.
    ContactAcceptance,
}

impl PayloadKind {
    /// Returns the canonical wire tag.
    pub fn tag(self) -> u8 {
        match self {
            PayloadKind::EncryptedText => 0,
            PayloadKind::Acknowledgment => 1,
            PayloadKind::KeyExchange => 2,
            PayloadKind::RatchetHeader => 3,
            PayloadKind::EncryptedTextWithGrant => 4,
            PayloadKind::ContactAcceptance => 5,
        }
    }

    /// Parses a canonical payload tag.
    pub fn from_tag(tag: u8) -> Result<Self, MessageEncodingError> {
        match tag {
            0 => Ok(PayloadKind::EncryptedText),
            1 => Ok(PayloadKind::Acknowledgment),
            2 => Ok(PayloadKind::KeyExchange),
            3 => Ok(PayloadKind::RatchetHeader),
            4 => Ok(PayloadKind::EncryptedTextWithGrant),
            5 => Ok(PayloadKind::ContactAcceptance),
            _ => Err(MessageEncodingError::UnsupportedPayloadKind(tag)),
        }
    }

    /// Returns whether the payload starts with the sender's Inbox Grant.
    pub fn carries_grant(self) -> bool {
        matches!(
            self,
            PayloadKind::EncryptedTextWithGrant | PayloadKind::ContactAcceptance
        )
    }
}

/// Fields authenticated by an established Message signature.
pub struct MessageTranscriptInput<'a> {
    /// Session the Message belongs to.
    pub session_id: SessionId,
    /// Canonical recipient Ed25519 Identity Key.
    pub recipient_identity_verifying_key: &'a [u8; PUBLIC_KEY_LEN],
    /// Sender-selected Message ID.
    pub id: MessageId,
    /// Sender-observed Unix timestamp in milliseconds.
    pub sent_at_millis: u64,
    /// Authenticated payload interpretation.
    pub payload_kind: PayloadKind,
    /// Padded plaintext authenticated by the signature.
    pub payload: &'a [u8],
    /// Exact domain-signed sender certificate.
    pub sender_certificate: &'a [u8],
}

/// Constructs the canonical transcript, excluding its signature context.
///
/// The caller signs or verifies these bytes under [`MESSAGE_TRANSCRIPT_CONTEXT`].
pub fn message_transcript(
    input: MessageTranscriptInput<'_>,
) -> Result<Zeroizing<Vec<u8>>, MessageEncodingError> {
    if input.payload.len() > MAX_TRANSCRIPT_PAYLOAD_LEN
        || input.sender_certificate.len() > MAX_TRANSCRIPT_SENDER_CERTIFICATE_LEN
    {
        return Err(MessageEncodingError::PayloadTooLarge);
    }
    let payload_len =
        u32::try_from(input.payload.len()).map_err(|_| MessageEncodingError::PayloadTooLarge)?;
    let sender_certificate_len = u32::try_from(input.sender_certificate.len())
        .map_err(|_| MessageEncodingError::PayloadTooLarge)?;
    let capacity = (SESSION_ID_LEN + PUBLIC_KEY_LEN + 16 + 8 + 1 + 4)
        .checked_add(input.payload.len())
        .and_then(|len| len.checked_add(4))
        .and_then(|len| len.checked_add(input.sender_certificate.len()))
        .ok_or(MessageEncodingError::PayloadTooLarge)?;
    let mut transcript = Zeroizing::new(Vec::with_capacity(capacity));
    transcript.extend_from_slice(input.session_id.as_bytes());
    transcript.extend_from_slice(input.recipient_identity_verifying_key);
    transcript.extend_from_slice(input.id.as_bytes());
    transcript.extend_from_slice(&input.sent_at_millis.to_be_bytes());
    transcript.push(input.payload_kind.tag());
    transcript.extend_from_slice(&payload_len.to_be_bytes());
    transcript.extend_from_slice(input.payload);
    transcript.extend_from_slice(&sender_certificate_len.to_be_bytes());
    transcript.extend_from_slice(input.sender_certificate);
    Ok(transcript)
}

/// An error returned while encoding authenticated Message metadata.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum MessageEncodingError {
    /// A transcript field exceeds the supported encoding length.
    #[error("message transcript field exceeds size limit")]
    PayloadTooLarge,
    /// The payload tag is unknown.
    #[error("unsupported message payload kind: {0}")]
    UnsupportedPayloadKind(u8),
}

/// Prefixes the plaintext length and fills the next supported bucket with zeros.
pub fn pad_sealed_payload(plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealedPayloadError> {
    let required_len = plaintext
        .len()
        .checked_add(SEALED_PAYLOAD_LEN_PREFIX_LEN)
        .ok_or(SealedPayloadError::LengthOverflow)?;
    let bucket = SEALED_PAYLOAD_BUCKETS
        .iter()
        .copied()
        .find(|bucket| required_len <= *bucket)
        .ok_or(SealedPayloadError::LengthTooLarge(plaintext.len()))?;
    let plaintext_len =
        u32::try_from(plaintext.len()).map_err(|_| SealedPayloadError::LengthExceedsU32)?;
    let mut padded = Zeroizing::new(Vec::with_capacity(bucket));
    padded.extend_from_slice(&plaintext_len.to_be_bytes());
    padded.extend_from_slice(plaintext);
    padded.resize(bucket, 0);
    Ok(padded)
}

/// Validates the bucket, length prefix, and zero fill before copying the plaintext.
pub fn unpad_sealed_payload(padded: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealedPayloadError> {
    if !SEALED_PAYLOAD_BUCKETS.contains(&padded.len()) {
        return Err(SealedPayloadError::InvalidBucket(padded.len()));
    }
    let len_bytes: [u8; SEALED_PAYLOAD_LEN_PREFIX_LEN] = padded
        .get(..SEALED_PAYLOAD_LEN_PREFIX_LEN)
        .ok_or(SealedPayloadError::TooShort)?
        .try_into()
        .map_err(|_| SealedPayloadError::InvalidLengthPrefix)?;
    let plaintext_len = usize::try_from(u32::from_be_bytes(len_bytes))
        .map_err(|_| SealedPayloadError::PlatformLimit)?;
    let plaintext_end = SEALED_PAYLOAD_LEN_PREFIX_LEN
        .checked_add(plaintext_len)
        .ok_or(SealedPayloadError::LengthOverflow)?;
    if plaintext_end > padded.len() {
        return Err(SealedPayloadError::LengthExceedsBucket);
    }
    if padded[plaintext_end..].iter().any(|byte| *byte != 0) {
        return Err(SealedPayloadError::MalformedPadding);
    }
    Ok(Zeroizing::new(
        padded[SEALED_PAYLOAD_LEN_PREFIX_LEN..plaintext_end].to_vec(),
    ))
}

/// An error returned by sealed payload padding or decoding.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum SealedPayloadError {
    /// Adding the length prefix overflows the platform size.
    #[error("sealed payload length overflowed")]
    LengthOverflow,
    /// The plaintext does not fit the largest supported bucket.
    #[error("sealed payload length exceeds limit: {0}")]
    LengthTooLarge(usize),
    /// The plaintext length cannot be encoded in four bytes.
    #[error("sealed payload length exceeds u32")]
    LengthExceedsU32,
    /// The padded length is not a supported bucket.
    #[error("sealed payload padding bucket is invalid: {0}")]
    InvalidBucket(usize),
    /// The length prefix is missing.
    #[error("sealed payload padding is too short")]
    TooShort,
    /// The length prefix is malformed.
    #[error("sealed payload length prefix is invalid")]
    InvalidLengthPrefix,
    /// The decoded length cannot fit the platform size.
    #[error("sealed payload length prefix exceeds platform limit")]
    PlatformLimit,
    /// The decoded plaintext extends beyond its bucket.
    #[error("sealed payload length exceeds padding bucket")]
    LengthExceedsBucket,
    /// The padding contains nonzero bytes.
    #[error("sealed payload padding is malformed")]
    MalformedPadding,
}
