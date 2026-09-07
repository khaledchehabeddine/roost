//! Authenticated Message metadata, transcript construction, and sealed payload padding.

use std::{error::Error, fmt};
use zeroize::Zeroizing;

const PUBLIC_KEY_LEN: usize = 32;
/// Domain separator for established Message signatures.
pub const MESSAGE_TRANSCRIPT_CONTEXT: &[u8] = b"AetherMessageTranscript-v1:";
/// Length of the original-plaintext size prefix.
pub const SEALED_PAYLOAD_LEN_PREFIX_LEN: usize = 4;
/// Supported padded payload lengths, including the length prefix.
pub const SEALED_PAYLOAD_BUCKETS: [usize; 12] = [
    32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16_384, 32_768, 65_536,
];

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
#[non_exhaustive]
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
}

impl PayloadKind {
    /// Returns the canonical wire tag.
    pub fn tag(self) -> u8 {
        match self {
            PayloadKind::EncryptedText => 0,
            PayloadKind::Acknowledgment => 1,
            PayloadKind::KeyExchange => 2,
            PayloadKind::RatchetHeader => 3,
        }
    }

    /// Parses a canonical payload tag.
    ///
    /// # Errors
    /// - [`MessageEncodingError::UnsupportedPayloadKind`] if the tag is unknown.
    pub fn from_tag(tag: u8) -> Result<Self, MessageEncodingError> {
        match tag {
            0 => Ok(PayloadKind::EncryptedText),
            1 => Ok(PayloadKind::Acknowledgment),
            2 => Ok(PayloadKind::KeyExchange),
            3 => Ok(PayloadKind::RatchetHeader),
            _ => Err(MessageEncodingError::UnsupportedPayloadKind(tag)),
        }
    }
}

/// Fields authenticated by an established Message signature.
pub struct MessageTranscriptInput<'a> {
    /// Session identifier bytes, at most 96 bytes.
    pub session_key: &'a [u8],
    /// Canonical recipient Ed25519 Identity Key.
    pub recipient_identity_verifying_key: &'a [u8; PUBLIC_KEY_LEN],
    /// Sender-selected Message ID.
    pub id: MessageId,
    /// Sender-observed Unix timestamp in milliseconds.
    pub timestamp_millis: u64,
    /// Authenticated payload interpretation.
    pub payload_kind: PayloadKind,
    /// Padded plaintext authenticated by the signature.
    pub payload: &'a [u8],
    /// Exact domain-signed sender certificate.
    pub sender_certificate: &'a [u8],
}

/// An error returned by sealed payload padding or decoding.
#[derive(Debug, Eq, PartialEq)]
pub enum SealedPayloadError {
    /// Adding the length prefix overflows the platform size.
    LengthOverflow,
    /// The plaintext does not fit the largest supported bucket.
    LengthTooLarge(usize),
    /// The plaintext length cannot be encoded in four bytes.
    LengthExceedsU32,
    /// The padded length is not a supported bucket.
    InvalidBucket(usize),
    /// The length prefix is missing.
    TooShort,
    /// The length prefix is malformed.
    InvalidLengthPrefix,
    /// The decoded length cannot fit the platform size.
    PlatformLimit,
    /// The decoded plaintext extends beyond its bucket.
    LengthExceedsBucket,
    /// The padding contains nonzero bytes.
    MalformedPadding,
}

impl fmt::Display for SealedPayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthOverflow => write!(f, "sealed payload length overflowed"),
            Self::LengthTooLarge(len) => {
                write!(f, "sealed payload length exceeds limit: {len}")
            }
            Self::LengthExceedsU32 => write!(f, "sealed payload length exceeds u32"),
            Self::InvalidBucket(len) => {
                write!(f, "sealed payload padding bucket is invalid: {len}")
            }
            Self::TooShort => write!(f, "sealed payload padding is too short"),
            Self::InvalidLengthPrefix => {
                write!(f, "sealed payload length prefix is invalid")
            }
            Self::PlatformLimit => {
                write!(f, "sealed payload length prefix exceeds platform limit")
            }
            Self::LengthExceedsBucket => {
                write!(f, "sealed payload length exceeds padding bucket")
            }
            Self::MalformedPadding => write!(f, "sealed payload padding is malformed"),
        }
    }
}

/// Constructs the canonical transcript, excluding its signature context.
///
/// The caller signs or verifies these bytes under [`MESSAGE_TRANSCRIPT_CONTEXT`].
///
/// # Errors
/// - [`MessageEncodingError::PayloadTooLarge`] if a field exceeds its fixed cap or its encoded length overflows.
pub fn message_transcript(
    input: MessageTranscriptInput<'_>,
) -> Result<Zeroizing<Vec<u8>>, MessageEncodingError> {
    if input.session_key.len() > 96
        || input.payload.len() > 65_536
        || input.sender_certificate.len() > 16 * 1024
    {
        return Err(MessageEncodingError::PayloadTooLarge);
    }
    let session_key_len = u32::try_from(input.session_key.len())
        .map_err(|_| MessageEncodingError::PayloadTooLarge)?;
    let payload_len =
        u32::try_from(input.payload.len()).map_err(|_| MessageEncodingError::PayloadTooLarge)?;
    let sender_certificate_len = u32::try_from(input.sender_certificate.len())
        .map_err(|_| MessageEncodingError::PayloadTooLarge)?;
    let capacity = 4usize
        .checked_add(input.session_key.len())
        .and_then(|len| len.checked_add(PUBLIC_KEY_LEN + 16 + 8 + 1 + 4))
        .and_then(|len| len.checked_add(input.payload.len()))
        .and_then(|len| len.checked_add(4))
        .and_then(|len| len.checked_add(input.sender_certificate.len()))
        .ok_or(MessageEncodingError::PayloadTooLarge)?;
    let mut transcript = Zeroizing::new(Vec::with_capacity(capacity));
    transcript.extend_from_slice(&session_key_len.to_be_bytes());
    transcript.extend_from_slice(input.session_key);
    transcript.extend_from_slice(input.recipient_identity_verifying_key);
    transcript.extend_from_slice(input.id.as_bytes());
    transcript.extend_from_slice(&input.timestamp_millis.to_be_bytes());
    transcript.push(input.payload_kind.tag());
    transcript.extend_from_slice(&payload_len.to_be_bytes());
    transcript.extend_from_slice(input.payload);
    transcript.extend_from_slice(&sender_certificate_len.to_be_bytes());
    transcript.extend_from_slice(input.sender_certificate);
    Ok(transcript)
}

/// Prefixes the plaintext length and fills the next supported bucket with zeros.
///
/// # Errors
/// - [`SealedPayloadError::LengthOverflow`] if adding the prefix overflows.
/// - [`SealedPayloadError::LengthTooLarge`] if no supported bucket fits the plaintext.
/// - [`SealedPayloadError::LengthExceedsU32`] if the length cannot fit its prefix.
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
    let mut padded = Zeroizing::new(vec![0u8; bucket]);
    padded[..SEALED_PAYLOAD_LEN_PREFIX_LEN].copy_from_slice(&plaintext_len.to_be_bytes());
    padded[SEALED_PAYLOAD_LEN_PREFIX_LEN..required_len].copy_from_slice(plaintext);
    Ok(padded)
}

/// Validates the bucket, length prefix, and zero fill before copying the plaintext.
///
/// # Errors
/// - [`SealedPayloadError::InvalidBucket`] if the padded length is unsupported.
/// - [`SealedPayloadError::TooShort`] or [`SealedPayloadError::InvalidLengthPrefix`] if the prefix cannot be read.
/// - [`SealedPayloadError::PlatformLimit`] or [`SealedPayloadError::LengthOverflow`] if the decoded length overflows.
/// - [`SealedPayloadError::LengthExceedsBucket`] if the plaintext exceeds the bucket.
/// - [`SealedPayloadError::MalformedPadding`] if any fill byte is nonzero.
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

/// An error returned while encoding authenticated Message metadata.
#[derive(Debug, Eq, PartialEq)]
pub enum MessageEncodingError {
    /// A transcript field exceeds the supported encoding length.
    PayloadTooLarge,
    /// The payload tag is unknown.
    UnsupportedPayloadKind(u8),
}

impl fmt::Display for MessageEncodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooLarge => write!(f, "message transcript field exceeds size limit"),
            Self::UnsupportedPayloadKind(tag) => {
                write!(f, "unsupported message payload kind: {tag}")
            }
        }
    }
}

impl Error for MessageEncodingError {}
impl Error for SealedPayloadError {}
