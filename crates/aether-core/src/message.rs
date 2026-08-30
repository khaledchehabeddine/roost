use std::error::Error;
use std::fmt;

use crate::hardening::ProtocolHardeningLimits;
use aether_crypto::{SealedFrame, SealedFramePreKeyReference};
use zeroize::Zeroizing;

const PUBLIC_KEY_LEN: usize = 32;
pub(crate) const MESSAGE_TRANSCRIPT_CONTEXT: &[u8] = b"AetherMessageTranscript-v1:";
pub(crate) const SEALED_PAYLOAD_LEN_PREFIX_LEN: usize = 4;
pub(crate) const SEALED_PAYLOAD_BUCKETS: [usize; 12] = [
    32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16_384, 32_768, 65_536,
];

/// The UUID-shaped identifier for a [`Message`].
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

/// A sealed-sender frame encoded for consumer transport.
pub struct Message {
    /// Sealed-frame wire version.
    pub version: u8,
    /// Recipient Discovery Key X25519 public key bytes. Always 32 bytes.
    pub recipient_public_key: [u8; PUBLIC_KEY_LEN],
    /// Optional X3DH prekey reference for initial messages.
    pub prekey_reference: Option<SealedFramePreKeyReference>,
    /// Per-frame ephemeral X25519 public key bytes. Always 32 bytes.
    pub ephemeral_public_key: [u8; PUBLIC_KEY_LEN],
    /// Opaque frame ciphertext bytes.
    pub ciphertext: Vec<u8>,
}

impl Message {
    /// Encodes this message to the sealed-frame wire format.
    ///
    /// The sealed-frame version is internal to the encoded message and independent of any
    /// transport envelope a consumer may add around the returned bytes.
    ///
    /// # Errors
    /// - [`MessageError::PayloadTooLarge`] if `ciphertext` exceeds the message payload cap.
    /// - [`MessageError::EncodedTooLarge`] if the encoded output exceeds the encoded-message cap.
    /// - [`MessageError::Encode`] if Postcard rejects the wire form.
    pub fn to_bytes(&self) -> Result<Vec<u8>, MessageError> {
        self.to_bytes_with_hardening_limits(ProtocolHardeningLimits::default())
    }

    /// Encodes this message with caller-selected hardening limits.
    ///
    /// # Errors
    /// - [`MessageError::PayloadTooLarge`] if `ciphertext` exceeds the configured payload cap.
    /// - [`MessageError::EncodedTooLarge`] if the encoded output exceeds the configured
    ///   encoded-message cap.
    /// - [`MessageError::Encode`] if Postcard rejects the wire form.
    pub fn to_bytes_with_hardening_limits(
        &self,
        limits: ProtocolHardeningLimits,
    ) -> Result<Vec<u8>, MessageError> {
        let limits = limits.bounded();
        if self.ciphertext.len() > limits.max_message_payload_len {
            return Err(MessageError::PayloadTooLarge);
        }
        let bytes = self
            .to_frame()
            .to_bytes()
            .map_err(|_| MessageError::Encode)?;
        if bytes.len() > limits.max_encoded_message_len {
            return Err(MessageError::EncodedTooLarge);
        }
        Ok(bytes)
    }

    /// Decodes a sealed-frame message from bytes produced by [`Self::to_bytes`].
    ///
    /// Unsupported message versions are rejected before the remaining Postcard body is decoded.
    ///
    /// # Errors
    /// - [`MessageError::EncodedTooLarge`] if `bytes` exceeds the encoded-message cap.
    /// - [`MessageError::Decode`] if the bytes are empty, malformed, unsupported, or have trailing
    ///   data.
    /// - [`MessageError::PayloadTooLarge`] if the decoded ciphertext exceeds the payload cap.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MessageError> {
        Self::from_bytes_with_hardening_limits(bytes, ProtocolHardeningLimits::default())
    }

    /// Decodes a sealed-frame message with caller-selected hardening limits.
    ///
    /// Unsupported message versions are rejected before the remaining Postcard body is decoded.
    ///
    /// # Errors
    /// - [`MessageError::EncodedTooLarge`] if `bytes` exceeds the configured encoded-message cap.
    /// - [`MessageError::Decode`] if the bytes are empty, malformed, unsupported, or have trailing
    ///   data.
    /// - [`MessageError::PayloadTooLarge`] if the decoded ciphertext exceeds the configured
    ///   payload cap.
    pub fn from_bytes_with_hardening_limits(
        bytes: &[u8],
        limits: ProtocolHardeningLimits,
    ) -> Result<Self, MessageError> {
        let limits = limits.bounded();
        if bytes.len() > limits.max_encoded_message_len {
            return Err(MessageError::EncodedTooLarge);
        }
        let frame = SealedFrame::from_bytes(bytes).map_err(|_| MessageError::Decode)?;
        if frame.ciphertext.len() > limits.max_message_payload_len {
            return Err(MessageError::PayloadTooLarge);
        }
        Ok(Self::from_frame(frame))
    }

    pub(crate) fn from_frame(frame: SealedFrame) -> Self {
        Self {
            version: frame.version,
            recipient_public_key: frame.recipient_public_key,
            prekey_reference: frame.prekey_reference,
            ephemeral_public_key: frame.ephemeral_public_key,
            ciphertext: frame.ciphertext,
        }
    }

    pub(crate) fn to_frame(&self) -> SealedFrame {
        SealedFrame {
            version: self.version,
            recipient_public_key: self.recipient_public_key,
            prekey_reference: self.prekey_reference,
            ephemeral_public_key: self.ephemeral_public_key,
            ciphertext: self.ciphertext.clone(),
        }
    }
}

/// The semantic type of a [`Message`] payload.
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
    pub(crate) fn tag(self) -> u8 {
        match self {
            PayloadKind::EncryptedText => 0,
            PayloadKind::Acknowledgment => 1,
            PayloadKind::KeyExchange => 2,
            PayloadKind::RatchetHeader => 3,
        }
    }

    pub(crate) fn from_tag(tag: u8) -> Result<Self, MessageError> {
        match tag {
            0 => Ok(PayloadKind::EncryptedText),
            1 => Ok(PayloadKind::Acknowledgment),
            2 => Ok(PayloadKind::KeyExchange),
            3 => Ok(PayloadKind::RatchetHeader),
            _ => Err(MessageError::UnsupportedPayloadKind(tag)),
        }
    }
}

pub(crate) struct MessageTranscriptInput<'a> {
    pub(crate) session_key: &'a [u8],
    pub(crate) recipient_identity_verifying_key: &'a [u8; PUBLIC_KEY_LEN],
    pub(crate) id: MessageId,
    pub(crate) timestamp_millis: u64,
    pub(crate) payload_kind: PayloadKind,
    pub(crate) payload: &'a [u8],
    pub(crate) sender_certificate: &'a [u8],
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum SealedPayloadError {
    LengthOverflow,
    LengthTooLarge(usize),
    LengthExceedsU32,
    InvalidBucket(usize),
    TooShort,
    InvalidLengthPrefix,
    PlatformLimit,
    LengthExceedsBucket,
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

pub(crate) fn message_transcript(
    input: MessageTranscriptInput<'_>,
) -> Result<Zeroizing<Vec<u8>>, MessageError> {
    let session_key_len =
        u32::try_from(input.session_key.len()).map_err(|_| MessageError::PayloadTooLarge)?;
    let payload_len =
        u32::try_from(input.payload.len()).map_err(|_| MessageError::PayloadTooLarge)?;
    let sender_certificate_len =
        u32::try_from(input.sender_certificate.len()).map_err(|_| MessageError::PayloadTooLarge)?;
    let capacity = 4usize
        .checked_add(input.session_key.len())
        .and_then(|len| len.checked_add(PUBLIC_KEY_LEN + 16 + 8 + 1 + 4))
        .and_then(|len| len.checked_add(input.payload.len()))
        .and_then(|len| len.checked_add(4))
        .and_then(|len| len.checked_add(input.sender_certificate.len()))
        .ok_or(MessageError::PayloadTooLarge)?;
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

pub(crate) fn pad_sealed_payload(
    plaintext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SealedPayloadError> {
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

pub(crate) fn unpad_sealed_payload(
    padded: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SealedPayloadError> {
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

/// An error returned by message encoding or decoding.
#[derive(Debug, Eq, PartialEq)]
pub enum MessageError {
    /// Message bytes failed structural decoding.
    Decode,
    /// Encoded message bytes exceed the configured size cap.
    EncodedTooLarge,
    /// Message bytes failed to encode.
    Encode,
    /// A public-key field did not contain exactly 32 bytes.
    InvalidPublicKey,
    /// The payload exceeds the message payload size cap.
    PayloadTooLarge,
    /// Encoded message bytes use a payload-kind tag this build does not understand.
    UnsupportedPayloadKind(u8),
    /// Encoded message bytes use a format version this build does not understand.
    UnsupportedVersion(u8),
}

impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MessageError::Decode => write!(f, "message bytes failed to decode"),
            MessageError::EncodedTooLarge => write!(f, "message bytes exceed size limit"),
            MessageError::Encode => write!(f, "message failed to encode"),
            MessageError::InvalidPublicKey => write!(f, "message public key field is invalid"),
            MessageError::PayloadTooLarge => write!(f, "message payload exceeds size limit"),
            MessageError::UnsupportedPayloadKind(kind) => {
                write!(f, "unsupported message payload kind: {kind}")
            }
            MessageError::UnsupportedVersion(version) => {
                write!(f, "unsupported message format version: {version}")
            }
        }
    }
}

impl Error for MessageError {}

#[cfg(test)]
mod tests {
    use super::*;
    use aether_crypto::{KeyPair, seal_frame};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn message() -> Message {
        let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
        let recipient = KeyPair::from_secret_bytes([3u8; PUBLIC_KEY_LEN]);
        let frame = seal_frame(&mut rng, &recipient.public, None, b"payload").unwrap();
        Message::from_frame(frame)
    }

    fn old_sender_visible_wire() -> Vec<u8> {
        use serde::Serialize;

        #[derive(Serialize)]
        struct SenderVisibleWireV1 {
            version: u8,
            id: [u8; 16],
            sender_public_key: Vec<u8>,
            recipient_public_key: Vec<u8>,
            timestamp_millis: u64,
            payload_kind: u8,
            payload: Vec<u8>,
        }

        postcard::to_stdvec(&SenderVisibleWireV1 {
            version: SealedFrame::VERSION,
            id: [1u8; 16],
            sender_public_key: vec![2u8; PUBLIC_KEY_LEN],
            recipient_public_key: vec![3u8; PUBLIC_KEY_LEN],
            timestamp_millis: 1_700_000_000_123,
            payload_kind: 0,
            payload: vec![0x90, 0x91, 0x92, 0x93, 0x94],
        })
        .unwrap()
    }

    fn old_message() -> Message {
        Message {
            version: SealedFrame::VERSION,
            recipient_public_key: [3u8; PUBLIC_KEY_LEN],
            prekey_reference: None,
            ephemeral_public_key: [4u8; PUBLIC_KEY_LEN],
            ciphertext: vec![0x90, 0x91, 0x92, 0x93, 0x94],
        }
    }

    fn assert_decode_error(bytes: &[u8], expected: MessageError) {
        match Message::from_bytes(bytes) {
            Ok(_) => panic!("message decoded unexpectedly"),
            Err(e) => assert_eq!(e, expected),
        }
    }

    #[test]
    fn round_trip_preserves_text_message() {
        let message = message();
        let decoded = Message::from_bytes(&message.to_bytes().unwrap()).unwrap();

        assert_eq!(decoded.version, message.version);
        assert_eq!(decoded.recipient_public_key, message.recipient_public_key);
        assert_eq!(decoded.prekey_reference, message.prekey_reference);
        assert_eq!(decoded.ephemeral_public_key, message.ephemeral_public_key);
        assert_eq!(decoded.ciphertext, message.ciphertext);
    }

    #[test]
    fn from_bytes_rejects_unsupported_version_before_full_decode() {
        let bytes = vec![2];

        assert_decode_error(&bytes, MessageError::Decode);
    }

    #[test]
    fn from_bytes_rejects_oversized_before_full_decode() {
        let max_len = ProtocolHardeningLimits::default()
            .bounded()
            .max_encoded_message_len;
        let bytes = vec![0; max_len + 1];

        assert_decode_error(&bytes, MessageError::EncodedTooLarge);
    }

    #[test]
    fn from_bytes_rejects_old_sender_visible_wire_layout() {
        assert_decode_error(&old_sender_visible_wire(), MessageError::Decode);
    }

    #[test]
    fn from_bytes_rejects_malformed_postcard() {
        let bytes = vec![SealedFrame::VERSION, 0xff];

        assert_decode_error(&bytes, MessageError::Decode);
    }

    #[test]
    fn from_bytes_rejects_trailing_bytes() {
        let mut bytes = message().to_bytes().unwrap();
        bytes.push(0);

        assert_decode_error(&bytes, MessageError::Decode);
    }

    #[test]
    fn from_bytes_rejects_recipient_public_key_with_wrong_shape() {
        let mut message = old_message();
        message.recipient_public_key = [0u8; PUBLIC_KEY_LEN];
        let bytes = message.to_bytes().unwrap_err();

        assert_eq!(bytes, MessageError::Encode);
    }

    #[test]
    fn to_bytes_rejects_oversized_payload() {
        let mut message = message();
        message.ciphertext =
            vec![0; ProtocolHardeningLimits::default().max_message_payload_len + 1];

        match message.to_bytes() {
            Ok(_) => panic!("message encoded unexpectedly"),
            Err(e) => assert_eq!(e, MessageError::PayloadTooLarge),
        }
    }
}
