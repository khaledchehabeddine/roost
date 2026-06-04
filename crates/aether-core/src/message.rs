use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};

const MESSAGE_WIRE_VERSION: u8 = 1;
const MAX_ENCODED_MESSAGE_LEN: usize = MAX_MESSAGE_PAYLOAD_LEN + 128;
const MAX_MESSAGE_PAYLOAD_LEN: usize = 64 * 1024;
const PUBLIC_KEY_LEN: usize = 32;

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

/// A Session packet encoded for consumer transport.
pub struct Message {
    /// Stable identifier for this message.
    pub id: MessageId,
    /// Sender X25519 public key bytes. Always 32 bytes.
    pub sender_public_key: [u8; PUBLIC_KEY_LEN],
    /// Recipient X25519 public key bytes. Always 32 bytes.
    pub recipient_public_key: [u8; PUBLIC_KEY_LEN],
    /// Sender-observed Unix timestamp in milliseconds.
    pub timestamp_millis: u64,
    /// Interpretation of the payload bytes.
    pub payload_kind: PayloadKind,
    /// Opaque payload bytes carried by the message.
    pub payload: Vec<u8>,
}

impl Message {
    /// Encodes this message to the Postcard wire format.
    ///
    /// The version byte is internal to the encoded message and is independent of any transport
    /// envelope a consumer may add around the returned bytes.
    ///
    /// # Errors
    /// - [`MessageError::PayloadTooLarge`] if `payload` exceeds the message payload cap.
    /// - [`MessageError::Encode`] if Postcard rejects the wire form or the encoded output exceeds
    ///   the message size cap.
    pub fn to_bytes(&self) -> Result<Vec<u8>, MessageError> {
        if self.payload.len() > MAX_MESSAGE_PAYLOAD_LEN {
            return Err(MessageError::PayloadTooLarge);
        }

        let bytes = postcard::to_stdvec(&MessageWire {
            version: MESSAGE_WIRE_VERSION,
            id: *self.id.as_bytes(),
            sender_public_key: self.sender_public_key.to_vec(),
            recipient_public_key: self.recipient_public_key.to_vec(),
            timestamp_millis: self.timestamp_millis,
            payload_kind: self.payload_kind.tag(),
            payload: self.payload.clone(),
        })
        .map_err(|_| MessageError::Encode)?;
        if bytes.len() > MAX_ENCODED_MESSAGE_LEN {
            return Err(MessageError::Encode);
        }
        Ok(bytes)
    }

    /// Decodes a message from bytes produced by [`Self::to_bytes`].
    ///
    /// Unsupported message versions are rejected before the remaining Postcard payload is decoded.
    ///
    /// # Errors
    /// - [`MessageError::Decode`] if the bytes are empty, oversized, malformed, or have trailing
    ///   data.
    /// - [`MessageError::InvalidPublicKey`] if either public-key field is not exactly 32 bytes.
    /// - [`MessageError::PayloadTooLarge`] if the decoded payload exceeds the payload cap.
    /// - [`MessageError::UnsupportedPayloadKind`] if the payload-kind tag is unknown.
    /// - [`MessageError::UnsupportedVersion`] if the message format version is not supported.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MessageError> {
        let version = *bytes.first().ok_or(MessageError::Decode)?;
        if version != MESSAGE_WIRE_VERSION {
            return Err(MessageError::UnsupportedVersion(version));
        }
        if bytes.len() > MAX_ENCODED_MESSAGE_LEN {
            return Err(MessageError::Decode);
        }

        let (wire, trailing): (MessageWire, &[u8]) =
            postcard::take_from_bytes(bytes).map_err(|_| MessageError::Decode)?;
        if !trailing.is_empty() {
            return Err(MessageError::Decode);
        }
        if wire.payload.len() > MAX_MESSAGE_PAYLOAD_LEN {
            return Err(MessageError::PayloadTooLarge);
        }

        Ok(Self {
            id: MessageId::from_bytes(wire.id),
            sender_public_key: public_key_bytes(wire.sender_public_key)?,
            recipient_public_key: public_key_bytes(wire.recipient_public_key)?,
            timestamp_millis: wire.timestamp_millis,
            payload_kind: PayloadKind::from_tag(wire.payload_kind)?,
            payload: wire.payload,
        })
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
    fn tag(self) -> u8 {
        match self {
            PayloadKind::EncryptedText => 0,
            PayloadKind::Acknowledgment => 1,
            PayloadKind::KeyExchange => 2,
            PayloadKind::RatchetHeader => 3,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, MessageError> {
        match tag {
            0 => Ok(PayloadKind::EncryptedText),
            1 => Ok(PayloadKind::Acknowledgment),
            2 => Ok(PayloadKind::KeyExchange),
            3 => Ok(PayloadKind::RatchetHeader),
            _ => Err(MessageError::UnsupportedPayloadKind(tag)),
        }
    }
}

/// An error returned by message encoding or decoding.
#[derive(Debug, Eq, PartialEq)]
pub enum MessageError {
    /// Message bytes failed structural decoding.
    Decode,
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

#[derive(Deserialize, Serialize)]
struct MessageWire {
    version: u8,
    id: [u8; 16],
    sender_public_key: Vec<u8>,
    recipient_public_key: Vec<u8>,
    timestamp_millis: u64,
    payload_kind: u8,
    payload: Vec<u8>,
}

fn public_key_bytes(bytes: Vec<u8>) -> Result<[u8; PUBLIC_KEY_LEN], MessageError> {
    bytes.try_into().map_err(|_| MessageError::InvalidPublicKey)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message() -> Message {
        Message {
            id: MessageId::from_bytes([1u8; 16]),
            sender_public_key: [2u8; PUBLIC_KEY_LEN],
            recipient_public_key: [3u8; PUBLIC_KEY_LEN],
            timestamp_millis: 1_700_000_000_123,
            payload_kind: PayloadKind::EncryptedText,
            payload: vec![0x90, 0x91, 0x92, 0x93, 0x94],
        }
    }

    fn wire() -> MessageWire {
        MessageWire {
            version: MESSAGE_WIRE_VERSION,
            id: [1u8; 16],
            sender_public_key: vec![2u8; PUBLIC_KEY_LEN],
            recipient_public_key: vec![3u8; PUBLIC_KEY_LEN],
            timestamp_millis: 1_700_000_000_123,
            payload_kind: 0,
            payload: vec![0x90, 0x91, 0x92, 0x93, 0x94],
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

        assert_eq!(decoded.id, message.id);
        assert_eq!(decoded.sender_public_key, message.sender_public_key);
        assert_eq!(decoded.recipient_public_key, message.recipient_public_key);
        assert_eq!(decoded.timestamp_millis, message.timestamp_millis);
        assert_eq!(decoded.payload_kind, message.payload_kind);
        assert_eq!(decoded.payload, message.payload);
    }

    #[test]
    fn from_bytes_rejects_unsupported_version_before_full_decode() {
        let bytes = [2u8];

        assert_decode_error(&bytes, MessageError::UnsupportedVersion(2));
    }

    #[test]
    fn from_bytes_rejects_malformed_postcard() {
        let bytes = [MESSAGE_WIRE_VERSION, 0xff];

        assert_decode_error(&bytes, MessageError::Decode);
    }

    #[test]
    fn from_bytes_rejects_trailing_bytes() {
        let mut bytes = message().to_bytes().unwrap();
        bytes.push(0);

        assert_decode_error(&bytes, MessageError::Decode);
    }

    #[test]
    fn from_bytes_rejects_sender_public_key_with_wrong_shape() {
        let mut wire = wire();
        wire.sender_public_key.pop();
        let bytes = postcard::to_stdvec(&wire).unwrap();

        assert_decode_error(&bytes, MessageError::InvalidPublicKey);
    }

    #[test]
    fn from_bytes_rejects_recipient_public_key_with_wrong_shape() {
        let mut wire = wire();
        wire.recipient_public_key.push(4);
        let bytes = postcard::to_stdvec(&wire).unwrap();

        assert_decode_error(&bytes, MessageError::InvalidPublicKey);
    }

    #[test]
    fn from_bytes_rejects_unknown_payload_kind() {
        let mut wire = wire();
        wire.payload_kind = 4;
        let bytes = postcard::to_stdvec(&wire).unwrap();

        assert_decode_error(&bytes, MessageError::UnsupportedPayloadKind(4));
    }

    #[test]
    fn to_bytes_rejects_oversized_payload() {
        let mut message = message();
        message.payload = vec![0; MAX_MESSAGE_PAYLOAD_LEN + 1];

        match message.to_bytes() {
            Ok(_) => panic!("message encoded unexpectedly"),
            Err(e) => assert_eq!(e, MessageError::PayloadTooLarge),
        }
    }
}
