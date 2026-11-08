//! Authenticated message metadata, transcript construction, and sealed payload padding.

use crate::key_encoding::PUBLIC_KEY_LEN;
use crate::sender_certificate::MAX_SENDER_CERTIFICATE_LEN;
use zeroize::Zeroizing;

const SESSION_ID_LEN: usize = 16;
const MESSAGE_ID_LEN: usize = 16;
/// Domain separator for established message signatures.
pub const MESSAGE_TRANSCRIPT_CONTEXT: &[u8] = b"RoostMessageTranscript-v1:";
const SEALED_PAYLOAD_LEN_PREFIX_LEN: usize = 4;
// Padded payload lengths, including the length prefix.
const SEALED_PAYLOAD_BUCKETS: [usize; 12] = [
    32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16_384, 32_768, 65_536,
];
// The transcript authenticates the padded payload, so its limit is the largest bucket.
const MAX_TRANSCRIPT_PAYLOAD_LEN: usize = SEALED_PAYLOAD_BUCKETS[SEALED_PAYLOAD_BUCKETS.len() - 1];
/// Longest plaintext the largest padding bucket holds.
pub const MAX_SEALED_PLAINTEXT_LEN: usize =
    MAX_TRANSCRIPT_PAYLOAD_LEN - SEALED_PAYLOAD_LEN_PREFIX_LEN;
// The fixed-width transcript fields, plus the length prefixes of its payload and certificate.
const TRANSCRIPT_FIXED_LEN: usize = SESSION_ID_LEN
    + PUBLIC_KEY_LEN
    + MESSAGE_ID_LEN
    + size_of::<u64>()
    + size_of::<u8>()
    + 2 * size_of::<u32>();

/// The identifier both peers derive from a session's handshake.
///
/// It addresses the session's state and travels sealed in every message on the session.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SessionId([u8; SESSION_ID_LEN]);

impl SessionId {
    /// Creates a session identifier from its bytes.
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

/// The identifier a sender gives a message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageId([u8; MESSAGE_ID_LEN]);

impl MessageId {
    /// Creates a message identifier from its bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; MESSAGE_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the identifier's bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; MESSAGE_ID_LEN] {
        &self.0
    }
}

/// The semantic type of a message payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadKind {
    /// Content from the app.
    Content,
    /// A delivery acknowledgment.
    Acknowledgment,
    /// Content from the app that follows the sender's inbox grant.
    ContentWithGrant,
    /// A contact acceptance: the accepter's inbox grant, then content from the app.
    ContactAcceptance,
    /// An acknowledgment that follows the sender's inbox grant.
    AcknowledgmentWithGrant,
    /// A grant update: the sender's inbox grant and no content.
    GrantUpdate,
}

impl PayloadKind {
    /// Returns the canonical wire tag.
    pub fn tag(self) -> u8 {
        match self {
            PayloadKind::Content => 0,
            PayloadKind::Acknowledgment => 1,
            // Tags 2 and 3 belonged to removed kinds.
            PayloadKind::ContentWithGrant => 4,
            PayloadKind::ContactAcceptance => 5,
            PayloadKind::AcknowledgmentWithGrant => 6,
            PayloadKind::GrantUpdate => 7,
        }
    }

    /// Returns the payload kind a canonical wire tag names, or `None` for an unknown tag.
    pub fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(PayloadKind::Content),
            1 => Some(PayloadKind::Acknowledgment),
            4 => Some(PayloadKind::ContentWithGrant),
            5 => Some(PayloadKind::ContactAcceptance),
            6 => Some(PayloadKind::AcknowledgmentWithGrant),
            7 => Some(PayloadKind::GrantUpdate),
            _ => None,
        }
    }

    /// Returns whether the payload starts with the sender's inbox grant.
    pub fn carries_grant(self) -> bool {
        matches!(
            self,
            PayloadKind::ContentWithGrant
                | PayloadKind::ContactAcceptance
                | PayloadKind::AcknowledgmentWithGrant
                | PayloadKind::GrantUpdate
        )
    }

    /// Returns whether the payload acknowledges an earlier message.
    pub fn is_acknowledgment(self) -> bool {
        matches!(
            self,
            PayloadKind::Acknowledgment | PayloadKind::AcknowledgmentWithGrant
        )
    }
}

/// Fields authenticated by an established message signature.
pub struct MessageTranscriptInput<'a> {
    /// Session the message belongs to.
    pub session_id: SessionId,
    /// The Ed25519 half of the recipient's identity key.
    pub recipient_identity_verifying_key: &'a [u8; PUBLIC_KEY_LEN],
    /// Sender-selected message ID.
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
) -> Result<Zeroizing<Vec<u8>>, MessageTranscriptError> {
    let payload_len = transcript_length_prefix(input.payload, MAX_TRANSCRIPT_PAYLOAD_LEN).ok_or(
        MessageTranscriptError::PayloadTooLong {
            len: input.payload.len(),
            max: MAX_TRANSCRIPT_PAYLOAD_LEN,
        },
    )?;
    let sender_certificate_len =
        transcript_length_prefix(input.sender_certificate, MAX_SENDER_CERTIFICATE_LEN).ok_or(
            MessageTranscriptError::SenderCertificateTooLong {
                len: input.sender_certificate.len(),
                max: MAX_SENDER_CERTIFICATE_LEN,
            },
        )?;

    // Both limits keep this sum far below `usize::MAX`.
    let capacity = TRANSCRIPT_FIXED_LEN + input.payload.len() + input.sender_certificate.len();
    let mut transcript = Zeroizing::new(Vec::with_capacity(capacity));
    transcript.extend_from_slice(input.session_id.as_bytes());
    transcript.extend_from_slice(input.recipient_identity_verifying_key);
    transcript.extend_from_slice(input.id.as_bytes());
    transcript.extend_from_slice(&input.sent_at_millis.to_be_bytes());
    transcript.push(input.payload_kind.tag());
    transcript.extend_from_slice(&payload_len);
    transcript.extend_from_slice(input.payload);
    transcript.extend_from_slice(&sender_certificate_len);
    transcript.extend_from_slice(input.sender_certificate);
    Ok(transcript)
}

fn transcript_length_prefix(field: &[u8], max_len: usize) -> Option<[u8; 4]> {
    if field.len() > max_len {
        return None;
    }
    u32::try_from(field.len()).ok().map(u32::to_be_bytes)
}

/// An error returned while building a message transcript.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum MessageTranscriptError {
    /// The payload is longer than a transcript accepts.
    #[error("message transcript payload is {len} bytes, more than {max}")]
    PayloadTooLong {
        /// Length of the payload.
        len: usize,
        /// Longest payload a transcript accepts.
        max: usize,
    },
    /// The sender certificate is longer than a transcript accepts.
    #[error("message transcript sender certificate is {len} bytes, more than {max}")]
    SenderCertificateTooLong {
        /// Length of the sender certificate.
        len: usize,
        /// Longest sender certificate a transcript accepts.
        max: usize,
    },
}

/// Prefixes the plaintext length and fills the next supported bucket with zeros.
pub fn pad_sealed_payload(plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealedPayloadError> {
    let too_long = || SealedPayloadError::PlaintextTooLong {
        len: plaintext.len(),
        max: MAX_SEALED_PLAINTEXT_LEN,
    };
    let bucket = SEALED_PAYLOAD_BUCKETS
        .into_iter()
        .find(|bucket| plaintext.len() <= bucket - SEALED_PAYLOAD_LEN_PREFIX_LEN)
        .ok_or_else(too_long)?;
    let plaintext_len = u32::try_from(plaintext.len()).map_err(|_| too_long())?;

    let mut padded = Zeroizing::new(Vec::with_capacity(bucket));
    padded.extend_from_slice(&plaintext_len.to_be_bytes());
    padded.extend_from_slice(plaintext);
    padded.resize(bucket, 0);
    Ok(padded)
}

/// Returns the plaintext of a padded payload after checking its bucket, length prefix, and zero
/// fill.
pub fn unpad_sealed_payload(padded: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealedPayloadError> {
    let invalid_bucket = || SealedPayloadError::InvalidBucket { len: padded.len() };
    if !SEALED_PAYLOAD_BUCKETS.contains(&padded.len()) {
        return Err(invalid_bucket());
    }

    let (len_prefix, body) = padded
        .split_first_chunk::<SEALED_PAYLOAD_LEN_PREFIX_LEN>()
        .ok_or_else(invalid_bucket)?;
    let plaintext_len = u32::from_be_bytes(*len_prefix);
    let (plaintext, fill) = usize::try_from(plaintext_len)
        .ok()
        .and_then(|len| body.split_at_checked(len))
        .ok_or(SealedPayloadError::LengthPrefixTooLarge {
            plaintext_len,
            max: body.len(),
        })?;

    if fill.iter().any(|byte| *byte != 0) {
        return Err(SealedPayloadError::NonzeroPadding);
    }
    Ok(Zeroizing::new(plaintext.to_vec()))
}

/// An error returned by sealed payload padding or unpadding.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum SealedPayloadError {
    /// The plaintext doesn't fit the largest bucket.
    #[error("sealed payload length exceeds limit: {len} bytes, at most {max}")]
    PlaintextTooLong {
        /// Length of the plaintext.
        len: usize,
        /// Longest plaintext the largest bucket holds.
        max: usize,
    },
    /// The padded length isn't a bucket length.
    #[error("sealed payload length {len} is not a padding bucket")]
    InvalidBucket {
        /// Length of the padded payload.
        len: usize,
    },
    /// The length prefix names more plaintext than the bucket holds.
    #[error(
        "sealed payload length prefix {plaintext_len} exceeds the {max} bytes its bucket holds"
    )]
    LengthPrefixTooLarge {
        /// Plaintext length the prefix names.
        plaintext_len: u32,
        /// Longest plaintext this bucket holds.
        max: usize,
    },
    /// The padding after the plaintext contains a nonzero byte.
    #[error("sealed payload padding is not all zeros")]
    NonzeroPadding,
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECIPIENT_KEY: [u8; PUBLIC_KEY_LEN] = [0x02; PUBLIC_KEY_LEN];

    fn transcript_input<'a>(
        payload: &'a [u8],
        sender_certificate: &'a [u8],
    ) -> MessageTranscriptInput<'a> {
        MessageTranscriptInput {
            session_id: SessionId::from_bytes([0x01; SESSION_ID_LEN]),
            recipient_identity_verifying_key: &RECIPIENT_KEY,
            id: MessageId::from_bytes([0x03; MESSAGE_ID_LEN]),
            sent_at_millis: 0x0405,
            payload_kind: PayloadKind::GrantUpdate,
            payload,
            sender_certificate,
        }
    }

    #[test]
    fn message_transcript_puts_each_field_in_order() {
        let transcript = message_transcript(transcript_input(b"pay", b"cert")).unwrap();

        let expected = [
            &[0x01; SESSION_ID_LEN][..],
            &RECIPIENT_KEY,
            &[0x03; MESSAGE_ID_LEN],
            &0x0405u64.to_be_bytes(),
            &[PayloadKind::GrantUpdate.tag()],
            &3u32.to_be_bytes(),
            b"pay",
            &4u32.to_be_bytes(),
            b"cert",
        ]
        .concat();
        assert_eq!(transcript.as_slice(), expected.as_slice());
    }

    #[test]
    fn message_transcript_allocates_exactly_its_length() {
        let transcript = message_transcript(transcript_input(&[0x04; 100], &[0x05; 200])).unwrap();
        assert_eq!(transcript.capacity(), transcript.len());
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
    fn sealed_payload_padding_rejects_invalid_bucket_lengths() {
        for len in [SEALED_PAYLOAD_BUCKETS[0] - 1, SEALED_PAYLOAD_BUCKETS[0] + 1] {
            assert_eq!(
                unpad_sealed_payload(&vec![0u8; len]),
                Err(SealedPayloadError::InvalidBucket { len })
            );
        }
    }

    #[test]
    fn sealed_payload_padding_rejects_overlarge_length_prefix() {
        let mut padded = vec![0u8; SEALED_PAYLOAD_BUCKETS[0]];
        let max = SEALED_PAYLOAD_BUCKETS[0] - SEALED_PAYLOAD_LEN_PREFIX_LEN;
        let plaintext_len = u32::try_from(max + 1).unwrap();
        padded[..SEALED_PAYLOAD_LEN_PREFIX_LEN].copy_from_slice(&plaintext_len.to_be_bytes());
        assert_eq!(
            unpad_sealed_payload(&padded),
            Err(SealedPayloadError::LengthPrefixTooLarge { plaintext_len, max })
        );
    }

    #[test]
    fn sealed_payload_padding_rejects_nonzero_fill() {
        let mut padded = vec![0u8; SEALED_PAYLOAD_BUCKETS[0]];
        padded[..SEALED_PAYLOAD_LEN_PREFIX_LEN].copy_from_slice(&1u32.to_be_bytes());
        padded[SEALED_PAYLOAD_LEN_PREFIX_LEN] = 0xaa;
        padded[SEALED_PAYLOAD_LEN_PREFIX_LEN + 1] = 0x01;
        assert_eq!(
            unpad_sealed_payload(&padded),
            Err(SealedPayloadError::NonzeroPadding)
        );
    }
}
