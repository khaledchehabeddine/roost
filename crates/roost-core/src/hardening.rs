use crate::ProtocolStateError;
use roost_crypto::SealedFrame;

pub(crate) const DEFAULT_DEDUPLICATION_CAPACITY: usize = 1024;
pub(crate) const MIN_DEDUPLICATION_CAPACITY: usize = 64;
pub(crate) const MAX_DEDUPLICATION_CAPACITY: usize = 2048;

const MAX_PROTOCOL_STATE_BLOB_LEN: usize = 64 * 1024;
const MAX_SENDER_CERTIFICATE_LEN: usize = 16 * 1024;
const MAX_SENDER_SIGNATURE_LEN: usize = 4 * 1024;
pub(crate) const MAX_PENDING_ACKNOWLEDGMENTS: usize = 1024;
pub(crate) const MAX_ACKNOWLEDGMENT_DIGESTS: usize = 1024;
/// How many distinct Messages each side may send a contact before the contact is accepted.
pub(crate) const MAX_MESSAGES_BEFORE_ACCEPTANCE: usize = 3;

/// The fixed ceilings on externally influenced protocol work, and the Deduplication Set's range.
///
/// Apps choose only the Deduplication Set's size, within the range here, and pass it with each
/// receive. Every other limit is fixed so no configuration can disable memory and CPU bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolHardeningLimits {
    /// Maximum encoded sealed-sender Message bytes accepted before parsing.
    pub max_encoded_message_len: usize,
    /// Maximum general Protocol State Blob bytes accepted before body decode.
    pub max_protocol_state_blob_len: usize,
    /// Maximum sender certificate bytes accepted after sealed-sender decrypt.
    pub max_sender_certificate_len: usize,
    /// Maximum sender signature bytes accepted after sealed-sender decrypt.
    pub max_sender_signature_len: usize,
    /// Maximum pending outbound Messages retained for acknowledgment processing.
    pub max_pending_acknowledgments: usize,
    /// Maximum processed acknowledgment digests retained for duplicate detection.
    pub max_acknowledgment_digests: usize,
    /// Smallest Deduplication Set an app may choose.
    pub min_deduplication_capacity: usize,
    /// Deduplication Set size for apps without a reason to choose another.
    pub default_deduplication_capacity: usize,
    /// Largest Deduplication Set an app may choose.
    pub max_deduplication_capacity: usize,
    /// Distinct Messages each side may send a contact before the contact is accepted.
    pub max_messages_before_acceptance: usize,
}

impl Default for ProtocolHardeningLimits {
    fn default() -> Self {
        Self {
            max_encoded_message_len: SealedFrame::MAX_ENCODED_LEN,
            max_protocol_state_blob_len: MAX_PROTOCOL_STATE_BLOB_LEN,
            max_sender_certificate_len: MAX_SENDER_CERTIFICATE_LEN,
            max_sender_signature_len: MAX_SENDER_SIGNATURE_LEN,
            max_pending_acknowledgments: MAX_PENDING_ACKNOWLEDGMENTS,
            max_acknowledgment_digests: MAX_ACKNOWLEDGMENT_DIGESTS,
            min_deduplication_capacity: MIN_DEDUPLICATION_CAPACITY,
            default_deduplication_capacity: DEFAULT_DEDUPLICATION_CAPACITY,
            max_deduplication_capacity: MAX_DEDUPLICATION_CAPACITY,
            max_messages_before_acceptance: MAX_MESSAGES_BEFORE_ACCEPTANCE,
        }
    }
}

pub(crate) fn is_supported_deduplication_capacity(capacity: usize) -> bool {
    (MIN_DEDUPLICATION_CAPACITY..=MAX_DEDUPLICATION_CAPACITY).contains(&capacity)
}

pub(crate) fn validate_deduplication_capacity(capacity: usize) -> Result<(), ProtocolStateError> {
    if !is_supported_deduplication_capacity(capacity) {
        return Err(ProtocolStateError::InvalidDeduplicationCapacity {
            capacity,
            minimum: MIN_DEDUPLICATION_CAPACITY,
            maximum: MAX_DEDUPLICATION_CAPACITY,
        });
    }
    Ok(())
}
