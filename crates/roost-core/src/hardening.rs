use crate::ProtocolStateError;
use roost_crypto::SealedFrame;

/// Default number of received-message digests retained per local Identity.
pub const DEFAULT_DEDUPLICATION_CAPACITY: usize = 1024;
/// Minimum supported received-message deduplication capacity.
pub const MIN_DEDUPLICATION_CAPACITY: usize = 64;
/// Maximum supported received-message deduplication capacity.
pub const MAX_DEDUPLICATION_CAPACITY: usize = 2048;

pub(crate) const DEFAULT_MAX_MESSAGE_PAYLOAD_LEN: usize = 128 * 1024;
pub(crate) const DEFAULT_MAX_PROTOCOL_STATE_BLOB_LEN: usize = 64 * 1024;
pub(crate) const DEFAULT_MAX_SENDER_CERTIFICATE_LEN: usize = 16 * 1024;
pub(crate) const DEFAULT_MAX_SENDER_SIGNATURE_LEN: usize = 4 * 1024;
pub(crate) const DEFAULT_MAX_PENDING_ACKNOWLEDGMENTS: usize = 1024;
pub(crate) const DEFAULT_MAX_ACKNOWLEDGMENT_DIGESTS: usize = 1024;

/// Consumer-configurable ceilings for externally influenced protocol work.
///
/// Defaults preserve the crate's standard mobile-client behavior. Callers on constrained hosts may
/// lower limits, but values above the supported ceilings are rejected so public configuration cannot
/// disable memory and CPU bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolHardeningLimits {
    /// Maximum encoded sealed-sender Message bytes accepted before parsing.
    pub max_encoded_message_len: usize,
    /// Maximum Message ciphertext payload bytes accepted after frame decode.
    pub max_message_payload_len: usize,
    /// Maximum general Protocol State Blob bytes accepted before body decode.
    pub max_protocol_state_blob_len: usize,
    /// Maximum sender certificate bytes accepted after sealed-sender decrypt.
    pub max_sender_certificate_len: usize,
    /// Maximum sender signature bytes accepted after sealed-sender decrypt.
    pub max_sender_signature_len: usize,
    /// Number of received-message digests retained per local Identity.
    pub deduplication_capacity: usize,
    /// Maximum pending outbound Messages retained for acknowledgment processing.
    pub max_pending_acknowledgments: usize,
    /// Maximum processed acknowledgment digests retained for duplicate detection.
    pub max_acknowledgment_digests: usize,
}

impl ProtocolHardeningLimits {
    /// Returns the default hardening limits.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn bounded(self) -> Self {
        Self {
            max_encoded_message_len: self
                .max_encoded_message_len
                .min(SealedFrame::MAX_ENCODED_LEN),
            max_message_payload_len: self
                .max_message_payload_len
                .min(DEFAULT_MAX_MESSAGE_PAYLOAD_LEN),
            max_protocol_state_blob_len: self
                .max_protocol_state_blob_len
                .min(DEFAULT_MAX_PROTOCOL_STATE_BLOB_LEN),
            max_sender_certificate_len: self
                .max_sender_certificate_len
                .min(DEFAULT_MAX_SENDER_CERTIFICATE_LEN),
            max_sender_signature_len: self
                .max_sender_signature_len
                .min(DEFAULT_MAX_SENDER_SIGNATURE_LEN),
            deduplication_capacity: self.deduplication_capacity.min(MAX_DEDUPLICATION_CAPACITY),
            max_pending_acknowledgments: self
                .max_pending_acknowledgments
                .min(DEFAULT_MAX_PENDING_ACKNOWLEDGMENTS),
            max_acknowledgment_digests: self
                .max_acknowledgment_digests
                .min(DEFAULT_MAX_ACKNOWLEDGMENT_DIGESTS),
        }
    }
}

impl Default for ProtocolHardeningLimits {
    fn default() -> Self {
        Self {
            max_encoded_message_len: SealedFrame::MAX_ENCODED_LEN,
            max_message_payload_len: DEFAULT_MAX_MESSAGE_PAYLOAD_LEN,
            max_protocol_state_blob_len: DEFAULT_MAX_PROTOCOL_STATE_BLOB_LEN,
            max_sender_certificate_len: DEFAULT_MAX_SENDER_CERTIFICATE_LEN,
            max_sender_signature_len: DEFAULT_MAX_SENDER_SIGNATURE_LEN,
            deduplication_capacity: DEFAULT_DEDUPLICATION_CAPACITY,
            max_pending_acknowledgments: DEFAULT_MAX_PENDING_ACKNOWLEDGMENTS,
            max_acknowledgment_digests: DEFAULT_MAX_ACKNOWLEDGMENT_DIGESTS,
        }
    }
}

pub(crate) fn validate_hardening_limits(
    limits: ProtocolHardeningLimits,
) -> Result<(), ProtocolStateError> {
    validate_ceiling(
        "encoded message",
        limits.max_encoded_message_len,
        1,
        SealedFrame::MAX_ENCODED_LEN,
    )?;
    validate_ceiling(
        "message payload",
        limits.max_message_payload_len,
        1,
        DEFAULT_MAX_MESSAGE_PAYLOAD_LEN,
    )?;
    validate_ceiling(
        "protocol-state blob",
        limits.max_protocol_state_blob_len,
        1,
        DEFAULT_MAX_PROTOCOL_STATE_BLOB_LEN,
    )?;
    validate_ceiling(
        "sender certificate",
        limits.max_sender_certificate_len,
        1,
        DEFAULT_MAX_SENDER_CERTIFICATE_LEN,
    )?;
    validate_ceiling(
        "sender signature",
        limits.max_sender_signature_len,
        1,
        DEFAULT_MAX_SENDER_SIGNATURE_LEN,
    )?;
    validate_deduplication_capacity(limits.deduplication_capacity)?;
    validate_ceiling(
        "pending acknowledgments",
        limits.max_pending_acknowledgments,
        1,
        DEFAULT_MAX_PENDING_ACKNOWLEDGMENTS,
    )?;
    validate_ceiling(
        "acknowledgment digests",
        limits.max_acknowledgment_digests,
        1,
        DEFAULT_MAX_ACKNOWLEDGMENT_DIGESTS,
    )?;
    Ok(())
}

pub(crate) fn validate_deduplication_capacity(capacity: usize) -> Result<(), ProtocolStateError> {
    if !(MIN_DEDUPLICATION_CAPACITY..=MAX_DEDUPLICATION_CAPACITY).contains(&capacity) {
        return Err(ProtocolStateError::InvalidDeduplicationCapacity {
            capacity,
            minimum: MIN_DEDUPLICATION_CAPACITY,
            maximum: MAX_DEDUPLICATION_CAPACITY,
        });
    }
    Ok(())
}

fn validate_ceiling(
    name: &'static str,
    value: usize,
    minimum: usize,
    maximum: usize,
) -> Result<(), ProtocolStateError> {
    if !(minimum..=maximum).contains(&value) {
        return Err(ProtocolStateError::InvalidHardeningLimit {
            name,
            value,
            minimum,
            maximum,
        });
    }
    Ok(())
}
