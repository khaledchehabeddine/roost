/// Roost's fixed limits on what one message or record may cost, and the deduplication set's range.
#[derive(uniffi::Record)]
pub struct ProtocolHardeningLimits {
    /// Maximum encoded message bytes Roost decodes.
    pub max_encoded_message_len: u64,
    /// Maximum protocol state blob bytes Roost decodes.
    pub max_protocol_state_blob_len: u64,
    /// Maximum sender certificate bytes a message may carry.
    pub max_sender_certificate_len: u64,
    /// Maximum sent messages that wait for the contact's acknowledgment on one session.
    pub max_pending_acknowledgments: u64,
    /// Smallest deduplication set size a receive may pass.
    pub min_deduplication_capacity: u32,
    /// Deduplication set size for apps without a reason to choose another.
    pub default_deduplication_capacity: u32,
    /// Largest deduplication set size a receive may pass.
    pub max_deduplication_capacity: u32,
    /// Distinct messages each side may send a contact before the contact accepts.
    pub max_messages_before_acceptance: u32,
}

/// Returns Roost's fixed limits and the deduplication set's range.
#[uniffi::export]
pub fn protocol_hardening_limits() -> ProtocolHardeningLimits {
    ProtocolHardeningLimits::from_core(roost_core::ProtocolHardeningLimits::default())
}

impl ProtocolHardeningLimits {
    fn from_core(value: roost_core::ProtocolHardeningLimits) -> Self {
        // Every limit is a fixed constant well inside both target types.
        Self {
            max_encoded_message_len: value.max_encoded_message_len as u64,
            max_protocol_state_blob_len: value.max_protocol_state_blob_len as u64,
            max_sender_certificate_len: value.max_sender_certificate_len as u64,
            max_pending_acknowledgments: value.max_pending_acknowledgments as u64,
            min_deduplication_capacity: value.min_deduplication_capacity as u32,
            default_deduplication_capacity: value.default_deduplication_capacity as u32,
            max_deduplication_capacity: value.max_deduplication_capacity as u32,
            max_messages_before_acceptance: value.max_messages_before_acceptance as u32,
        }
    }
}
