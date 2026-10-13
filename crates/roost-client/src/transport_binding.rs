//! The UniFFI record for caller-owned Message bindings.

use crate::error::RoostError;
use roost_core::TransportBinding as CoreTransportBinding;

/// Opaque public bytes authenticated with one encrypted Message.
///
/// The host defines the bytes and their meaning. Roost authenticates them, but never interprets,
/// transmits, or stores them. Established-Message and acknowledgment receive paths also include
/// the bytes in deduplication. Retain the exact value with an outbound Message and supply it again
/// for receive or retransmission.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct TransportBinding {
    /// Non-empty caller-owned bytes, limited to 1,024 bytes.
    pub bytes: Vec<u8>,
}

impl TransportBinding {
    pub(crate) fn into_core(self) -> Result<CoreTransportBinding, RoostError> {
        Ok(CoreTransportBinding::new(self.bytes)?)
    }
}
