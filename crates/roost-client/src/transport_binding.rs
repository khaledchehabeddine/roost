//! UniFFI records for caller-owned Message bindings and prekey selection.

use crate::error::RoostError;
use roost_core::{
    PreKeySelection as CorePreKeySelection, TransportBinding as CoreTransportBinding,
};

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

/// Stable prekey identifiers selected for an X3DH initial Message.
///
/// Obtain these identifiers from the recipient publication and supply them again when inspecting
/// or accepting a Transport-Bound initial Message. Both identifiers are scoped to one Discovery
/// Key Epoch, and their sequences are independent.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Record)]
pub struct PreKeySelection {
    /// Identifier of the selected signed pre-key within one Discovery Key Epoch.
    pub signed_prekey_id: u64,
    /// Identifier of the selected one-time pre-key, when one was used.
    pub one_time_prekey_id: Option<u64>,
}

impl PreKeySelection {
    pub(crate) fn to_core(self) -> CorePreKeySelection {
        CorePreKeySelection {
            signed_prekey_id: self.signed_prekey_id,
            one_time_prekey_id: self.one_time_prekey_id,
        }
    }
}
