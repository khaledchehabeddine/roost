//! Defines opaque caller-owned bytes authenticated with encrypted Messages.

const MAX_TRANSPORT_BINDING_LEN: usize = 1024;

/// Opaque public bytes supplied by a Caller-Owned Transport.
///
/// Core authenticates these bytes with one encrypted Message, but never interprets, transmits, or
/// stores them. Established-Message and acknowledgment receive paths also include the bytes in
/// deduplication. The caller must retain the exact value with an outbound Message and supply the
/// same value for receive or retransmission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportBinding(Vec<u8>);

impl TransportBinding {
    /// Maximum number of caller-owned bytes authenticated with one Message.
    pub const MAX_LEN: usize = MAX_TRANSPORT_BINDING_LEN;

    /// Creates a non-empty Transport Binding within the supported size limit.
    pub fn new(bytes: Vec<u8>) -> Result<Self, TransportBindingError> {
        if bytes.is_empty() {
            return Err(TransportBindingError::Empty);
        }
        if bytes.len() > MAX_TRANSPORT_BINDING_LEN {
            return Err(TransportBindingError::TooLong {
                length: bytes.len(),
                maximum: MAX_TRANSPORT_BINDING_LEN,
            });
        }
        Ok(Self(bytes))
    }

    /// Returns the exact caller-owned bytes authenticated with the Message.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Stable prekey identifiers selected for an X3DH initial Message.
///
/// The caller obtains these identifiers from the recipient publication and supplies them again
/// when receiving a Transport-Bound initial Message. Core uses them only to select and validate
/// Aether-owned prekey state; it does not infer any transport encoding from them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreKeySelection {
    /// Identifier of the selected signed pre-key within one Discovery Key Epoch.
    pub signed_prekey_id: u64,
    /// Identifier of the selected one-time pre-key, when one was used.
    pub one_time_prekey_id: Option<u64>,
}

/// Errors returned while constructing a [`TransportBinding`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TransportBindingError {
    /// The caller supplied no bytes for an explicitly bound operation.
    #[error("transport binding is empty")]
    Empty,
    /// The caller-supplied value exceeded the supported size limit.
    #[error("transport binding length {length} exceeds {maximum}")]
    TooLong {
        /// Supplied byte length.
        length: usize,
        /// Maximum accepted byte length.
        maximum: usize,
    },
}
