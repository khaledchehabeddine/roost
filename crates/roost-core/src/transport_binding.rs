const MAX_TRANSPORT_BINDING_LEN: usize = 1024;

/// Opaque public bytes supplied by a Caller-Owned Transport.
///
/// Core authenticates these bytes with one encrypted Message, but never interprets, transmits, or
/// stores them. Each receive also includes them in the digest that catches a repeated delivery.
/// The caller must retain the exact value with an outbound Message and supply the same value for
/// receive or retransmission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportBinding(Vec<u8>);

impl TransportBinding {
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
