const MAX_TRANSPORT_BINDING_LEN: usize = 1024;

/// Public bytes the app attaches to a message, which Roost authenticates but never reads or
/// stores.
///
/// Each receive also includes them in the digest that catches a repeated delivery. The app must
/// keep the exact value with an outbound message and pass the same value to receive or resend it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportBinding(Vec<u8>);

impl TransportBinding {
    /// Creates a non-empty transport binding within the supported size limit.
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

    /// Returns the exact bytes the app passed.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// An error returned while creating a [`TransportBinding`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TransportBindingError {
    /// The app passed no bytes.
    #[error("transport binding is empty")]
    Empty,
    /// The app passed more bytes than a transport binding holds.
    #[error("transport binding length {length} exceeds {maximum}")]
    TooLong {
        /// Supplied byte length.
        length: usize,
        /// Maximum accepted byte length.
        maximum: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_transport_binding_keeps_exact_bytes_up_to_its_limit() {
        const MAX_LEN: usize = 1024;
        for (bytes, expected) in [
            (vec![0x41, 0x00, 0xff, 0x7f], Ok(())),
            (vec![0x41; MAX_LEN], Ok(())),
            (Vec::new(), Err(TransportBindingError::Empty)),
            (
                vec![0x41; MAX_LEN + 1],
                Err(TransportBindingError::TooLong {
                    length: MAX_LEN + 1,
                    maximum: MAX_LEN,
                }),
            ),
        ] {
            let bound =
                TransportBinding::new(bytes.clone()).map(|binding| binding.as_bytes().to_vec());
            assert_eq!(bound, expected.map(|()| bytes));
        }
    }
}
