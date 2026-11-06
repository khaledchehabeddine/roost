use ed25519_dalek::{Signature, VerifyingKey};
use zeroize::Zeroizing;

/// An error returned while framing or verifying a signature.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum SignatureError {
    /// The signature context is empty.
    #[error("signature context is invalid")]
    InvalidSignatureContext,
    /// The message is too long for its `u32` length prefix.
    #[error("signed message is {len} bytes, more than a u32 length can hold")]
    MessageTooLong {
        /// Length of the message.
        len: usize,
    },
    /// The signature does not authenticate the supplied bytes.
    #[error("signature verification failed")]
    SignatureInvalid,
}

/// Verifies a signature over the bytes [`contextual_message`] builds from `context` and `message`.
///
/// Verification is strict, so a small-order verifying key or signature nonce fails.
pub fn verify_with_context(
    verifying_key: &VerifyingKey,
    context: &[u8],
    message: &[u8],
    signature: &Signature,
) -> Result<(), SignatureError> {
    verifying_key
        .verify_strict(&contextual_message(context, message)?, signature)
        .map_err(|_| SignatureError::SignatureInvalid)
}

/// Returns `context`, the message's big-endian `u32` length, and the message, joined in zeroizing
/// memory.
///
/// An empty `context` fails.
pub fn contextual_message(
    context: &[u8],
    message: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SignatureError> {
    if context.is_empty() {
        return Err(SignatureError::InvalidSignatureContext);
    }
    let message_len = u32::try_from(message.len())
        .map_err(|_| SignatureError::MessageTooLong { len: message.len() })?;

    // On 64-bit targets the `u32` length keeps this sum far below `usize::MAX`.
    let capacity = context.len() + size_of::<u32>() + message.len();
    let mut signed = Zeroizing::new(Vec::with_capacity(capacity));
    signed.extend_from_slice(context);
    signed.extend_from_slice(&message_len.to_be_bytes());
    signed.extend_from_slice(message);
    Ok(signed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contextual_message_puts_the_message_length_after_the_context() {
        let signed = contextual_message(b"RoostExample-v1:", b"abc").unwrap();
        assert_eq!(signed.as_slice(), b"RoostExample-v1:\0\0\0\x03abc");
    }

    #[test]
    fn contextual_message_allocates_exactly_its_length() {
        let signed = contextual_message(b"RoostExample-v1:", b"abc").unwrap();
        assert_eq!(signed.capacity(), signed.len());
    }
}
