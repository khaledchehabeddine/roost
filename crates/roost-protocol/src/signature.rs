use ed25519_dalek::{Signature, VerifyingKey};
use zeroize::Zeroizing;

/// An error returned while framing or verifying a signature.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum SignatureError {
    /// The signature context is empty.
    #[error("signature context is invalid")]
    InvalidSignatureContext,
    /// The signature does not authenticate the supplied bytes.
    #[error("signature verification failed")]
    SignatureInvalid,
}

/// Verifies a signature over caller-supplied `context || message` bytes.
pub fn verify_with_context(
    verifying_key: &VerifyingKey,
    context: &[u8],
    message: &[u8],
    signature: &Signature,
) -> Result<(), SignatureError> {
    use ed25519_dalek::Verifier;

    verifying_key
        .verify(&contextual_message(context, message)?, signature)
        .map_err(|_| SignatureError::SignatureInvalid)
}

/// Joins a non-empty domain context and message in zeroizing memory.
pub fn contextual_message(
    context: &[u8],
    message: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SignatureError> {
    if context.is_empty() {
        return Err(SignatureError::InvalidSignatureContext);
    }
    // Each slice is at most `isize::MAX` bytes, so the sum fits in `usize`.
    let mut signed = Zeroizing::new(Vec::with_capacity(context.len() + message.len()));
    signed.extend_from_slice(context);
    signed.extend_from_slice(message);
    Ok(signed)
}
