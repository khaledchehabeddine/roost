//! Shared context framing and Ed25519 verification.

use ed25519_dalek::{Signature, VerifyingKey};
use std::{error::Error, fmt};
use zeroize::Zeroizing;

/// An error returned while framing or verifying a signature.
#[derive(Debug, Eq, PartialEq)]
pub enum SignatureError {
    /// The signature context is empty or the combined length overflows.
    InvalidSignatureContext,
    /// The signature does not authenticate the supplied bytes.
    SignatureInvalid,
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSignatureContext => write!(f, "signature context is invalid"),
            Self::SignatureInvalid => write!(f, "signature verification failed"),
        }
    }
}

impl Error for SignatureError {}

/// Verifies a signature over caller-supplied `context || message` bytes.
pub fn verify_with_context(
    verifying_key: &VerifyingKey,
    context: &[u8],
    message: &[u8],
    signature: &Signature,
) -> Result<(), SignatureError> {
    use ed25519_dalek::Verifier;

    if context.is_empty() {
        return Err(SignatureError::InvalidSignatureContext);
    }
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
    let mut signed = Zeroizing::new(Vec::with_capacity(
        context
            .len()
            .checked_add(message.len())
            .ok_or(SignatureError::InvalidSignatureContext)?,
    ));
    signed.extend_from_slice(context);
    signed.extend_from_slice(message);
    Ok(signed)
}
