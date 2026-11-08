//! Wire formats, signature framing, and sender certificate validation.
//!
//! Handles session and message identifiers, payload kinds, the message transcript, sealed payload
//! padding, public key validation and the identity key encoding, context-framed Ed25519
//! verification, sender certificate validation, transport bindings, and Unix time conversions. It
//! holds no state, secret keys, storage, or network I/O.

mod identity_key;
mod key_encoding;
mod message;
mod sender_certificate;
mod signature;
mod transport_binding;
mod unix_time;

pub use identity_key::IdentityKey;
pub use key_encoding::{
    PUBLIC_KEY_LEN, is_valid_x25519_public_key, parse_ed25519_verifying_key_bytes,
};
pub use message::{
    MAX_SEALED_PLAINTEXT_LEN, MESSAGE_TRANSCRIPT_CONTEXT, MessageId, MessageTranscriptError,
    MessageTranscriptInput, PayloadKind, SealedPayloadError, SessionId, message_transcript,
    pad_sealed_payload, unpad_sealed_payload,
};
pub use sender_certificate::{
    DomainSigningKey, MAX_CERTIFICATE_GRACE_WINDOW, MAX_SENDER_CERTIFICATE_LEN, RevocationState,
    SenderCertificateValidation, SenderCertificateValidationError, ValidatedSenderCertificate,
};
pub use signature::{SignatureError, contextual_message, verify_with_context};
pub use transport_binding::{TransportBinding, TransportBindingError};
pub use unix_time::{from_unix_millis, from_unix_secs, to_unix_millis, to_unix_secs};
