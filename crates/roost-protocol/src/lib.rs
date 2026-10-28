//! Wire formats, signature framing, and sender certificate validation shared by the Roost crates.
//!
//! Handles Session and Message identifiers, payload kinds, the Message Transcript, Sealed Payload
//! Padding, public key validation and the Identity Key encoding, context-framed Ed25519
//! verification, sender certificate validation, and Unix time conversions. It holds no state,
//! secret keys, storage, or network I/O.

mod key_encoding;
mod message;
mod sender_certificate;
mod signature;
mod unix_time;

pub use key_encoding::{
    IDENTITY_KEY_ENCODING_LEN, PUBLIC_KEY_LEN, identity_key_encoding, is_valid_x25519_public_key,
    parse_ed25519_verifying_key_bytes,
};
pub use message::{
    MAX_SEALED_PLAINTEXT_LEN, MESSAGE_TRANSCRIPT_CONTEXT, MessageId, MessageTranscriptError,
    MessageTranscriptInput, PayloadKind, SealedPayloadError, SessionId, message_transcript,
    pad_sealed_payload, unpad_sealed_payload,
};
pub use sender_certificate::{
    DomainSigningKey, DomainSigningKeyStatus, MAX_CERTIFICATE_GRACE_WINDOW, RevocationState,
    SenderCertificateIdentityKey, SenderCertificateValidationError,
    SenderCertificateValidationInput, ValidatedSenderCertificate, validate_sender_certificate,
};
pub use signature::{SignatureError, contextual_message, verify_with_context};
pub use unix_time::{from_unix_millis, from_unix_secs, to_unix_millis, to_unix_secs};
