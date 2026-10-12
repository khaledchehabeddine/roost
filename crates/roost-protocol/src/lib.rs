//! Shared encodings and stateless authenticity verification for Roost consumers.
//!
//! This is an implementation dependency of Client. It owns certificates, canonical key validation,
//! Message transcript framing, and padding.
//! It has no device state, secret-key lifecycle, storage, session engine, or network I/O.

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
    MESSAGE_TRANSCRIPT_CONTEXT, MessageEncodingError, MessageId, MessageTranscriptInput,
    PayloadKind, SEALED_PAYLOAD_BUCKETS, SEALED_PAYLOAD_LEN_PREFIX_LEN, SealedPayloadError,
    SessionId, message_transcript, pad_sealed_payload, unpad_sealed_payload,
};
pub use sender_certificate::{
    DomainSigningKey, DomainSigningKeyStatus, MAX_CERTIFICATE_GRACE_WINDOW, RevocationState,
    SenderCertificateIdentityKey, SenderCertificateValidationError,
    SenderCertificateValidationInput, ValidatedSenderCertificate, validate_sender_certificate,
};
pub use signature::{SignatureError, contextual_message, verify_with_context};
pub use unix_time::{from_unix_millis, from_unix_secs, to_unix_millis, to_unix_secs};
