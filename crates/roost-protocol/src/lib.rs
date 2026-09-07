//! Shared encodings and stateless authenticity verification for Roost consumers.
//!
//! This is an implementation dependency of Client and Server. It owns certificates, canonical
//! key validation, Message transcript framing, padding, and Evidence Bundle encoding and verification.
//! It has no device state, secret-key lifecycle, storage, session engine, or network I/O.
//!
//! # Examples
//! ```
//! use roost_protocol::EvidenceProfile;
//!
//! let profile = EvidenceProfile::MessageTranscriptV1;
//! assert_eq!(profile, EvidenceProfile::MessageTranscriptV1);
//! ```

mod evidence;
mod key_encoding;
mod message;
mod sender_certificate;
mod signature;

pub use evidence::{
    AcceptedMessageEvidenceInput, EvidenceBundle, EvidenceProfile, EvidenceVerificationError,
    EvidenceVerificationInput, MAX_EVIDENCE_DOMAIN_SIGNING_KEYS, MAX_EVIDENCE_GRACE_WINDOW_SECS,
    VerifiedEvidenceBundle, generate_evidence_bundle, verify_evidence_bundle,
};
pub use key_encoding::{
    IDENTITY_KEY_ENCODING_LEN, PUBLIC_KEY_LEN, identity_key_encoding,
    parse_ed25519_verifying_key_bytes, validate_x25519_public_key,
};
pub use message::{
    MESSAGE_TRANSCRIPT_CONTEXT, MessageEncodingError, MessageId, MessageTranscriptInput,
    PayloadKind, SEALED_PAYLOAD_BUCKETS, SEALED_PAYLOAD_LEN_PREFIX_LEN, SealedPayloadError,
    message_transcript, pad_sealed_payload, unpad_sealed_payload,
};
pub use sender_certificate::{
    DomainSigningKey, DomainSigningKeyStatus, RevocationState, SenderCertificateIdentityKey,
    SenderCertificateValidationError, SenderCertificateValidationInput, ValidatedSenderCertificate,
    encode_sender_certificate, validate_sender_certificate,
};
pub use signature::{SignatureError, contextual_message, verify_with_context};
