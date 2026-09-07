//! Stateless Evidence Bundle verification for Rust backends.
//!
//! This is Roost's narrow backend entry crate. Verification authenticates a Message at a
//! caller-supplied acceptance time and requires no Client, SecureStorage, session state, or network
//! I/O. The backend supplies trusted domain keys and its expected relay domain. Before counting
//! reports or performing downstream work, it must persist and deduplicate the returned Evidence
//! Identity. Message IDs and raw bundle bytes are not substitutes.
//!
//! Bundles and verified results contain plaintext. The caller owns reporting policy and protection
//! of persisted evidence. Verification cannot establish whether the supplied acceptance time is true.
//!
//! # Examples
//! ```
//! use roost_server::{
//!     DomainSigningKey, EvidenceProfile, EvidenceVerificationError, EvidenceVerificationInput,
//!     VerifiedEvidenceBundle, verify_evidence_bundle,
//! };
//!
//! fn verify_report(
//!     bundle: &[u8],
//!     trusted_keys: &[DomainSigningKey<'_>],
//!     relay_domain: &[u8],
//!     accepted_timestamp_secs: u64,
//! ) -> Result<VerifiedEvidenceBundle, EvidenceVerificationError> {
//!     verify_evidence_bundle(EvidenceVerificationInput {
//!         bundle,
//!         expected_profile: EvidenceProfile::MessageTranscriptV1,
//!         domain_signing_keys: trusted_keys,
//!         expected_relay_domain: relay_domain,
//!         accepted_timestamp_secs,
//!         grace_window_secs: 0,
//!     })
//! }
//! ```

pub use roost_protocol::{
    DomainSigningKey, DomainSigningKeyStatus, EvidenceProfile, EvidenceVerificationError,
    EvidenceVerificationInput, MAX_EVIDENCE_DOMAIN_SIGNING_KEYS, MAX_EVIDENCE_GRACE_WINDOW_SECS,
    MessageId, PayloadKind, SenderCertificateIdentityKey, SenderCertificateValidationError,
    VerifiedEvidenceBundle, verify_evidence_bundle,
};
