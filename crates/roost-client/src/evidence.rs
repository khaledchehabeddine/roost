//! Evidence Bundle records and standalone verification exposed through UniFFI.

use zeroize::Zeroizing;

use crate::certificate::{DomainSigningKey, domain_signing_keys_to_protocol};
use crate::error::ClientError;
use crate::message::PayloadKind;
use crate::protocol::IdentityKey;
use crate::time::{millis_from_secs, time_from_millis};
use std::time::Duration;

/// The authenticated transcript interpretation required by an evidence verifier.
///
/// Callers pin a profile explicitly so a future bundle version cannot silently change the
/// authenticated transcript semantics they interpret.
///
/// # Examples
/// ```
/// use roost_client::EvidenceProfile;
///
/// let profile = EvidenceProfile::MessageTranscriptVersion1;
/// assert!(matches!(
///     profile,
///     EvidenceProfile::MessageTranscriptVersion1
/// ));
/// ```
#[derive(Clone, Copy, Eq, PartialEq, uniffi::Enum)]
pub enum EvidenceProfile {
    /// The version-one Message transcript signature profile.
    MessageTranscriptVersion1,
}

/// Authenticated context recovered from a verified Evidence Bundle.
///
/// The plaintext and contextual fields come from the sender-signed Message transcript. The sender
/// Identity Key, relay domain, and expiry come from the domain-signed certificate, whose exact
/// bytes are also bound by the Message transcript signature.
/// Verification needs no local Session or Protocol State Blob and does not track repeat
/// submissions. Before counting or downstream work, consumers must persist and deduplicate
/// `evidence_identity`; raw bundle bytes and Message ID are not stable substitutes.
///
/// # Examples
/// ```
/// use roost_client::{EvidenceProfile, VerifiedEvidenceBundle};
///
/// # fn inspect(verified: &VerifiedEvidenceBundle) {
/// assert!(matches!(
///     verified.profile,
///     EvidenceProfile::MessageTranscriptVersion1
/// ));
/// assert_eq!(verified.evidence_identity.len(), 32);
/// assert_eq!(verified.message_id.len(), 16);
/// assert_eq!(verified.recipient_identity_verifying_key.len(), 32);
/// # }
/// ```
#[derive(uniffi::Record)]
pub struct VerifiedEvidenceBundle {
    /// Transcript profile used for verification.
    pub profile: EvidenceProfile,
    /// Stable idempotency key derived from the authenticated sender, relay, and Message Transcript.
    /// Always 32 bytes.
    pub evidence_identity: Vec<u8>,
    /// Session-scoped protocol-state key signed into the Message transcript.
    pub session_key: Vec<u8>,
    /// Recipient Ed25519 Identity Key verifying half signed into the Message transcript.
    /// Always 32 bytes.
    pub recipient_identity_verifying_key: Vec<u8>,
    /// Message ID signed into the Message transcript. Always 16 bytes.
    pub message_id: Vec<u8>,
    /// Sender-observed Unix timestamp signed into the Message transcript.
    pub sent_at_millis: u64,
    /// Payload kind signed into the Message transcript.
    pub payload_kind: PayloadKind,
    /// Accepted plaintext recovered from the authenticated padded payload.
    pub plaintext: Vec<u8>,
    /// Sender Identity Key authenticated by both the certificate and Message signature.
    pub sender_identity_key: IdentityKey,
    /// Relay domain authenticated by the transcript-bound sender certificate.
    pub relay_domain: Vec<u8>,
    /// Certificate expiry authenticated by the domain-signing key, in Unix milliseconds.
    pub certificate_expires_at_millis: u64,
}

/// Verifies an Evidence Bundle without device or Session state.
///
/// The caller pins the expected transcript profile and relay domain, supplies the trusted
/// domain-signing keys, and supplies the Unix timestamp when it accepted the Message. Certificate
/// validity is evaluated at that acceptance time with a grace window no greater than 300 seconds
/// and without current revocation policy, so later revocation does not invalidate authentic
/// historical evidence.
///
/// # Examples
/// ```no_run
/// use roost_client::{
///     DomainSigningKey, DomainSigningKeyStatus, EvidenceProfile, verify_evidence_bundle,
/// };
///
/// # fn verify(
/// #     bundle: Vec<u8>,
/// #     key_id: Vec<u8>,
/// #     verifying_key: Vec<u8>,
/// # ) -> Result<(), roost_client::ClientError> {
/// let verified = verify_evidence_bundle(
///     bundle,
///     EvidenceProfile::MessageTranscriptVersion1,
///     vec![DomainSigningKey {
///         id: key_id,
///         verifying_key,
///         status: DomainSigningKeyStatus::Trusted,
///     }],
///     b"relay.example".to_vec(),
///     1_700_000_000,
///     0,
/// )?;
/// assert_eq!(verified.relay_domain, b"relay.example");
/// # Ok(())
/// # }
/// ```
///
/// # Errors
/// - [`ClientError::InvalidData`] if the bundle is malformed, oversized, names a profile other
///   than `expected_profile`, uses a grace window greater than 300 seconds, or if a trusted
///   verifying key is malformed.
/// - [`ClientError::UnsupportedVersion`] if the Evidence Bundle envelope version is unsupported.
/// - [`ClientError::CertificateRejected`] if certificate trust, relay-domain, signature, or
///   acceptance-time validation fails.
/// - [`ClientError::AuthenticationFailed`] if the Message transcript signature fails.
#[uniffi::export]
pub fn verify_evidence_bundle(
    evidence_bundle: Vec<u8>,
    expected_profile: EvidenceProfile,
    domain_signing_keys: Vec<DomainSigningKey>,
    expected_relay_domain: Vec<u8>,
    accepted_at_millis: u64,
    grace_window_millis: u64,
) -> Result<VerifiedEvidenceBundle, ClientError> {
    let evidence_bundle = Zeroizing::new(evidence_bundle);
    if domain_signing_keys.len() > roost_protocol::MAX_EVIDENCE_DOMAIN_SIGNING_KEYS {
        return Err(
            roost_protocol::EvidenceVerificationError::TooManyDomainSigningKeys {
                count: domain_signing_keys.len(),
                maximum: roost_protocol::MAX_EVIDENCE_DOMAIN_SIGNING_KEYS,
            }
            .into(),
        );
    }
    let protocol_domain_signing_keys = domain_signing_keys_to_protocol(&domain_signing_keys)?;
    let verified =
        roost_protocol::verify_evidence_bundle(roost_protocol::EvidenceVerificationInput {
            bundle: &evidence_bundle,
            expected_profile: expected_profile.to_protocol(),
            domain_signing_keys: &protocol_domain_signing_keys,
            expected_relay_domain: &expected_relay_domain,
            accepted_at: time_from_millis(accepted_at_millis, "accepted_at_millis")?,
            grace_window: Duration::from_millis(grace_window_millis),
        })?;
    Ok(VerifiedEvidenceBundle {
        profile: expected_profile,
        evidence_identity: verified.evidence_identity.to_vec(),
        session_key: verified.session_key.clone(),
        recipient_identity_verifying_key: verified.recipient_identity_verifying_key.to_vec(),
        message_id: verified.message_id.as_bytes().to_vec(),
        sent_at_millis: verified.sent_at_millis,
        payload_kind: PayloadKind::from_protocol(verified.payload_kind),
        plaintext: verified.plaintext.to_vec(),
        sender_identity_key: IdentityKey {
            x25519_public_key: verified.sender_identity_key.x25519_public_key.to_vec(),
            ed25519_verifying_key: verified.sender_identity_key.ed25519_verifying_key.to_vec(),
        },
        relay_domain: verified.relay_domain.clone(),
        certificate_expires_at_millis: millis_from_secs(
            verified.certificate_expires_at_secs,
            "certificate expiry",
        )?,
    })
}

impl EvidenceProfile {
    fn to_protocol(self) -> roost_protocol::EvidenceProfile {
        match self {
            Self::MessageTranscriptVersion1 => roost_protocol::EvidenceProfile::MessageTranscriptV1,
        }
    }
}
