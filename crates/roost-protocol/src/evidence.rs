//! Versioned evidence bundles produced from accepted Messages.

use std::error::Error;
use std::fmt;

use crate::signature::verify_with_context;
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::key_encoding::parse_ed25519_verifying_key_bytes;
use crate::message::{
    MESSAGE_TRANSCRIPT_CONTEXT, MessageTranscriptInput, message_transcript, unpad_sealed_payload,
};
use crate::sender_certificate::{
    DomainSigningKey, RevocationState, SenderCertificateIdentityKey,
    SenderCertificateValidationError, SenderCertificateValidationInput,
    validate_sender_certificate,
};
use crate::{MessageId, PayloadKind};

const CURRENT_EVIDENCE_BUNDLE_VERSION: u8 = 1;
const MESSAGE_TRANSCRIPT_V1_PROFILE: u8 = 1;
const MAX_EVIDENCE_BUNDLE_LEN: usize = 160 * 1024;
const MAX_EVIDENCE_SESSION_KEY_LEN: usize = 96;
const MAX_EVIDENCE_PADDED_PAYLOAD_LEN: usize = 65_536;
const MAX_EVIDENCE_CERTIFICATE_LEN: usize = 16 * 1024;
const EVIDENCE_IDENTITY_CONTEXT: &str = "AetherEvidenceIdentity-v1";
/// Maximum number of domain-signing keys scanned by one evidence verdict.
pub const MAX_EVIDENCE_DOMAIN_SIGNING_KEYS: usize = 32;
/// Maximum certificate grace window accepted by the Message evidence profile.
pub const MAX_EVIDENCE_GRACE_WINDOW_SECS: u64 = 300;
const SIGNATURE_LEN: usize = 64;

/// The authenticated transcript interpretation required by an evidence verifier.
#[non_exhaustive]
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceProfile {
    /// The `AetherMessageTranscript-v1:` Message signature profile.
    MessageTranscriptV1 = MESSAGE_TRANSCRIPT_V1_PROFILE,
}

impl EvidenceProfile {
    fn tag(self) -> u8 {
        self as u8
    }
}

/// An opaque, versioned export of one accepted Message's authenticity evidence.
///
/// The encoded bytes contain the accepted plaintext and are zeroized when dropped. Persisting or
/// transmitting them creates a durable, non-repudiable record; callers should retain a bundle only
/// when their reporting policy requires it.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EvidenceBundle {
    bytes: ZeroizingBuffer,
}

impl EvidenceBundle {
    /// Returns the opaque evidence-bundle bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

/// Inputs for one standalone evidence authenticity verdict.
///
/// Verification is pure and needs no Session or Protocol State Blob. It authenticates one bundle
/// but does not track repeat submissions; reporting backends must deduplicate verified semantic
/// identities rather than raw bundle encodings. Certificate expiry is evaluated at
/// `accepted_timestamp_secs`; current sender revocation is intentionally not an input because
/// revocation after acceptance must not invalidate authentic historical evidence.
pub struct EvidenceVerificationInput<'a> {
    /// Opaque bytes returned in an accepted Message result.
    pub bundle: &'a [u8],
    /// Transcript profile the caller is prepared to interpret.
    pub expected_profile: EvidenceProfile,
    /// Known domain-signing keys indexed by certificate signing-key identifier.
    pub domain_signing_keys: &'a [DomainSigningKey<'a>],
    /// Relay domain the sender certificate must name.
    pub expected_relay_domain: &'a [u8],
    /// Caller-recorded Unix timestamp in seconds when the Message was accepted.
    pub accepted_timestamp_secs: u64,
    /// Caller-selected certificate grace window in seconds, capped at 300 by this profile.
    pub grace_window_secs: u64,
}

/// Authenticated context recovered from a verified evidence bundle.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VerifiedEvidenceBundle {
    /// Transcript profile used for verification.
    #[zeroize(skip)]
    pub profile: EvidenceProfile,
    /// Stable identity derived from the authenticated sender, relay, and Message Transcript.
    #[zeroize(skip)]
    pub evidence_identity: [u8; 32],
    /// Session-scoped protocol-state key signed into the Message transcript.
    #[zeroize(skip)]
    pub session_key: Vec<u8>,
    /// Recipient Ed25519 Identity Key verifying half signed into the Message transcript.
    #[zeroize(skip)]
    pub recipient_identity_verifying_key: [u8; 32],
    /// Message ID signed into the Message transcript.
    #[zeroize(skip)]
    pub message_id: MessageId,
    /// Sender-observed Unix timestamp signed into the Message transcript.
    #[zeroize(skip)]
    pub timestamp_millis: u64,
    /// Payload kind signed into the Message transcript.
    #[zeroize(skip)]
    pub payload_kind: PayloadKind,
    /// Accepted plaintext recovered from the authenticated padded payload.
    pub plaintext: Zeroizing<Vec<u8>>,
    /// Sender Identity Key authenticated by both the certificate and Message signature.
    #[zeroize(skip)]
    pub sender_identity_key: SenderCertificateIdentityKey,
    /// Relay domain authenticated by the sender certificate.
    #[zeroize(skip)]
    pub relay_domain: Vec<u8>,
    /// Certificate expiry authenticated by the domain-signing key.
    #[zeroize(skip)]
    pub certificate_expires_at_secs: u64,
}

/// An error returned while verifying an evidence bundle.
#[non_exhaustive]
#[derive(Debug, Eq, PartialEq)]
pub enum EvidenceVerificationError {
    /// Encoded evidence exceeds the fixed verification cap.
    BundleTooLarge,
    /// Encoded evidence is truncated, malformed, oversized internally, or has trailing bytes.
    MalformedBundle,
    /// The evidence envelope version is not supported by this build.
    UnsupportedVersion(u8),
    /// The bundle names a transcript profile other than the one the caller pinned.
    WrongProfile {
        /// Caller-pinned transcript profile.
        expected: EvidenceProfile,
        /// Numeric profile tag encoded in the bundle.
        actual: u8,
    },
    /// The caller supplied more trusted domain-signing keys than the verifier scans.
    TooManyDomainSigningKeys {
        /// Number of supplied domain-signing keys.
        count: usize,
        /// Maximum number accepted by the verifier.
        maximum: usize,
    },
    /// The caller supplied a grace window outside the evidence profile.
    GraceWindowTooLarge {
        /// Caller-supplied grace window in seconds.
        actual: u64,
        /// Maximum grace window accepted by this evidence profile.
        maximum: u64,
    },
    /// Sender-certificate validation rejected the evidence at its acceptance context.
    SenderCertificate(SenderCertificateValidationError),
    /// The Message transcript signature is malformed or does not verify.
    SignatureFailure,
}

impl fmt::Display for EvidenceVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BundleTooLarge => write!(f, "evidence bundle exceeds size limit"),
            Self::MalformedBundle => write!(f, "evidence bundle is malformed"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported evidence bundle version: {version}")
            }
            Self::WrongProfile { expected, actual } => write!(
                f,
                "evidence profile does not match expected profile: expected {}, got {actual}",
                expected.tag()
            ),
            Self::TooManyDomainSigningKeys { count, maximum } => write!(
                f,
                "evidence domain-signing key count exceeds limit: {count} > {maximum}"
            ),
            Self::GraceWindowTooLarge { actual, maximum } => write!(
                f,
                "evidence certificate grace window exceeds limit: {actual} > {maximum}"
            ),
            Self::SenderCertificate(error) => {
                write!(f, "evidence sender certificate failed: {error}")
            }
            Self::SignatureFailure => write!(f, "evidence message signature failed"),
        }
    }
}

impl Error for EvidenceVerificationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SenderCertificate(error) => Some(error),
            _ => None,
        }
    }
}

impl From<SenderCertificateValidationError> for EvidenceVerificationError {
    fn from(error: SenderCertificateValidationError) -> Self {
        Self::SenderCertificate(error)
    }
}

/// Authenticated fields exported by Core after Message acceptance.
pub struct AcceptedMessageEvidenceInput<'a> {
    /// Session identifier bytes.
    pub session_key: &'a [u8],
    /// Canonical recipient Ed25519 Identity Key.
    pub recipient_identity_verifying_key: &'a [u8; 32],
    /// Sender-selected Message ID.
    pub message_id: MessageId,
    /// Sender-observed Unix timestamp in milliseconds.
    pub timestamp_millis: u64,
    /// Authenticated payload interpretation.
    pub payload_kind: PayloadKind,
    /// Authenticated padded plaintext.
    pub padded_payload: &'a [u8],
    /// Exact domain-signed sender certificate.
    pub sender_certificate: &'a [u8],
    /// Domain signature over the sender certificate.
    pub sender_certificate_signature: &'a [u8],
    /// Sender Identity Key signature over the Message transcript.
    pub transcript_signature: &'a [u8],
}

#[derive(Serialize)]
struct EvidenceBundleWire<'a> {
    version: u8,
    profile: u8,
    session_key: &'a [u8],
    recipient_identity_verifying_key: [u8; 32],
    message_id: [u8; 16],
    timestamp_millis: u64,
    payload_kind: u8,
    padded_payload: &'a [u8],
    sender_certificate: &'a [u8],
    sender_certificate_signature: &'a [u8],
    transcript_signature: &'a [u8],
}

#[derive(Deserialize)]
struct DecodedEvidenceBundleWire<'a> {
    version: u8,
    profile: u8,
    #[serde(borrow)]
    session_key: &'a [u8],
    recipient_identity_verifying_key: [u8; 32],
    message_id: [u8; 16],
    timestamp_millis: u64,
    payload_kind: u8,
    #[serde(borrow)]
    padded_payload: &'a [u8],
    #[serde(borrow)]
    sender_certificate: &'a [u8],
    #[serde(borrow)]
    sender_certificate_signature: &'a [u8],
    #[serde(borrow)]
    transcript_signature: &'a [u8],
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct ZeroizingBuffer {
    bytes: Vec<u8>,
}

impl ZeroizingBuffer {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

impl Extend<u8> for ZeroizingBuffer {
    fn extend<T>(&mut self, iter: T)
    where
        T: IntoIterator<Item = u8>,
    {
        self.bytes.extend(iter);
    }
}

/// Encodes an accepted Message's authenticated fields as an opaque Evidence Bundle.
///
/// The caller must first authenticate and accept the Message. Encoding does not grant an
/// authenticity verdict; consumers must call [`verify_evidence_bundle`] on submitted evidence.
///
/// # Errors
/// - [`EvidenceVerificationError::MalformedBundle`] if a field exceeds the evidence profile's limits or encoding fails.
pub fn generate_evidence_bundle(
    input: AcceptedMessageEvidenceInput<'_>,
) -> Result<EvidenceBundle, EvidenceVerificationError> {
    if input.session_key.is_empty()
        || input.session_key.len() > MAX_EVIDENCE_SESSION_KEY_LEN
        || input.padded_payload.len() > MAX_EVIDENCE_PADDED_PAYLOAD_LEN
        || input.sender_certificate.len() > MAX_EVIDENCE_CERTIFICATE_LEN
        || input.sender_certificate_signature.len() != SIGNATURE_LEN
        || input.transcript_signature.len() != SIGNATURE_LEN
    {
        return Err(EvidenceVerificationError::MalformedBundle);
    }
    let wire = EvidenceBundleWire {
        version: CURRENT_EVIDENCE_BUNDLE_VERSION,
        profile: EvidenceProfile::MessageTranscriptV1.tag(),
        session_key: input.session_key,
        recipient_identity_verifying_key: *input.recipient_identity_verifying_key,
        message_id: *input.message_id.as_bytes(),
        timestamp_millis: input.timestamp_millis,
        payload_kind: input.payload_kind.tag(),
        padded_payload: input.padded_payload,
        sender_certificate: input.sender_certificate,
        sender_certificate_signature: input.sender_certificate_signature,
        transcript_signature: input.transcript_signature,
    };
    let encoded_len = postcard::experimental::serialized_size(&wire)
        .map_err(|_| EvidenceVerificationError::MalformedBundle)?;
    let buffer = ZeroizingBuffer::with_capacity(encoded_len);
    let bytes = postcard::to_extend(&wire, buffer)
        .map_err(|_| EvidenceVerificationError::MalformedBundle)?;
    debug_assert_eq!(bytes.as_slice().len(), encoded_len);
    Ok(EvidenceBundle { bytes })
}

/// Verifies a versioned evidence bundle without device or Session state.
///
/// The verifier first pins the envelope version and caller-selected profile, then validates the
/// sender certificate for `accepted_timestamp_secs` and `expected_relay_domain`, and finally
/// verifies the original Message signature over the exported transcript fields. Revocation is not
/// evaluated so a later revocation does not erase previously authentic evidence.
///
/// # Examples
/// ```no_run
/// use roost_protocol::{
///     DomainSigningKey, DomainSigningKeyStatus, EvidenceProfile, EvidenceVerificationInput,
///     verify_evidence_bundle,
/// };
///
/// # fn verify(
/// #     bundle: &[u8],
/// #     key_identifier: &[u8],
/// #     verifying_key: &[u8],
/// # ) -> Result<(), roost_protocol::EvidenceVerificationError> {
/// let trusted_keys = [DomainSigningKey {
///     identifier: key_identifier,
///     verifying_key,
///     status: DomainSigningKeyStatus::Trusted,
/// }];
/// let verified = verify_evidence_bundle(EvidenceVerificationInput {
///     bundle,
///     expected_profile: EvidenceProfile::MessageTranscriptV1,
///     domain_signing_keys: &trusted_keys,
///     expected_relay_domain: b"relay.example",
///     accepted_timestamp_secs: 1_700_000_000,
///     grace_window_secs: 0,
/// })?;
/// assert_eq!(verified.relay_domain, b"relay.example");
/// # Ok(())
/// # }
/// ```
///
/// # Errors
/// - [`EvidenceVerificationError::BundleTooLarge`] if the encoded bundle exceeds 160 KiB.
/// - [`EvidenceVerificationError::MalformedBundle`] if the bundle fails exact structural or
///   bounded-field validation.
/// - [`EvidenceVerificationError::UnsupportedVersion`] if the envelope version is unsupported.
/// - [`EvidenceVerificationError::WrongProfile`] if the encoded profile differs from
///   [`EvidenceVerificationInput::expected_profile`].
/// - [`EvidenceVerificationError::TooManyDomainSigningKeys`] if the caller supplies more than 32
///   trusted domain-signing keys.
/// - [`EvidenceVerificationError::GraceWindowTooLarge`] if the caller supplies a certificate grace
///   window greater than 300 seconds.
/// - [`EvidenceVerificationError::SenderCertificate`] for any certificate trust, relay-domain,
///   canonical-key, signature, or acceptance-time failure.
/// - [`EvidenceVerificationError::SignatureFailure`] if the Message signature is malformed or
///   does not authenticate the exported transcript.
pub fn verify_evidence_bundle(
    input: EvidenceVerificationInput<'_>,
) -> Result<VerifiedEvidenceBundle, EvidenceVerificationError> {
    if input.grace_window_secs > MAX_EVIDENCE_GRACE_WINDOW_SECS {
        return Err(EvidenceVerificationError::GraceWindowTooLarge {
            actual: input.grace_window_secs,
            maximum: MAX_EVIDENCE_GRACE_WINDOW_SECS,
        });
    }
    if input.domain_signing_keys.len() > MAX_EVIDENCE_DOMAIN_SIGNING_KEYS {
        return Err(EvidenceVerificationError::TooManyDomainSigningKeys {
            count: input.domain_signing_keys.len(),
            maximum: MAX_EVIDENCE_DOMAIN_SIGNING_KEYS,
        });
    }
    if input.bundle.len() > MAX_EVIDENCE_BUNDLE_LEN {
        return Err(EvidenceVerificationError::BundleTooLarge);
    }
    let Some((&version, remaining)) = input.bundle.split_first() else {
        return Err(EvidenceVerificationError::MalformedBundle);
    };
    if version != CURRENT_EVIDENCE_BUNDLE_VERSION {
        return Err(EvidenceVerificationError::UnsupportedVersion(version));
    }
    let Some(&profile) = remaining.first() else {
        return Err(EvidenceVerificationError::MalformedBundle);
    };
    if profile != input.expected_profile.tag() {
        return Err(EvidenceVerificationError::WrongProfile {
            expected: input.expected_profile,
            actual: profile,
        });
    }

    let (decoded, trailing): (DecodedEvidenceBundleWire<'_>, &[u8]) =
        postcard::take_from_bytes(input.bundle)
            .map_err(|_| EvidenceVerificationError::MalformedBundle)?;
    if !trailing.is_empty()
        || decoded.version != version
        || decoded.profile != profile
        || decoded.session_key.is_empty()
        || decoded.session_key.len() > MAX_EVIDENCE_SESSION_KEY_LEN
        || decoded.padded_payload.len() > MAX_EVIDENCE_PADDED_PAYLOAD_LEN
        || decoded.sender_certificate.len() > MAX_EVIDENCE_CERTIFICATE_LEN
        || decoded.sender_certificate_signature.len() != SIGNATURE_LEN
        || decoded.transcript_signature.len() != SIGNATURE_LEN
    {
        return Err(EvidenceVerificationError::MalformedBundle);
    }
    if parse_ed25519_verifying_key_bytes(&decoded.recipient_identity_verifying_key).is_none() {
        return Err(EvidenceVerificationError::MalformedBundle);
    }
    let plaintext = unpad_sealed_payload(decoded.padded_payload)
        .map_err(|_| EvidenceVerificationError::MalformedBundle)?;
    let payload_kind = PayloadKind::from_tag(decoded.payload_kind)
        .map_err(|_| EvidenceVerificationError::MalformedBundle)?;
    let validated_certificate = validate_sender_certificate(SenderCertificateValidationInput {
        certificate: decoded.sender_certificate,
        signature: decoded.sender_certificate_signature,
        domain_signing_keys: input.domain_signing_keys,
        expected_relay_domain: input.expected_relay_domain,
        revocation_state: RevocationState::Available(&[]),
        reference_timestamp_secs: input.accepted_timestamp_secs,
        grace_window_secs: input.grace_window_secs,
    })?;
    let verifying_key = parse_ed25519_verifying_key_bytes(
        &validated_certificate.identity_key.ed25519_verifying_key,
    )
    .ok_or(EvidenceVerificationError::SignatureFailure)?;
    let signature_bytes: [u8; SIGNATURE_LEN] = decoded
        .transcript_signature
        .try_into()
        .map_err(|_| EvidenceVerificationError::SignatureFailure)?;
    let signature = Signature::from_bytes(&signature_bytes);
    let transcript = message_transcript(MessageTranscriptInput {
        session_key: decoded.session_key,
        recipient_identity_verifying_key: &decoded.recipient_identity_verifying_key,
        id: MessageId::from_bytes(decoded.message_id),
        timestamp_millis: decoded.timestamp_millis,
        payload_kind,
        payload: decoded.padded_payload,
        sender_certificate: decoded.sender_certificate,
    })
    .map_err(|_| EvidenceVerificationError::MalformedBundle)?;
    verify_with_context(
        &verifying_key,
        MESSAGE_TRANSCRIPT_CONTEXT,
        &transcript,
        &signature,
    )
    .map_err(|_| EvidenceVerificationError::SignatureFailure)?;
    let evidence_identity = derive_evidence_identity(
        &validated_certificate.identity_key,
        &validated_certificate.relay_domain,
        &transcript,
    )?;

    Ok(VerifiedEvidenceBundle {
        profile: input.expected_profile,
        evidence_identity,
        session_key: decoded.session_key.to_vec(),
        recipient_identity_verifying_key: decoded.recipient_identity_verifying_key,
        message_id: MessageId::from_bytes(decoded.message_id),
        timestamp_millis: decoded.timestamp_millis,
        payload_kind,
        plaintext,
        sender_identity_key: validated_certificate.identity_key,
        relay_domain: validated_certificate.relay_domain,
        certificate_expires_at_secs: validated_certificate.expires_at_secs,
    })
}

fn derive_evidence_identity(
    sender_identity_key: &SenderCertificateIdentityKey,
    relay_domain: &[u8],
    transcript: &[u8],
) -> Result<[u8; 32], EvidenceVerificationError> {
    let relay_domain_len =
        u8::try_from(relay_domain.len()).map_err(|_| EvidenceVerificationError::MalformedBundle)?;
    let mut hasher = Zeroizing::new(blake3::Hasher::new_derive_key(EVIDENCE_IDENTITY_CONTEXT));
    hasher.update(&sender_identity_key.x25519_public_key);
    hasher.update(&sender_identity_key.ed25519_verifying_key);
    hasher.update(&[relay_domain_len]);
    hasher.update(relay_domain);
    hasher.update(MESSAGE_TRANSCRIPT_CONTEXT);
    hasher.update(transcript);
    let digest = Zeroizing::new(hasher.finalize());
    Ok(*digest.as_bytes())
}
