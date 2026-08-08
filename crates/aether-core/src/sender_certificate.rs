//! Sender certificate validation against caller-supplied trust policy.

use crate::key_encoding::{
    PUBLIC_KEY_LEN, parse_ed25519_verifying_key as parse_key_encoding_ed25519_verifying_key,
    parse_ed25519_verifying_key_bytes as parse_key_encoding_ed25519_verifying_key_bytes,
    validate_x25519_public_key as validate_key_encoding_x25519_public_key,
};
use aether_crypto::{Signature, VerifyingKey};
#[cfg(feature = "development-certificates")]
use aether_crypto::{SigningKeyPair, generate_signing_key_pair};
#[cfg(feature = "development-certificates")]
use rand::rngs::OsRng;
use std::error::Error;
use std::fmt;
use subtle::{Choice, ConstantTimeEq};

const CERTIFICATE_DOMAIN_TAG: &[u8] = b"AetherSenderCertificate-v1:";
const CERTIFICATE_VERSION: u8 = 1;
const IDENTITY_KEY_DOMAIN_TAG: &[u8] = b"AetherIK-v1:";
const SIGNATURE_LEN: usize = 64;
const MAX_SIGNING_KEY_IDENTIFIER_LEN: usize = 64;
const IDENTITY_KEY_ENCODING_LEN: usize = IDENTITY_KEY_DOMAIN_TAG.len() + PUBLIC_KEY_LEN * 2;

/// Inputs for one sender certificate validation verdict.
///
/// Validation is a pure function of these inputs. It does not read the device clock, does not
/// cache successful results, and evaluates revocation against the current `revocation_state`
/// input on every call.
pub struct SenderCertificateValidationInput<'a> {
    /// Fixed-byte sender certificate bytes.
    pub certificate: &'a [u8],
    /// Ed25519 signature over `certificate`.
    pub signature: &'a [u8],
    /// Known domain-signing keys indexed by certificate signing-key identifier.
    pub domain_signing_keys: &'a [DomainSigningKey<'a>],
    /// Caller-supplied revocation input for the sender Identity Key check.
    pub revocation_state: RevocationState<'a>,
    /// Caller-supplied Unix timestamp in seconds used for expiry evaluation.
    pub reference_timestamp_secs: u64,
    /// Caller-supplied grace window in seconds, with no library-imposed ceiling.
    ///
    /// Callers own all grace-window bounds. Larger values tolerate more sender/receiver clock
    /// skew and delivery delay but keep expired certificates acceptable for longer; `u64::MAX`
    /// keeps every expired certificate acceptable forever. The consumer sets this from its own
    /// product requirements with that trade-off in view.
    pub grace_window_secs: u64,
}

/// A domain-signing key known to the validator.
#[derive(Clone, Copy, Debug)]
pub struct DomainSigningKey<'a> {
    /// Identifier matched exactly against the certificate signing-key identifier.
    pub identifier: &'a [u8],
    /// Canonical Ed25519 verifying-key bytes for this domain-signing key.
    pub verifying_key: &'a [u8],
    /// Current trust status for this identifier.
    pub status: DomainSigningKeyStatus,
}

/// Trust status for a known domain-signing key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainSigningKeyStatus {
    /// Certificates signed by this key may validate.
    Trusted,
    /// Certificates naming this key must fail with an untrusted-key verdict.
    Untrusted,
}

/// Caller-supplied revocation input for one validation verdict.
///
/// Distinguishes a loaded revocation set from a revocation source that failed to load, so an
/// empty set always means "nothing revoked" and never "feed missing". Validation fails closed on
/// [`RevocationState::Unavailable`] instead of trusting every caller to fail closed on its own.
#[derive(Clone, Copy, Debug)]
pub enum RevocationState<'a> {
    /// The revocation set loaded; an empty slice revokes no Identity Key.
    Available(&'a [SenderCertificateIdentityKey]),
    /// The revocation source failed to load; validation fails closed.
    Unavailable,
}

/// A sender Identity Key carried by a sender certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SenderCertificateIdentityKey {
    /// Canonical X25519 public key bytes.
    pub x25519_public_key: [u8; PUBLIC_KEY_LEN],
    /// Canonical Ed25519 verifying-key bytes.
    pub ed25519_verifying_key: [u8; PUBLIC_KEY_LEN],
}

impl SenderCertificateIdentityKey {
    /// Returns the canonical revocation-key encoding for this Identity Key.
    #[must_use]
    pub fn canonical_encoding(&self) -> [u8; IDENTITY_KEY_ENCODING_LEN] {
        let mut encoding = [0u8; IDENTITY_KEY_ENCODING_LEN];
        let mut offset = 0;
        encoding[offset..offset + IDENTITY_KEY_DOMAIN_TAG.len()]
            .copy_from_slice(IDENTITY_KEY_DOMAIN_TAG);
        offset += IDENTITY_KEY_DOMAIN_TAG.len();
        encoding[offset..offset + PUBLIC_KEY_LEN].copy_from_slice(&self.x25519_public_key);
        offset += PUBLIC_KEY_LEN;
        encoding[offset..offset + PUBLIC_KEY_LEN].copy_from_slice(&self.ed25519_verifying_key);
        encoding
    }
}

/// A sender Discovery Key carried by a sender certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SenderCertificateDiscoveryKey {
    /// Canonical X25519 public key bytes.
    pub x25519_public_key: [u8; PUBLIC_KEY_LEN],
    /// Canonical Ed25519 verifying-key bytes.
    pub ed25519_verifying_key: [u8; PUBLIC_KEY_LEN],
    /// Discovery Key epoch bound into the certificate.
    pub epoch: u32,
}

/// A validated sender certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedSenderCertificate {
    /// Signing-key identifier read from the certificate bytes.
    pub signing_key_identifier: Vec<u8>,
    /// Sender Identity Key bound by the certificate.
    pub identity_key: SenderCertificateIdentityKey,
    /// Sender Discovery Key bound by the certificate.
    pub discovery_key: SenderCertificateDiscoveryKey,
    /// Certificate expiry Unix timestamp in seconds.
    pub expires_at_secs: u64,
}

/// An in-memory certificate authority for local development peers.
///
/// The authority generates one process-local Ed25519 signing key from the operating-system CSPRNG
/// and never exposes its secret bytes. Certificates it issues pass the ordinary validation path
/// only when the caller explicitly trusts this authority's identifier and verifying key. The type
/// is available only with the `development-certificates` feature and must not back production
/// sender identity.
#[cfg(feature = "development-certificates")]
pub struct DevelopmentCertificateAuthority {
    signing_key_identifier: Vec<u8>,
    signing_key: SigningKeyPair,
}

/// Certificate bytes and signature issued by a [`DevelopmentCertificateAuthority`].
#[cfg(feature = "development-certificates")]
pub struct DevelopmentSenderCertificate {
    /// Fixed-byte sender certificate bytes.
    pub certificate: Vec<u8>,
    /// Ed25519 signature over `certificate`.
    pub signature: Vec<u8>,
}

/// Errors returned while constructing development sender certificates.
#[cfg(feature = "development-certificates")]
#[derive(Debug, Eq, PartialEq)]
pub enum DevelopmentCertificateError {
    /// The signing-key identifier is empty or exceeds the certificate format limit.
    InvalidSigningKeyIdentifier,
    /// The sender Identity Key is not canonically encoded.
    InvalidIdentityKey,
    /// The sender Discovery Key is not canonically encoded.
    InvalidDiscoveryKey,
}

#[cfg(feature = "development-certificates")]
impl fmt::Display for DevelopmentCertificateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSigningKeyIdentifier => {
                write!(
                    f,
                    "development certificate signing-key identifier is invalid"
                )
            }
            Self::InvalidIdentityKey => {
                write!(f, "development certificate identity key is invalid")
            }
            Self::InvalidDiscoveryKey => {
                write!(f, "development certificate discovery key is invalid")
            }
        }
    }
}

#[cfg(feature = "development-certificates")]
impl Error for DevelopmentCertificateError {}

#[cfg(feature = "development-certificates")]
impl DevelopmentCertificateAuthority {
    /// Constructs a process-local development certificate authority.
    ///
    /// The signing key is generated from the operating-system CSPRNG and zeroized on drop. Peers
    /// must explicitly include [`Self::verifying_key`] under [`Self::signing_key_identifier`] in
    /// their validation input before certificates from this authority are accepted.
    ///
    /// # Examples
    /// ```
    /// use aether_core::DevelopmentCertificateAuthority;
    ///
    /// let authority = DevelopmentCertificateAuthority::new(b"local-loopback".to_vec())?;
    /// assert_eq!(authority.verifying_key().len(), 32);
    /// # Ok::<(), aether_core::DevelopmentCertificateError>(())
    /// ```
    ///
    /// # Errors
    /// - [`DevelopmentCertificateError::InvalidSigningKeyIdentifier`] if the identifier is empty
    ///   or exceeds the certificate format's 64-byte limit.
    pub fn new(signing_key_identifier: Vec<u8>) -> Result<Self, DevelopmentCertificateError> {
        validate_development_signing_key_identifier(&signing_key_identifier)?;
        Ok(Self {
            signing_key_identifier,
            signing_key: generate_signing_key_pair(&mut OsRng),
        })
    }

    /// Returns the identifier embedded in every certificate from this authority.
    #[must_use]
    pub fn signing_key_identifier(&self) -> &[u8] {
        &self.signing_key_identifier
    }

    /// Returns the Ed25519 verifying key peers explicitly trust for local development.
    #[must_use]
    pub fn verifying_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.signing_key.verifying.to_bytes()
    }

    /// Issues a development sender certificate for one Identity Key and Discovery Key.
    ///
    /// The returned bytes use the production certificate encoding and signature verification
    /// path. This method does not validate the Identity Key binding signature or Discovery Key
    /// lineage; callers must obtain both values from an already initialized keystore.
    ///
    /// # Examples
    /// ```
    /// use aether_core::{
    ///     DevelopmentCertificateAuthority, SenderCertificateDiscoveryKey,
    ///     SenderCertificateIdentityKey,
    /// };
    ///
    /// # use aether_crypto::{generate_key_pair, generate_signing_key_pair};
    /// # use rand::rngs::OsRng;
    /// # let identity_agreement = generate_key_pair(&mut OsRng);
    /// # let identity_signing = generate_signing_key_pair(&mut OsRng);
    /// # let discovery_agreement = generate_key_pair(&mut OsRng);
    /// # let discovery_signing = generate_signing_key_pair(&mut OsRng);
    /// # let identity = SenderCertificateIdentityKey {
    /// #     x25519_public_key: *identity_agreement.public.as_bytes(),
    /// #     ed25519_verifying_key: identity_signing.verifying.to_bytes(),
    /// # };
    /// # let discovery = SenderCertificateDiscoveryKey {
    /// #     x25519_public_key: *discovery_agreement.public.as_bytes(),
    /// #     ed25519_verifying_key: discovery_signing.verifying.to_bytes(),
    /// #     epoch: 0,
    /// # };
    /// let authority = DevelopmentCertificateAuthority::new(b"local-loopback".to_vec())?;
    /// let issued = authority.issue(identity, discovery, 1_800_000_000)?;
    /// assert_eq!(issued.signature.len(), 64);
    /// # Ok::<(), aether_core::DevelopmentCertificateError>(())
    /// ```
    ///
    /// # Errors
    /// - [`DevelopmentCertificateError::InvalidIdentityKey`] if either Identity Key public key is
    ///   not canonically encoded.
    /// - [`DevelopmentCertificateError::InvalidDiscoveryKey`] if either Discovery Key public key
    ///   is not canonically encoded.
    pub fn issue(
        &self,
        identity_key: SenderCertificateIdentityKey,
        discovery_key: SenderCertificateDiscoveryKey,
        expires_at_secs: u64,
    ) -> Result<DevelopmentSenderCertificate, DevelopmentCertificateError> {
        validate_identity_key(&identity_key)
            .map_err(|_| DevelopmentCertificateError::InvalidIdentityKey)?;
        validate_discovery_key(&discovery_key)
            .map_err(|_| DevelopmentCertificateError::InvalidDiscoveryKey)?;

        let mut certificate = Vec::with_capacity(
            CERTIFICATE_DOMAIN_TAG.len()
                + 2
                + self.signing_key_identifier.len()
                + PUBLIC_KEY_LEN * 4
                + 4
                + 8,
        );
        certificate.extend_from_slice(CERTIFICATE_DOMAIN_TAG);
        certificate.push(CERTIFICATE_VERSION);
        certificate.push(self.signing_key_identifier.len() as u8);
        certificate.extend_from_slice(&self.signing_key_identifier);
        certificate.extend_from_slice(&identity_key.x25519_public_key);
        certificate.extend_from_slice(&identity_key.ed25519_verifying_key);
        certificate.extend_from_slice(&discovery_key.x25519_public_key);
        certificate.extend_from_slice(&discovery_key.ed25519_verifying_key);
        certificate.extend_from_slice(&discovery_key.epoch.to_be_bytes());
        certificate.extend_from_slice(&expires_at_secs.to_be_bytes());
        let signature = self.signing_key.sign(&certificate).to_bytes().to_vec();

        Ok(DevelopmentSenderCertificate {
            certificate,
            signature,
        })
    }
}

#[cfg(feature = "development-certificates")]
fn validate_development_signing_key_identifier(
    identifier: &[u8],
) -> Result<(), DevelopmentCertificateError> {
    if identifier.is_empty() || identifier.len() > MAX_SIGNING_KEY_IDENTIFIER_LEN {
        Err(DevelopmentCertificateError::InvalidSigningKeyIdentifier)
    } else {
        Ok(())
    }
}

/// Errors returned by sender certificate validation.
#[non_exhaustive]
#[derive(Debug, Eq, PartialEq)]
pub enum SenderCertificateValidationError {
    /// Certificate bytes are malformed.
    MalformedCertificate,
    /// A public-key byte field is not canonically encoded.
    InvalidKeyEncoding,
    /// The certificate names no known signing-key identifier.
    UnknownSigningKeyIdentifier,
    /// The certificate names a known but currently untrusted signing-key identifier.
    UntrustedSigningKeyIdentifier,
    /// The trusted-key set contains the same signing-key identifier more than once.
    DuplicateSigningKeyIdentifier,
    /// The certificate signature does not verify under the matching trusted signing key.
    SignatureFailure,
    /// The revocation source is unavailable, so no revocation verdict is possible.
    RevocationStateUnavailable,
    /// The certificate Identity Key is currently revoked.
    RevokedIdentityKey,
    /// The certificate is expired outside the supplied grace window.
    ExpiredCertificate,
}

impl fmt::Display for SenderCertificateValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedCertificate => write!(f, "sender certificate is malformed"),
            Self::InvalidKeyEncoding => write!(f, "sender certificate key encoding is invalid"),
            Self::UnknownSigningKeyIdentifier => {
                write!(f, "sender certificate signing-key identifier is unknown")
            }
            Self::UntrustedSigningKeyIdentifier => {
                write!(f, "sender certificate signing-key identifier is untrusted")
            }
            Self::DuplicateSigningKeyIdentifier => {
                write!(f, "sender certificate signing-key identifier is duplicated")
            }
            Self::SignatureFailure => write!(f, "sender certificate signature failed"),
            Self::RevocationStateUnavailable => {
                write!(f, "sender certificate revocation state is unavailable")
            }
            Self::RevokedIdentityKey => write!(f, "sender certificate identity key is revoked"),
            Self::ExpiredCertificate => write!(f, "sender certificate is expired"),
        }
    }
}

impl Error for SenderCertificateValidationError {}

struct ParsedSenderCertificate<'a> {
    signing_key_identifier: &'a [u8],
    identity_key: SenderCertificateIdentityKey,
    discovery_key: SenderCertificateDiscoveryKey,
    expires_at_secs: u64,
}

/// Validates a sender certificate against caller-supplied trust, revocation, and time inputs.
///
/// The certificate signature is verified only against the trusted domain-signing key whose
/// identifier exactly matches the identifier embedded in `input.certificate`. Expiry is evaluated
/// against `reference_timestamp_secs` and `grace_window_secs`; this function never reads the
/// device clock and never caps the supplied grace window. Revocation is evaluated from the current
/// `revocation_state` input on every call after signature verification, and an unavailable
/// revocation source fails validation closed rather than validating against an empty set.
///
/// # Errors
/// - [`SenderCertificateValidationError::MalformedCertificate`] when certificate bytes fail the
///   fixed-byte format, version, identifier length, or exact-length checks.
/// - [`SenderCertificateValidationError::InvalidKeyEncoding`] when certificate keys, the matching
///   domain-signing key, or revoked identity keys are not canonically encoded.
/// - [`SenderCertificateValidationError::UnknownSigningKeyIdentifier`] when no domain key has the
///   certificate signing-key identifier.
/// - [`SenderCertificateValidationError::UntrustedSigningKeyIdentifier`] when the matching domain
///   key is known but untrusted.
/// - [`SenderCertificateValidationError::DuplicateSigningKeyIdentifier`] when more than one
///   domain key has the certificate signing-key identifier.
/// - [`SenderCertificateValidationError::SignatureFailure`] when the signature bytes are malformed
///   or do not verify under the matching trusted signing key.
/// - [`SenderCertificateValidationError::RevocationStateUnavailable`] when `revocation_state` is
///   [`RevocationState::Unavailable`] and no revocation verdict is possible.
/// - [`SenderCertificateValidationError::RevokedIdentityKey`] when the certificate Identity Key is
///   present in the available revocation set.
/// - [`SenderCertificateValidationError::ExpiredCertificate`] when the certificate expiry is
///   outside the supplied grace window.
pub fn validate_sender_certificate(
    input: SenderCertificateValidationInput<'_>,
) -> Result<ValidatedSenderCertificate, SenderCertificateValidationError> {
    let certificate = parse_certificate(input.certificate)?;
    validate_identity_key(&certificate.identity_key)?;
    validate_discovery_key(&certificate.discovery_key)?;

    let domain_signing_key = matching_domain_signing_key(
        certificate.signing_key_identifier,
        input.domain_signing_keys,
    )?;
    if domain_signing_key.status == DomainSigningKeyStatus::Untrusted {
        return Err(SenderCertificateValidationError::UntrustedSigningKeyIdentifier);
    }
    let verifying_key = parse_ed25519_verifying_key(domain_signing_key.verifying_key)?;
    let signature = parse_signature(input.signature)?;
    if verifying_key
        .verify_strict(input.certificate, &signature)
        .is_err()
    {
        return Err(SenderCertificateValidationError::SignatureFailure);
    }
    let RevocationState::Available(revoked_identity_keys) = input.revocation_state else {
        return Err(SenderCertificateValidationError::RevocationStateUnavailable);
    };
    if identity_key_is_revoked(&certificate.identity_key, revoked_identity_keys)? {
        return Err(SenderCertificateValidationError::RevokedIdentityKey);
    }
    if certificate_is_expired(
        certificate.expires_at_secs,
        input.reference_timestamp_secs,
        input.grace_window_secs,
    ) {
        return Err(SenderCertificateValidationError::ExpiredCertificate);
    }

    Ok(ValidatedSenderCertificate {
        signing_key_identifier: certificate.signing_key_identifier.to_vec(),
        identity_key: certificate.identity_key,
        discovery_key: certificate.discovery_key,
        expires_at_secs: certificate.expires_at_secs,
    })
}

fn parse_certificate(
    bytes: &[u8],
) -> Result<ParsedSenderCertificate<'_>, SenderCertificateValidationError> {
    let prefix_len = CERTIFICATE_DOMAIN_TAG.len() + 2;
    if bytes.len() < prefix_len || &bytes[..CERTIFICATE_DOMAIN_TAG.len()] != CERTIFICATE_DOMAIN_TAG
    {
        return Err(SenderCertificateValidationError::MalformedCertificate);
    }
    let mut offset = CERTIFICATE_DOMAIN_TAG.len();
    let version = bytes[offset];
    offset += 1;
    if version != CERTIFICATE_VERSION {
        return Err(SenderCertificateValidationError::MalformedCertificate);
    }
    let identifier_len = bytes[offset] as usize;
    offset += 1;
    if identifier_len == 0 || identifier_len > MAX_SIGNING_KEY_IDENTIFIER_LEN {
        return Err(SenderCertificateValidationError::MalformedCertificate);
    }
    let expected_len =
        CERTIFICATE_DOMAIN_TAG.len() + 2 + identifier_len + PUBLIC_KEY_LEN * 4 + 4 + 8;
    if bytes.len() != expected_len {
        return Err(SenderCertificateValidationError::MalformedCertificate);
    }

    let signing_key_identifier = read_slice(bytes, &mut offset, identifier_len)?;
    let identity_key = SenderCertificateIdentityKey {
        x25519_public_key: read_array(bytes, &mut offset)?,
        ed25519_verifying_key: read_array(bytes, &mut offset)?,
    };
    let discovery_key = SenderCertificateDiscoveryKey {
        x25519_public_key: read_array(bytes, &mut offset)?,
        ed25519_verifying_key: read_array(bytes, &mut offset)?,
        epoch: u32::from_be_bytes(read_array(bytes, &mut offset)?),
    };
    let expires_at_secs = u64::from_be_bytes(read_array(bytes, &mut offset)?);
    if offset != bytes.len() {
        return Err(SenderCertificateValidationError::MalformedCertificate);
    }

    Ok(ParsedSenderCertificate {
        signing_key_identifier,
        identity_key,
        discovery_key,
        expires_at_secs,
    })
}

fn read_slice<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    len: usize,
) -> Result<&'a [u8], SenderCertificateValidationError> {
    let end = offset
        .checked_add(len)
        .ok_or(SenderCertificateValidationError::MalformedCertificate)?;
    let value = bytes
        .get(*offset..end)
        .ok_or(SenderCertificateValidationError::MalformedCertificate)?;
    *offset = end;
    Ok(value)
}

fn read_array<const N: usize>(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], SenderCertificateValidationError> {
    read_slice(bytes, offset, N)?
        .try_into()
        .map_err(|_| SenderCertificateValidationError::MalformedCertificate)
}

fn matching_domain_signing_key<'a>(
    identifier: &[u8],
    domain_signing_keys: &'a [DomainSigningKey<'a>],
) -> Result<&'a DomainSigningKey<'a>, SenderCertificateValidationError> {
    let mut matched = None;
    for key in domain_signing_keys {
        if key.identifier == identifier {
            if matched.is_some() {
                return Err(SenderCertificateValidationError::DuplicateSigningKeyIdentifier);
            }
            matched = Some(key);
        }
    }
    matched.ok_or(SenderCertificateValidationError::UnknownSigningKeyIdentifier)
}

fn identity_key_is_revoked(
    identity_key: &SenderCertificateIdentityKey,
    revoked_identity_keys: &[SenderCertificateIdentityKey],
) -> Result<bool, SenderCertificateValidationError> {
    let encoding = identity_key.canonical_encoding();
    let mut revoked = Choice::from(0);
    for revoked_identity_key in revoked_identity_keys {
        validate_identity_key(revoked_identity_key)?;
        revoked |= encoding.ct_eq(&revoked_identity_key.canonical_encoding());
    }
    Ok(revoked.into())
}

fn validate_identity_key(
    identity_key: &SenderCertificateIdentityKey,
) -> Result<(), SenderCertificateValidationError> {
    validate_x25519_public_key(&identity_key.x25519_public_key)?;
    parse_ed25519_verifying_key_bytes(&identity_key.ed25519_verifying_key)?;
    Ok(())
}

fn validate_discovery_key(
    discovery_key: &SenderCertificateDiscoveryKey,
) -> Result<(), SenderCertificateValidationError> {
    validate_x25519_public_key(&discovery_key.x25519_public_key)?;
    parse_ed25519_verifying_key_bytes(&discovery_key.ed25519_verifying_key)?;
    Ok(())
}

fn validate_x25519_public_key(
    bytes: &[u8; PUBLIC_KEY_LEN],
) -> Result<(), SenderCertificateValidationError> {
    if validate_key_encoding_x25519_public_key(bytes) {
        Ok(())
    } else {
        Err(SenderCertificateValidationError::InvalidKeyEncoding)
    }
}

fn parse_ed25519_verifying_key(
    bytes: &[u8],
) -> Result<VerifyingKey, SenderCertificateValidationError> {
    parse_key_encoding_ed25519_verifying_key(bytes)
        .ok_or(SenderCertificateValidationError::InvalidKeyEncoding)
}

fn parse_ed25519_verifying_key_bytes(
    bytes: &[u8; PUBLIC_KEY_LEN],
) -> Result<VerifyingKey, SenderCertificateValidationError> {
    parse_key_encoding_ed25519_verifying_key_bytes(bytes)
        .ok_or(SenderCertificateValidationError::InvalidKeyEncoding)
}

fn parse_signature(bytes: &[u8]) -> Result<Signature, SenderCertificateValidationError> {
    let bytes: [u8; SIGNATURE_LEN] = bytes
        .try_into()
        .map_err(|_| SenderCertificateValidationError::SignatureFailure)?;
    Ok(Signature::from_bytes(&bytes))
}

fn certificate_is_expired(expires_at_secs: u64, reference_secs: u64, grace_secs: u64) -> bool {
    reference_secs > expires_at_secs && reference_secs - expires_at_secs > grace_secs
}

#[cfg(test)]
fn x25519_field_modulus() -> [u8; PUBLIC_KEY_LEN] {
    let mut modulus = [0xff; PUBLIC_KEY_LEN];
    modulus[0] = 0xed;
    modulus[PUBLIC_KEY_LEN - 1] = 0x7f;
    modulus
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether_crypto::{SigningKeyPair, generate_signing_key_pair};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    const NOW_SECS: u64 = 1_700_000_000;
    const GRACE_SECS: u64 = 30;
    const PRIMARY_IDENTIFIER: &[u8] = b"primary";
    const SECONDARY_IDENTIFIER: &[u8] = b"secondary";

    struct SignedCertificate {
        certificate: Vec<u8>,
        signature: Vec<u8>,
        identity_key: SenderCertificateIdentityKey,
        discovery_key: SenderCertificateDiscoveryKey,
        expires_at_secs: u64,
    }

    fn signing_key(seed: u8) -> SigningKeyPair {
        generate_signing_key_pair(&mut ChaCha20Rng::from_seed([seed; 32]))
    }

    fn identity_key() -> SenderCertificateIdentityKey {
        SenderCertificateIdentityKey {
            x25519_public_key: [0x11; PUBLIC_KEY_LEN],
            ed25519_verifying_key: signing_key(0x21).verifying.to_bytes(),
        }
    }

    fn discovery_key() -> SenderCertificateDiscoveryKey {
        SenderCertificateDiscoveryKey {
            x25519_public_key: [0x31; PUBLIC_KEY_LEN],
            ed25519_verifying_key: signing_key(0x41).verifying.to_bytes(),
            epoch: 7,
        }
    }

    fn certificate_bytes(
        identifier: &[u8],
        identity_key: SenderCertificateIdentityKey,
        discovery_key: SenderCertificateDiscoveryKey,
        expires_at_secs: u64,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(CERTIFICATE_DOMAIN_TAG);
        bytes.push(CERTIFICATE_VERSION);
        bytes.push(identifier.len() as u8);
        bytes.extend_from_slice(identifier);
        bytes.extend_from_slice(&identity_key.x25519_public_key);
        bytes.extend_from_slice(&identity_key.ed25519_verifying_key);
        bytes.extend_from_slice(&discovery_key.x25519_public_key);
        bytes.extend_from_slice(&discovery_key.ed25519_verifying_key);
        bytes.extend_from_slice(&discovery_key.epoch.to_be_bytes());
        bytes.extend_from_slice(&expires_at_secs.to_be_bytes());
        bytes
    }

    fn signed_certificate(
        identifier: &[u8],
        domain_key: &SigningKeyPair,
        expires_at_secs: u64,
    ) -> SignedCertificate {
        let identity_key = identity_key();
        let discovery_key = discovery_key();
        let certificate =
            certificate_bytes(identifier, identity_key, discovery_key, expires_at_secs);
        let signature = domain_key.sign(&certificate).to_bytes().to_vec();
        SignedCertificate {
            certificate,
            signature,
            identity_key,
            discovery_key,
            expires_at_secs,
        }
    }

    fn validation_input<'a>(
        signed: &'a SignedCertificate,
        domain_signing_keys: &'a [DomainSigningKey<'a>],
        revoked_identity_keys: &'a [SenderCertificateIdentityKey],
    ) -> SenderCertificateValidationInput<'a> {
        SenderCertificateValidationInput {
            certificate: &signed.certificate,
            signature: &signed.signature,
            domain_signing_keys,
            revocation_state: RevocationState::Available(revoked_identity_keys),
            reference_timestamp_secs: NOW_SECS,
            grace_window_secs: GRACE_SECS,
        }
    }

    fn trusted_key<'a>(identifier: &'a [u8], verifying_key: &'a [u8]) -> DomainSigningKey<'a> {
        DomainSigningKey {
            identifier,
            verifying_key,
            status: DomainSigningKeyStatus::Trusted,
        }
    }

    fn assert_validation_error(
        input: SenderCertificateValidationInput<'_>,
        expected: SenderCertificateValidationError,
    ) {
        match validate_sender_certificate(input) {
            Ok(_) => panic!("sender certificate validated unexpectedly"),
            Err(actual) => assert_eq!(actual, expected),
        }
    }

    #[test]
    fn validates_certificates_for_two_concurrently_trusted_signing_keys() {
        let primary_key = signing_key(0x01);
        let secondary_key = signing_key(0x02);
        let primary_verifying = primary_key.verifying.to_bytes();
        let secondary_verifying = secondary_key.verifying.to_bytes();
        let domain_keys = [
            trusted_key(PRIMARY_IDENTIFIER, &primary_verifying),
            trusted_key(SECONDARY_IDENTIFIER, &secondary_verifying),
        ];
        let primary_certificate =
            signed_certificate(PRIMARY_IDENTIFIER, &primary_key, NOW_SECS + 300);
        let secondary_certificate =
            signed_certificate(SECONDARY_IDENTIFIER, &secondary_key, NOW_SECS + 300);

        let primary =
            validate_sender_certificate(validation_input(&primary_certificate, &domain_keys, &[]))
                .unwrap();
        let secondary = validate_sender_certificate(validation_input(
            &secondary_certificate,
            &domain_keys,
            &[],
        ))
        .unwrap();

        assert_eq!(primary.signing_key_identifier, PRIMARY_IDENTIFIER);
        assert_eq!(primary.identity_key, primary_certificate.identity_key);
        assert_eq!(primary.discovery_key, primary_certificate.discovery_key);
        assert_eq!(secondary.signing_key_identifier, SECONDARY_IDENTIFIER);
        assert_eq!(
            secondary.expires_at_secs,
            secondary_certificate.expires_at_secs
        );
    }

    #[test]
    fn rejects_unknown_signing_key_identifier() {
        let signing_key = signing_key(0x01);
        let verifying_key = signing_key.verifying.to_bytes();
        let signed = signed_certificate(PRIMARY_IDENTIFIER, &signing_key, NOW_SECS + 300);
        let domain_keys = [trusted_key(b"other", &verifying_key)];

        assert_validation_error(
            validation_input(&signed, &domain_keys, &[]),
            SenderCertificateValidationError::UnknownSigningKeyIdentifier,
        );
    }

    #[test]
    fn rejects_untrusted_signing_key_identifier() {
        let signing_key = signing_key(0x01);
        let verifying_key = signing_key.verifying.to_bytes();
        let signed = signed_certificate(PRIMARY_IDENTIFIER, &signing_key, NOW_SECS + 300);
        let domain_keys = [DomainSigningKey {
            identifier: PRIMARY_IDENTIFIER,
            verifying_key: &verifying_key,
            status: DomainSigningKeyStatus::Untrusted,
        }];

        assert_validation_error(
            validation_input(&signed, &domain_keys, &[]),
            SenderCertificateValidationError::UntrustedSigningKeyIdentifier,
        );
    }

    #[test]
    fn rejects_untrusted_identifier_before_parsing_signing_key() {
        let signing_key = signing_key(0x01);
        let signed = signed_certificate(PRIMARY_IDENTIFIER, &signing_key, NOW_SECS + 300);
        let non_canonical = [0xff; PUBLIC_KEY_LEN];
        let domain_keys = [DomainSigningKey {
            identifier: PRIMARY_IDENTIFIER,
            verifying_key: &non_canonical,
            status: DomainSigningKeyStatus::Untrusted,
        }];

        assert_validation_error(
            validation_input(&signed, &domain_keys, &[]),
            SenderCertificateValidationError::UntrustedSigningKeyIdentifier,
        );
    }

    #[test]
    fn rejects_invalid_signature() {
        let signing_key = signing_key(0x01);
        let verifying_key = signing_key.verifying.to_bytes();
        let mut signed = signed_certificate(PRIMARY_IDENTIFIER, &signing_key, NOW_SECS + 300);
        signed.signature[0] ^= 0x01;
        let domain_keys = [trusted_key(PRIMARY_IDENTIFIER, &verifying_key)];

        assert_validation_error(
            validation_input(&signed, &domain_keys, &[]),
            SenderCertificateValidationError::SignatureFailure,
        );
    }

    #[test]
    fn rejects_invalid_signature_before_revocation() {
        let signing_key = signing_key(0x01);
        let verifying_key = signing_key.verifying.to_bytes();
        let mut signed = signed_certificate(PRIMARY_IDENTIFIER, &signing_key, NOW_SECS + 300);
        signed.signature[0] ^= 0x01;
        let domain_keys = [trusted_key(PRIMARY_IDENTIFIER, &verifying_key)];
        let revoked = [signed.identity_key];

        assert_validation_error(
            validation_input(&signed, &domain_keys, &revoked),
            SenderCertificateValidationError::SignatureFailure,
        );
    }

    #[test]
    fn rejects_validation_when_revocation_state_unavailable() {
        let signing_key = signing_key(0x01);
        let verifying_key = signing_key.verifying.to_bytes();
        let signed = signed_certificate(PRIMARY_IDENTIFIER, &signing_key, NOW_SECS + 300);
        let domain_keys = [trusted_key(PRIMARY_IDENTIFIER, &verifying_key)];
        let mut input = validation_input(&signed, &domain_keys, &[]);
        input.revocation_state = RevocationState::Unavailable;

        assert_validation_error(
            input,
            SenderCertificateValidationError::RevocationStateUnavailable,
        );
    }

    #[test]
    fn rejects_invalid_signature_before_unavailable_revocation_state() {
        let signing_key = signing_key(0x01);
        let verifying_key = signing_key.verifying.to_bytes();
        let mut signed = signed_certificate(PRIMARY_IDENTIFIER, &signing_key, NOW_SECS + 300);
        signed.signature[0] ^= 0x01;
        let domain_keys = [trusted_key(PRIMARY_IDENTIFIER, &verifying_key)];
        let mut input = validation_input(&signed, &domain_keys, &[]);
        input.revocation_state = RevocationState::Unavailable;

        assert_validation_error(input, SenderCertificateValidationError::SignatureFailure);
    }

    #[test]
    fn accepts_certificate_with_empty_available_revocation_set() {
        let signing_key = signing_key(0x01);
        let verifying_key = signing_key.verifying.to_bytes();
        let signed = signed_certificate(PRIMARY_IDENTIFIER, &signing_key, NOW_SECS + 300);
        let domain_keys = [trusted_key(PRIMARY_IDENTIFIER, &verifying_key)];

        let mut input = validation_input(&signed, &domain_keys, &[]);
        input.revocation_state = RevocationState::Available(&[]);

        validate_sender_certificate(input).unwrap();
    }

    #[test]
    fn rejects_revoked_identity_key() {
        let signing_key = signing_key(0x01);
        let verifying_key = signing_key.verifying.to_bytes();
        let signed = signed_certificate(PRIMARY_IDENTIFIER, &signing_key, NOW_SECS + 300);
        let domain_keys = [trusted_key(PRIMARY_IDENTIFIER, &verifying_key)];
        let revoked = [signed.identity_key];

        assert_validation_error(
            validation_input(&signed, &domain_keys, &revoked),
            SenderCertificateValidationError::RevokedIdentityKey,
        );
    }

    #[test]
    fn rejects_previously_valid_certificate_after_identity_key_is_revoked() {
        let signing_key = signing_key(0x01);
        let verifying_key = signing_key.verifying.to_bytes();
        let signed = signed_certificate(PRIMARY_IDENTIFIER, &signing_key, NOW_SECS + 300);
        let domain_keys = [trusted_key(PRIMARY_IDENTIFIER, &verifying_key)];

        validate_sender_certificate(validation_input(&signed, &domain_keys, &[])).unwrap();

        let revoked = [signed.identity_key];
        assert_validation_error(
            validation_input(&signed, &domain_keys, &revoked),
            SenderCertificateValidationError::RevokedIdentityKey,
        );
    }

    #[test]
    fn rejects_expired_certificate_outside_grace_window() {
        let signing_key = signing_key(0x01);
        let verifying_key = signing_key.verifying.to_bytes();
        let signed =
            signed_certificate(PRIMARY_IDENTIFIER, &signing_key, NOW_SECS - GRACE_SECS - 1);
        let domain_keys = [trusted_key(PRIMARY_IDENTIFIER, &verifying_key)];

        assert_validation_error(
            validation_input(&signed, &domain_keys, &[]),
            SenderCertificateValidationError::ExpiredCertificate,
        );
    }

    #[test]
    fn accepts_expired_certificate_at_grace_window_boundary() {
        let signing_key = signing_key(0x01);
        let verifying_key = signing_key.verifying.to_bytes();
        let signed = signed_certificate(PRIMARY_IDENTIFIER, &signing_key, NOW_SECS - GRACE_SECS);
        let domain_keys = [trusted_key(PRIMARY_IDENTIFIER, &verifying_key)];

        validate_sender_certificate(validation_input(&signed, &domain_keys, &[])).unwrap();
    }

    #[test]
    fn accepts_expired_certificate_inside_unbounded_grace_window() {
        let signing_key = signing_key(0x01);
        let verifying_key = signing_key.verifying.to_bytes();
        let signed = signed_certificate(PRIMARY_IDENTIFIER, &signing_key, 0);
        let domain_keys = [trusted_key(PRIMARY_IDENTIFIER, &verifying_key)];
        let mut input = validation_input(&signed, &domain_keys, &[]);
        input.reference_timestamp_secs = u64::MAX;
        input.grace_window_secs = u64::MAX;

        validate_sender_certificate(input).unwrap();
    }

    #[test]
    fn rejects_malformed_certificate() {
        let signing_key = signing_key(0x01);
        let verifying_key = signing_key.verifying.to_bytes();
        let mut signed = signed_certificate(PRIMARY_IDENTIFIER, &signing_key, NOW_SECS + 300);
        signed.certificate.pop();
        let domain_keys = [trusted_key(PRIMARY_IDENTIFIER, &verifying_key)];

        assert_validation_error(
            validation_input(&signed, &domain_keys, &[]),
            SenderCertificateValidationError::MalformedCertificate,
        );
    }

    #[test]
    fn rejects_non_canonical_certificate_x25519_key() {
        let signing_key = signing_key(0x01);
        let verifying_key = signing_key.verifying.to_bytes();
        let mut identity_key = identity_key();
        identity_key.x25519_public_key = x25519_field_modulus();
        let discovery_key = discovery_key();
        let certificate = certificate_bytes(
            PRIMARY_IDENTIFIER,
            identity_key,
            discovery_key,
            NOW_SECS + 300,
        );
        let signed = SignedCertificate {
            signature: signing_key.sign(&certificate).to_bytes().to_vec(),
            certificate,
            identity_key,
            discovery_key,
            expires_at_secs: NOW_SECS + 300,
        };
        let domain_keys = [trusted_key(PRIMARY_IDENTIFIER, &verifying_key)];

        assert_validation_error(
            validation_input(&signed, &domain_keys, &[]),
            SenderCertificateValidationError::InvalidKeyEncoding,
        );
    }

    #[test]
    fn rejects_low_order_certificate_x25519_key() {
        let signing_key = signing_key(0x01);
        let verifying_key = signing_key.verifying.to_bytes();
        let mut identity_key = identity_key();
        identity_key.x25519_public_key = [0; PUBLIC_KEY_LEN];
        let discovery_key = discovery_key();
        let certificate = certificate_bytes(
            PRIMARY_IDENTIFIER,
            identity_key,
            discovery_key,
            NOW_SECS + 300,
        );
        let signed = SignedCertificate {
            signature: signing_key.sign(&certificate).to_bytes().to_vec(),
            certificate,
            identity_key,
            discovery_key,
            expires_at_secs: NOW_SECS + 300,
        };
        let domain_keys = [trusted_key(PRIMARY_IDENTIFIER, &verifying_key)];

        assert_validation_error(
            validation_input(&signed, &domain_keys, &[]),
            SenderCertificateValidationError::InvalidKeyEncoding,
        );
    }

    #[test]
    fn rejects_twist_low_order_certificate_x25519_key() {
        let signing_key = signing_key(0x01);
        let verifying_key = signing_key.verifying.to_bytes();
        let mut identity_key = identity_key();
        identity_key.x25519_public_key = x25519_field_modulus();
        identity_key.x25519_public_key[0] -= 1;
        let discovery_key = discovery_key();
        let certificate = certificate_bytes(
            PRIMARY_IDENTIFIER,
            identity_key,
            discovery_key,
            NOW_SECS + 300,
        );
        let signed = SignedCertificate {
            signature: signing_key.sign(&certificate).to_bytes().to_vec(),
            certificate,
            identity_key,
            discovery_key,
            expires_at_secs: NOW_SECS + 300,
        };
        let domain_keys = [trusted_key(PRIMARY_IDENTIFIER, &verifying_key)];

        assert_validation_error(
            validation_input(&signed, &domain_keys, &[]),
            SenderCertificateValidationError::InvalidKeyEncoding,
        );
    }

    #[test]
    fn rejects_weak_certificate_ed25519_key() {
        let signing_key = signing_key(0x01);
        let verifying_key = signing_key.verifying.to_bytes();
        let mut identity_key = identity_key();
        identity_key.ed25519_verifying_key = [0; PUBLIC_KEY_LEN];
        identity_key.ed25519_verifying_key[0] = 1;
        let discovery_key = discovery_key();
        let certificate = certificate_bytes(
            PRIMARY_IDENTIFIER,
            identity_key,
            discovery_key,
            NOW_SECS + 300,
        );
        let signed = SignedCertificate {
            signature: signing_key.sign(&certificate).to_bytes().to_vec(),
            certificate,
            identity_key,
            discovery_key,
            expires_at_secs: NOW_SECS + 300,
        };
        let domain_keys = [trusted_key(PRIMARY_IDENTIFIER, &verifying_key)];

        assert_validation_error(
            validation_input(&signed, &domain_keys, &[]),
            SenderCertificateValidationError::InvalidKeyEncoding,
        );
    }

    #[test]
    fn rejects_non_canonical_domain_signing_key() {
        let signing_key = signing_key(0x01);
        let signed = signed_certificate(PRIMARY_IDENTIFIER, &signing_key, NOW_SECS + 300);
        let non_canonical = [0xff; PUBLIC_KEY_LEN];
        let domain_keys = [trusted_key(PRIMARY_IDENTIFIER, &non_canonical)];

        assert_validation_error(
            validation_input(&signed, &domain_keys, &[]),
            SenderCertificateValidationError::InvalidKeyEncoding,
        );
    }

    #[test]
    fn ignores_unrelated_non_canonical_domain_signing_key() {
        let signing_key = signing_key(0x01);
        let verifying_key = signing_key.verifying.to_bytes();
        let signed = signed_certificate(PRIMARY_IDENTIFIER, &signing_key, NOW_SECS + 300);
        let non_canonical = [0xff; PUBLIC_KEY_LEN];
        let domain_keys = [
            trusted_key(PRIMARY_IDENTIFIER, &verifying_key),
            trusted_key(b"other", &non_canonical),
        ];

        validate_sender_certificate(validation_input(&signed, &domain_keys, &[])).unwrap();
    }

    #[cfg(feature = "development-certificates")]
    #[test]
    fn development_authority_issues_through_production_validation_path() {
        let authority = DevelopmentCertificateAuthority::new(PRIMARY_IDENTIFIER.to_vec()).unwrap();
        let identity_key = identity_key();
        let discovery_key = discovery_key();
        let issued = authority
            .issue(identity_key, discovery_key, NOW_SECS + 300)
            .unwrap();
        let verifying_key = authority.verifying_key();
        let domain_keys = [trusted_key(
            authority.signing_key_identifier(),
            &verifying_key,
        )];

        let validated = validate_sender_certificate(SenderCertificateValidationInput {
            certificate: &issued.certificate,
            signature: &issued.signature,
            domain_signing_keys: &domain_keys,
            revocation_state: RevocationState::Available(&[]),
            reference_timestamp_secs: NOW_SECS,
            grace_window_secs: 0,
        })
        .unwrap();

        assert_eq!(validated.identity_key, identity_key);
        assert_eq!(validated.discovery_key, discovery_key);
    }

    #[cfg(feature = "development-certificates")]
    #[test]
    fn development_authority_rejects_invalid_identifier() {
        assert!(matches!(
            DevelopmentCertificateAuthority::new(Vec::new()),
            Err(DevelopmentCertificateError::InvalidSigningKeyIdentifier)
        ));
        assert!(matches!(
            DevelopmentCertificateAuthority::new(vec![0; MAX_SIGNING_KEY_IDENTIFIER_LEN + 1]),
            Err(DevelopmentCertificateError::InvalidSigningKeyIdentifier)
        ));
    }
}
