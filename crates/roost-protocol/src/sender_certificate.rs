//! Sender certificate validation against caller-supplied trust policy.

use crate::key_encoding::{
    PUBLIC_KEY_LEN, is_valid_x25519_public_key,
    parse_ed25519_verifying_key as parse_key_encoding_ed25519_verifying_key,
    parse_ed25519_verifying_key_bytes as parse_key_encoding_ed25519_verifying_key_bytes,
};
use crate::unix_time::from_unix_secs;
use ed25519_dalek::{Signature, VerifyingKey};
use std::error::Error;
use std::fmt;
use std::time::{Duration, SystemTime};
use subtle::{Choice, ConstantTimeEq};

const CERTIFICATE_DOMAIN_TAG: &[u8] = b"AetherSenderCertificate-v2:";
const CERTIFICATE_VERSION: u8 = 2;
// A relay domain is a DNS name; 255 is the widest a single length byte can express.
const MAX_RELAY_DOMAIN_LEN: usize = 255;
const SIGNATURE_LEN: usize = 64;
const MAX_SIGNING_KEY_ID_LEN: usize = 64;

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
    /// Relay domain the recipient expects the certificate to name.
    ///
    /// Checked against the domain signed into the certificate. Without this comparison the signed
    /// domain would be decorative and a certificate would stay replayable at any relay that trusts
    /// the same signing key.
    pub expected_relay_domain: &'a [u8],
    /// Caller-supplied revocation input for the sender Identity Key check.
    pub revocation_state: RevocationState<'a>,
    /// Caller-supplied time used for expiry evaluation.
    pub reference_time: SystemTime,
    /// Caller-supplied grace window, with no library-imposed ceiling.
    ///
    /// Callers own all grace-window bounds. Larger values tolerate more sender/receiver clock
    /// skew and delivery delay but keep expired certificates acceptable for longer;
    /// [`Duration::MAX`] keeps every expired certificate acceptable forever. The consumer sets this
    /// from its own product requirements with that trade-off in view.
    pub grace_window: Duration,
}

/// A domain-signing key known to the validator.
#[derive(Clone, Copy, Debug)]
pub struct DomainSigningKey<'a> {
    /// Identifier matched exactly against the certificate signing-key identifier.
    pub id: &'a [u8],
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
    pub fn canonical_encoding(&self) -> [u8; crate::IDENTITY_KEY_ENCODING_LEN] {
        crate::identity_key_encoding(&self.x25519_public_key, &self.ed25519_verifying_key)
    }
}

/// A validated sender certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedSenderCertificate {
    /// Signing-key identifier read from the certificate bytes.
    pub signing_key_id: Vec<u8>,
    /// Sender Identity Key bound by the certificate.
    pub identity_key: SenderCertificateIdentityKey,
    /// Relay domain bound by the certificate.
    pub relay_domain: Vec<u8>,
    /// Certificate expiry Unix timestamp in seconds.
    pub expires_at_secs: u64,
}

/// Errors returned by sender certificate validation.
#[derive(Debug, Eq, PartialEq)]
pub enum SenderCertificateValidationError {
    /// Certificate bytes are malformed.
    MalformedCertificate,
    /// The certificate names a different relay domain than the recipient expects.
    RelayDomainMismatch,
    /// A public-key byte field is not canonically encoded.
    InvalidKeyEncoding,
    /// The certificate names no known signing-key identifier.
    UnknownSigningKeyId,
    /// The certificate names a known but currently untrusted signing-key identifier.
    UntrustedSigningKeyId,
    /// The trusted-key set contains the same signing-key identifier more than once.
    DuplicateSigningKeyId,
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
            Self::RelayDomainMismatch => {
                write!(f, "sender certificate names an unexpected relay domain")
            }
            Self::InvalidKeyEncoding => write!(f, "sender certificate key encoding is invalid"),
            Self::UnknownSigningKeyId => {
                write!(f, "sender certificate signing-key identifier is unknown")
            }
            Self::UntrustedSigningKeyId => {
                write!(f, "sender certificate signing-key identifier is untrusted")
            }
            Self::DuplicateSigningKeyId => {
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
    signing_key_id: &'a [u8],
    relay_domain: &'a [u8],
    identity_key: SenderCertificateIdentityKey,
    expires_at_secs: u64,
}

/// Validates a sender certificate against caller-supplied trust, revocation, and time inputs.
///
/// The certificate signature is verified only against the trusted domain-signing key whose
/// identifier exactly matches the identifier embedded in `input.certificate`. Expiry is evaluated
/// against `reference_time` and `grace_window`; this function never reads the
/// device clock and never caps the supplied grace window. Revocation is evaluated from the current
/// `revocation_state` input on every call after signature verification, and an unavailable
/// revocation source fails validation closed rather than validating against an empty set.
pub fn validate_sender_certificate(
    input: SenderCertificateValidationInput<'_>,
) -> Result<ValidatedSenderCertificate, SenderCertificateValidationError> {
    let certificate = parse_certificate(input.certificate)?;
    validate_identity_key(&certificate.identity_key)?;
    if certificate.relay_domain != input.expected_relay_domain {
        return Err(SenderCertificateValidationError::RelayDomainMismatch);
    }

    let domain_signing_key =
        matching_domain_signing_key(certificate.signing_key_id, input.domain_signing_keys)?;
    if domain_signing_key.status == DomainSigningKeyStatus::Untrusted {
        return Err(SenderCertificateValidationError::UntrustedSigningKeyId);
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
        input.reference_time,
        input.grace_window,
    ) {
        return Err(SenderCertificateValidationError::ExpiredCertificate);
    }

    Ok(ValidatedSenderCertificate {
        signing_key_id: certificate.signing_key_id.to_vec(),
        identity_key: certificate.identity_key,
        relay_domain: certificate.relay_domain.to_vec(),
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
    let id_len = bytes[offset] as usize;
    offset += 1;
    if id_len == 0 || id_len > MAX_SIGNING_KEY_ID_LEN {
        return Err(SenderCertificateValidationError::MalformedCertificate);
    }
    let signing_key_id = read_slice(bytes, &mut offset, id_len)?;
    if offset >= bytes.len() {
        return Err(SenderCertificateValidationError::MalformedCertificate);
    }
    let domain_len = bytes[offset] as usize;
    offset += 1;
    if domain_len == 0 || domain_len > MAX_RELAY_DOMAIN_LEN {
        return Err(SenderCertificateValidationError::MalformedCertificate);
    }
    let expected_len =
        CERTIFICATE_DOMAIN_TAG.len() + 3 + id_len + domain_len + PUBLIC_KEY_LEN * 2 + 8;
    if bytes.len() != expected_len {
        return Err(SenderCertificateValidationError::MalformedCertificate);
    }
    let relay_domain = read_slice(bytes, &mut offset, domain_len)?;
    let identity_key = SenderCertificateIdentityKey {
        x25519_public_key: read_array(bytes, &mut offset)?,
        ed25519_verifying_key: read_array(bytes, &mut offset)?,
    };
    let expires_at_secs = u64::from_be_bytes(read_array(bytes, &mut offset)?);
    if offset != bytes.len() {
        return Err(SenderCertificateValidationError::MalformedCertificate);
    }

    Ok(ParsedSenderCertificate {
        signing_key_id,
        relay_domain,
        identity_key,
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
    id: &[u8],
    domain_signing_keys: &'a [DomainSigningKey<'a>],
) -> Result<&'a DomainSigningKey<'a>, SenderCertificateValidationError> {
    let mut matched = None;
    for key in domain_signing_keys {
        if key.id == id {
            if matched.is_some() {
                return Err(SenderCertificateValidationError::DuplicateSigningKeyId);
            }
            matched = Some(key);
        }
    }
    matched.ok_or(SenderCertificateValidationError::UnknownSigningKeyId)
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

fn validate_x25519_public_key(
    bytes: &[u8; PUBLIC_KEY_LEN],
) -> Result<(), SenderCertificateValidationError> {
    if is_valid_x25519_public_key(bytes) {
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

fn certificate_is_expired(
    expires_at_secs: u64,
    reference_time: SystemTime,
    grace_window: Duration,
) -> bool {
    // An expiry beyond what `SystemTime` can represent is later than any reference time.
    from_unix_secs(expires_at_secs).is_some_and(|expires_at| {
        reference_time
            .duration_since(expires_at)
            .is_ok_and(|elapsed| elapsed > grace_window)
    })
}

/// Encodes the public certificate fields for a domain authority to sign.
pub fn encode_sender_certificate(
    signing_key_id: &[u8],
    relay_domain: &[u8],
    identity_key: SenderCertificateIdentityKey,
    expires_at_secs: u64,
) -> Result<Vec<u8>, SenderCertificateValidationError> {
    if signing_key_id.is_empty()
        || signing_key_id.len() > MAX_SIGNING_KEY_ID_LEN
        || relay_domain.is_empty()
        || relay_domain.len() > MAX_RELAY_DOMAIN_LEN
    {
        return Err(SenderCertificateValidationError::MalformedCertificate);
    }
    validate_identity_key(&identity_key)?;
    let mut certificate = Vec::with_capacity(
        CERTIFICATE_DOMAIN_TAG.len()
            + 3
            + signing_key_id.len()
            + relay_domain.len()
            + PUBLIC_KEY_LEN * 2
            + 8,
    );
    certificate.extend_from_slice(CERTIFICATE_DOMAIN_TAG);
    certificate.push(CERTIFICATE_VERSION);
    certificate.push(signing_key_id.len() as u8);
    certificate.extend_from_slice(signing_key_id);
    certificate.push(relay_domain.len() as u8);
    certificate.extend_from_slice(relay_domain);
    certificate.extend_from_slice(&identity_key.x25519_public_key);
    certificate.extend_from_slice(&identity_key.ed25519_verifying_key);
    certificate.extend_from_slice(&expires_at_secs.to_be_bytes());
    Ok(certificate)
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
    use ed25519_dalek::{Signer, SigningKey};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    const NOW_SECS: u64 = 1_700_000_000;
    const GRACE_SECS: u64 = 30;

    fn at(secs: u64) -> SystemTime {
        from_unix_secs(secs).unwrap()
    }
    const PRIMARY_ID: &[u8] = b"primary";
    const SECONDARY_ID: &[u8] = b"secondary";

    struct SignedCertificate {
        certificate: Vec<u8>,
        signature: Vec<u8>,
        identity_key: SenderCertificateIdentityKey,
        expires_at_secs: u64,
    }

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::generate(&mut ChaCha20Rng::from_seed([seed; 32]))
    }

    fn identity_key() -> SenderCertificateIdentityKey {
        SenderCertificateIdentityKey {
            x25519_public_key: [0x11; PUBLIC_KEY_LEN],
            ed25519_verifying_key: signing_key(0x21).verifying_key().to_bytes(),
        }
    }

    const RELAY_DOMAIN: &[u8] = b"relay.example";
    const OTHER_RELAY_DOMAIN: &[u8] = b"other.example";

    fn certificate_bytes(
        id: &[u8],
        identity_key: SenderCertificateIdentityKey,
        relay_domain: &[u8],
        expires_at_secs: u64,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(CERTIFICATE_DOMAIN_TAG);
        bytes.push(CERTIFICATE_VERSION);
        bytes.push(id.len() as u8);
        bytes.extend_from_slice(id);
        bytes.push(relay_domain.len() as u8);
        bytes.extend_from_slice(relay_domain);
        bytes.extend_from_slice(&identity_key.x25519_public_key);
        bytes.extend_from_slice(&identity_key.ed25519_verifying_key);
        bytes.extend_from_slice(&expires_at_secs.to_be_bytes());
        bytes
    }

    fn signed_certificate(
        id: &[u8],
        domain_key: &SigningKey,
        expires_at_secs: u64,
    ) -> SignedCertificate {
        let identity_key = identity_key();
        let certificate = certificate_bytes(id, identity_key, RELAY_DOMAIN, expires_at_secs);
        let signature = domain_key.sign(&certificate).to_bytes().to_vec();
        SignedCertificate {
            certificate,
            signature,
            identity_key,
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
            expected_relay_domain: RELAY_DOMAIN,
            revocation_state: RevocationState::Available(revoked_identity_keys),
            reference_time: at(NOW_SECS),
            grace_window: Duration::from_secs(GRACE_SECS),
        }
    }

    fn trusted_key<'a>(id: &'a [u8], verifying_key: &'a [u8]) -> DomainSigningKey<'a> {
        DomainSigningKey {
            id,
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

    /// A certificate issued for one relay must not validate at another, even when both relays
    /// trust the same domain-signing key. Without the signed relay domain this replay succeeded,
    /// which is why the domain is part of the signed content.
    #[test]
    fn certificate_for_another_relay_is_rejected() {
        let domain_key = signing_key(0x01);
        let verifying = domain_key.verifying_key().to_bytes();
        let domain_keys = [trusted_key(PRIMARY_ID, &verifying)];
        let identity_key = identity_key();
        // Issued naming a different relay, but signed by a key this recipient trusts.
        let certificate =
            certificate_bytes(PRIMARY_ID, identity_key, OTHER_RELAY_DOMAIN, NOW_SECS + 300);
        let signature = domain_key.sign(&certificate).to_bytes().to_vec();

        let result = validate_sender_certificate(SenderCertificateValidationInput {
            certificate: &certificate,
            signature: &signature,
            domain_signing_keys: &domain_keys,
            expected_relay_domain: RELAY_DOMAIN,
            revocation_state: RevocationState::Available(&[]),
            reference_time: at(NOW_SECS),
            grace_window: Duration::from_secs(GRACE_SECS),
        });

        assert_eq!(
            result.unwrap_err(),
            SenderCertificateValidationError::RelayDomainMismatch
        );
    }

    #[test]
    fn validates_certificates_for_two_concurrently_trusted_signing_keys() {
        let primary_key = signing_key(0x01);
        let secondary_key = signing_key(0x02);
        let primary_verifying = primary_key.verifying_key().to_bytes();
        let secondary_verifying = secondary_key.verifying_key().to_bytes();
        let domain_keys = [
            trusted_key(PRIMARY_ID, &primary_verifying),
            trusted_key(SECONDARY_ID, &secondary_verifying),
        ];
        let primary_certificate = signed_certificate(PRIMARY_ID, &primary_key, NOW_SECS + 300);
        let secondary_certificate =
            signed_certificate(SECONDARY_ID, &secondary_key, NOW_SECS + 300);

        let primary =
            validate_sender_certificate(validation_input(&primary_certificate, &domain_keys, &[]))
                .unwrap();
        let secondary = validate_sender_certificate(validation_input(
            &secondary_certificate,
            &domain_keys,
            &[],
        ))
        .unwrap();

        assert_eq!(primary.signing_key_id, PRIMARY_ID);
        assert_eq!(primary.identity_key, primary_certificate.identity_key);
        assert_eq!(primary.relay_domain, RELAY_DOMAIN.to_vec());
        assert_eq!(secondary.signing_key_id, SECONDARY_ID);
        assert_eq!(
            secondary.expires_at_secs,
            secondary_certificate.expires_at_secs
        );
    }

    #[test]
    fn rejects_unknown_signing_key_id() {
        let signing_key = signing_key(0x01);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let signed = signed_certificate(PRIMARY_ID, &signing_key, NOW_SECS + 300);
        let domain_keys = [trusted_key(b"other", &verifying_key)];

        assert_validation_error(
            validation_input(&signed, &domain_keys, &[]),
            SenderCertificateValidationError::UnknownSigningKeyId,
        );
    }

    #[test]
    fn rejects_untrusted_signing_key_id() {
        let signing_key = signing_key(0x01);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let signed = signed_certificate(PRIMARY_ID, &signing_key, NOW_SECS + 300);
        let domain_keys = [DomainSigningKey {
            id: PRIMARY_ID,
            verifying_key: &verifying_key,
            status: DomainSigningKeyStatus::Untrusted,
        }];

        assert_validation_error(
            validation_input(&signed, &domain_keys, &[]),
            SenderCertificateValidationError::UntrustedSigningKeyId,
        );
    }

    #[test]
    fn rejects_untrusted_id_before_parsing_signing_key() {
        let signing_key = signing_key(0x01);
        let signed = signed_certificate(PRIMARY_ID, &signing_key, NOW_SECS + 300);
        let non_canonical = [0xff; PUBLIC_KEY_LEN];
        let domain_keys = [DomainSigningKey {
            id: PRIMARY_ID,
            verifying_key: &non_canonical,
            status: DomainSigningKeyStatus::Untrusted,
        }];

        assert_validation_error(
            validation_input(&signed, &domain_keys, &[]),
            SenderCertificateValidationError::UntrustedSigningKeyId,
        );
    }

    #[test]
    fn rejects_invalid_signature() {
        let signing_key = signing_key(0x01);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let mut signed = signed_certificate(PRIMARY_ID, &signing_key, NOW_SECS + 300);
        signed.signature[0] ^= 0x01;
        let domain_keys = [trusted_key(PRIMARY_ID, &verifying_key)];

        for signature in [signed.signature.as_slice(), &signed.signature[..1]] {
            let mut input = validation_input(&signed, &domain_keys, &[]);
            input.signature = signature;
            assert_validation_error(input, SenderCertificateValidationError::SignatureFailure);
        }
    }

    #[test]
    fn rejects_invalid_signature_before_revocation() {
        let signing_key = signing_key(0x01);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let mut signed = signed_certificate(PRIMARY_ID, &signing_key, NOW_SECS + 300);
        signed.signature[0] ^= 0x01;
        let domain_keys = [trusted_key(PRIMARY_ID, &verifying_key)];
        let revoked = [signed.identity_key];

        assert_validation_error(
            validation_input(&signed, &domain_keys, &revoked),
            SenderCertificateValidationError::SignatureFailure,
        );
    }

    #[test]
    fn rejects_validation_when_revocation_state_unavailable() {
        let signing_key = signing_key(0x01);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let signed = signed_certificate(PRIMARY_ID, &signing_key, NOW_SECS + 300);
        let domain_keys = [trusted_key(PRIMARY_ID, &verifying_key)];
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
        let verifying_key = signing_key.verifying_key().to_bytes();
        let mut signed = signed_certificate(PRIMARY_ID, &signing_key, NOW_SECS + 300);
        signed.signature[0] ^= 0x01;
        let domain_keys = [trusted_key(PRIMARY_ID, &verifying_key)];
        let mut input = validation_input(&signed, &domain_keys, &[]);
        input.revocation_state = RevocationState::Unavailable;

        assert_validation_error(input, SenderCertificateValidationError::SignatureFailure);
    }

    #[test]
    fn accepts_certificate_with_empty_available_revocation_set() {
        let signing_key = signing_key(0x01);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let signed = signed_certificate(PRIMARY_ID, &signing_key, NOW_SECS + 300);
        let domain_keys = [trusted_key(PRIMARY_ID, &verifying_key)];

        let mut input = validation_input(&signed, &domain_keys, &[]);
        input.revocation_state = RevocationState::Available(&[]);

        validate_sender_certificate(input).unwrap();
    }

    #[test]
    fn rejects_revoked_identity_key() {
        let signing_key = signing_key(0x01);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let signed = signed_certificate(PRIMARY_ID, &signing_key, NOW_SECS + 300);
        let domain_keys = [trusted_key(PRIMARY_ID, &verifying_key)];
        let revoked = [signed.identity_key];

        assert_validation_error(
            validation_input(&signed, &domain_keys, &revoked),
            SenderCertificateValidationError::RevokedIdentityKey,
        );
    }

    #[test]
    fn rejects_previously_valid_certificate_after_identity_key_is_revoked() {
        let signing_key = signing_key(0x01);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let signed = signed_certificate(PRIMARY_ID, &signing_key, NOW_SECS + 300);
        let domain_keys = [trusted_key(PRIMARY_ID, &verifying_key)];

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
        let verifying_key = signing_key.verifying_key().to_bytes();
        let signed = signed_certificate(PRIMARY_ID, &signing_key, NOW_SECS - GRACE_SECS - 1);
        let domain_keys = [trusted_key(PRIMARY_ID, &verifying_key)];

        assert_validation_error(
            validation_input(&signed, &domain_keys, &[]),
            SenderCertificateValidationError::ExpiredCertificate,
        );
    }

    #[test]
    fn accepts_expired_certificate_at_grace_window_boundary() {
        let signing_key = signing_key(0x01);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let signed = signed_certificate(PRIMARY_ID, &signing_key, NOW_SECS - GRACE_SECS);
        let domain_keys = [trusted_key(PRIMARY_ID, &verifying_key)];

        validate_sender_certificate(validation_input(&signed, &domain_keys, &[])).unwrap();
    }

    #[test]
    fn accepts_expired_certificate_inside_unbounded_grace_window() {
        let signing_key = signing_key(0x01);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let signed = signed_certificate(PRIMARY_ID, &signing_key, 0);
        let domain_keys = [trusted_key(PRIMARY_ID, &verifying_key)];
        let mut input = validation_input(&signed, &domain_keys, &[]);
        input.reference_time = at(u64::from(u32::MAX) * 1_000);
        input.grace_window = Duration::MAX;

        validate_sender_certificate(input).unwrap();
    }

    #[test]
    fn rejects_malformed_certificate() {
        let signing_key = signing_key(0x01);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let mut signed = signed_certificate(PRIMARY_ID, &signing_key, NOW_SECS + 300);
        signed.certificate.pop();
        let domain_keys = [trusted_key(PRIMARY_ID, &verifying_key)];

        assert_validation_error(
            validation_input(&signed, &domain_keys, &[]),
            SenderCertificateValidationError::MalformedCertificate,
        );
    }

    #[test]
    fn rejects_non_canonical_certificate_x25519_key() {
        let signing_key = signing_key(0x01);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let mut identity_key = identity_key();
        identity_key.x25519_public_key = x25519_field_modulus();
        let certificate = certificate_bytes(PRIMARY_ID, identity_key, RELAY_DOMAIN, NOW_SECS + 300);
        let signed = SignedCertificate {
            signature: signing_key.sign(&certificate).to_bytes().to_vec(),
            certificate,
            identity_key,
            expires_at_secs: NOW_SECS + 300,
        };
        let domain_keys = [trusted_key(PRIMARY_ID, &verifying_key)];

        assert_validation_error(
            validation_input(&signed, &domain_keys, &[]),
            SenderCertificateValidationError::InvalidKeyEncoding,
        );
    }

    #[test]
    fn rejects_low_order_certificate_x25519_key() {
        let signing_key = signing_key(0x01);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let mut identity_key = identity_key();
        identity_key.x25519_public_key = [0; PUBLIC_KEY_LEN];
        let certificate = certificate_bytes(PRIMARY_ID, identity_key, RELAY_DOMAIN, NOW_SECS + 300);
        let signed = SignedCertificate {
            signature: signing_key.sign(&certificate).to_bytes().to_vec(),
            certificate,
            identity_key,
            expires_at_secs: NOW_SECS + 300,
        };
        let domain_keys = [trusted_key(PRIMARY_ID, &verifying_key)];

        assert_validation_error(
            validation_input(&signed, &domain_keys, &[]),
            SenderCertificateValidationError::InvalidKeyEncoding,
        );
    }

    #[test]
    fn rejects_twist_low_order_certificate_x25519_key() {
        let signing_key = signing_key(0x01);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let mut identity_key = identity_key();
        identity_key.x25519_public_key = x25519_field_modulus();
        identity_key.x25519_public_key[0] -= 1;
        let certificate = certificate_bytes(PRIMARY_ID, identity_key, RELAY_DOMAIN, NOW_SECS + 300);
        let signed = SignedCertificate {
            signature: signing_key.sign(&certificate).to_bytes().to_vec(),
            certificate,
            identity_key,
            expires_at_secs: NOW_SECS + 300,
        };
        let domain_keys = [trusted_key(PRIMARY_ID, &verifying_key)];

        assert_validation_error(
            validation_input(&signed, &domain_keys, &[]),
            SenderCertificateValidationError::InvalidKeyEncoding,
        );
    }

    #[test]
    fn rejects_weak_certificate_ed25519_key() {
        let signing_key = signing_key(0x01);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let mut identity_key = identity_key();
        identity_key.ed25519_verifying_key = [0; PUBLIC_KEY_LEN];
        identity_key.ed25519_verifying_key[0] = 1;
        let certificate = certificate_bytes(PRIMARY_ID, identity_key, RELAY_DOMAIN, NOW_SECS + 300);
        let signed = SignedCertificate {
            signature: signing_key.sign(&certificate).to_bytes().to_vec(),
            certificate,
            identity_key,
            expires_at_secs: NOW_SECS + 300,
        };
        let domain_keys = [trusted_key(PRIMARY_ID, &verifying_key)];

        assert_validation_error(
            validation_input(&signed, &domain_keys, &[]),
            SenderCertificateValidationError::InvalidKeyEncoding,
        );
    }

    #[test]
    fn rejects_non_canonical_domain_signing_key() {
        let signing_key = signing_key(0x01);
        let signed = signed_certificate(PRIMARY_ID, &signing_key, NOW_SECS + 300);
        let non_canonical = [0xff; PUBLIC_KEY_LEN];
        let domain_keys = [trusted_key(PRIMARY_ID, &non_canonical)];

        assert_validation_error(
            validation_input(&signed, &domain_keys, &[]),
            SenderCertificateValidationError::InvalidKeyEncoding,
        );
    }

    #[test]
    fn ignores_unrelated_non_canonical_domain_signing_key() {
        let signing_key = signing_key(0x01);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let signed = signed_certificate(PRIMARY_ID, &signing_key, NOW_SECS + 300);
        let non_canonical = [0xff; PUBLIC_KEY_LEN];
        let domain_keys = [
            trusted_key(PRIMARY_ID, &verifying_key),
            trusted_key(b"other", &non_canonical),
        ];

        validate_sender_certificate(validation_input(&signed, &domain_keys, &[])).unwrap();
    }
}
