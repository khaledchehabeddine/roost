use crate::key_encoding::{
    IDENTITY_KEY_ENCODING_LEN, PUBLIC_KEY_LEN, identity_key_encoding, is_valid_x25519_public_key,
    parse_ed25519_verifying_key_bytes,
};
use crate::unix_time::from_unix_secs;
use ed25519_dalek::Signature;
use std::time::{Duration, SystemTime};
use subtle::{Choice, ConstantTimeEq};

const CERTIFICATE_DOMAIN_TAG: &[u8] = b"RoostSenderCertificate-v2:";
const CERTIFICATE_VERSION: u8 = 2;
// A relay domain is a DNS name; 255 is the widest a single length byte can express.
const MAX_RELAY_DOMAIN_LEN: usize = 255;
const SIGNATURE_LEN: usize = 64;
const MAX_SIGNING_KEY_ID_LEN: usize = 64;

/// Largest grace window a caller may allow for an expired sender certificate.
pub const MAX_CERTIFICATE_GRACE_WINDOW: Duration = Duration::from_secs(300);

/// Inputs for one sender certificate validation verdict.
pub struct SenderCertificateValidationInput<'a> {
    /// Sender certificate bytes, exactly as the domain authority signed them.
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
    /// Caller-supplied grace window, at most [`MAX_CERTIFICATE_GRACE_WINDOW`].
    ///
    /// Larger values tolerate more sender/receiver clock skew and delivery delay but keep expired
    /// certificates acceptable for longer.
    pub grace_window: Duration,
}

/// A domain-signing key known to the validator.
#[derive(Clone, Copy, Debug)]
pub struct DomainSigningKey<'a> {
    /// Identifier matched exactly against the certificate signing-key identifier.
    pub id: &'a [u8],
    /// Canonical Ed25519 verifying-key bytes for this domain-signing key.
    pub verifying_key: &'a [u8; PUBLIC_KEY_LEN],
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
    fn canonical_encoding(&self) -> [u8; IDENTITY_KEY_ENCODING_LEN] {
        identity_key_encoding(&self.x25519_public_key, &self.ed25519_verifying_key)
    }

    fn validate(&self) -> Result<(), SenderCertificateValidationError> {
        if is_valid_x25519_public_key(&self.x25519_public_key)
            && parse_ed25519_verifying_key_bytes(&self.ed25519_verifying_key).is_some()
        {
            Ok(())
        } else {
            Err(SenderCertificateValidationError::InvalidKeyEncoding)
        }
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
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum SenderCertificateValidationError {
    /// Certificate bytes are malformed.
    #[error("sender certificate is malformed")]
    MalformedCertificate,
    /// The certificate names a different relay domain than the recipient expects.
    #[error("sender certificate names an unexpected relay domain")]
    RelayDomainMismatch,
    /// A public-key byte field is not canonically encoded.
    #[error("sender certificate key encoding is invalid")]
    InvalidKeyEncoding,
    /// The certificate names no known signing-key identifier.
    #[error("sender certificate signing-key identifier is unknown")]
    UnknownSigningKeyId,
    /// The certificate names a known but currently untrusted signing-key identifier.
    #[error("sender certificate signing-key identifier is untrusted")]
    UntrustedSigningKeyId,
    /// The trusted-key set contains the same signing-key identifier more than once.
    #[error("sender certificate signing-key identifier is duplicated")]
    DuplicateSigningKeyId,
    /// The certificate signature does not verify under the matching trusted signing key.
    #[error("sender certificate signature failed")]
    SignatureFailure,
    /// The revocation source is unavailable, so no revocation verdict is possible.
    #[error("sender certificate revocation state is unavailable")]
    RevocationStateUnavailable,
    /// The certificate Identity Key is currently revoked.
    #[error("sender certificate identity key is revoked")]
    RevokedIdentityKey,
    /// The certificate is expired outside the supplied grace window.
    #[error("sender certificate is expired")]
    ExpiredCertificate,
    /// The supplied grace window exceeds [`MAX_CERTIFICATE_GRACE_WINDOW`].
    #[error("sender certificate grace window {grace_window:?} exceeds {max:?}")]
    GraceWindowTooLarge {
        /// Grace window the caller supplied.
        grace_window: Duration,
        /// Largest grace window allowed.
        max: Duration,
    },
}

struct ParsedSenderCertificate<'a> {
    signing_key_id: &'a [u8],
    relay_domain: &'a [u8],
    identity_key: SenderCertificateIdentityKey,
    expires_at_secs: u64,
}

/// Validates a sender certificate against caller-supplied trust, revocation, and time inputs.
///
/// Verifies the signature only under the domain-signing key whose identifier matches the one in
/// the certificate, and checks revocation and expiry only after the signature verifies. It never
/// reads the device clock or caches a verdict, so a newly revoked Identity Key fails on the next
/// call.
pub fn validate_sender_certificate(
    input: SenderCertificateValidationInput<'_>,
) -> Result<ValidatedSenderCertificate, SenderCertificateValidationError> {
    if input.grace_window > MAX_CERTIFICATE_GRACE_WINDOW {
        return Err(SenderCertificateValidationError::GraceWindowTooLarge {
            grace_window: input.grace_window,
            max: MAX_CERTIFICATE_GRACE_WINDOW,
        });
    }
    let certificate = parse_certificate(input.certificate)?;
    certificate.identity_key.validate()?;
    if certificate.relay_domain != input.expected_relay_domain {
        return Err(SenderCertificateValidationError::RelayDomainMismatch);
    }

    let domain_signing_key =
        matching_domain_signing_key(certificate.signing_key_id, input.domain_signing_keys)?;
    if domain_signing_key.status == DomainSigningKeyStatus::Untrusted {
        return Err(SenderCertificateValidationError::UntrustedSigningKeyId);
    }
    let verifying_key = parse_ed25519_verifying_key_bytes(domain_signing_key.verifying_key)
        .ok_or(SenderCertificateValidationError::InvalidKeyEncoding)?;
    let signature = parse_signature(input.signature)?;
    verifying_key
        .verify_strict(input.certificate, &signature)
        .map_err(|_| SenderCertificateValidationError::SignatureFailure)?;
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
    let mut rest = bytes;
    if take(&mut rest, CERTIFICATE_DOMAIN_TAG.len())? != CERTIFICATE_DOMAIN_TAG {
        return Err(SenderCertificateValidationError::MalformedCertificate);
    }
    if take_array(&mut rest)? != [CERTIFICATE_VERSION] {
        return Err(SenderCertificateValidationError::MalformedCertificate);
    }
    let signing_key_id = take_field(&mut rest, MAX_SIGNING_KEY_ID_LEN)?;
    let relay_domain = take_field(&mut rest, MAX_RELAY_DOMAIN_LEN)?;
    let identity_key = SenderCertificateIdentityKey {
        x25519_public_key: take_array(&mut rest)?,
        ed25519_verifying_key: take_array(&mut rest)?,
    };
    let expires_at_secs = u64::from_be_bytes(take_array(&mut rest)?);
    if !rest.is_empty() {
        return Err(SenderCertificateValidationError::MalformedCertificate);
    }

    Ok(ParsedSenderCertificate {
        signing_key_id,
        relay_domain,
        identity_key,
        expires_at_secs,
    })
}

// Splits the next `len` bytes off `bytes`.
fn take<'a>(
    bytes: &mut &'a [u8],
    len: usize,
) -> Result<&'a [u8], SenderCertificateValidationError> {
    let (value, rest) = bytes
        .split_at_checked(len)
        .ok_or(SenderCertificateValidationError::MalformedCertificate)?;
    *bytes = rest;
    Ok(value)
}

fn take_array<const N: usize>(
    bytes: &mut &[u8],
) -> Result<[u8; N], SenderCertificateValidationError> {
    let (value, rest) = bytes
        .split_first_chunk::<N>()
        .ok_or(SenderCertificateValidationError::MalformedCertificate)?;
    *bytes = rest;
    Ok(*value)
}

// Splits off a field that follows its one-byte length, which must be from 1 to `max_len`.
fn take_field<'a>(
    bytes: &mut &'a [u8],
    max_len: usize,
) -> Result<&'a [u8], SenderCertificateValidationError> {
    let [len] = take_array(bytes)?;
    let len = usize::from(len);
    if len == 0 || len > max_len {
        return Err(SenderCertificateValidationError::MalformedCertificate);
    }
    take(bytes, len)
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
        revoked_identity_key.validate()?;
        revoked |= encoding.ct_eq(&revoked_identity_key.canonical_encoding());
    }
    Ok(revoked.into())
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

    fn trusted_key<'a>(
        id: &'a [u8],
        verifying_key: &'a [u8; PUBLIC_KEY_LEN],
    ) -> DomainSigningKey<'a> {
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
    fn accepts_expired_certificate_inside_the_largest_grace_window() {
        let signing_key = signing_key(0x01);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let max_secs = MAX_CERTIFICATE_GRACE_WINDOW.as_secs();
        let signed = signed_certificate(PRIMARY_ID, &signing_key, NOW_SECS - max_secs);
        let domain_keys = [trusted_key(PRIMARY_ID, &verifying_key)];
        let mut input = validation_input(&signed, &domain_keys, &[]);
        input.grace_window = MAX_CERTIFICATE_GRACE_WINDOW;

        validate_sender_certificate(input).unwrap();
    }

    #[test]
    fn rejects_grace_window_above_the_maximum() {
        let signing_key = signing_key(0x01);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let signed = signed_certificate(PRIMARY_ID, &signing_key, NOW_SECS + 300);
        let domain_keys = [trusted_key(PRIMARY_ID, &verifying_key)];
        let mut input = validation_input(&signed, &domain_keys, &[]);
        let grace_window = MAX_CERTIFICATE_GRACE_WINDOW + Duration::from_secs(1);
        input.grace_window = grace_window;

        assert_validation_error(
            input,
            SenderCertificateValidationError::GraceWindowTooLarge {
                grace_window,
                max: MAX_CERTIFICATE_GRACE_WINDOW,
            },
        );
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
