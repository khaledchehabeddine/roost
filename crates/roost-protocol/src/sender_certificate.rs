use crate::identity_key::IdentityKey;
use crate::key_encoding::{PUBLIC_KEY_LEN, parse_ed25519_verifying_key_bytes};
use crate::unix_time::from_unix_secs;
use ed25519_dalek::{Signature, VerifyingKey};
use std::time::{Duration, SystemTime};
use subtle::{Choice, ConstantTimeEq};

const SENDER_CERTIFICATE_LABEL: &[u8] = b"RoostSenderCertificate-v1:";
// A new layout bumps this version and keeps the label.
const SENDER_CERTIFICATE_VERSION: u8 = 1;

/// Longest sender certificate a message may carry.
pub const MAX_SENDER_CERTIFICATE_LEN: usize = 16 * 1024;

/// Largest grace window an app may allow for an expired sender certificate.
pub const MAX_CERTIFICATE_GRACE_WINDOW: Duration = Duration::from_secs(300);

/// The trust, revocation, and time inputs for validating sender certificates.
pub struct SenderCertificateValidation {
    domain_signing_keys: Vec<ParsedDomainSigningKey>,
    expected_relay_domain: Vec<u8>,
    revocation_state: RevocationState,
    reference_time: SystemTime,
}

struct ParsedDomainSigningKey {
    id: Vec<u8>,
    verifying_key: VerifyingKey,
}

/// A domain signing key the app trusts.
pub struct DomainSigningKey {
    /// Identifier that certificates signed by this key carry.
    pub id: Vec<u8>,
    /// Canonical Ed25519 verifying-key bytes.
    pub verifying_key: [u8; PUBLIC_KEY_LEN],
}

/// The app's list of revoked identity keys, if the list loaded.
pub enum RevocationState {
    /// The list loaded. An empty list revokes no key.
    Available(Vec<IdentityKey>),
    /// The list failed to load, so every certificate fails.
    Unavailable,
}

/// The contents of a sender certificate that passed validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedSenderCertificate {
    /// Identifier of the domain signing key that signed the certificate.
    pub signing_key_id: Vec<u8>,
    /// Sender's identity key the certificate binds.
    pub identity_key: IdentityKey,
    /// When the certificate expires, in Unix seconds.
    pub expires_at_secs: u64,
}

/// An error returned while building a [`SenderCertificateValidation`] or validating a sender
/// certificate.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum SenderCertificateValidationError {
    /// The certificate bytes are malformed.
    #[error("sender certificate is malformed")]
    MalformedCertificate,
    /// The certificate is longer than [`MAX_SENDER_CERTIFICATE_LEN`].
    #[error("sender certificate is {len} bytes, more than {max}")]
    CertificateTooLong {
        /// Length of the certificate.
        len: usize,
        /// Longest certificate allowed.
        max: usize,
    },
    /// The certificate has a version Roost doesn't read.
    #[error("sender certificate version {version} is unsupported")]
    UnsupportedVersion {
        /// Version the certificate names.
        version: u8,
    },
    /// The certificate names a different relay domain than the app expects.
    #[error("sender certificate names an unexpected relay domain")]
    RelayDomainMismatch,
    /// The certificate's identity key isn't canonically encoded, or is low order or weak.
    #[error("sender certificate key encoding is invalid")]
    InvalidKeyEncoding,
    /// No trusted domain signing key has the identifier the certificate names.
    #[error("sender certificate signing-key identifier is unknown")]
    UnknownSigningKeyId,
    /// A trusted domain signing key has an empty identifier.
    #[error("trusted domain signing key {index} has an empty identifier")]
    EmptySigningKeyId {
        /// Position of the key in the app's list.
        index: usize,
    },
    /// More than one trusted domain signing key has the same identifier.
    #[error("trusted domain signing key {index} repeats an earlier key's identifier")]
    DuplicateSigningKeyId {
        /// Position of the later key in the app's list.
        index: usize,
    },
    /// A trusted domain signing key isn't canonically encoded, or is weak.
    #[error("trusted domain signing key {index} is invalid")]
    InvalidDomainSigningKey {
        /// Position of the key in the app's list.
        index: usize,
    },
    /// The relay domain the app expects is empty.
    #[error("expected relay domain is empty")]
    EmptyRelayDomain,
    /// A revoked identity key isn't canonically encoded, or is low order or weak.
    #[error("revoked identity key {index} is invalid")]
    InvalidRevokedIdentityKey {
        /// Position of the key in the app's list.
        index: usize,
    },
    /// The signature doesn't verify under the domain signing key the certificate names.
    #[error("sender certificate signature failed")]
    SignatureFailure,
    /// The app's list of revoked identity keys failed to load.
    #[error("sender certificate revocation state is unavailable")]
    RevocationStateUnavailable,
    /// The app revoked the certificate's identity key.
    #[error("sender certificate identity key is revoked")]
    RevokedIdentityKey,
    /// The certificate expired longer ago than the grace window.
    #[error("sender certificate is expired")]
    ExpiredCertificate,
    /// The grace window exceeds [`MAX_CERTIFICATE_GRACE_WINDOW`].
    #[error("sender certificate grace window {grace_window:?} exceeds {max:?}")]
    GraceWindowTooLarge {
        /// Grace window the app passed.
        grace_window: Duration,
        /// Largest grace window allowed.
        max: Duration,
    },
}

impl SenderCertificateValidation {
    /// Returns validation inputs after checking each trusted key, identifier, and revoked key.
    ///
    /// [`validate`](Self::validate) checks expiry at `reference_time`.
    pub fn new(
        domain_signing_keys: Vec<DomainSigningKey>,
        expected_relay_domain: Vec<u8>,
        revocation_state: RevocationState,
        reference_time: SystemTime,
    ) -> Result<Self, SenderCertificateValidationError> {
        let domain_signing_keys = parse_domain_signing_keys(domain_signing_keys)?;
        if expected_relay_domain.is_empty() {
            return Err(SenderCertificateValidationError::EmptyRelayDomain);
        }
        if let RevocationState::Available(revoked_identity_keys) = &revocation_state
            && let Some(index) = revoked_identity_keys.iter().position(|key| !key.is_valid())
        {
            return Err(SenderCertificateValidationError::InvalidRevokedIdentityKey { index });
        }

        Ok(Self {
            domain_signing_keys,
            expected_relay_domain,
            revocation_state,
            reference_time,
        })
    }

    /// Validates a sender certificate, accepting one that expired at most `grace_window` ago.
    ///
    /// Verifies the signature only under the domain signing key the certificate names, and checks
    /// revocation and expiry only after the signature verifies. It never reads the device clock or
    /// caches a result, so a newly revoked identity key fails on the next call.
    pub fn validate(
        &self,
        certificate: &[u8],
        signature: &Signature,
        grace_window: Duration,
    ) -> Result<ValidatedSenderCertificate, SenderCertificateValidationError> {
        if grace_window > MAX_CERTIFICATE_GRACE_WINDOW {
            return Err(SenderCertificateValidationError::GraceWindowTooLarge {
                grace_window,
                max: MAX_CERTIFICATE_GRACE_WINDOW,
            });
        }
        if certificate.len() > MAX_SENDER_CERTIFICATE_LEN {
            return Err(SenderCertificateValidationError::CertificateTooLong {
                len: certificate.len(),
                max: MAX_SENDER_CERTIFICATE_LEN,
            });
        }

        let (relay_domain, parsed) = parse_certificate(certificate)?;
        if !parsed.identity_key.is_valid() {
            return Err(SenderCertificateValidationError::InvalidKeyEncoding);
        }
        if relay_domain != self.expected_relay_domain.as_slice() {
            return Err(SenderCertificateValidationError::RelayDomainMismatch);
        }

        let domain_signing_key = self
            .domain_signing_keys
            .iter()
            .find(|key| key.id == parsed.signing_key_id)
            .ok_or(SenderCertificateValidationError::UnknownSigningKeyId)?;
        domain_signing_key
            .verifying_key
            .verify_strict(certificate, signature)
            .map_err(|_| SenderCertificateValidationError::SignatureFailure)?;

        let RevocationState::Available(revoked_identity_keys) = &self.revocation_state else {
            return Err(SenderCertificateValidationError::RevocationStateUnavailable);
        };
        if identity_key_is_revoked(&parsed.identity_key, revoked_identity_keys) {
            return Err(SenderCertificateValidationError::RevokedIdentityKey);
        }
        if certificate_is_expired(parsed.expires_at_secs, self.reference_time, grace_window) {
            return Err(SenderCertificateValidationError::ExpiredCertificate);
        }

        Ok(parsed)
    }
}

// Returns the certificate's relay domain and the fields validation returns.
fn parse_certificate(
    bytes: &[u8],
) -> Result<(&[u8], ValidatedSenderCertificate), SenderCertificateValidationError> {
    let mut rest = bytes;
    if take(&mut rest, SENDER_CERTIFICATE_LABEL.len())? != SENDER_CERTIFICATE_LABEL {
        return Err(SenderCertificateValidationError::MalformedCertificate);
    }
    let [version] = take_array(&mut rest)?;
    if version != SENDER_CERTIFICATE_VERSION {
        return Err(SenderCertificateValidationError::UnsupportedVersion { version });
    }

    let signing_key_id = take_field(&mut rest)?;
    let relay_domain = take_field(&mut rest)?;
    let identity_key = IdentityKey {
        x25519_public_key: take_array(&mut rest)?,
        ed25519_verifying_key: take_array(&mut rest)?,
    };
    let expires_at_secs = u64::from_be_bytes(take_array(&mut rest)?);
    if !rest.is_empty() {
        return Err(SenderCertificateValidationError::MalformedCertificate);
    }

    Ok((
        relay_domain,
        ValidatedSenderCertificate {
            signing_key_id: signing_key_id.to_vec(),
            identity_key,
            expires_at_secs,
        },
    ))
}

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

// Splits off a field that follows its big-endian `u32` length.
fn take_field<'a>(bytes: &mut &'a [u8]) -> Result<&'a [u8], SenderCertificateValidationError> {
    let len = u32::from_be_bytes(take_array(bytes)?);
    let len =
        usize::try_from(len).map_err(|_| SenderCertificateValidationError::MalformedCertificate)?;
    take(bytes, len)
}

fn parse_domain_signing_keys(
    domain_signing_keys: Vec<DomainSigningKey>,
) -> Result<Vec<ParsedDomainSigningKey>, SenderCertificateValidationError> {
    let mut parsed: Vec<ParsedDomainSigningKey> = Vec::new();
    for (index, key) in domain_signing_keys.into_iter().enumerate() {
        if key.id.is_empty() {
            return Err(SenderCertificateValidationError::EmptySigningKeyId { index });
        }
        if parsed.iter().any(|earlier| earlier.id == key.id) {
            return Err(SenderCertificateValidationError::DuplicateSigningKeyId { index });
        }
        let verifying_key = parse_ed25519_verifying_key_bytes(&key.verifying_key)
            .ok_or(SenderCertificateValidationError::InvalidDomainSigningKey { index })?;
        parsed.push(ParsedDomainSigningKey {
            id: key.id,
            verifying_key,
        });
    }
    Ok(parsed)
}

fn identity_key_is_revoked(
    identity_key: &IdentityKey,
    revoked_identity_keys: &[IdentityKey],
) -> bool {
    let mut revoked = Choice::from(0);
    for revoked_identity_key in revoked_identity_keys {
        revoked |= identity_key.ct_eq(revoked_identity_key);
    }
    revoked.into()
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

    const NOW_SECS: u64 = 1_700_000_000;
    const GRACE_WINDOW: Duration = Duration::from_secs(30);
    const PRIMARY_ID: &[u8] = b"primary";
    const SECONDARY_ID: &[u8] = b"secondary";
    const RELAY_DOMAIN: &[u8] = b"relay.example";
    const OTHER_RELAY_DOMAIN: &[u8] = b"other.example";

    struct SignedCertificate {
        certificate: Vec<u8>,
        signature: Signature,
    }

    impl SignedCertificate {
        fn validate(
            &self,
            validation: &SenderCertificateValidation,
        ) -> Result<ValidatedSenderCertificate, SenderCertificateValidationError> {
            validation.validate(&self.certificate, &self.signature, GRACE_WINDOW)
        }
    }

    fn at(secs: u64) -> SystemTime {
        from_unix_secs(secs).unwrap()
    }

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn identity_key() -> IdentityKey {
        IdentityKey {
            x25519_public_key: [0x11; PUBLIC_KEY_LEN],
            ed25519_verifying_key: signing_key(0x21).verifying_key().to_bytes(),
        }
    }

    fn certificate_bytes(
        id: &[u8],
        identity_key: IdentityKey,
        relay_domain: &[u8],
        expires_at_secs: u64,
    ) -> Vec<u8> {
        let mut bytes = SENDER_CERTIFICATE_LABEL.to_vec();
        bytes.push(SENDER_CERTIFICATE_VERSION);
        for field in [id, relay_domain] {
            bytes.extend_from_slice(&u32::try_from(field.len()).unwrap().to_be_bytes());
            bytes.extend_from_slice(field);
        }
        bytes.extend_from_slice(&identity_key.x25519_public_key);
        bytes.extend_from_slice(&identity_key.ed25519_verifying_key);
        bytes.extend_from_slice(&expires_at_secs.to_be_bytes());
        bytes
    }

    fn signed(domain_key: &SigningKey, certificate: Vec<u8>) -> SignedCertificate {
        SignedCertificate {
            signature: domain_key.sign(&certificate),
            certificate,
        }
    }

    fn signed_certificate(
        id: &[u8],
        domain_key: &SigningKey,
        expires_at_secs: u64,
    ) -> SignedCertificate {
        let certificate = certificate_bytes(id, identity_key(), RELAY_DOMAIN, expires_at_secs);
        signed(domain_key, certificate)
    }

    fn trusted_key(id: &[u8], domain_key: &SigningKey) -> DomainSigningKey {
        DomainSigningKey {
            id: id.to_vec(),
            verifying_key: domain_key.verifying_key().to_bytes(),
        }
    }

    fn validation(
        domain_signing_keys: Vec<DomainSigningKey>,
        revoked_identity_keys: Vec<IdentityKey>,
    ) -> SenderCertificateValidation {
        SenderCertificateValidation::new(
            domain_signing_keys,
            RELAY_DOMAIN.to_vec(),
            RevocationState::Available(revoked_identity_keys),
            at(NOW_SECS),
        )
        .unwrap()
    }

    #[test]
    fn certificate_for_another_relay_is_rejected() {
        let domain_key = signing_key(0x01);
        let certificate = certificate_bytes(
            PRIMARY_ID,
            identity_key(),
            OTHER_RELAY_DOMAIN,
            NOW_SECS + 300,
        );
        let signed = signed(&domain_key, certificate);
        let validation = validation(vec![trusted_key(PRIMARY_ID, &domain_key)], vec![]);

        assert_eq!(
            signed.validate(&validation),
            Err(SenderCertificateValidationError::RelayDomainMismatch)
        );
    }

    #[test]
    fn validates_certificates_for_two_concurrently_trusted_signing_keys() {
        let primary_key = signing_key(0x01);
        let secondary_key = signing_key(0x02);
        let validation = validation(
            vec![
                trusted_key(PRIMARY_ID, &primary_key),
                trusted_key(SECONDARY_ID, &secondary_key),
            ],
            vec![],
        );

        for (id, domain_key) in [(PRIMARY_ID, &primary_key), (SECONDARY_ID, &secondary_key)] {
            let signed = signed_certificate(id, domain_key, NOW_SECS + 300);

            assert_eq!(
                signed.validate(&validation),
                Ok(ValidatedSenderCertificate {
                    signing_key_id: id.to_vec(),
                    identity_key: identity_key(),
                    expires_at_secs: NOW_SECS + 300,
                })
            );
        }
    }

    #[test]
    fn rejects_unknown_signing_key_id() {
        let domain_key = signing_key(0x01);
        let signed = signed_certificate(PRIMARY_ID, &domain_key, NOW_SECS + 300);
        let validation = validation(vec![trusted_key(b"other", &domain_key)], vec![]);
        assert_eq!(
            signed.validate(&validation),
            Err(SenderCertificateValidationError::UnknownSigningKeyId)
        );
    }

    #[test]
    fn rejects_unsupported_version() {
        let domain_key = signing_key(0x01);
        let mut certificate =
            certificate_bytes(PRIMARY_ID, identity_key(), RELAY_DOMAIN, NOW_SECS + 300);
        certificate[SENDER_CERTIFICATE_LABEL.len()] = 2;
        let signed = signed(&domain_key, certificate);
        let validation = validation(vec![trusted_key(PRIMARY_ID, &domain_key)], vec![]);
        assert_eq!(
            signed.validate(&validation),
            Err(SenderCertificateValidationError::UnsupportedVersion { version: 2 })
        );
    }

    #[test]
    fn rejects_invalid_signature() {
        let domain_key = signing_key(0x01);
        let signed = signed_certificate(PRIMARY_ID, &domain_key, NOW_SECS + 300);
        let other_signed = signed_certificate(SECONDARY_ID, &domain_key, NOW_SECS + 300);
        let validation = validation(vec![trusted_key(PRIMARY_ID, &domain_key)], vec![]);
        assert_eq!(
            validation.validate(&signed.certificate, &other_signed.signature, GRACE_WINDOW),
            Err(SenderCertificateValidationError::SignatureFailure)
        );
    }

    #[test]
    fn rejects_invalid_signature_before_revocation() {
        let domain_key = signing_key(0x01);
        let signed = signed_certificate(PRIMARY_ID, &domain_key, NOW_SECS + 300);
        let other_signed = signed_certificate(SECONDARY_ID, &domain_key, NOW_SECS + 300);
        let validation = validation(
            vec![trusted_key(PRIMARY_ID, &domain_key)],
            vec![identity_key()],
        );

        assert_eq!(
            validation.validate(&signed.certificate, &other_signed.signature, GRACE_WINDOW),
            Err(SenderCertificateValidationError::SignatureFailure)
        );
    }

    #[test]
    fn rejects_validation_when_revocation_state_unavailable() {
        let domain_key = signing_key(0x01);
        let signed = signed_certificate(PRIMARY_ID, &domain_key, NOW_SECS + 300);
        let mut validation = validation(vec![trusted_key(PRIMARY_ID, &domain_key)], vec![]);
        validation.revocation_state = RevocationState::Unavailable;
        assert_eq!(
            signed.validate(&validation),
            Err(SenderCertificateValidationError::RevocationStateUnavailable)
        );
    }

    #[test]
    fn rejects_invalid_signature_before_unavailable_revocation_state() {
        let domain_key = signing_key(0x01);
        let signed = signed_certificate(PRIMARY_ID, &domain_key, NOW_SECS + 300);
        let other_signed = signed_certificate(SECONDARY_ID, &domain_key, NOW_SECS + 300);
        let mut validation = validation(vec![trusted_key(PRIMARY_ID, &domain_key)], vec![]);
        validation.revocation_state = RevocationState::Unavailable;
        assert_eq!(
            validation.validate(&signed.certificate, &other_signed.signature, GRACE_WINDOW),
            Err(SenderCertificateValidationError::SignatureFailure)
        );
    }

    #[test]
    fn accepts_certificate_with_empty_available_revocation_set() {
        let domain_key = signing_key(0x01);
        let signed = signed_certificate(PRIMARY_ID, &domain_key, NOW_SECS + 300);
        let mut validation = validation(vec![trusted_key(PRIMARY_ID, &domain_key)], vec![]);
        validation.revocation_state = RevocationState::Available(vec![]);
        signed.validate(&validation).unwrap();
    }

    #[test]
    fn accepts_certificate_when_another_identity_key_is_revoked() {
        let domain_key = signing_key(0x01);
        let signed = signed_certificate(PRIMARY_ID, &domain_key, NOW_SECS + 300);
        let other_identity_key = IdentityKey {
            ed25519_verifying_key: signing_key(0x22).verifying_key().to_bytes(),
            ..identity_key()
        };
        let validation = validation(
            vec![trusted_key(PRIMARY_ID, &domain_key)],
            vec![other_identity_key],
        );

        signed.validate(&validation).unwrap();
    }

    #[test]
    fn rejects_revoked_identity_key() {
        let domain_key = signing_key(0x01);
        let signed = signed_certificate(PRIMARY_ID, &domain_key, NOW_SECS + 300);
        let validation = validation(
            vec![trusted_key(PRIMARY_ID, &domain_key)],
            vec![identity_key()],
        );
        assert_eq!(
            signed.validate(&validation),
            Err(SenderCertificateValidationError::RevokedIdentityKey)
        );
    }

    #[test]
    fn rejects_previously_valid_certificate_after_identity_key_is_revoked() {
        let domain_key = signing_key(0x01);
        let signed = signed_certificate(PRIMARY_ID, &domain_key, NOW_SECS + 300);
        let mut validation = validation(vec![trusted_key(PRIMARY_ID, &domain_key)], vec![]);
        signed.validate(&validation).unwrap();
        validation.revocation_state = RevocationState::Available(vec![identity_key()]);
        assert_eq!(
            signed.validate(&validation),
            Err(SenderCertificateValidationError::RevokedIdentityKey)
        );
    }

    #[test]
    fn rejects_expired_certificate_outside_grace_window() {
        let domain_key = signing_key(0x01);
        let expires_at_secs = NOW_SECS - GRACE_WINDOW.as_secs() - 1;
        let signed = signed_certificate(PRIMARY_ID, &domain_key, expires_at_secs);
        let validation = validation(vec![trusted_key(PRIMARY_ID, &domain_key)], vec![]);
        assert_eq!(
            signed.validate(&validation),
            Err(SenderCertificateValidationError::ExpiredCertificate)
        );
    }

    #[test]
    fn accepts_expired_certificate_at_grace_window_boundary() {
        let domain_key = signing_key(0x01);
        let expires_at_secs = NOW_SECS - GRACE_WINDOW.as_secs();
        let signed = signed_certificate(PRIMARY_ID, &domain_key, expires_at_secs);
        let validation = validation(vec![trusted_key(PRIMARY_ID, &domain_key)], vec![]);
        signed.validate(&validation).unwrap();
    }

    #[test]
    fn accepts_expired_certificate_inside_the_largest_grace_window() {
        let domain_key = signing_key(0x01);
        let expires_at_secs = NOW_SECS - MAX_CERTIFICATE_GRACE_WINDOW.as_secs();
        let signed = signed_certificate(PRIMARY_ID, &domain_key, expires_at_secs);
        let validation = validation(vec![trusted_key(PRIMARY_ID, &domain_key)], vec![]);

        validation
            .validate(
                &signed.certificate,
                &signed.signature,
                MAX_CERTIFICATE_GRACE_WINDOW,
            )
            .unwrap();
    }

    #[test]
    fn rejects_grace_window_above_the_maximum() {
        let domain_key = signing_key(0x01);
        let signed = signed_certificate(PRIMARY_ID, &domain_key, NOW_SECS + 300);
        let validation = validation(vec![trusted_key(PRIMARY_ID, &domain_key)], vec![]);
        let grace_window = MAX_CERTIFICATE_GRACE_WINDOW + Duration::from_secs(1);

        assert_eq!(
            validation.validate(&signed.certificate, &signed.signature, grace_window),
            Err(SenderCertificateValidationError::GraceWindowTooLarge {
                grace_window,
                max: MAX_CERTIFICATE_GRACE_WINDOW,
            })
        );
    }

    #[test]
    fn rejects_malformed_certificate() {
        let domain_key = signing_key(0x01);
        let mut certificate =
            certificate_bytes(PRIMARY_ID, identity_key(), RELAY_DOMAIN, NOW_SECS + 300);
        certificate.pop();
        let signed = signed(&domain_key, certificate);
        let validation = validation(vec![trusted_key(PRIMARY_ID, &domain_key)], vec![]);
        assert_eq!(
            signed.validate(&validation),
            Err(SenderCertificateValidationError::MalformedCertificate)
        );
    }

    #[test]
    fn rejects_certificate_longer_than_the_limit() {
        let domain_key = signing_key(0x01);
        let fixed_len = certificate_bytes(&[], identity_key(), RELAY_DOMAIN, NOW_SECS + 300).len();
        let longest_id = vec![b'k'; MAX_SENDER_CERTIFICATE_LEN - fixed_len];
        let too_long_id = vec![b'k'; MAX_SENDER_CERTIFICATE_LEN - fixed_len + 1];
        let validation = validation(
            vec![
                trusted_key(&longest_id, &domain_key),
                trusted_key(&too_long_id, &domain_key),
            ],
            vec![],
        );

        signed_certificate(&longest_id, &domain_key, NOW_SECS + 300)
            .validate(&validation)
            .unwrap();
        assert_eq!(
            signed_certificate(&too_long_id, &domain_key, NOW_SECS + 300).validate(&validation),
            Err(SenderCertificateValidationError::CertificateTooLong {
                len: MAX_SENDER_CERTIFICATE_LEN + 1,
                max: MAX_SENDER_CERTIFICATE_LEN,
            })
        );
    }

    #[test]
    fn rejects_low_order_certificate_x25519_key() {
        let domain_key = signing_key(0x01);
        let identity_key = IdentityKey {
            x25519_public_key: [0; PUBLIC_KEY_LEN],
            ..identity_key()
        };
        let certificate = certificate_bytes(PRIMARY_ID, identity_key, RELAY_DOMAIN, NOW_SECS + 300);
        let signed = signed(&domain_key, certificate);
        let validation = validation(vec![trusted_key(PRIMARY_ID, &domain_key)], vec![]);

        assert_eq!(
            signed.validate(&validation),
            Err(SenderCertificateValidationError::InvalidKeyEncoding)
        );
    }

    #[test]
    fn rejects_weak_certificate_ed25519_key() {
        let domain_key = signing_key(0x01);
        let mut weak_key = [0; PUBLIC_KEY_LEN];
        weak_key[0] = 1;
        let identity_key = IdentityKey {
            ed25519_verifying_key: weak_key,
            ..identity_key()
        };
        let certificate = certificate_bytes(PRIMARY_ID, identity_key, RELAY_DOMAIN, NOW_SECS + 300);
        let signed = signed(&domain_key, certificate);
        let validation = validation(vec![trusted_key(PRIMARY_ID, &domain_key)], vec![]);

        assert_eq!(
            signed.validate(&validation),
            Err(SenderCertificateValidationError::InvalidKeyEncoding)
        );
    }

    #[test]
    fn rejects_each_invalid_app_input() {
        let domain_key = signing_key(0x01);
        let trusted = || trusted_key(PRIMARY_ID, &domain_key);
        let non_canonical = DomainSigningKey {
            id: SECONDARY_ID.to_vec(),
            verifying_key: [0xff; PUBLIC_KEY_LEN],
        };
        let low_order = IdentityKey {
            x25519_public_key: [0; PUBLIC_KEY_LEN],
            ..identity_key()
        };
        let cases = [
            (
                vec![trusted(), trusted_key(b"", &domain_key)],
                RELAY_DOMAIN,
                vec![],
                SenderCertificateValidationError::EmptySigningKeyId { index: 1 },
            ),
            (
                vec![trusted(), trusted()],
                RELAY_DOMAIN,
                vec![],
                SenderCertificateValidationError::DuplicateSigningKeyId { index: 1 },
            ),
            (
                vec![trusted(), non_canonical],
                RELAY_DOMAIN,
                vec![],
                SenderCertificateValidationError::InvalidDomainSigningKey { index: 1 },
            ),
            (
                vec![trusted()],
                b"".as_slice(),
                vec![],
                SenderCertificateValidationError::EmptyRelayDomain,
            ),
            (
                vec![trusted()],
                RELAY_DOMAIN,
                vec![identity_key(), low_order],
                SenderCertificateValidationError::InvalidRevokedIdentityKey { index: 1 },
            ),
        ];

        for (domain_signing_keys, relay_domain, revoked_identity_keys, expected) in cases {
            let result = SenderCertificateValidation::new(
                domain_signing_keys,
                relay_domain.to_vec(),
                RevocationState::Available(revoked_identity_keys),
                at(NOW_SECS),
            );
            assert_eq!(result.err(), Some(expected));
        }
    }
}
