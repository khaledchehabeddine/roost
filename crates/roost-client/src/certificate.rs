use crate::IdentityContext;
use crate::encoding::fixed_32;
use crate::error::RoostError;
use crate::identity::IdentityKey;
use crate::message_operation::SignedSenderCertificate;
use crate::time::{millis_from_secs, time_from_millis};
use roost_core::Signature;
use std::time::Duration;

/// A domain signing key the app trusts.
#[derive(uniffi::Record)]
pub struct DomainSigningKey {
    /// Identifier that certificates signed by this key carry.
    ///
    /// It must not be empty. No other trusted key may have the same identifier.
    pub id: Vec<u8>,
    /// Ed25519 verifying key bytes. Always 32 bytes.
    pub verifying_key: Vec<u8>,
}

/// The app's list of revoked identity keys, if the list loaded.
#[derive(uniffi::Record)]
pub struct RevocationState {
    /// True when the list loaded.
    pub available: bool,
    /// Revoked identity keys. Ignored when `available` is false.
    pub revoked_identity_keys: Vec<IdentityKey>,
}

/// The trust, revocation, and time inputs for validating a sender certificate.
///
/// The grace for expired certificates comes with each receive, in
/// [`ReceiveSettings`](crate::ReceiveSettings).
#[derive(uniffi::Record)]
pub struct SenderCertificateValidation {
    /// Domain signing keys the app trusts.
    pub domain_signing_keys: Vec<DomainSigningKey>,
    /// Relay domain incoming certificates must name.
    ///
    /// It must not be empty.
    pub expected_relay_domain: Vec<u8>,
    /// The app's list of revoked identity keys, if the list loaded.
    pub revocation_state: RevocationState,
    /// The time to validate the certificate at, in Unix milliseconds.
    pub reference_time_millis: u64,
}

/// Validated sender certificate contents.
#[derive(uniffi::Record)]
pub struct ValidatedSenderCertificate {
    /// Signing-key identifier read from the certificate.
    pub signing_key_id: Vec<u8>,
    /// Sender identity key bound by the certificate.
    pub identity_key: IdentityKey,
    /// Certificate expiry Unix timestamp in milliseconds, always a whole number of seconds.
    pub expires_at_millis: u64,
}

#[uniffi::export]
impl IdentityContext {
    /// Validates a sender certificate against the app's trust, revocation, and time inputs.
    ///
    /// An expired certificate still validates for `certificate_grace_millis` after it expires, at
    /// most 300,000.
    ///
    /// # Errors
    /// - [`RoostError::CertificateRejected`] if the certificate fails validation, such as when it's
    ///   malformed, expired, revoked, or signed by a key the app doesn't trust.
    /// - [`RoostError::UnsupportedVersion`] if the certificate has a version Roost doesn't read.
    /// - [`RoostError::InvalidData`] if a key, the signature, the reference time, or the grace is
    ///   malformed or too large, if a key identifier or the relay domain is empty, or if two
    ///   trusted keys share an identifier.
    pub fn validate_sender_certificate(
        &self,
        certificate: SignedSenderCertificate,
        validation: SenderCertificateValidation,
        certificate_grace_millis: u64,
    ) -> Result<ValidatedSenderCertificate, RoostError> {
        let certificate = certificate.into_core()?;
        let validated = validation.to_core()?.validate(
            &certificate.certificate,
            &Signature::from_bytes(&certificate.signature),
            Duration::from_millis(certificate_grace_millis),
        )?;
        Ok(ValidatedSenderCertificate {
            signing_key_id: validated.signing_key_id,
            identity_key: IdentityKey::from_core(validated.identity_key),
            expires_at_millis: millis_from_secs(validated.expires_at_secs, "certificate expiry")?,
        })
    }
}

impl SenderCertificateValidation {
    pub(crate) fn to_core(&self) -> Result<roost_core::SenderCertificateValidation, RoostError> {
        let domain_signing_keys = self
            .domain_signing_keys
            .iter()
            .map(DomainSigningKey::to_core)
            .collect::<Result<_, _>>()?;
        Ok(roost_core::SenderCertificateValidation::new(
            domain_signing_keys,
            self.expected_relay_domain.clone(),
            self.revocation_state.to_core()?,
            time_from_millis(self.reference_time_millis, "reference_time_millis")?,
        )?)
    }
}

impl DomainSigningKey {
    fn to_core(&self) -> Result<roost_core::DomainSigningKey, RoostError> {
        Ok(roost_core::DomainSigningKey {
            id: self.id.clone(),
            verifying_key: fixed_32(&self.verifying_key, "domain signing verifying key")?,
        })
    }
}

impl RevocationState {
    fn to_core(&self) -> Result<roost_core::RevocationState, RoostError> {
        if !self.available {
            return Ok(roost_core::RevocationState::Unavailable);
        }
        self.revoked_identity_keys
            .iter()
            .map(IdentityKey::to_core)
            .collect::<Result<_, _>>()
            .map(roost_core::RevocationState::Available)
    }
}
