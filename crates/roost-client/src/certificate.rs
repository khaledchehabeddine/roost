//! Sender-certificate validation records exposed through UniFFI.

use crate::IdentityContext;
use crate::error::RoostError;
use crate::protocol::IdentityKey;
use crate::records::fixed_32;
use crate::time::{millis_from_secs, time_from_millis};
use roost_protocol::{
    DomainSigningKey as ProtocolDomainSigningKey,
    DomainSigningKeyStatus as ProtocolDomainSigningKeyStatus,
    RevocationState as ProtocolRevocationState, SenderCertificateIdentityKey,
    SenderCertificateValidationInput,
};

/// Trust status for a domain-signing key.
#[derive(Clone, Copy, uniffi::Enum)]
pub enum DomainSigningKeyStatus {
    /// Certificates signed by this key may validate.
    Trusted,
    /// Certificates naming this key fail validation.
    Untrusted,
}

/// Domain-signing key known to the validator.
#[derive(uniffi::Record)]
pub struct DomainSigningKey {
    /// Signing-key identifier bytes.
    pub id: Vec<u8>,
    /// Ed25519 verifying key bytes. Always 32 bytes.
    pub verifying_key: Vec<u8>,
    /// Trust status.
    pub status: DomainSigningKeyStatus,
}

/// Caller-supplied revocation input.
#[derive(uniffi::Record)]
pub struct RevocationState {
    /// True when the revocation source loaded successfully.
    pub available: bool,
    /// Revoked Identity Keys. Ignored when `available` is false.
    pub revoked_identity_keys: Vec<IdentityKey>,
}

/// The trust, revocation, and time inputs for validating a sender certificate.
///
/// The grace for expired certificates comes from the context's configuration.
#[derive(uniffi::Record)]
pub struct SenderCertificateValidation {
    /// Known domain-signing keys.
    pub domain_signing_keys: Vec<DomainSigningKey>,
    /// Relay domain incoming certificates must name.
    pub expected_relay_domain: Vec<u8>,
    /// Caller-supplied revocation state.
    pub revocation_state: RevocationState,
    /// Caller-supplied Unix timestamp in milliseconds.
    pub reference_time_millis: u64,
}

/// Validated sender certificate contents.
#[derive(uniffi::Record)]
pub struct ValidatedSenderCertificate {
    /// Signing-key identifier read from the certificate.
    pub signing_key_id: Vec<u8>,
    /// Sender Identity Key bound by the certificate.
    pub identity_key: IdentityKey,
    /// Relay domain bound by the certificate.
    ///
    /// A certificate is valid only at the relay it names, so this cannot be replayed at another
    /// relay that happens to trust the same signing key.
    pub relay_domain: Vec<u8>,
    /// Certificate expiry Unix timestamp in milliseconds, always a whole number of seconds.
    pub expires_at_millis: u64,
}

#[uniffi::export]
impl IdentityContext {
    /// Validates a sender certificate against the host's trust, revocation, and time inputs.
    ///
    /// An expired certificate still validates within the configured certificate grace.
    ///
    /// # Errors
    /// - [`RoostError::CertificateRejected`] if the certificate is expired, revoked, untrusted, or
    ///   signed for another relay domain.
    /// - [`RoostError::InvalidData`] if a key or the reference time is malformed.
    pub fn validate_sender_certificate(
        &self,
        certificate: Vec<u8>,
        signature: Vec<u8>,
        validation: SenderCertificateValidation,
    ) -> Result<ValidatedSenderCertificate, RoostError> {
        let domain_signing_keys = domain_signing_keys_to_protocol(&validation.domain_signing_keys)?;
        let revoked_identity_keys =
            revoked_identity_keys_to_protocol(&validation.revocation_state)?;
        let validated =
            roost_protocol::validate_sender_certificate(SenderCertificateValidationInput {
                certificate: &certificate,
                signature: &signature,
                domain_signing_keys: &domain_signing_keys,
                expected_relay_domain: &validation.expected_relay_domain,
                revocation_state: revocation_state_to_protocol(
                    &validation.revocation_state,
                    &revoked_identity_keys,
                ),
                reference_time: time_from_millis(
                    validation.reference_time_millis,
                    "reference_time_millis",
                )?,
                grace_window: self.inner.protocol_engine().certificate_grace(),
            })?;
        Ok(ValidatedSenderCertificate {
            signing_key_id: validated.signing_key_id,
            identity_key: IdentityKey {
                agreement_key: validated.identity_key.x25519_public_key.to_vec(),
                signing_key: validated.identity_key.ed25519_verifying_key.to_vec(),
            },
            relay_domain: validated.relay_domain,
            expires_at_millis: millis_from_secs(validated.expires_at_secs, "certificate expiry")?,
        })
    }
}

impl DomainSigningKey {
    pub(crate) fn to_protocol(&self) -> Result<ProtocolDomainSigningKey<'_>, RoostError> {
        fixed_32(&self.verifying_key, "domain signing verifying key")?;
        Ok(ProtocolDomainSigningKey {
            id: &self.id,
            verifying_key: &self.verifying_key,
            status: self.status.to_protocol(),
        })
    }
}

impl DomainSigningKeyStatus {
    fn to_protocol(self) -> ProtocolDomainSigningKeyStatus {
        match self {
            Self::Trusted => ProtocolDomainSigningKeyStatus::Trusted,
            Self::Untrusted => ProtocolDomainSigningKeyStatus::Untrusted,
        }
    }
}

pub(crate) fn domain_signing_keys_to_protocol(
    values: &[DomainSigningKey],
) -> Result<Vec<ProtocolDomainSigningKey<'_>>, RoostError> {
    values.iter().map(DomainSigningKey::to_protocol).collect()
}

pub(crate) fn revoked_identity_keys_to_protocol(
    state: &RevocationState,
) -> Result<Vec<SenderCertificateIdentityKey>, RoostError> {
    state
        .revoked_identity_keys
        .iter()
        .map(|identity_key| {
            let key = identity_key.to_core()?;
            Ok(SenderCertificateIdentityKey {
                x25519_public_key: key.x25519_public_key,
                ed25519_verifying_key: key.ed25519_verifying_key,
            })
        })
        .collect()
}

pub(crate) fn revocation_state_to_protocol<'a>(
    state: &RevocationState,
    revoked_identity_keys: &'a [SenderCertificateIdentityKey],
) -> ProtocolRevocationState<'a> {
    if state.available {
        ProtocolRevocationState::Available(revoked_identity_keys)
    } else {
        ProtocolRevocationState::Unavailable
    }
}
