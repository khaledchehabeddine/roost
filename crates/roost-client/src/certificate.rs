//! Sender-certificate validation records exposed through UniFFI.

use crate::IdentityContext;
use crate::error::RoostError;
use crate::message_operation::SignedSenderCertificate;
use crate::protocol::IdentityKey;
use crate::records::fixed_32;
use crate::time::{millis_from_secs, time_from_millis};
use roost_core::{InboundSenderCertificateValidation, KnownDomainSigningKey};
use roost_protocol::{
    DomainSigningKeyStatus as ProtocolDomainSigningKeyStatus, SenderCertificateIdentityKey,
};
use std::time::Duration;

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
/// The grace for expired certificates comes with each receive, in [`ReceiveSettings`](crate::ReceiveSettings).
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
    /// An expired certificate still validates for `certificate_grace_millis` after it expires, at
    /// most 300,000.
    ///
    /// # Errors
    /// - [`RoostError::CertificateRejected`] if the certificate is expired, revoked, untrusted, or
    ///   signed for another relay domain.
    /// - [`RoostError::InvalidData`] if a key, the reference time, or the grace is malformed or
    ///   too large.
    pub fn validate_sender_certificate(
        &self,
        certificate: SignedSenderCertificate,
        validation: SenderCertificateValidation,
        certificate_grace_millis: u64,
    ) -> Result<ValidatedSenderCertificate, RoostError> {
        let validated = validation.to_core()?.validate(
            &certificate.certificate,
            &certificate.signature,
            Duration::from_millis(certificate_grace_millis),
        )?;
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

impl SenderCertificateValidation {
    pub(crate) fn to_core(&self) -> Result<InboundSenderCertificateValidation, RoostError> {
        Ok(InboundSenderCertificateValidation {
            domain_signing_keys: self
                .domain_signing_keys
                .iter()
                .map(DomainSigningKey::to_core)
                .collect::<Result<_, _>>()?,
            expected_relay_domain: self.expected_relay_domain.clone(),
            revoked_identity_keys: self.revocation_state.to_core()?,
            reference_time: time_from_millis(self.reference_time_millis, "reference_time_millis")?,
        })
    }
}

impl DomainSigningKey {
    fn to_core(&self) -> Result<KnownDomainSigningKey, RoostError> {
        Ok(KnownDomainSigningKey {
            id: self.id.clone(),
            verifying_key: fixed_32(&self.verifying_key, "domain signing verifying key")?,
            status: self.status.to_protocol(),
        })
    }
}

impl RevocationState {
    // Returns `None` when the revocation source failed to load, which fails validation closed.
    fn to_core(&self) -> Result<Option<Vec<SenderCertificateIdentityKey>>, RoostError> {
        if !self.available {
            return Ok(None);
        }
        self.revoked_identity_keys
            .iter()
            .map(|identity_key| {
                let key = identity_key.to_core()?;
                Ok(SenderCertificateIdentityKey {
                    x25519_public_key: key.x25519_public_key,
                    ed25519_verifying_key: key.ed25519_verifying_key,
                })
            })
            .collect::<Result<_, _>>()
            .map(Some)
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
