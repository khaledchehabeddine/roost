//! Sender-certificate validation records exposed through UniFFI.

use crate::error::AetherError;
use crate::protocol::IdentityKey;
use crate::records::fixed_32;
use aether_core::{
    DomainSigningKey as CoreDomainSigningKey, DomainSigningKeyStatus as CoreDomainSigningKeyStatus,
    RevocationState as CoreRevocationState, SenderCertificateIdentityKey,
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
    pub identifier: Vec<u8>,
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

/// Sender-certificate validation policy for one receive operation.
#[derive(uniffi::Record)]
pub struct SenderCertificateValidation {
    /// Known domain-signing keys.
    pub domain_signing_keys: Vec<DomainSigningKey>,
    /// Relay domain incoming certificates must name.
    pub expected_relay_domain: Vec<u8>,
    /// Caller-supplied revocation state.
    pub revocation_state: RevocationState,
    /// Caller-supplied Unix timestamp in seconds.
    pub reference_timestamp_secs: u64,
    /// Caller-supplied grace window in seconds.
    pub grace_window_secs: u64,
}

/// Validated sender certificate contents.
#[derive(uniffi::Record)]
pub struct ValidatedSenderCertificate {
    /// Signing-key identifier read from the certificate.
    pub signing_key_identifier: Vec<u8>,
    /// Sender Identity Key bound by the certificate.
    pub identity_key: IdentityKey,
    /// Relay domain bound by the certificate.
    ///
    /// A certificate is valid only at the relay it names, so this cannot be replayed at another
    /// relay that happens to trust the same signing key.
    pub relay_domain: Vec<u8>,
    /// Certificate expiry Unix timestamp in seconds.
    pub expires_at_secs: u64,
}

/// Validates a sender certificate against caller-supplied trust, revocation, and time inputs.
#[uniffi::export]
pub fn validate_sender_certificate(
    certificate: Vec<u8>,
    signature: Vec<u8>,
    domain_signing_keys: Vec<DomainSigningKey>,
    expected_relay_domain: Vec<u8>,
    revocation_state: RevocationState,
    reference_timestamp_secs: u64,
    grace_window_secs: u64,
) -> Result<ValidatedSenderCertificate, AetherError> {
    let core_domain_keys = domain_signing_keys_to_core(&domain_signing_keys)?;
    let revoked_identity_keys = revoked_identity_keys_to_core(&revocation_state)?;
    let core_revocation_state = revocation_state_to_core(&revocation_state, &revoked_identity_keys);
    let validated = aether_core::validate_sender_certificate(SenderCertificateValidationInput {
        certificate: &certificate,
        signature: &signature,
        domain_signing_keys: &core_domain_keys,
        expected_relay_domain: &expected_relay_domain,
        revocation_state: core_revocation_state,
        reference_timestamp_secs,
        grace_window_secs,
    })?;
    Ok(ValidatedSenderCertificate {
        signing_key_identifier: validated.signing_key_identifier,
        identity_key: IdentityKey {
            x25519_public_key: validated.identity_key.x25519_public_key.to_vec(),
            ed25519_verifying_key: validated.identity_key.ed25519_verifying_key.to_vec(),
        },
        relay_domain: validated.relay_domain,
        expires_at_secs: validated.expires_at_secs,
    })
}

impl DomainSigningKey {
    pub(crate) fn to_core(&self) -> Result<CoreDomainSigningKey<'_>, AetherError> {
        fixed_32(&self.verifying_key, "domain signing verifying key")?;
        Ok(CoreDomainSigningKey {
            identifier: &self.identifier,
            verifying_key: &self.verifying_key,
            status: self.status.into(),
        })
    }
}

impl From<DomainSigningKeyStatus> for CoreDomainSigningKeyStatus {
    fn from(value: DomainSigningKeyStatus) -> Self {
        match value {
            DomainSigningKeyStatus::Trusted => Self::Trusted,
            DomainSigningKeyStatus::Untrusted => Self::Untrusted,
        }
    }
}

pub(crate) fn domain_signing_keys_to_core(
    values: &[DomainSigningKey],
) -> Result<Vec<CoreDomainSigningKey<'_>>, AetherError> {
    values.iter().map(DomainSigningKey::to_core).collect()
}

pub(crate) fn revoked_identity_keys_to_core(
    state: &RevocationState,
) -> Result<Vec<SenderCertificateIdentityKey>, AetherError> {
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

pub(crate) fn revocation_state_to_core<'a>(
    state: &RevocationState,
    revoked_identity_keys: &'a [SenderCertificateIdentityKey],
) -> CoreRevocationState<'a> {
    if state.available {
        CoreRevocationState::Available(revoked_identity_keys)
    } else {
        CoreRevocationState::Unavailable
    }
}
