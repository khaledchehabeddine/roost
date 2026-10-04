//! Opt-in development sender-certificate issuance for local peer simulations.

use crate::certificate::{
    DomainSigningKey, DomainSigningKeyStatus, RevocationState, SenderCertificateValidation,
};
use crate::error::ClientError;
use crate::records::{Identity, fixed_32};
use crate::time::whole_secs_from_millis;
use roost_core::DevelopmentCertificateAuthority as CoreDevelopmentCertificateAuthority;
use roost_protocol::SenderCertificateIdentityKey;
use std::sync::Arc;

/// Certificate bytes and signature issued for a local development peer.
///
/// Both values use the production sender-certificate encoding and verification path. They are
/// trusted only by validation input returned from the issuing [`DevelopmentCertificateAuthority`].
#[derive(uniffi::Record)]
pub struct DevelopmentSenderCertificate {
    /// Fixed-byte sender certificate bytes.
    pub certificate: Vec<u8>,
    /// Ed25519 signature over `certificate`.
    pub signature: Vec<u8>,
}

/// An in-memory certificate authority for local development peers.
///
/// Each instance owns one process-local Ed25519 signing key generated from the operating-system
/// CSPRNG. The secret never crosses UniFFI and is zeroized when the authority is dropped. This API
/// exists only when the `development-certificates` Cargo feature is enabled; normal artifacts do
/// not contain it.
#[derive(uniffi::Object)]
pub struct DevelopmentCertificateAuthority {
    inner: CoreDevelopmentCertificateAuthority,
}

#[uniffi::export]
impl DevelopmentCertificateAuthority {
    /// Constructs an in-memory development certificate authority.
    ///
    /// Create one authority per local peer simulation and use it to issue every participating
    /// peer's certificate plus the validation input used by receivers.
    ///
    /// # Errors
    /// - [`ClientError::InvalidData`] if `signing_key_id` is empty or longer than 64
    ///   bytes.
    #[uniffi::constructor]
    pub fn new(signing_key_id: Vec<u8>, relay_domain: Vec<u8>) -> Result<Arc<Self>, ClientError> {
        let inner = CoreDevelopmentCertificateAuthority::new(signing_key_id, relay_domain)
            .map_err(|e| ClientError::InvalidData {
                reason: e.to_string(),
            })?;
        Ok(Arc::new(Self { inner }))
    }

    /// Issues a development certificate for initialized public identity and discovery material.
    ///
    /// Callers should read both values from the same initialized [`Client`](crate::Client).
    /// The certificate expires at the caller-supplied Unix timestamp and is accepted only by
    /// validation input from this authority.
    ///
    /// # Errors
    /// - [`ClientError::InvalidData`] if an identity or discovery public key is the wrong length,
    ///   is not canonically encoded, or is a weak key.
    pub fn issue(
        &self,
        identity: Identity,
        expires_at_millis: u64,
    ) -> Result<DevelopmentSenderCertificate, ClientError> {
        let identity_key = SenderCertificateIdentityKey {
            x25519_public_key: fixed_32(
                &identity.x25519_public_key,
                "development certificate identity X25519 public key",
            )?,
            ed25519_verifying_key: fixed_32(
                &identity.ed25519_verifying_key,
                "development certificate identity Ed25519 verifying key",
            )?,
        };
        let issued = self
            .inner
            .issue(
                identity_key,
                whole_secs_from_millis(expires_at_millis, "expires_at_millis")?,
            )
            .map_err(|e| ClientError::InvalidData {
                reason: e.to_string(),
            })?;
        Ok(DevelopmentSenderCertificate {
            certificate: issued.certificate,
            signature: issued.signature,
        })
    }

    /// Returns validation input that trusts certificates issued by this authority.
    ///
    /// Revocation is explicitly available with an empty local-development set. The caller owns
    /// the reference timestamp and grace window just like the production validation API.
    pub fn sender_certificate_validation(
        &self,
        reference_time_millis: u64,
        grace_window_millis: u64,
    ) -> SenderCertificateValidation {
        SenderCertificateValidation {
            domain_signing_keys: vec![DomainSigningKey {
                id: self.inner.signing_key_id().to_vec(),
                verifying_key: self.inner.verifying_key().to_vec(),
                status: DomainSigningKeyStatus::Trusted,
            }],
            expected_relay_domain: self.inner.relay_domain().to_vec(),
            revocation_state: RevocationState {
                available: true,
                revoked_identity_keys: Vec::new(),
            },
            reference_time_millis,
            grace_window_millis,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;
    use crate::{Client, validate_sender_certificate};

    #[test]
    fn issued_record_validates_through_uniffi_records() {
        let store = Client::new(Arc::new(MemoryStorage::default()));
        let identity = store.generate_identity().unwrap();
        store.rotate_signed_prekey_now().unwrap();
        let authority = DevelopmentCertificateAuthority::new(
            b"relay-loopback".to_vec(),
            b"relay.example".to_vec(),
        )
        .unwrap();
        let issued = authority.issue(identity, 1_800_000_000_000).unwrap();
        let validation = authority.sender_certificate_validation(1_700_000_000_000, 0);

        validate_sender_certificate(
            issued.certificate,
            issued.signature,
            validation.domain_signing_keys,
            validation.expected_relay_domain,
            validation.revocation_state,
            validation.reference_time_millis,
            validation.grace_window_millis,
        )
        .unwrap();
    }
}
