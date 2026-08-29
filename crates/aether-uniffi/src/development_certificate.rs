//! Opt-in development sender-certificate issuance for local peer simulations.

use crate::certificate::{
    DomainSigningKey, DomainSigningKeyStatus, RevocationState, SenderCertificateValidation,
};
use crate::error::AetherError;
use crate::records::{Identity, fixed_32};
use aether_core::{
    DevelopmentCertificateAuthority as CoreDevelopmentCertificateAuthority,
    SenderCertificateIdentityKey,
};
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
    /// # Examples
    /// ```
    /// use aether::DevelopmentCertificateAuthority;
    ///
    /// let authority = DevelopmentCertificateAuthority::new(b"relay-loopback".to_vec(), b"relay.example".to_vec())?;
    /// let validation = authority.sender_certificate_validation(1_700_000_000, 0);
    /// assert_eq!(validation.domain_signing_keys.len(), 1);
    /// # Ok::<(), aether::AetherError>(())
    /// ```
    ///
    /// # Errors
    /// - [`AetherError::InvalidData`] if `signing_key_identifier` is empty or longer than 64
    ///   bytes.
    #[uniffi::constructor]
    pub fn new(
        signing_key_identifier: Vec<u8>,
        relay_domain: Vec<u8>,
    ) -> Result<Arc<Self>, AetherError> {
        let inner = CoreDevelopmentCertificateAuthority::new(signing_key_identifier, relay_domain)
            .map_err(|e| AetherError::InvalidData {
                reason: e.to_string(),
            })?;
        Ok(Arc::new(Self { inner }))
    }

    /// Issues a development certificate for initialized public identity and discovery material.
    ///
    /// Callers should read both values from the same initialized [`KeyStore`](crate::KeyStore).
    /// The certificate expires at the caller-supplied Unix timestamp and is accepted only by
    /// validation input from this authority.
    ///
    /// # Examples
    /// ```
    /// use aether::{
    ///     DevelopmentCertificateAuthority, InMemorySecureStorage, KeyStore, SecureStorage,
    /// };
    /// use std::sync::Arc;
    ///
    /// let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// let store = KeyStore::new(storage);
    /// let prepared = store.prepare_generate_identity()?;
    /// store.commit_operation(prepared.operation.identifier.clone())?;
    /// store.finalize_operation(prepared.operation.identifier)?;
    /// let identity = prepared.identity;
    /// let authority = DevelopmentCertificateAuthority::new(b"relay-loopback".to_vec(), b"relay.example".to_vec())?;
    /// let issued = authority.issue(identity, 1_800_000_000)?;
    /// assert_eq!(issued.signature.len(), 64);
    /// # Ok::<(), aether::AetherError>(())
    /// ```
    ///
    /// # Errors
    /// - [`AetherError::InvalidData`] if an identity or discovery public key is the wrong length,
    ///   is not canonically encoded, or is a weak key.
    pub fn issue(
        &self,
        identity: Identity,
        expires_at_secs: u64,
    ) -> Result<DevelopmentSenderCertificate, AetherError> {
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
            .issue(identity_key, expires_at_secs)
            .map_err(|e| AetherError::InvalidData {
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
    ///
    /// # Examples
    /// ```
    /// use aether::DevelopmentCertificateAuthority;
    ///
    /// let authority = DevelopmentCertificateAuthority::new(b"relay-loopback".to_vec(), b"relay.example".to_vec())?;
    /// let validation = authority.sender_certificate_validation(1_700_000_000, 30);
    /// assert!(validation.revocation_state.available);
    /// # Ok::<(), aether::AetherError>(())
    /// ```
    pub fn sender_certificate_validation(
        &self,
        reference_timestamp_secs: u64,
        grace_window_secs: u64,
    ) -> SenderCertificateValidation {
        SenderCertificateValidation {
            domain_signing_keys: vec![DomainSigningKey {
                identifier: self.inner.signing_key_identifier().to_vec(),
                verifying_key: self.inner.verifying_key().to_vec(),
                status: DomainSigningKeyStatus::Trusted,
            }],
            expected_relay_domain: self.inner.relay_domain().to_vec(),
            revocation_state: RevocationState {
                available: true,
                revoked_identity_keys: Vec::new(),
            },
            reference_timestamp_secs,
            grace_window_secs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InMemorySecureStorage, KeyStore, validate_sender_certificate};

    #[test]
    fn issued_record_validates_through_uniffi_records() {
        let store = KeyStore::new(Arc::new(InMemorySecureStorage::new()));
        let identity = store.generate_identity().unwrap();
        store.rotate_signed_prekey_now().unwrap();
        let authority = DevelopmentCertificateAuthority::new(
            b"relay-loopback".to_vec(),
            b"relay.example".to_vec(),
        )
        .unwrap();
        let issued = authority.issue(identity, 1_800_000_000).unwrap();
        let validation = authority.sender_certificate_validation(1_700_000_000, 0);

        validate_sender_certificate(
            issued.certificate,
            issued.signature,
            validation.domain_signing_keys,
            validation.expected_relay_domain,
            validation.revocation_state,
            validation.reference_timestamp_secs,
            validation.grace_window_secs,
        )
        .unwrap();
    }
}
