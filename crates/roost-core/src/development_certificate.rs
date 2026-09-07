//! Process-local certificate authority for development peers.

use rand::rngs::OsRng;
use roost_crypto::{SigningKeyPair, generate_signing_key_pair};
use roost_protocol::{PUBLIC_KEY_LEN, SenderCertificateIdentityKey};
use std::{error::Error, fmt};

const MAX_RELAY_DOMAIN_LEN: usize = 255;
const MAX_SIGNING_KEY_IDENTIFIER_LEN: usize = 64;

/// An in-memory certificate authority for local development peers.
///
/// The authority generates one process-local Ed25519 signing key from the operating-system CSPRNG
/// and never exposes its secret bytes. Certificates it issues pass the ordinary validation path
/// only when the caller explicitly trusts this authority's identifier and verifying key. The type
/// is available only with the `development-certificates` feature and must not back production
/// sender identity.
pub struct DevelopmentCertificateAuthority {
    signing_key_identifier: Vec<u8>,
    relay_domain: Vec<u8>,
    signing_key: SigningKeyPair,
}

/// Certificate bytes and signature issued by a [`DevelopmentCertificateAuthority`].
pub struct DevelopmentSenderCertificate {
    /// Fixed-byte sender certificate bytes.
    pub certificate: Vec<u8>,
    /// Ed25519 signature over `certificate`.
    pub signature: Vec<u8>,
}

/// Errors returned while constructing development sender certificates.
#[derive(Debug, Eq, PartialEq)]
pub enum DevelopmentCertificateError {
    /// The signing-key identifier is empty or exceeds the certificate format limit.
    InvalidSigningKeyIdentifier,
    /// The sender Identity Key is not canonically encoded.
    InvalidIdentityKey,
    /// The sender Discovery Key is not canonically encoded.
    InvalidDiscoveryKey,
    /// The relay domain is empty or longer than a single length byte can express.
    InvalidRelayDomain,
}

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
            Self::InvalidRelayDomain => {
                write!(f, "development certificate relay domain is invalid")
            }
        }
    }
}

impl Error for DevelopmentCertificateError {}

impl DevelopmentCertificateAuthority {
    /// Constructs a process-local development certificate authority.
    ///
    /// The signing key is generated from the operating-system CSPRNG and zeroized on drop. Peers
    /// must explicitly include [`Self::verifying_key`] under [`Self::signing_key_identifier`] in
    /// their validation input before certificates from this authority are accepted.
    ///
    /// # Examples
    /// ```
    /// use roost_core::DevelopmentCertificateAuthority;
    ///
    /// let authority = DevelopmentCertificateAuthority::new(
    ///     b"local-loopback".to_vec(),
    ///     b"relay.example".to_vec(),
    /// )?;
    /// assert_eq!(authority.verifying_key().len(), 32);
    /// assert_eq!(authority.relay_domain(), b"relay.example");
    /// # Ok::<(), roost_core::DevelopmentCertificateError>(())
    /// ```
    ///
    /// # Errors
    /// - [`DevelopmentCertificateError::InvalidSigningKeyIdentifier`] if the identifier is empty
    ///   or exceeds the certificate format's 64-byte limit.
    /// - [`DevelopmentCertificateError::InvalidRelayDomain`] if the relay domain is empty or
    ///   longer than a single length byte can express.
    pub fn new(
        signing_key_identifier: Vec<u8>,
        relay_domain: Vec<u8>,
    ) -> Result<Self, DevelopmentCertificateError> {
        validate_development_signing_key_identifier(&signing_key_identifier)?;
        if relay_domain.is_empty() || relay_domain.len() > MAX_RELAY_DOMAIN_LEN {
            return Err(DevelopmentCertificateError::InvalidRelayDomain);
        }
        Ok(Self {
            signing_key_identifier,
            relay_domain,
            signing_key: generate_signing_key_pair(&mut OsRng),
        })
    }

    /// Returns the identifier embedded in every certificate from this authority.
    #[must_use]
    pub fn signing_key_identifier(&self) -> &[u8] {
        &self.signing_key_identifier
    }

    /// Returns the relay domain every certificate from this authority names.
    ///
    /// A certificate is only valid at the relay it names, so a validator needs this same value as
    /// its expected domain. Holding it on the authority keeps the two sides from drifting.
    #[must_use]
    pub fn relay_domain(&self) -> &[u8] {
        &self.relay_domain
    }

    /// Returns the Ed25519 verifying key peers explicitly trust for local development.
    #[must_use]
    pub fn verifying_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.signing_key.verifying.to_bytes()
    }

    /// Issues a development sender certificate for one Identity Key.
    ///
    /// The returned bytes use the production certificate encoding and signature verification path,
    /// naming this authority's relay domain. This method does not validate the Identity Key binding
    /// signature; callers must obtain the key from an already initialized keystore.
    ///
    /// # Examples
    /// ```
    /// use roost_core::{DevelopmentCertificateAuthority};
    /// use roost_protocol::{SenderCertificateIdentityKey};
    ///
    /// # use roost_crypto::{generate_key_pair, generate_signing_key_pair};
    /// # use rand::rngs::OsRng;
    /// # let identity_agreement = generate_key_pair(&mut OsRng);
    /// # let identity_signing = generate_signing_key_pair(&mut OsRng);
    /// # let identity = SenderCertificateIdentityKey {
    /// #     x25519_public_key: *identity_agreement.public.as_bytes(),
    /// #     ed25519_verifying_key: identity_signing.verifying.to_bytes(),
    /// # };
    /// let authority = DevelopmentCertificateAuthority::new(
    ///     b"local-loopback".to_vec(),
    ///     b"relay.example".to_vec(),
    /// )?;
    /// let issued = authority.issue(identity, 1_800_000_000)?;
    /// assert_eq!(issued.signature.len(), 64);
    /// # Ok::<(), roost_core::DevelopmentCertificateError>(())
    /// ```
    ///
    /// # Errors
    /// - [`DevelopmentCertificateError::InvalidIdentityKey`] if either Identity Key public key is
    ///   not canonically encoded.
    pub fn issue(
        &self,
        identity_key: SenderCertificateIdentityKey,
        expires_at_secs: u64,
    ) -> Result<DevelopmentSenderCertificate, DevelopmentCertificateError> {
        let certificate = roost_protocol::encode_sender_certificate(
            &self.signing_key_identifier,
            &self.relay_domain,
            identity_key,
            expires_at_secs,
        )
        .map_err(|_| DevelopmentCertificateError::InvalidIdentityKey)?;
        let signature = self.signing_key.sign(&certificate).to_bytes().to_vec();

        Ok(DevelopmentSenderCertificate {
            certificate,
            signature,
        })
    }
}

fn validate_development_signing_key_identifier(
    identifier: &[u8],
) -> Result<(), DevelopmentCertificateError> {
    if identifier.is_empty() || identifier.len() > MAX_SIGNING_KEY_IDENTIFIER_LEN {
        Err(DevelopmentCertificateError::InvalidSigningKeyIdentifier)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use roost_protocol::{
        DomainSigningKey, DomainSigningKeyStatus, RevocationState,
        SenderCertificateValidationError, SenderCertificateValidationInput,
        validate_sender_certificate,
    };
    const PRIMARY_IDENTIFIER: &[u8] = b"primary";
    const OTHER_RELAY_DOMAIN: &[u8] = b"other.example";
    const RELAY_DOMAIN: &[u8] = b"relay.example";
    const NOW_SECS: u64 = 1_700_000_000;
    fn identity_key() -> SenderCertificateIdentityKey {
        SenderCertificateIdentityKey {
            x25519_public_key: [0x31; 32],
            ed25519_verifying_key: SigningKeyPair::from_signing_bytes([0x21; 32])
                .verifying
                .to_bytes(),
        }
    }
    fn trusted_key<'a>(identifier: &'a [u8], verifying_key: &'a [u8]) -> DomainSigningKey<'a> {
        DomainSigningKey {
            identifier,
            verifying_key,
            status: DomainSigningKeyStatus::Trusted,
        }
    }
    #[test]
    fn development_authority_issues_through_production_validation_path() {
        let authority = DevelopmentCertificateAuthority::new(
            PRIMARY_IDENTIFIER.to_vec(),
            RELAY_DOMAIN.to_vec(),
        )
        .unwrap();
        let identity_key = identity_key();
        let issued = authority.issue(identity_key, NOW_SECS + 300).unwrap();
        let verifying_key = authority.verifying_key();
        let domain_keys = [trusted_key(
            authority.signing_key_identifier(),
            &verifying_key,
        )];

        let validated = validate_sender_certificate(SenderCertificateValidationInput {
            certificate: &issued.certificate,
            signature: &issued.signature,
            domain_signing_keys: &domain_keys,
            expected_relay_domain: authority.relay_domain(),
            revocation_state: RevocationState::Available(&[]),
            reference_timestamp_secs: NOW_SECS,
            grace_window_secs: 0,
        })
        .unwrap();

        assert_eq!(validated.identity_key, identity_key);
        assert_eq!(validated.relay_domain, RELAY_DOMAIN.to_vec());
    }

    /// An authority speaks for one relay, so a certificate it issues must not validate at another.
    #[test]
    fn development_authority_certificate_is_scoped_to_its_relay() {
        let authority = DevelopmentCertificateAuthority::new(
            PRIMARY_IDENTIFIER.to_vec(),
            RELAY_DOMAIN.to_vec(),
        )
        .unwrap();
        let issued = authority.issue(identity_key(), NOW_SECS + 300).unwrap();
        let verifying_key = authority.verifying_key();
        let domain_keys = [trusted_key(
            authority.signing_key_identifier(),
            &verifying_key,
        )];

        let result = validate_sender_certificate(SenderCertificateValidationInput {
            certificate: &issued.certificate,
            signature: &issued.signature,
            domain_signing_keys: &domain_keys,
            expected_relay_domain: OTHER_RELAY_DOMAIN,
            revocation_state: RevocationState::Available(&[]),
            reference_timestamp_secs: NOW_SECS,
            grace_window_secs: 0,
        });

        assert_eq!(
            result.unwrap_err(),
            SenderCertificateValidationError::RelayDomainMismatch
        );
    }

    #[test]
    fn development_authority_rejects_invalid_identifier() {
        assert!(matches!(
            DevelopmentCertificateAuthority::new(Vec::new(), RELAY_DOMAIN.to_vec()),
            Err(DevelopmentCertificateError::InvalidSigningKeyIdentifier)
        ));
        assert!(matches!(
            DevelopmentCertificateAuthority::new(
                vec![0; MAX_SIGNING_KEY_IDENTIFIER_LEN + 1],
                RELAY_DOMAIN.to_vec()
            ),
            Err(DevelopmentCertificateError::InvalidSigningKeyIdentifier)
        ));
        assert!(matches!(
            DevelopmentCertificateAuthority::new(PRIMARY_IDENTIFIER.to_vec(), Vec::new()),
            Err(DevelopmentCertificateError::InvalidRelayDomain)
        ));
    }
}
