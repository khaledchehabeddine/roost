//! Defines the canonical Relay route associated data authenticated by encrypted Messages.

use std::error::Error;
use std::fmt;
use subtle::ConstantTimeEq;

const RELAY_ROUTE_LABEL: &[u8; 14] = b"relay-route-v1";
const INITIAL_ROUTE_KIND: u8 = 1;
const ESTABLISHED_ROUTE_KIND: u8 = 2;
const RECIPIENT_SIGNING_KEY_LEN: usize = 32;
const PREKEY_REFERENCE_LEN: u16 = 17;
const ESTABLISHED_ASSOCIATED_DATA_LEN: usize =
    RELAY_ROUTE_LABEL.len() + size_of::<u16>() + size_of::<u8>() + RECIPIENT_SIGNING_KEY_LEN;
const INITIAL_ASSOCIATED_DATA_LEN: usize =
    ESTABLISHED_ASSOCIATED_DATA_LEN + size_of::<u16>() + PREKEY_REFERENCE_LEN as usize;

/// Stable identifiers for the prekeys selected by an X3DH initial Message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayPreKeyReference {
    /// Identifier of the signed pre-key selected for the Session.
    pub signed_prekey_id: u64,
    /// Identifier of the one-time pre-key selected for the Session, when one was available.
    pub one_time_prekey_id: Option<u64>,
}

/// A typed public Relay route whose canonical bytes are authenticated by a Message.
///
/// The route contains only recipient-visible Relay metadata. Recipient delivery capabilities stay
/// outside this value because they authorize relay admission and rotate independently of queued
/// ciphertext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayRoute {
    protocol_version: u16,
    recipient_signing_key: [u8; RECIPIENT_SIGNING_KEY_LEN],
    destination: RelayRouteDestination,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RelayRouteDestination {
    Initial(RelayPreKeyReference),
    Established,
}

impl RelayRoute {
    /// Builds an X3DH-initial route addressed to a recipient Discovery Key.
    ///
    pub fn initial(
        protocol_version: u16,
        recipient_discovery_signing_key: [u8; RECIPIENT_SIGNING_KEY_LEN],
        prekey_reference: RelayPreKeyReference,
    ) -> Self {
        Self {
            protocol_version,
            recipient_signing_key: recipient_discovery_signing_key,
            destination: RelayRouteDestination::Initial(prekey_reference),
        }
    }

    /// Builds an established-Session route addressed to a recipient Identity Key.
    ///
    pub fn established(
        protocol_version: u16,
        recipient_identity_signing_key: [u8; RECIPIENT_SIGNING_KEY_LEN],
    ) -> Self {
        Self {
            protocol_version,
            recipient_signing_key: recipient_identity_signing_key,
            destination: RelayRouteDestination::Established,
        }
    }

    /// Returns the selected Relay protocol version authenticated by this route.
    pub fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    /// Returns the recipient Discovery Key or Identity Key Ed25519 verifying bytes.
    pub fn recipient_signing_key(&self) -> &[u8; RECIPIENT_SIGNING_KEY_LEN] {
        &self.recipient_signing_key
    }

    /// Returns the selected prekeys for an initial route.
    pub fn prekey_reference(&self) -> Option<RelayPreKeyReference> {
        match self.destination {
            RelayRouteDestination::Initial(reference) => Some(reference),
            RelayRouteDestination::Established => None,
        }
    }

    /// Encodes the route as canonical Relay route associated data.
    #[must_use]
    pub fn associated_data(&self) -> Vec<u8> {
        let capacity = match self.destination {
            RelayRouteDestination::Initial(_) => INITIAL_ASSOCIATED_DATA_LEN,
            RelayRouteDestination::Established => ESTABLISHED_ASSOCIATED_DATA_LEN,
        };
        let mut bytes = Vec::with_capacity(capacity);
        bytes.extend_from_slice(RELAY_ROUTE_LABEL);
        bytes.extend_from_slice(&self.protocol_version.to_be_bytes());
        match self.destination {
            RelayRouteDestination::Initial(reference) => {
                bytes.push(INITIAL_ROUTE_KIND);
                bytes.extend_from_slice(&self.recipient_signing_key);
                bytes.extend_from_slice(&PREKEY_REFERENCE_LEN.to_be_bytes());
                bytes.extend_from_slice(&reference.signed_prekey_id.to_be_bytes());
                match reference.one_time_prekey_id {
                    Some(id) => {
                        bytes.push(1);
                        bytes.extend_from_slice(&id.to_be_bytes());
                    }
                    None => {
                        bytes.push(0);
                        bytes.extend_from_slice(&0u64.to_be_bytes());
                    }
                }
            }
            RelayRouteDestination::Established => {
                bytes.push(ESTABLISHED_ROUTE_KIND);
                bytes.extend_from_slice(&self.recipient_signing_key);
            }
        }
        debug_assert_eq!(bytes.len(), capacity);
        bytes
    }

    /// Verifies that `associated_data` is the canonical encoding of this route.
    ///
    /// # Errors
    /// - [`RelayRouteError::AssociatedDataMismatch`] when the bytes differ in length or content.
    pub fn verify_associated_data(&self, associated_data: &[u8]) -> Result<(), RelayRouteError> {
        let expected = self.associated_data();
        if expected.ct_eq(associated_data).into() {
            Ok(())
        } else {
            Err(RelayRouteError::AssociatedDataMismatch)
        }
    }

    pub(crate) fn validate_initial(
        &self,
        recipient_discovery_signing_key: &[u8; RECIPIENT_SIGNING_KEY_LEN],
        prekey_reference: RelayPreKeyReference,
    ) -> Result<(), RelayRouteError> {
        let RelayRouteDestination::Initial(actual_reference) = self.destination else {
            return Err(RelayRouteError::WrongKind);
        };
        self.validate_recipient(recipient_discovery_signing_key)?;
        if actual_reference != prekey_reference {
            return Err(RelayRouteError::PreKeyReferenceMismatch);
        }
        Ok(())
    }

    pub(crate) fn validate_established(
        &self,
        recipient_identity_signing_key: &[u8; RECIPIENT_SIGNING_KEY_LEN],
    ) -> Result<(), RelayRouteError> {
        if self.destination != RelayRouteDestination::Established {
            return Err(RelayRouteError::WrongKind);
        }
        self.validate_recipient(recipient_identity_signing_key)
    }

    fn validate_recipient(
        &self,
        recipient_signing_key: &[u8; RECIPIENT_SIGNING_KEY_LEN],
    ) -> Result<(), RelayRouteError> {
        if self
            .recipient_signing_key
            .ct_eq(recipient_signing_key)
            .into()
        {
            Ok(())
        } else {
            Err(RelayRouteError::RecipientMismatch)
        }
    }
}

/// Errors returned by Relay route construction and verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayRouteError {
    /// Candidate associated data is not the canonical encoding of the expected route.
    AssociatedDataMismatch,
    /// The route kind does not match the Message operation.
    WrongKind,
    /// The route names a different recipient signing key.
    RecipientMismatch,
    /// An initial route names different signed or one-time pre-key identifiers.
    PreKeyReferenceMismatch,
}

impl fmt::Display for RelayRouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AssociatedDataMismatch => write!(f, "relay route associated data mismatch"),
            Self::WrongKind => write!(f, "relay route kind does not match message operation"),
            Self::RecipientMismatch => write!(f, "relay route recipient does not match message"),
            Self::PreKeyReferenceMismatch => {
                write!(f, "relay route pre-key reference does not match message")
            }
        }
    }
}

impl Error for RelayRouteError {}
