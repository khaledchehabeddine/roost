//! UniFFI records and operations for authenticated Relay Routes.

use crate::error::AetherError;
use crate::records::fixed_32;
use aether_core::{RelayPreKeyReference as CoreRelayPreKeyReference, RelayRoute as CoreRelayRoute};

/// The destination kind authenticated by a Relay Route.
///
/// Initial routes address a Discovery Key and select prekeys. Established routes address an
/// Identity Key and carry no prekey reference.
///
/// # Examples
/// ```
/// use aether::RelayRouteKind;
///
/// let kind = RelayRouteKind::Established;
/// assert!(matches!(kind, RelayRouteKind::Established));
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum RelayRouteKind {
    /// An X3DH initial Message addressed to a Discovery Key.
    Initial,
    /// An established-session Message addressed to an Identity Key.
    Established,
}

/// Stable prekey identifiers selected by an initial Relay Route.
///
/// Both identifiers are scoped to one Discovery Key Epoch. Signed- and one-time-prekey sequences
/// are independent, so the values may be equal.
///
/// # Examples
/// ```
/// use aether::RelayPreKeyReference;
///
/// let reference = RelayPreKeyReference {
///     signed_prekey_identifier: 7,
///     one_time_prekey_identifier: Some(42),
/// };
/// assert_eq!(reference.one_time_prekey_identifier, Some(42));
/// ```
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct RelayPreKeyReference {
    /// Stable signed-prekey identifier within the Discovery Key Epoch.
    pub signed_prekey_identifier: u64,
    /// Stable one-time-prekey identifier within the Discovery Key Epoch, when one was selected.
    pub one_time_prekey_identifier: Option<u64>,
}

/// A typed public Relay Route supplied separately from an encrypted Message.
///
/// The host must retain this exact value with an outbound Message and reuse it for retransmission.
/// An initial route requires a [`RelayPreKeyReference`]; an established route must omit it.
///
/// # Examples
/// ```
/// use aether::{RelayPreKeyReference, RelayRoute, RelayRouteKind};
///
/// let route = RelayRoute {
///     protocol_version: 1,
///     kind: RelayRouteKind::Initial,
///     recipient_signing_key: vec![0x44; 32],
///     prekey_reference: Some(RelayPreKeyReference {
///         signed_prekey_identifier: 7,
///         one_time_prekey_identifier: None,
///     }),
/// };
/// assert_eq!(route.protocol_version, 1);
/// ```
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct RelayRoute {
    /// Relay protocol version authenticated by the route.
    pub protocol_version: u16,
    /// Whether the route carries an initial or established-session Message.
    pub kind: RelayRouteKind,
    /// Recipient Discovery Key or Identity Key Ed25519 verifying bytes. Always 32 bytes.
    pub recipient_signing_key: Vec<u8>,
    /// Selected prekeys for an initial route; absent for an established route.
    pub prekey_reference: Option<RelayPreKeyReference>,
}

impl RelayRoute {
    pub(crate) fn to_core(&self) -> Result<CoreRelayRoute, AetherError> {
        let recipient_signing_key = fixed_32(
            &self.recipient_signing_key,
            "relay route recipient signing key",
        )?;
        match (self.kind, self.prekey_reference.as_ref()) {
            (RelayRouteKind::Initial, Some(reference)) => Ok(CoreRelayRoute::initial(
                self.protocol_version,
                recipient_signing_key,
                CoreRelayPreKeyReference {
                    signed_prekey_id: reference.signed_prekey_identifier,
                    one_time_prekey_id: reference.one_time_prekey_identifier,
                },
            )),
            (RelayRouteKind::Initial, None) => Err(AetherError::InvalidData {
                reason: "initial Relay Route requires a prekey reference".into(),
            }),
            (RelayRouteKind::Established, None) => Ok(CoreRelayRoute::established(
                self.protocol_version,
                recipient_signing_key,
            )),
            (RelayRouteKind::Established, Some(_)) => Err(AetherError::InvalidData {
                reason: "established Relay Route must not carry a prekey reference".into(),
            }),
        }
    }
}

/// Encodes a Relay Route into canonical associated-data bytes.
///
/// Pass the returned bytes to a Relay that independently derives the same canonical value. Route-
/// aware Message operations perform this encoding internally and do not require these bytes.
///
/// # Examples
/// ```
/// use aether::{encode_relay_route_associated_data, RelayRoute, RelayRouteKind};
///
/// let bytes = encode_relay_route_associated_data(RelayRoute {
///     protocol_version: 1,
///     kind: RelayRouteKind::Established,
///     recipient_signing_key: vec![0x44; 32],
///     prekey_reference: None,
/// })?;
/// assert_eq!(bytes.len(), 49);
/// # Ok::<(), aether::AetherError>(())
/// ```
///
/// # Errors
/// - [`AetherError::InvalidData`] when the signing key is not 32 bytes or the route kind and
///   prekey reference disagree.
#[uniffi::export]
pub fn encode_relay_route_associated_data(route: RelayRoute) -> Result<Vec<u8>, AetherError> {
    Ok(route.to_core()?.associated_data())
}

/// Verifies candidate associated data against a typed Relay Route.
///
/// Verification compares the complete canonical value, including its length, and rejects altered
/// kinds, identifiers, presence markers, padding, and trailing bytes.
///
/// # Examples
/// ```
/// use aether::{
///     encode_relay_route_associated_data, verify_relay_route_associated_data, RelayRoute,
///     RelayRouteKind,
/// };
///
/// let route = RelayRoute {
///     protocol_version: 1,
///     kind: RelayRouteKind::Established,
///     recipient_signing_key: vec![0x44; 32],
///     prekey_reference: None,
/// };
/// let bytes = encode_relay_route_associated_data(route.clone())?;
/// verify_relay_route_associated_data(route, bytes)?;
/// # Ok::<(), aether::AetherError>(())
/// ```
///
/// # Errors
/// - [`AetherError::InvalidData`] when the signing key is not 32 bytes or the route kind and
///   prekey reference disagree.
/// - [`AetherError::RelayRouteRejected`] when `associated_data` is not the route's canonical
///   encoding.
#[uniffi::export]
pub fn verify_relay_route_associated_data(
    route: RelayRoute,
    associated_data: Vec<u8>,
) -> Result<(), AetherError> {
    Ok(route.to_core()?.verify_associated_data(&associated_data)?)
}
