//! Inbox grants: the discovery key, its binding signatures, and the delivery capability that an
//! identity sends a contact inside the payload of a message.

use super::{ProtocolStateError, encode_zeroizing};
use crate::contact::ContactDiscoveryKey;
use roost_crypto::{
    PublicDiscoveryKey, PublicIdentityKey, PublicKey, RecipientDeliveryCapability, Signature,
    verify_discovery_to_identity_binding, verify_public_discovery_key,
};
use roost_protocol::{
    PUBLIC_KEY_LEN, is_valid_x25519_public_key, parse_ed25519_verifying_key_bytes,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub(super) const SIGNATURE_LEN: usize = 64;
pub(super) const CAPABILITY_LEN: usize = 32;
// Longest varint postcard writes for a `u32` and a `u64`, and the one byte it writes for each
// signature's length.
const MAX_EPOCH_LEN: usize = 5;
const MAX_CREATED_AT_LEN: usize = 10;
const SIGNATURE_LEN_PREFIX_LEN: usize = 1;
/// Length of the longest grant [`encode_granted_payload`] puts before a plaintext, which every
/// message's content leaves room for.
pub(super) const MAX_ENCODED_GRANT_LEN: usize = 2 * PUBLIC_KEY_LEN
    + MAX_EPOCH_LEN
    + MAX_CREATED_AT_LEN
    + 2 * (SIGNATURE_LEN_PREFIX_LEN + SIGNATURE_LEN)
    + CAPABILITY_LEN;

/// Where a discovery key falls in the order contacts keep the newest by: its signed creation
/// time, then its epoch, since a restored backup can repeat an epoch.
///
/// The derived ordering compares the fields in declaration order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct DiscoveryKeyStamp {
    pub(super) created_at_secs: u64,
    pub(super) epoch: u32,
}

impl DiscoveryKeyStamp {
    pub(super) fn of(discovery_key: &ContactDiscoveryKey) -> Self {
        Self {
            created_at_secs: discovery_key.created_at_secs,
            epoch: discovery_key.epoch,
        }
    }

    pub(super) fn to_wire(self) -> (u64, u32) {
        (self.created_at_secs, self.epoch)
    }

    pub(super) fn from_wire((created_at_secs, epoch): (u64, u32)) -> Self {
        Self {
            created_at_secs,
            epoch,
        }
    }
}

/// Returns whether `candidate` is newer than `current` in the order contacts keep the newest by.
pub fn is_newer_discovery_key(
    candidate: &ContactDiscoveryKey,
    current: &ContactDiscoveryKey,
) -> bool {
    DiscoveryKeyStamp::of(candidate) > DiscoveryKeyStamp::of(current)
}

/// Returns the public discovery key these fields describe, or `None` when a key or the signature
/// is malformed. The caller still verifies the signature.
pub(super) fn parse_discovery_key(
    x25519_public_key: [u8; PUBLIC_KEY_LEN],
    ed25519_verifying_key: &[u8; PUBLIC_KEY_LEN],
    epoch: u32,
    created_at_secs: u64,
    identity_signature: &[u8],
) -> Option<PublicDiscoveryKey> {
    let identity_signature: &[u8; SIGNATURE_LEN] = identity_signature.try_into().ok()?;
    if !is_valid_x25519_public_key(&x25519_public_key) {
        return None;
    }
    Some(PublicDiscoveryKey {
        public_key: PublicKey::from(x25519_public_key),
        verifying_key: parse_ed25519_verifying_key_bytes(ed25519_verifying_key)?,
        epoch,
        created_at_secs,
        signature: Signature::from_bytes(identity_signature),
    })
}

/// A verified inbox grant from an authenticated sender.
pub(super) struct InboxGrant {
    pub(super) discovery_key: ContactDiscoveryKey,
    pub(super) delivery_capability: Zeroizing<[u8; CAPABILITY_LEN]>,
}

/// The local identity's own inbox grant, built from SecureStorage for one operation.
pub(super) struct LocalGrant<'a> {
    pub(super) discovery_key: &'a PublicDiscoveryKey,
    pub(super) discovery_to_identity: &'a Signature,
    pub(super) delivery_capability: &'a RecipientDeliveryCapability,
}

impl LocalGrant<'_> {
    pub(super) fn stamp(&self) -> DiscoveryKeyStamp {
        DiscoveryKeyStamp {
            created_at_secs: self.discovery_key.created_at_secs,
            epoch: self.discovery_key.epoch,
        }
    }
}

/// Returns `grant` followed by `plaintext`, the payload of a message whose kind carries a grant.
pub(super) fn encode_granted_payload(
    grant: &LocalGrant<'_>,
    plaintext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ProtocolStateError> {
    let identity_signature = grant.discovery_key.signature.to_bytes();
    let discovery_to_identity = grant.discovery_to_identity.to_bytes();
    let capability = grant.delivery_capability.to_bytes();
    let encoded_grant = encode_zeroizing(&InboxGrantWire {
        x25519_public_key: *grant.discovery_key.public_key.as_bytes(),
        ed25519_verifying_key: grant.discovery_key.verifying_key.to_bytes(),
        epoch: grant.discovery_key.epoch,
        created_at_secs: grant.discovery_key.created_at_secs,
        identity_signature: &identity_signature,
        discovery_to_identity: &discovery_to_identity,
        delivery_capability: &capability,
    })
    .map_err(|_| invalid("inbox grant failed to encode"))?;
    let mut payload = Zeroizing::new(Vec::with_capacity(encoded_grant.len() + plaintext.len()));
    payload.extend_from_slice(&encoded_grant);
    payload.extend_from_slice(plaintext);
    Ok(payload)
}

/// Splits a granted payload into the grant, verified against `sender`, and the plaintext after it.
///
/// A grant that fails to decode or whose signatures `sender` doesn't verify rejects the message.
pub(super) fn open_granted_payload(
    payload: &[u8],
    sender: &PublicIdentityKey,
) -> Result<(InboxGrant, Zeroizing<Vec<u8>>), ProtocolStateError> {
    let (wire, plaintext): (DecodedInboxGrantWire<'_>, &[u8]) =
        postcard::take_from_bytes(payload).map_err(|_| invalid("inbox grant failed to decode"))?;
    let grant = verify_grant(&wire, sender)?;
    Ok((grant, Zeroizing::new(plaintext.to_vec())))
}

fn verify_grant(
    wire: &DecodedInboxGrantWire<'_>,
    sender: &PublicIdentityKey,
) -> Result<InboxGrant, ProtocolStateError> {
    let discovery_to_identity: [u8; SIGNATURE_LEN] = wire
        .discovery_to_identity
        .try_into()
        .map_err(|_| invalid("inbox grant signature length is invalid"))?;
    let discovery_key = parse_discovery_key(
        wire.x25519_public_key,
        &wire.ed25519_verifying_key,
        wire.epoch,
        wire.created_at_secs,
        wire.identity_signature,
    )
    .ok_or_else(|| invalid("inbox grant discovery key is invalid"))?;
    verify_public_discovery_key(&discovery_key, &sender.verifying_key)
        .map_err(|_| ProtocolStateError::InvalidInboxGrant)?;
    verify_discovery_to_identity_binding(
        sender,
        &discovery_key.verifying_key,
        &Signature::from_bytes(&discovery_to_identity),
    )
    .map_err(|_| ProtocolStateError::InvalidInboxGrant)?;
    Ok(InboxGrant {
        discovery_key: ContactDiscoveryKey::from(&discovery_key),
        delivery_capability: Zeroizing::new(wire.delivery_capability),
    })
}

fn invalid(reason: &str) -> ProtocolStateError {
    ProtocolStateError::InvalidMessage {
        reason: reason.into(),
    }
}

#[derive(Serialize)]
struct InboxGrantWire<'a> {
    x25519_public_key: [u8; PUBLIC_KEY_LEN],
    ed25519_verifying_key: [u8; PUBLIC_KEY_LEN],
    epoch: u32,
    created_at_secs: u64,
    identity_signature: &'a [u8],
    discovery_to_identity: &'a [u8],
    delivery_capability: &'a [u8; CAPABILITY_LEN],
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct DecodedInboxGrantWire<'a> {
    #[zeroize(skip)]
    x25519_public_key: [u8; PUBLIC_KEY_LEN],
    #[zeroize(skip)]
    ed25519_verifying_key: [u8; PUBLIC_KEY_LEN],
    #[zeroize(skip)]
    epoch: u32,
    #[zeroize(skip)]
    created_at_secs: u64,
    #[serde(borrow)]
    #[zeroize(skip)]
    identity_signature: &'a [u8],
    #[serde(borrow)]
    #[zeroize(skip)]
    discovery_to_identity: &'a [u8],
    delivery_capability: [u8; CAPABILITY_LEN],
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use roost_crypto::{
        DiscoveryKey, KeyPair, SigningKeyPair, generate_discovery_key, sign_identity_key_binding,
    };

    struct Owner {
        identity: PublicIdentityKey,
        discovery_key: DiscoveryKey,
        discovery_to_identity: Signature,
        capability: RecipientDeliveryCapability,
    }

    fn owner(seed: u8) -> Owner {
        let signing_key = SigningKeyPair::from_signing_bytes([seed; 32]);
        let agreement_key = KeyPair::from_secret_bytes([seed.wrapping_add(1); 32]);
        let identity = PublicIdentityKey {
            public_key: agreement_key.public,
            verifying_key: signing_key.verifying,
            binding_signature: sign_identity_key_binding(&signing_key, &agreement_key.public)
                .unwrap(),
        };
        let discovery_key = generate_discovery_key(
            &mut ChaCha20Rng::from_seed([seed; 32]),
            &signing_key,
            3,
            1_700_000_000,
        )
        .unwrap();
        Owner {
            discovery_to_identity: discovery_key.sign_identity_binding(&identity).unwrap(),
            identity,
            discovery_key,
            capability: RecipientDeliveryCapability::from_bytes([seed; 32]),
        }
    }

    fn payload(owner: &Owner, discovery_to_identity: &Signature) -> Zeroizing<Vec<u8>> {
        encode_granted_payload(
            &LocalGrant {
                discovery_key: &owner.discovery_key.public(),
                discovery_to_identity,
                delivery_capability: &owner.capability,
            },
            b"hello",
        )
        .unwrap()
    }

    #[test]
    fn a_grant_opens_for_its_owner_and_leaves_the_plaintext() {
        let owner = owner(7);

        let (grant, plaintext) = open_granted_payload(
            &payload(&owner, &owner.discovery_to_identity),
            &owner.identity,
        )
        .unwrap();

        assert_eq!(plaintext.as_slice(), b"hello");
        assert_eq!(
            grant.discovery_key,
            ContactDiscoveryKey::from(&owner.discovery_key.public())
        );
        assert_eq!(*grant.delivery_capability, [7; 32]);
    }

    #[test]
    fn a_grant_for_another_identity_is_rejected() {
        let stranger = owner(9).identity;
        let owner = owner(7);

        assert!(matches!(
            open_granted_payload(&payload(&owner, &owner.discovery_to_identity), &stranger),
            Err(ProtocolStateError::InvalidInboxGrant)
        ));
    }

    #[test]
    fn a_grant_whose_discovery_key_signs_another_identity_is_rejected() {
        let other = owner(9);
        let owner = owner(7);
        let wrong_binding = owner
            .discovery_key
            .sign_identity_binding(&other.identity)
            .unwrap();

        assert!(matches!(
            open_granted_payload(&payload(&owner, &wrong_binding), &owner.identity),
            Err(ProtocolStateError::InvalidInboxGrant)
        ));
    }

    #[test]
    fn the_longest_grant_takes_the_length_messages_leave_room_for() {
        let owner = owner(7);
        let mut discovery_key = owner.discovery_key.public();
        discovery_key.epoch = u32::MAX;
        discovery_key.created_at_secs = u64::MAX;

        let payload = encode_granted_payload(
            &LocalGrant {
                discovery_key: &discovery_key,
                discovery_to_identity: &owner.discovery_to_identity,
                delivery_capability: &owner.capability,
            },
            b"hello",
        )
        .unwrap();

        assert_eq!(payload.len() - b"hello".len(), MAX_ENCODED_GRANT_LEN);
    }

    #[test]
    fn discovery_keys_order_by_creation_time_then_epoch() {
        let stamp = |created_at_secs, epoch| DiscoveryKeyStamp {
            created_at_secs,
            epoch,
        };

        assert!(stamp(2, 1) > stamp(1, 9));
        assert!(stamp(1, 2) > stamp(1, 1));
        assert_eq!(stamp(1, 1), stamp(1, 1));
    }
}
