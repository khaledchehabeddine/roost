//! The one record Roost keeps for each contact, keyed by the contact's Identity Key.

use super::grant::{
    CAPABILITY_LEN, DiscoveryKeyStamp, InboxGrant, is_newer_discovery_key, parse_discovery_key,
};
use super::session::Starter;
use super::{
    ProtocolStateAddress, ProtocolStateBlob, ProtocolStateError, ProtocolStateKind,
    ProtocolStateSnapshot, blob_body, encode_blob, encode_zeroizing,
};
use crate::contact::{ContactDiscoveryKey, ContactIdentityKey, ContactState, ContactTrustState};
use crate::hardening::{MAX_MESSAGES_BEFORE_ACCEPTANCE, ProtocolHardeningLimits};
use crate::safety_number::identity_key_is_valid;
use roost_crypto::RecipientDeliveryCapability;
use roost_protocol::{MessageId, PUBLIC_KEY_LEN, parse_ed25519_verifying_key_bytes};
use serde::de::{Error as DeError, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::marker::PhantomData;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const MESSAGE_ID_LEN: usize = 16;

pub(super) fn contact_address(identity_key: ContactIdentityKey) -> ProtocolStateAddress {
    ProtocolStateAddress::new(ProtocolStateKind::ContactState, identity_key.into())
}

/// Whether a Message received before acceptance fits the limit on Messages before acceptance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReceivedCount {
    WithinLimit,
    PastLimit,
}

/// A Message this side sent before acceptance, and the local grant it carried.
#[derive(Clone, Copy)]
struct SentBeforeAcceptance {
    message_id: MessageId,
    grant: Option<DiscoveryKeyStamp>,
}

/// A contact as Roost stores it, including the peer's Delivery Capability.
pub(super) struct ContactRecord {
    pub(super) identity_key: ContactIdentityKey,
    pub(super) discovery_key: Option<ContactDiscoveryKey>,
    /// The peer's capability for `discovery_key`, once a grant for it arrived.
    delivery_capability: Option<Zeroizing<[u8; CAPABILITY_LEN]>>,
    /// The newest of the local Identity's grants the contact acknowledged a Message carrying.
    acknowledged_grant: Option<DiscoveryKeyStamp>,
    pub(super) trust_state: ContactTrustState,
    pub(super) blocked: bool,
    sent_before_acceptance: Vec<SentBeforeAcceptance>,
    received_before_acceptance: Vec<MessageId>,
    /// Whether the next send first checks the contact's current prekey bundle, since the contact
    /// may have rotated its inbox while blocked.
    pub(super) needs_discovery_key_check: bool,
}

impl ContactRecord {
    /// Starts a Pending record for a contact whose Discovery Key Roost has verified.
    pub(super) fn pending(
        identity_key: ContactIdentityKey,
        discovery_key: Option<ContactDiscoveryKey>,
    ) -> Self {
        Self {
            identity_key,
            discovery_key,
            delivery_capability: None,
            acknowledged_grant: None,
            trust_state: ContactTrustState::Pending,
            blocked: false,
            sent_before_acceptance: Vec::new(),
            received_before_acceptance: Vec::new(),
            needs_discovery_key_check: false,
        }
    }

    pub(super) fn to_contact_state(&self) -> ContactState {
        ContactState {
            identity_key: self.identity_key,
            discovery_key: self.discovery_key,
            trust_state: self.trust_state,
            blocked: self.blocked,
        }
    }

    pub(super) fn is_accepted(&self) -> bool {
        self.trust_state != ContactTrustState::Pending
    }

    /// Records both consents, which ends the limit on Messages before acceptance.
    pub(super) fn accept(&mut self) {
        if self.trust_state == ContactTrustState::Pending {
            self.trust_state = ContactTrustState::Unverified;
        }
        self.sent_before_acceptance.clear();
        self.received_before_acceptance.clear();
    }

    /// Returns whether this side acknowledges the contact's Messages on a Session `starter`
    /// started.
    ///
    /// An accepted contact gets acknowledgments. Before acceptance only the asked side
    /// acknowledges, once it has replied, so a stranger can't tell whether a request arrived.
    pub(super) fn should_acknowledge(&self, starter: Starter) -> bool {
        self.is_accepted() || (starter == Starter::Peer && !self.sent_before_acceptance.is_empty())
    }

    /// Counts a Message this side sends before acceptance with the local grant stamped `grant`,
    /// refusing one past the limit.
    ///
    /// A MessageID already counted, such as a resent draft, counts once.
    pub(super) fn count_sent(
        &mut self,
        message_id: MessageId,
        grant: Option<DiscoveryKeyStamp>,
    ) -> Result<(), ProtocolStateError> {
        if let Some(sent) = self
            .sent_before_acceptance
            .iter_mut()
            .find(|sent| sent.message_id == message_id)
        {
            sent.grant = sent.grant.max(grant);
            return Ok(());
        }
        if self.sent_before_acceptance.len() == MAX_MESSAGES_BEFORE_ACCEPTANCE {
            return Err(ProtocolStateError::PendingLimitReached {
                limit: MAX_MESSAGES_BEFORE_ACCEPTANCE,
            });
        }
        self.sent_before_acceptance
            .push(SentBeforeAcceptance { message_id, grant });
        Ok(())
    }

    /// Counts a Message received before acceptance. A MessageID already counted counts once.
    pub(super) fn count_received(&mut self, message_id: MessageId) -> ReceivedCount {
        if self.received_before_acceptance.contains(&message_id) {
            return ReceivedCount::WithinLimit;
        }
        if self.received_before_acceptance.len() == MAX_MESSAGES_BEFORE_ACCEPTANCE {
            return ReceivedCount::PastLimit;
        }
        self.received_before_acceptance.push(message_id);
        ReceivedCount::WithinLimit
    }

    /// Lifts the block, and makes the next send check whether the contact rotated meanwhile.
    pub(super) fn unblock(&mut self) {
        self.blocked = false;
        self.needs_discovery_key_check = true;
    }

    /// Returns whether the stored Discovery Key is newer than `discovery_key`, such as one from a
    /// stale prekey bundle.
    pub(super) fn has_newer_discovery_key_than(&self, discovery_key: &ContactDiscoveryKey) -> bool {
        self.discovery_key
            .is_some_and(|current| is_newer_discovery_key(&current, discovery_key))
    }

    /// Replaces the Discovery Key with `discovery_key` when it is newer, dropping the capability,
    /// which belongs to the older one.
    pub(super) fn record_discovery_key(&mut self, discovery_key: ContactDiscoveryKey) {
        if self
            .discovery_key
            .is_none_or(|current| is_newer_discovery_key(&discovery_key, &current))
        {
            self.discovery_key = Some(discovery_key);
            self.delivery_capability = None;
        }
    }

    /// Keeps `grant` when its Discovery Key is newer, or is the stored one without a capability.
    ///
    /// A stale grant changes nothing.
    pub(super) fn record_grant(&mut self, grant: InboxGrant) {
        let is_newer = self
            .discovery_key
            .is_none_or(|current| is_newer_discovery_key(&grant.discovery_key, &current));
        let completes_current = self.delivery_capability.is_none()
            && self
                .discovery_key
                .is_some_and(|current| current == grant.discovery_key);
        if is_newer || completes_current {
            self.discovery_key = Some(grant.discovery_key);
            self.delivery_capability = Some(grant.delivery_capability);
        }
    }

    /// Returns the peer's Discovery Key and capability, which an established Message needs.
    pub(super) fn established_route(
        &self,
    ) -> Result<([u8; PUBLIC_KEY_LEN], RecipientDeliveryCapability), ProtocolStateError> {
        match (&self.discovery_key, &self.delivery_capability) {
            (Some(discovery_key), Some(capability)) => Ok((
                discovery_key.x25519_public_key,
                RecipientDeliveryCapability::from_bytes(**capability),
            )),
            _ => Err(ProtocolStateError::NoDeliveryCapability),
        }
    }

    /// Returns whether the contact hasn't yet acknowledged a Message carrying the local grant
    /// stamped `current`.
    pub(super) fn needs_grant(&self, current: DiscoveryKeyStamp) -> bool {
        self.acknowledged_grant
            .is_none_or(|acknowledged| acknowledged < current)
    }

    /// Returns whether the contact gets the local grant stamped `current` on a Message or
    /// acknowledgment on a Session `starter` started.
    ///
    /// The asked side keeps its grant private until it accepts, so a requester it turns down never
    /// holds the capability, and a blocked contact never gets one.
    pub(super) fn receives_grant(&self, starter: Starter, current: DiscoveryKeyStamp) -> bool {
        !self.blocked
            && (self.is_accepted() || starter == Starter::Local)
            && self.needs_grant(current)
    }

    /// Records that the contact acknowledged a Message carrying the grant stamped `stamp`.
    pub(super) fn acknowledge_grant(&mut self, stamp: DiscoveryKeyStamp) {
        if self
            .acknowledged_grant
            .is_none_or(|current| current < stamp)
        {
            self.acknowledged_grant = Some(stamp);
        }
    }

    /// Records that the contact acknowledged `message_id`, which this side sent before acceptance,
    /// and with it any grant that Message carried.
    pub(super) fn acknowledge_sent_before_acceptance(&mut self, message_id: MessageId) {
        let grant = self
            .sent_before_acceptance
            .iter()
            .find(|sent| sent.message_id == message_id)
            .and_then(|sent| sent.grant);
        if let Some(stamp) = grant {
            self.acknowledge_grant(stamp);
        }
    }

    pub(super) fn encode(
        &self,
        address: &ProtocolStateAddress,
        limits: ProtocolHardeningLimits,
    ) -> Result<ProtocolStateBlob, ProtocolStateError> {
        let sent: Vec<SentBeforeAcceptanceWire> = self
            .sent_before_acceptance
            .iter()
            .map(|sent| {
                (
                    *sent.message_id.as_bytes(),
                    sent.grant.map(DiscoveryKeyStamp::to_wire),
                )
            })
            .collect();
        let received: Vec<[u8; MESSAGE_ID_LEN]> = self
            .received_before_acceptance
            .iter()
            .map(|id| *id.as_bytes())
            .collect();
        let body = encode_zeroizing(&ContactRecordWire {
            identity_x25519_public_key: self.identity_key.x25519_public_key,
            identity_ed25519_verifying_key: self.identity_key.ed25519_verifying_key,
            discovery_key: self
                .discovery_key
                .as_ref()
                .map(|discovery_key| DiscoveryKeyWire {
                    x25519_public_key: discovery_key.x25519_public_key,
                    ed25519_verifying_key: discovery_key.ed25519_verifying_key,
                    epoch: discovery_key.epoch,
                    created_at_secs: discovery_key.created_at_secs,
                    identity_signature: &discovery_key.identity_signature,
                }),
            delivery_capability: self.delivery_capability.as_deref(),
            acknowledged_grant: self.acknowledged_grant.map(DiscoveryKeyStamp::to_wire),
            trust_state: self.trust_state,
            blocked: self.blocked,
            sent_before_acceptance: &sent,
            received_before_acceptance: &received,
            needs_discovery_key_check: self.needs_discovery_key_check,
        })
        .map_err(|_| ProtocolStateError::BlobEncode {
            address: address.clone(),
            reason: "contact state failed to encode".into(),
        })?;
        encode_blob(address, &body, limits.max_protocol_state_blob_len)
    }

    pub(super) fn decode(
        address: &ProtocolStateAddress,
        blob: &ProtocolStateBlob,
        limits: ProtocolHardeningLimits,
    ) -> Result<Self, ProtocolStateError> {
        let body = blob_body(address, blob, limits.max_protocol_state_blob_len)?;
        let (wire, trailing): (DecodedContactRecordWire, &[u8]) =
            postcard::take_from_bytes(body)
                .map_err(|_| decode_error(address, "contact-state payload failed to decode"))?;
        if !trailing.is_empty() {
            return Err(decode_error(address, "contact state has trailing bytes"));
        }
        let identity_key = ContactIdentityKey {
            x25519_public_key: wire.identity_x25519_public_key,
            ed25519_verifying_key: wire.identity_ed25519_verifying_key,
        };
        if !identity_key_is_valid(&identity_key) {
            return Err(decode_error(address, "contact identity key is invalid"));
        }
        if address
            .key()
            .as_bytes()
            .ct_eq(&identity_key.canonical_encoding())
            .unwrap_u8()
            != 1
        {
            return Err(decode_error(
                address,
                "contact identity key does not match address",
            ));
        }
        let discovery_key = wire
            .discovery_key
            .as_ref()
            .map(|discovery_key| decoded_discovery_key(address, &identity_key, discovery_key))
            .transpose()?;
        if wire.delivery_capability.is_some() && discovery_key.is_none() {
            return Err(decode_error(
                address,
                "contact capability has no discovery key",
            ));
        }
        Ok(Self {
            identity_key,
            discovery_key,
            delivery_capability: wire.delivery_capability.map(Zeroizing::new),
            acknowledged_grant: wire.acknowledged_grant.map(DiscoveryKeyStamp::from_wire),
            trust_state: wire.trust_state,
            blocked: wire.blocked,
            needs_discovery_key_check: wire.needs_discovery_key_check,
            sent_before_acceptance: wire
                .sent_before_acceptance
                .iter()
                .map(|(message_id, grant)| SentBeforeAcceptance {
                    message_id: MessageId::from_bytes(*message_id),
                    grant: grant.map(DiscoveryKeyStamp::from_wire),
                })
                .collect(),
            received_before_acceptance: wire
                .received_before_acceptance
                .iter()
                .copied()
                .map(MessageId::from_bytes)
                .collect(),
        })
    }
}

/// Returns the contact record at `address` in `snapshot`, if present.
pub(super) fn load_contact(
    snapshot: &ProtocolStateSnapshot,
    address: &ProtocolStateAddress,
    limits: ProtocolHardeningLimits,
) -> Result<Option<ContactRecord>, ProtocolStateError> {
    snapshot
        .get(address)
        .map(|blob| ContactRecord::decode(address, blob, limits))
        .transpose()
}

fn decoded_discovery_key(
    address: &ProtocolStateAddress,
    identity_key: &ContactIdentityKey,
    wire: &DecodedDiscoveryKeyWire,
) -> Result<ContactDiscoveryKey, ProtocolStateError> {
    let (Some(public), Some(identity_verifying_key)) = (
        parse_discovery_key(
            wire.x25519_public_key,
            &wire.ed25519_verifying_key,
            wire.epoch,
            wire.created_at_secs,
            &wire.identity_signature,
        ),
        parse_ed25519_verifying_key_bytes(&identity_key.ed25519_verifying_key),
    ) else {
        return Err(decode_error(address, "contact discovery key is invalid"));
    };
    roost_crypto::verify_public_discovery_key(&public, &identity_verifying_key)
        .map_err(|_| decode_error(address, "contact discovery key signature failed"))?;
    Ok(ContactDiscoveryKey::from(&public))
}

fn decode_error(address: &ProtocolStateAddress, reason: &str) -> ProtocolStateError {
    ProtocolStateError::BlobDecode {
        address: address.clone(),
        reason: reason.into(),
    }
}

// A MessageID sent before acceptance and the stamp of the grant it carried.
type SentBeforeAcceptanceWire = ([u8; MESSAGE_ID_LEN], Option<(u64, u32)>);

#[derive(Serialize)]
struct ContactRecordWire<'a> {
    identity_x25519_public_key: [u8; PUBLIC_KEY_LEN],
    identity_ed25519_verifying_key: [u8; PUBLIC_KEY_LEN],
    discovery_key: Option<DiscoveryKeyWire<'a>>,
    delivery_capability: Option<&'a [u8; CAPABILITY_LEN]>,
    acknowledged_grant: Option<(u64, u32)>,
    trust_state: ContactTrustState,
    blocked: bool,
    sent_before_acceptance: &'a [SentBeforeAcceptanceWire],
    received_before_acceptance: &'a [[u8; MESSAGE_ID_LEN]],
    needs_discovery_key_check: bool,
}

#[derive(Serialize)]
struct DiscoveryKeyWire<'a> {
    x25519_public_key: [u8; PUBLIC_KEY_LEN],
    ed25519_verifying_key: [u8; PUBLIC_KEY_LEN],
    epoch: u32,
    created_at_secs: u64,
    identity_signature: &'a [u8],
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct DecodedContactRecordWire {
    #[zeroize(skip)]
    identity_x25519_public_key: [u8; PUBLIC_KEY_LEN],
    #[zeroize(skip)]
    identity_ed25519_verifying_key: [u8; PUBLIC_KEY_LEN],
    #[zeroize(skip)]
    discovery_key: Option<DecodedDiscoveryKeyWire>,
    delivery_capability: Option<[u8; CAPABILITY_LEN]>,
    #[zeroize(skip)]
    acknowledged_grant: Option<(u64, u32)>,
    #[zeroize(skip)]
    trust_state: ContactTrustState,
    #[zeroize(skip)]
    blocked: bool,
    #[zeroize(skip)]
    #[serde(deserialize_with = "deserialize_counted")]
    sent_before_acceptance: Vec<SentBeforeAcceptanceWire>,
    #[zeroize(skip)]
    #[serde(deserialize_with = "deserialize_counted")]
    received_before_acceptance: Vec<[u8; MESSAGE_ID_LEN]>,
    #[zeroize(skip)]
    needs_discovery_key_check: bool,
}

#[derive(Deserialize)]
struct DecodedDiscoveryKeyWire {
    x25519_public_key: [u8; PUBLIC_KEY_LEN],
    ed25519_verifying_key: [u8; PUBLIC_KEY_LEN],
    epoch: u32,
    created_at_secs: u64,
    identity_signature: Vec<u8>,
}

// Decodes a list of Messages counted before acceptance, refusing more than the limit.
fn deserialize_counted<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct CountedVisitor<T>(PhantomData<T>);

    impl<'de, T: Deserialize<'de>> Visitor<'de> for CountedVisitor<T> {
        type Value = Vec<T>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "at most {MAX_MESSAGES_BEFORE_ACCEPTANCE} counted messages"
            )
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut counted = Vec::with_capacity(MAX_MESSAGES_BEFORE_ACCEPTANCE);
            while let Some(entry) = seq.next_element()? {
                if counted.len() == MAX_MESSAGES_BEFORE_ACCEPTANCE {
                    return Err(A::Error::custom("counted messages exceed the limit"));
                }
                counted.push(entry);
            }
            Ok(counted)
        }
    }

    deserializer.deserialize_seq(CountedVisitor(PhantomData))
}

#[cfg(test)]
mod tests {
    use super::super::grant::SIGNATURE_LEN;
    use super::*;

    fn discovery_key(seed: u8, created_at_secs: u64, epoch: u32) -> ContactDiscoveryKey {
        ContactDiscoveryKey {
            x25519_public_key: [seed; PUBLIC_KEY_LEN],
            ed25519_verifying_key: [seed; PUBLIC_KEY_LEN],
            epoch,
            created_at_secs,
            identity_signature: [seed; SIGNATURE_LEN],
        }
    }

    fn grant(discovery_key: ContactDiscoveryKey, capability: u8) -> InboxGrant {
        InboxGrant {
            discovery_key,
            delivery_capability: Zeroizing::new([capability; CAPABILITY_LEN]),
        }
    }

    fn contact(discovery_key: ContactDiscoveryKey) -> ContactRecord {
        let identity_key = ContactIdentityKey {
            x25519_public_key: [7; PUBLIC_KEY_LEN],
            ed25519_verifying_key: [7; PUBLIC_KEY_LEN],
        };
        ContactRecord::pending(identity_key, Some(discovery_key))
    }

    fn capability(contact: &ContactRecord) -> Option<[u8; CAPABILITY_LEN]> {
        contact
            .established_route()
            .ok()
            .map(|(_, capability)| *capability.to_bytes())
    }

    #[test]
    fn a_grant_with_a_later_creation_time_replaces_one_with_a_higher_epoch() {
        let mut contact = contact(discovery_key(1, 100, 5));

        contact.record_grant(grant(discovery_key(2, 200, 1), 2));

        assert_eq!(contact.discovery_key, Some(discovery_key(2, 200, 1)));
        assert_eq!(capability(&contact), Some([2; CAPABILITY_LEN]));
    }

    #[test]
    fn a_grant_for_an_older_discovery_key_changes_nothing() {
        let mut contact = contact(discovery_key(2, 200, 1));
        contact.record_grant(grant(discovery_key(2, 200, 1), 2));

        contact.record_grant(grant(discovery_key(1, 100, 9), 1));

        assert_eq!(contact.discovery_key, Some(discovery_key(2, 200, 1)));
        assert_eq!(capability(&contact), Some([2; CAPABILITY_LEN]));
    }

    #[test]
    fn a_newer_discovery_key_without_a_grant_drops_the_old_capability() {
        let mut contact = contact(discovery_key(1, 100, 1));
        contact.record_grant(grant(discovery_key(1, 100, 1), 1));

        contact.record_discovery_key(discovery_key(2, 200, 2));

        assert!(matches!(
            contact.established_route(),
            Err(ProtocolStateError::NoDeliveryCapability)
        ));
    }

    #[test]
    fn a_resent_message_counts_once_toward_the_limit() {
        let mut contact = contact(discovery_key(1, 100, 1));
        let ids: Vec<_> = (0..=MAX_MESSAGES_BEFORE_ACCEPTANCE as u8)
            .map(|byte| MessageId::from_bytes([byte; MESSAGE_ID_LEN]))
            .collect();
        for id in &ids[..MAX_MESSAGES_BEFORE_ACCEPTANCE] {
            contact.count_sent(*id, None).unwrap();
            assert_eq!(contact.count_received(*id), ReceivedCount::WithinLimit);
        }

        contact.count_sent(ids[0], None).unwrap();
        assert_eq!(contact.count_received(ids[0]), ReceivedCount::WithinLimit);
        assert!(matches!(
            contact.count_sent(ids[MAX_MESSAGES_BEFORE_ACCEPTANCE], None),
            Err(ProtocolStateError::PendingLimitReached { .. })
        ));
        assert_eq!(
            contact.count_received(ids[MAX_MESSAGES_BEFORE_ACCEPTANCE]),
            ReceivedCount::PastLimit
        );
    }
}
