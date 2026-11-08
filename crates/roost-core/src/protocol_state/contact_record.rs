//! The one record Roost keeps for each contact, keyed by the contact's identity key.

use super::grant::{
    CAPABILITY_LEN, DiscoveryKeyStamp, InboxGrant, is_newer_discovery_key, parse_discovery_key,
};
use super::session::Starter;
use super::{
    DiscoveryKeyWire, ProtocolStateAddress, ProtocolStateBlob, ProtocolStateError,
    ProtocolStateKind, ProtocolStateSnapshot, decode_blob, decode_error, deserialize_bounded,
    encode_blob, encode_zeroizing,
};
use crate::contact::{ContactDiscoveryKey, ContactState, ContactTrustState};
use crate::hardening::{MAX_MESSAGES_BEFORE_ACCEPTANCE, ProtocolHardeningLimits};
use crate::stored_data::{signature_from_wire, signature_to_wire};
use roost_crypto::RecipientDeliveryCapability;
use roost_protocol::{IdentityKey, MessageId, PUBLIC_KEY_LEN, parse_ed25519_verifying_key_bytes};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{ZeroizeOnDrop, Zeroizing};

const MESSAGE_ID_LEN: usize = 16;

pub(super) fn contact_address(identity_key: IdentityKey) -> ProtocolStateAddress {
    ProtocolStateAddress::new(ProtocolStateKind::ContactState, identity_key.into())
}

/// Whether a message received before acceptance fits the limit on messages before acceptance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReceivedCount {
    WithinLimit,
    PastLimit,
}

/// A message this side sent before acceptance, and the local grant it carried.
#[derive(Clone, Copy)]
struct SentBeforeAcceptance {
    message_id: MessageId,
    grant: Option<DiscoveryKeyStamp>,
}

/// A recovery a delivery check signaled for the contact's unacknowledged messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RecoverySignal {
    /// When the delivery check signaled it, in Unix milliseconds.
    pub(super) signaled_at_millis: u64,
    pub(super) progress: RecoveryProgress,
}

/// How far a signaled recovery got.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RecoveryProgress {
    /// Nothing is resent yet.
    Signaled,
    /// Messages went out again on a session the contact delivered on.
    Resent,
    /// This message went out first on a new session, and the rest wait for its acknowledgment.
    Probed(MessageId),
}

/// A contact as Roost stores it, including the peer's delivery capability.
pub(super) struct ContactRecord {
    pub(super) identity_key: IdentityKey,
    pub(super) discovery_key: Option<ContactDiscoveryKey>,
    /// The peer's capability for `discovery_key`, once a grant for it arrived.
    delivery_capability: Option<Zeroizing<[u8; CAPABILITY_LEN]>>,
    /// The newest of the local identity's grants the contact acknowledged a message carrying.
    acknowledged_grant: Option<DiscoveryKeyStamp>,
    pub(super) trust_state: ContactTrustState,
    pub(super) blocked: bool,
    sent_before_acceptance: Vec<SentBeforeAcceptance>,
    /// The last grant update this side sent before acceptance, which doesn't count toward the
    /// limit.
    grant_update_before_acceptance: Option<SentBeforeAcceptance>,
    received_before_acceptance: Vec<MessageId>,
    /// Whether the next send first checks the contact's current prekey bundle, since the contact
    /// may have rotated its inbox while blocked.
    pub(super) needs_discovery_key_check: bool,
    /// The recovery signaled for the contact's unacknowledged messages, until none is left or the
    /// contact proves a newer grant or session.
    recovery: Option<RecoverySignal>,
}

impl ContactRecord {
    /// Starts a pending record for a contact whose discovery key Roost has verified.
    pub(super) fn pending(
        identity_key: IdentityKey,
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
            grant_update_before_acceptance: None,
            received_before_acceptance: Vec::new(),
            needs_discovery_key_check: false,
            recovery: None,
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

    /// Records both consents, which ends the limit on messages before acceptance.
    pub(super) fn accept(&mut self) {
        if self.trust_state == ContactTrustState::Pending {
            self.trust_state = ContactTrustState::Unverified;
        }
        self.sent_before_acceptance.clear();
        self.grant_update_before_acceptance = None;
        self.received_before_acceptance.clear();
    }

    /// Records that the contact's inbox grant arrived on a session `starter` started, which accepts
    /// the contact when this side started it.
    ///
    /// The asked side shares its grant only once it accepts, so its grant on the requester's
    /// session accepts as a contact acceptance does. A restore can lose that acceptance, and the
    /// grant then arrives again on the next session the requester starts.
    pub(super) fn accept_by_grant(&mut self, starter: Starter) {
        if starter == Starter::Local {
            self.accept();
        }
    }

    /// Returns whether this side acknowledges the contact's messages on a session `starter`
    /// started.
    ///
    /// An accepted contact gets acknowledgments. Before acceptance only the asked side
    /// acknowledges, once it has replied, so a stranger can't tell whether a request arrived.
    ///
    /// Either way it waits for the contact's capability, which a bundle naming a newer discovery
    /// key drops. The message still arrives. The contact's grant then comes with its next message,
    /// or with the resends of the recovery that the missing acknowledgment starts.
    pub(super) fn should_acknowledge(&self, starter: Starter) -> bool {
        self.delivery_capability.is_some()
            && (self.is_accepted()
                || (starter == Starter::Peer && !self.sent_before_acceptance.is_empty()))
    }

    /// Counts a message this side sends before acceptance with the local grant stamped `grant`,
    /// refusing one past the limit.
    ///
    /// A message ID already counted, such as a resent draft, counts once.
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

    /// Forgets the messages this side sent before acceptance, so the limit counts from zero.
    pub(super) fn forget_sent_before_acceptance(&mut self) {
        self.sent_before_acceptance.clear();
    }

    /// Records a grant update this side sends before acceptance with the local grant stamped
    /// `grant`, so its acknowledgment shows the contact holds that grant.
    ///
    /// It doesn't count toward the limit, and only the latest one is kept, since an older one
    /// carries an older grant.
    pub(super) fn record_grant_update(&mut self, message_id: MessageId, grant: DiscoveryKeyStamp) {
        self.grant_update_before_acceptance = Some(SentBeforeAcceptance {
            message_id,
            grant: Some(grant),
        });
    }

    /// Counts a message received before acceptance. A message ID already counted counts once.
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

    /// Returns whether the contact sent this side a message before acceptance, as every requester
    /// did with its request.
    pub(super) fn has_written_before_acceptance(&self) -> bool {
        !self.received_before_acceptance.is_empty()
    }

    /// Lifts the block, makes the next send check whether the contact rotated meanwhile, and
    /// forgets a recovery signaled before the block, whose job may have failed on it.
    pub(super) fn unblock(&mut self) {
        self.blocked = false;
        self.needs_discovery_key_check = true;
        self.forget_recovery();
    }

    /// Returns whether the stored discovery key is newer than `discovery_key`, such as one from a
    /// stale prekey bundle.
    pub(super) fn has_newer_discovery_key_than(&self, discovery_key: &ContactDiscoveryKey) -> bool {
        self.discovery_key
            .is_some_and(|current| is_newer_discovery_key(&current, discovery_key))
    }

    /// Replaces the discovery key with `discovery_key` when it is newer, dropping the capability,
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

    /// Keeps `grant` when its discovery key is newer, or is the stored one without a capability.
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
            self.recovery = None;
        }
    }

    /// Returns the recovery signaled for the contact's unacknowledged messages, if any.
    pub(super) fn recovery(&self) -> Option<RecoverySignal> {
        self.recovery
    }

    /// Forgets the signaled recovery, so the next delivery check may signal one again.
    pub(super) fn forget_recovery(&mut self) {
        self.recovery = None;
    }

    /// Records a recovery signaled at `now_millis`.
    pub(super) fn signal_recovery(&mut self, now_millis: u64) {
        self.recovery = Some(RecoverySignal {
            signaled_at_millis: now_millis,
            progress: RecoveryProgress::Signaled,
        });
    }

    /// Records that a recovery resent a message, as the probe on a new session when `probe` holds
    /// its ID.
    ///
    /// The first resend attaches the local grant again until the contact acknowledges it, since a
    /// contact that lost its session may have lost the grant too.
    pub(super) fn record_resend(&mut self, probe: Option<MessageId>) {
        if self
            .recovery
            .is_none_or(|recovery| recovery.progress == RecoveryProgress::Signaled)
        {
            self.acknowledged_grant = None;
        }
        if let Some(recovery) = &mut self.recovery {
            recovery.progress = probe.map_or(RecoveryProgress::Resent, RecoveryProgress::Probed);
        }
    }

    /// Returns whether the contact granted a discovery key newer than the one stamped `sent_to`,
    /// so a message sent to that one may have gone to a dead inbox, which the relay doesn't report.
    ///
    /// A newer key known without its grant came with a new session, and the messages left behind
    /// go out on it once the contact replies there.
    pub(super) fn has_newer_grant_than(&self, sent_to: Option<DiscoveryKeyStamp>) -> bool {
        self.delivery_capability.is_some()
            && self.discovery_key.is_some_and(|current| {
                sent_to.is_some_and(|sent_to| DiscoveryKeyStamp::of(&current) > sent_to)
            })
    }

    /// Returns the peer's discovery key and capability, which an established message needs.
    pub(super) fn established_route(
        &self,
    ) -> Result<([u8; PUBLIC_KEY_LEN], RecipientDeliveryCapability), ProtocolStateError> {
        match (&self.discovery_key, &self.delivery_capability) {
            (Some(discovery_key), Some(capability)) => Ok((
                discovery_key.x25519_public_key,
                RecipientDeliveryCapability::from_bytes(capability),
            )),
            _ => Err(ProtocolStateError::NoDeliveryCapability),
        }
    }

    /// Returns whether the contact hasn't yet acknowledged a message carrying the local grant
    /// stamped `current`.
    fn needs_grant(&self, current: DiscoveryKeyStamp) -> bool {
        self.acknowledged_grant
            .is_none_or(|acknowledged| acknowledged < current)
    }

    /// Returns whether the contact gets the local grant stamped `current` on a message or
    /// acknowledgment on a session `starter` started.
    ///
    /// The asked side keeps its grant private until it accepts, so a requester it turns down never
    /// holds the capability, and a blocked contact never gets one.
    pub(super) fn receives_grant(&self, starter: Starter, current: DiscoveryKeyStamp) -> bool {
        !self.blocked
            && (self.is_accepted() || starter == Starter::Local)
            && self.needs_grant(current)
    }

    /// Forgets which local grant the contact acknowledged, so the next acknowledgment and messages
    /// carry the grant again.
    pub(super) fn forget_acknowledged_grant(&mut self) {
        self.acknowledged_grant = None;
    }

    /// Records that the contact acknowledged a message carrying the grant stamped `stamp`.
    pub(super) fn acknowledge_grant(&mut self, stamp: DiscoveryKeyStamp) {
        if self
            .acknowledged_grant
            .is_none_or(|current| current < stamp)
        {
            self.acknowledged_grant = Some(stamp);
        }
    }

    /// Records that the contact acknowledged `message_id`, which this side sent before acceptance,
    /// and with it any grant that message carried.
    pub(super) fn acknowledge_sent_before_acceptance(&mut self, message_id: MessageId) {
        let grant = self
            .sent_before_acceptance
            .iter()
            .chain(&self.grant_update_before_acceptance)
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
        let grant_update = self.grant_update_before_acceptance.map(|sent| {
            (
                *sent.message_id.as_bytes(),
                sent.grant.map(DiscoveryKeyStamp::to_wire),
            )
        });
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
                    identity_signature: signature_to_wire(&discovery_key.identity_signature),
                }),
            delivery_capability: self.delivery_capability.as_deref(),
            acknowledged_grant: self.acknowledged_grant.map(DiscoveryKeyStamp::to_wire),
            trust_state: self.trust_state,
            blocked: self.blocked,
            sent_before_acceptance: &sent,
            grant_update_before_acceptance: grant_update,
            received_before_acceptance: &received,
            needs_discovery_key_check: self.needs_discovery_key_check,
            recovery: self.recovery.map(|recovery| {
                (
                    recovery.signaled_at_millis,
                    match recovery.progress {
                        RecoveryProgress::Signaled => RecoveryProgressWire::Signaled,
                        RecoveryProgress::Resent => RecoveryProgressWire::Resent,
                        RecoveryProgress::Probed(probe) => {
                            RecoveryProgressWire::Probed(*probe.as_bytes())
                        }
                    },
                )
            }),
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
        let wire: DecodedContactRecordWire =
            decode_blob(address, blob, limits.max_protocol_state_blob_len)?;
        let identity_key = IdentityKey {
            x25519_public_key: wire.identity_x25519_public_key,
            ed25519_verifying_key: wire.identity_ed25519_verifying_key,
        };
        if !identity_key.is_valid() {
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
            recovery: wire
                .recovery
                .map(|(signaled_at_millis, progress)| RecoverySignal {
                    signaled_at_millis,
                    progress: match progress {
                        RecoveryProgressWire::Signaled => RecoveryProgress::Signaled,
                        RecoveryProgressWire::Resent => RecoveryProgress::Resent,
                        RecoveryProgressWire::Probed(probe) => {
                            RecoveryProgress::Probed(MessageId::from_bytes(probe))
                        }
                    },
                }),
            sent_before_acceptance: wire
                .sent_before_acceptance
                .iter()
                .map(|(message_id, grant)| SentBeforeAcceptance {
                    message_id: MessageId::from_bytes(*message_id),
                    grant: grant.map(DiscoveryKeyStamp::from_wire),
                })
                .collect(),
            grant_update_before_acceptance: wire.grant_update_before_acceptance.map(
                |(message_id, grant)| SentBeforeAcceptance {
                    message_id: MessageId::from_bytes(message_id),
                    grant: grant.map(DiscoveryKeyStamp::from_wire),
                },
            ),
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
    identity_key: &IdentityKey,
    wire: &DiscoveryKeyWire,
) -> Result<ContactDiscoveryKey, ProtocolStateError> {
    let (Some(public), Some(identity_verifying_key)) = (
        parse_discovery_key(
            wire.x25519_public_key,
            &wire.ed25519_verifying_key,
            wire.epoch,
            wire.created_at_secs,
            &signature_from_wire(&wire.identity_signature),
        ),
        parse_ed25519_verifying_key_bytes(&identity_key.ed25519_verifying_key),
    ) else {
        return Err(decode_error(address, "contact discovery key is invalid"));
    };
    roost_crypto::verify_public_discovery_key(&public, &identity_verifying_key)
        .map_err(|_| decode_error(address, "contact discovery key signature failed"))?;
    Ok(ContactDiscoveryKey::from(&public))
}

// A message ID sent before acceptance and the stamp of the grant it carried.
type SentBeforeAcceptanceWire = ([u8; MESSAGE_ID_LEN], Option<(u64, u32)>);

// When a recovery was signaled, and how far it got.
type RecoverySignalWire = (u64, RecoveryProgressWire);

#[derive(Clone, Copy, Deserialize, Serialize)]
enum RecoveryProgressWire {
    Signaled,
    Resent,
    Probed([u8; MESSAGE_ID_LEN]),
}

#[derive(Serialize)]
struct ContactRecordWire<'a> {
    identity_x25519_public_key: [u8; PUBLIC_KEY_LEN],
    identity_ed25519_verifying_key: [u8; PUBLIC_KEY_LEN],
    discovery_key: Option<DiscoveryKeyWire>,
    delivery_capability: Option<&'a [u8; CAPABILITY_LEN]>,
    acknowledged_grant: Option<(u64, u32)>,
    trust_state: ContactTrustState,
    blocked: bool,
    sent_before_acceptance: &'a [SentBeforeAcceptanceWire],
    grant_update_before_acceptance: Option<SentBeforeAcceptanceWire>,
    received_before_acceptance: &'a [[u8; MESSAGE_ID_LEN]],
    needs_discovery_key_check: bool,
    recovery: Option<RecoverySignalWire>,
}

#[derive(Deserialize, ZeroizeOnDrop)]
struct DecodedContactRecordWire {
    #[zeroize(skip)]
    identity_x25519_public_key: [u8; PUBLIC_KEY_LEN],
    #[zeroize(skip)]
    identity_ed25519_verifying_key: [u8; PUBLIC_KEY_LEN],
    #[zeroize(skip)]
    discovery_key: Option<DiscoveryKeyWire>,
    delivery_capability: Option<[u8; CAPABILITY_LEN]>,
    #[zeroize(skip)]
    acknowledged_grant: Option<(u64, u32)>,
    #[zeroize(skip)]
    trust_state: ContactTrustState,
    #[zeroize(skip)]
    blocked: bool,
    #[zeroize(skip)]
    #[serde(deserialize_with = "deserialize_bounded::<_, _, MAX_MESSAGES_BEFORE_ACCEPTANCE>")]
    sent_before_acceptance: Vec<SentBeforeAcceptanceWire>,
    #[zeroize(skip)]
    grant_update_before_acceptance: Option<SentBeforeAcceptanceWire>,
    #[zeroize(skip)]
    #[serde(deserialize_with = "deserialize_bounded::<_, _, MAX_MESSAGES_BEFORE_ACCEPTANCE>")]
    received_before_acceptance: Vec<[u8; MESSAGE_ID_LEN]>,
    #[zeroize(skip)]
    needs_discovery_key_check: bool,
    #[zeroize(skip)]
    recovery: Option<RecoverySignalWire>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use roost_crypto::Signature;

    fn discovery_key(seed: u8, created_at_secs: u64, epoch: u32) -> ContactDiscoveryKey {
        ContactDiscoveryKey {
            x25519_public_key: [seed; PUBLIC_KEY_LEN],
            ed25519_verifying_key: [seed; PUBLIC_KEY_LEN],
            epoch,
            created_at_secs,
            identity_signature: [seed; Signature::BYTE_SIZE],
        }
    }

    fn grant(discovery_key: ContactDiscoveryKey, capability: u8) -> InboxGrant {
        InboxGrant {
            discovery_key,
            delivery_capability: Zeroizing::new([capability; CAPABILITY_LEN]),
        }
    }

    fn contact(discovery_key: ContactDiscoveryKey) -> ContactRecord {
        let identity_key = IdentityKey {
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
            Err(ProtocolStateError::PendingLimitReached {
                limit: MAX_MESSAGES_BEFORE_ACCEPTANCE
            })
        ));
        assert_eq!(
            contact.count_received(ids[MAX_MESSAGES_BEFORE_ACCEPTANCE]),
            ReceivedCount::PastLimit
        );
    }

    #[test]
    fn the_asked_side_keeps_its_grant_until_it_accepts_and_a_blocked_contact_never_gets_it() {
        let current = DiscoveryKeyStamp {
            created_at_secs: 100,
            epoch: 1,
        };
        let mut contact = contact(discovery_key(1, 100, 1));

        assert!(!contact.receives_grant(Starter::Peer, current));
        assert!(contact.receives_grant(Starter::Local, current));
        contact.accept();
        assert!(contact.receives_grant(Starter::Peer, current));
        contact.blocked = true;
        assert!(!contact.receives_grant(Starter::Peer, current));
        assert!(!contact.receives_grant(Starter::Local, current));
    }

    #[test]
    fn a_contact_record_is_stored_under_the_contacts_identity_key() {
        let identity_key = IdentityKey {
            x25519_public_key: [7; PUBLIC_KEY_LEN],
            ed25519_verifying_key: [8; PUBLIC_KEY_LEN],
        };
        let address = contact_address(identity_key);
        assert_eq!(address.kind(), ProtocolStateKind::ContactState);
        assert_eq!(address.key().as_bytes(), identity_key.canonical_encoding());
    }
}
