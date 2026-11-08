use super::{
    IdentityKeyWire, ProtocolStateAddress, ProtocolStateBlob, ProtocolStateError, ProtocolStateKey,
    ProtocolStateKind, ProtocolStateSnapshot, decode_blob, decode_error, deserialize_bounded,
    encode_blob, encode_zeroizing,
};
use crate::hardening::ProtocolHardeningLimits;
use roost_crypto::{
    Handshake, OneTimePreKeyReference, PublicKey, RatchetState, SealedFramePreKeyReference,
};
use roost_protocol::{IdentityKey, PUBLIC_KEY_LEN, SessionId, is_valid_x25519_public_key};
use serde::{Deserialize, Serialize};

/// Most sessions kept per peer besides the one Roost sends on.
const MAX_OLDER_SESSIONS: usize = 5;
const MAX_DELETED_SESSIONS: usize = 5;

pub(super) fn session_address(session_id: SessionId) -> ProtocolStateAddress {
    ProtocolStateAddress::new(ProtocolStateKind::RatchetSession, session_id.into())
}

pub(super) fn pending_acknowledgment_address(session_id: SessionId) -> ProtocolStateAddress {
    ProtocolStateAddress::new(ProtocolStateKind::PendingAcknowledgments, session_id.into())
}

pub(super) fn session_record_addresses(session_id: SessionId) -> [ProtocolStateAddress; 2] {
    [
        session_address(session_id),
        pending_acknowledgment_address(session_id),
    ]
}

pub(super) fn peer_sessions_address(identity_key: IdentityKey) -> ProtocolStateAddress {
    ProtocolStateAddress::new(ProtocolStateKind::PeerSessions, identity_key.into())
}

impl From<SessionId> for ProtocolStateKey {
    fn from(value: SessionId) -> Self {
        Self(value.as_bytes().to_vec())
    }
}

pub(super) struct LoadedSession {
    /// The peer the handshake authenticated, fixed for the session's life.
    pub(super) peer_identity_key: IdentityKey,
    pub(super) state: Box<RatchetState>,
    /// The handshake this side started, which its messages carry until the peer replies, or for a
    /// contact request until the peer accepts.
    pub(super) pending_handshake: Option<PendingHandshake>,
}

/// A handshake this side started, and the signed prekey ID its route names.
#[derive(Clone, Copy)]
pub(super) struct PendingHandshake {
    pub(super) handshake: Handshake,
    pub(super) signed_prekey_id: u64,
}

pub(super) fn load_session(
    snapshot: &ProtocolStateSnapshot,
    address: &ProtocolStateAddress,
    limits: ProtocolHardeningLimits,
) -> Result<Option<LoadedSession>, ProtocolStateError> {
    snapshot
        .get(address)
        .map(|blob| decode_session(address, blob, limits))
        .transpose()
}

pub(super) fn load_required_session(
    snapshot: &ProtocolStateSnapshot,
    address: &ProtocolStateAddress,
    limits: ProtocolHardeningLimits,
) -> Result<LoadedSession, ProtocolStateError> {
    load_session(snapshot, address, limits)?.ok_or_else(|| {
        ProtocolStateError::MissingRequiredState {
            address: address.clone(),
        }
    })
}

pub(super) fn encode_session(
    address: &ProtocolStateAddress,
    peer_identity_key: IdentityKey,
    state: &RatchetState,
    pending_handshake: Option<&PendingHandshake>,
    limits: ProtocolHardeningLimits,
) -> Result<ProtocolStateBlob, ProtocolStateError> {
    let ratchet_state = state.to_bytes()?;
    let wire = SessionWire {
        peer_identity_key: peer_identity_key.into(),
        ratchet_state: &ratchet_state,
        pending_handshake: pending_handshake.map(HandshakeWire::from),
    };
    let body = encode_zeroizing(&wire).map_err(|_| ProtocolStateError::BlobEncode {
        address: address.clone(),
        reason: "ratchet/session state failed to encode".into(),
    })?;
    encode_blob(address, &body, limits.max_protocol_state_blob_len)
}

fn decode_session(
    address: &ProtocolStateAddress,
    blob: &ProtocolStateBlob,
    limits: ProtocolHardeningLimits,
) -> Result<LoadedSession, ProtocolStateError> {
    // Borrow ratchet bytes so a failed decode or key validation leaves no unsanitized heap copy.
    let wire: SessionWire<'_> = decode_blob(address, blob, limits.max_protocol_state_blob_len)?;
    let peer_identity_key = IdentityKey::from(wire.peer_identity_key);
    if !peer_identity_key.is_valid() {
        return Err(decode_error(
            address,
            "session contact identity key is invalid",
        ));
    }
    Ok(LoadedSession {
        peer_identity_key,
        state: Box::new(
            RatchetState::from_bytes(wire.ratchet_state)
                .map_err(|_| decode_error(address, "ratchet/session state failed to decode"))?,
        ),
        pending_handshake: wire
            .pending_handshake
            .map(|handshake| handshake.to_handshake(address))
            .transpose()?,
    })
}

/// Where a responder's session came from, so its session ID can be refused while the prekey that
/// could recreate it still exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SignedPreKeyUse {
    pub(super) epoch: u32,
    pub(super) public_key: [u8; PUBLIC_KEY_LEN],
}

/// Which side started a session with its handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Starter {
    Local,
    Peer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SessionEntry {
    pub(super) session_id: SessionId,
    /// The signed prekey this side accepted the session with, or `None` if this side started it.
    accepted_with: Option<SignedPreKeyUse>,
    /// Where the session falls in the order this side started or accepted the peer's sessions.
    position: u64,
}

impl SessionEntry {
    fn starter(&self) -> Starter {
        match self.accepted_with {
            Some(_) => Starter::Peer,
            None => Starter::Local,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DeletedSession {
    session_id: SessionId,
    signed_prekey: SignedPreKeyUse,
}

/// The sessions kept with one peer: the one Roost sends on, older ones that still receive, and
/// deleted session IDs a replayed first message must not bring back.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct PeerSessions {
    current: SessionEntry,
    /// Oldest first.
    older: Vec<SessionEntry>,
    /// Oldest first.
    deleted: Vec<DeletedSession>,
}

impl PeerSessions {
    pub(super) fn new(session_id: SessionId, accepted_with: Option<SignedPreKeyUse>) -> Self {
        Self {
            current: SessionEntry {
                session_id,
                accepted_with,
                position: 0,
            },
            older: Vec::new(),
            deleted: Vec::new(),
        }
    }

    /// Returns the session Roost sends on.
    pub(super) fn current(&self) -> SessionId {
        self.current.session_id
    }

    pub(super) fn current_starter(&self) -> Starter {
        self.current.starter()
    }

    pub(super) fn starter(&self, session_id: SessionId) -> Option<Starter> {
        self.entry(session_id).map(SessionEntry::starter)
    }

    /// Returns every session kept with this peer, the one Roost sends on first.
    pub(super) fn session_ids(&self) -> impl Iterator<Item = SessionId> + '_ {
        self.entries().map(|entry| entry.session_id)
    }

    /// Returns whether this side started or accepted `session_id` before `later`, or `false` when
    /// either isn't kept with this peer.
    pub(super) fn started_before(&self, session_id: SessionId, later: SessionId) -> bool {
        let position = |session_id| self.entry(session_id).map(|entry| entry.position);
        position(session_id)
            .zip(position(later))
            .is_some_and(|(earlier, later)| earlier < later)
    }

    pub(super) fn contains(&self, session_id: SessionId) -> bool {
        self.current.session_id == session_id
            || self
                .older
                .iter()
                .any(|entry| entry.session_id == session_id)
    }

    /// Returns whether `session_id` was deleted and must not be recreated.
    pub(super) fn was_deleted(&self, session_id: SessionId) -> bool {
        self.deleted
            .iter()
            .any(|deleted| deleted.session_id == session_id)
    }

    /// Forgets deleted session IDs whose signed prekey is gone, since no handshake can recreate
    /// them.
    pub(super) fn forget_deletions_unless(&mut self, is_held: impl Fn(&SignedPreKeyUse) -> bool) {
        self.deleted
            .retain(|deleted| is_held(&deleted.signed_prekey));
    }

    /// Returns the sessions starting one more would evict, whichever session it makes current.
    pub(super) fn evicted_by_next_start(&self) -> &[SessionEntry] {
        let excess = (self.older.len() + 1).saturating_sub(MAX_OLDER_SESSIONS);
        &self.older[..excess]
    }

    /// Makes a new session the one Roost sends on, and returns the sessions this evicts.
    pub(super) fn start(
        &mut self,
        session_id: SessionId,
        accepted_with: Option<SignedPreKeyUse>,
    ) -> Vec<SessionId> {
        let entry = self.next_entry(session_id, accepted_with);
        let previous = std::mem::replace(&mut self.current, entry);
        self.older.push(previous);
        self.evict()
    }

    /// Adds a session the peer started while this side's own start still awaits a reply, and
    /// returns the sessions this evicts.
    ///
    /// Both peers send on the lower session ID, so they converge when they start at once.
    pub(super) fn start_alongside(
        &mut self,
        session_id: SessionId,
        accepted_with: Option<SignedPreKeyUse>,
    ) -> Vec<SessionId> {
        if session_id < self.current.session_id {
            return self.start(session_id, accepted_with);
        }
        let entry = self.next_entry(session_id, accepted_with);
        self.older.push(entry);
        self.evict()
    }

    // Returns the entry for a session that starts after every one kept. A peer can't start
    // `u64::MAX` sessions, so the position never saturates.
    fn next_entry(
        &self,
        session_id: SessionId,
        accepted_with: Option<SignedPreKeyUse>,
    ) -> SessionEntry {
        let last = self
            .entries()
            .map(|entry| entry.position)
            .max()
            .unwrap_or_default();
        SessionEntry {
            session_id,
            accepted_with,
            position: last.saturating_add(1),
        }
    }

    fn entries(&self) -> impl Iterator<Item = &SessionEntry> {
        std::iter::once(&self.current).chain(&self.older)
    }

    fn entry(&self, session_id: SessionId) -> Option<&SessionEntry> {
        self.entries().find(|entry| entry.session_id == session_id)
    }

    /// Makes `session_id` the one Roost sends on because it just delivered a message, and returns
    /// whether that changed anything.
    pub(super) fn record_delivery(
        &mut self,
        address: &ProtocolStateAddress,
        session_id: SessionId,
    ) -> Result<bool, ProtocolStateError> {
        if self.current.session_id == session_id {
            return Ok(false);
        }
        let index = self
            .older
            .iter()
            .position(|entry| entry.session_id == session_id)
            .ok_or_else(|| ProtocolStateError::InvalidStateBinding {
                address: address.clone(),
                reason: "session is not kept for its peer".into(),
            })?;
        let delivered = self.older.remove(index);
        let previous = std::mem::replace(&mut self.current, delivered);
        self.older.push(previous);
        Ok(true)
    }

    // Deletes the oldest sessions beyond the limit, remembering the ones this side accepted.
    fn evict(&mut self) -> Vec<SessionId> {
        let excess = self.older.len().saturating_sub(MAX_OLDER_SESSIONS);
        let evicted: Vec<SessionEntry> = self.older.drain(..excess).collect();
        for entry in &evicted {
            if let Some(signed_prekey) = entry.accepted_with {
                self.deleted.push(DeletedSession {
                    session_id: entry.session_id,
                    signed_prekey,
                });
            }
        }
        let forgotten = self.deleted.len().saturating_sub(MAX_DELETED_SESSIONS);
        self.deleted.drain(..forgotten);
        evicted.iter().map(|entry| entry.session_id).collect()
    }
}

pub(super) fn load_peer_sessions(
    snapshot: &ProtocolStateSnapshot,
    address: &ProtocolStateAddress,
    limits: ProtocolHardeningLimits,
) -> Result<Option<PeerSessions>, ProtocolStateError> {
    let Some(blob) = snapshot.get(address) else {
        return Ok(None);
    };
    let wire: PeerSessionsWire = decode_blob(address, blob, limits.max_protocol_state_blob_len)?;
    let sessions = PeerSessions {
        current: wire.current.into(),
        older: wire.older.into_iter().map(Into::into).collect(),
        deleted: wire.deleted.into_iter().map(Into::into).collect(),
    };
    let mut session_ids: Vec<SessionId> = std::iter::once(&sessions.current)
        .chain(&sessions.older)
        .map(|entry| entry.session_id)
        .chain(sessions.deleted.iter().map(|deleted| deleted.session_id))
        .collect();
    session_ids.sort_unstable();
    if session_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(decode_error(address, "peer sessions repeat a session"));
    }
    Ok(Some(sessions))
}

pub(super) fn encode_peer_sessions(
    address: &ProtocolStateAddress,
    sessions: &PeerSessions,
    limits: ProtocolHardeningLimits,
) -> Result<ProtocolStateBlob, ProtocolStateError> {
    let body = postcard::to_stdvec(&PeerSessionsWire {
        current: sessions.current.into(),
        older: sessions.older.iter().copied().map(Into::into).collect(),
        deleted: sessions.deleted.iter().copied().map(Into::into).collect(),
    })
    .map_err(|_| ProtocolStateError::BlobEncode {
        address: address.clone(),
        reason: "peer sessions failed to encode".into(),
    })?;
    encode_blob(address, &body, limits.max_protocol_state_blob_len)
}

#[derive(Deserialize, Serialize)]
struct SessionWire<'a> {
    peer_identity_key: IdentityKeyWire,
    #[serde(borrow)]
    ratchet_state: &'a [u8],
    pending_handshake: Option<HandshakeWire>,
}

#[derive(Deserialize, Serialize)]
struct HandshakeWire {
    base_key: [u8; PUBLIC_KEY_LEN],
    responder_discovery_key: [u8; PUBLIC_KEY_LEN],
    discovery_epoch: u32,
    signed_prekey_id: u64,
    signed_prekey_public_key: [u8; PUBLIC_KEY_LEN],
    one_time_prekey: Option<(u64, [u8; PUBLIC_KEY_LEN])>,
}

impl From<&PendingHandshake> for HandshakeWire {
    fn from(value: &PendingHandshake) -> Self {
        let reference = value.handshake.prekey_reference;
        Self {
            base_key: *value.handshake.base_key.as_bytes(),
            responder_discovery_key: *value.handshake.responder_discovery_key.as_bytes(),
            discovery_epoch: reference.discovery_epoch,
            signed_prekey_id: value.signed_prekey_id,
            signed_prekey_public_key: reference.signed_prekey_public_key,
            one_time_prekey: reference
                .one_time_prekey
                .map(|prekey| (prekey.id, prekey.public_key)),
        }
    }
}

impl HandshakeWire {
    fn to_handshake(
        &self,
        address: &ProtocolStateAddress,
    ) -> Result<PendingHandshake, ProtocolStateError> {
        let keys_valid = [
            &self.base_key,
            &self.responder_discovery_key,
            &self.signed_prekey_public_key,
        ]
        .into_iter()
        .chain(self.one_time_prekey.as_ref().map(|(_, key)| key))
        .all(is_valid_x25519_public_key);
        if !keys_valid {
            return Err(decode_error(address, "session handshake key is invalid"));
        }
        Ok(PendingHandshake {
            handshake: Handshake {
                base_key: PublicKey::from(self.base_key),
                responder_discovery_key: PublicKey::from(self.responder_discovery_key),
                prekey_reference: SealedFramePreKeyReference {
                    discovery_epoch: self.discovery_epoch,
                    signed_prekey_public_key: self.signed_prekey_public_key,
                    one_time_prekey: self
                        .one_time_prekey
                        .map(|(id, public_key)| OneTimePreKeyReference { id, public_key }),
                },
            },
            signed_prekey_id: self.signed_prekey_id,
        })
    }
}

#[derive(Deserialize, Serialize)]
struct PeerSessionsWire {
    current: SessionEntryWire,
    #[serde(deserialize_with = "deserialize_bounded::<_, _, MAX_OLDER_SESSIONS>")]
    older: Vec<SessionEntryWire>,
    #[serde(deserialize_with = "deserialize_bounded::<_, _, MAX_DELETED_SESSIONS>")]
    deleted: Vec<DeletedSessionWire>,
}

#[derive(Deserialize, Serialize)]
struct SessionEntryWire {
    session_id: [u8; 16],
    accepted_with: Option<SignedPreKeyUseWire>,
    position: u64,
}

#[derive(Deserialize, Serialize)]
struct DeletedSessionWire {
    session_id: [u8; 16],
    signed_prekey: SignedPreKeyUseWire,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
struct SignedPreKeyUseWire {
    epoch: u32,
    public_key: [u8; PUBLIC_KEY_LEN],
}

impl From<SessionEntry> for SessionEntryWire {
    fn from(value: SessionEntry) -> Self {
        Self {
            session_id: *value.session_id.as_bytes(),
            accepted_with: value.accepted_with.map(Into::into),
            position: value.position,
        }
    }
}

impl From<SessionEntryWire> for SessionEntry {
    fn from(value: SessionEntryWire) -> Self {
        Self {
            session_id: SessionId::from_bytes(value.session_id),
            accepted_with: value.accepted_with.map(Into::into),
            position: value.position,
        }
    }
}

impl From<DeletedSession> for DeletedSessionWire {
    fn from(value: DeletedSession) -> Self {
        Self {
            session_id: *value.session_id.as_bytes(),
            signed_prekey: value.signed_prekey.into(),
        }
    }
}

impl From<DeletedSessionWire> for DeletedSession {
    fn from(value: DeletedSessionWire) -> Self {
        Self {
            session_id: SessionId::from_bytes(value.session_id),
            signed_prekey: value.signed_prekey.into(),
        }
    }
}

impl From<SignedPreKeyUse> for SignedPreKeyUseWire {
    fn from(value: SignedPreKeyUse) -> Self {
        Self {
            epoch: value.epoch,
            public_key: value.public_key,
        }
    }
}

impl From<SignedPreKeyUseWire> for SignedPreKeyUse {
    fn from(value: SignedPreKeyUseWire) -> Self {
        Self {
            epoch: value.epoch,
            public_key: value.public_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> SessionId {
        SessionId::from_bytes([byte; 16])
    }

    fn accepted(byte: u8) -> Option<SignedPreKeyUse> {
        Some(SignedPreKeyUse {
            epoch: 1,
            public_key: [byte; 32],
        })
    }

    #[test]
    fn nested_ratchet_decode_failure_does_not_echo_state_bytes() {
        let address = session_address(id(9));
        let peer_identity_key = IdentityKey {
            x25519_public_key: [9; 32],
            ed25519_verifying_key: [9; 32],
        };
        let mut bytes = vec![super::super::PROTOCOL_STATE_BLOB_VERSION];
        bytes.extend(
            postcard::to_stdvec(&SessionWire {
                peer_identity_key: peer_identity_key.into(),
                ratchet_state: &[0x42],
                pending_handshake: None,
            })
            .unwrap(),
        );
        let blob = ProtocolStateBlob::from_bytes(bytes);

        let Err(error) = decode_session(&address, &blob, ProtocolHardeningLimits::default()) else {
            panic!("malformed nested ratchet state decoded");
        };
        let rendered = error.to_string();
        assert!(
            matches!(&error, ProtocolStateError::BlobDecode { address: actual, reason }
            if *actual == address && reason == "ratchet/session state failed to decode"),
            "{rendered}"
        );
        assert!(!rendered.contains("66"));
        assert!(!rendered.contains("0x42"));
    }

    #[test]
    fn remembered_deletions_forget_the_oldest_beyond_five() {
        let mut sessions = PeerSessions::new(id(1), accepted(1));
        for byte in 2..=12 {
            sessions.start(id(byte), accepted(byte));
        }
        assert!(!sessions.was_deleted(id(1)));
        for byte in 2..=6 {
            assert!(sessions.was_deleted(id(byte)));
        }
    }

    #[test]
    fn deletions_are_forgotten_once_their_signed_prekey_is_gone() {
        let mut sessions = PeerSessions::new(id(1), accepted(1));
        for byte in 2..=8 {
            sessions.start(id(byte), accepted(byte % 2));
        }
        assert!(sessions.was_deleted(id(1)));
        assert!(sessions.was_deleted(id(2)));

        sessions.forget_deletions_unless(|signed_prekey| signed_prekey.public_key == [0; 32]);

        assert!(!sessions.was_deleted(id(1)));
        assert!(sessions.was_deleted(id(2)));
    }

    #[test]
    fn delivery_on_an_older_session_makes_it_current() {
        let address = peer_sessions_address(IdentityKey {
            x25519_public_key: [9; 32],
            ed25519_verifying_key: [9; 32],
        });
        let mut sessions = PeerSessions::new(id(1), None);
        sessions.start(id(2), accepted(2));

        assert!(sessions.record_delivery(&address, id(1)).unwrap());
        assert!(!sessions.record_delivery(&address, id(1)).unwrap());
        assert_eq!(sessions.current(), id(1));
        assert!(matches!(
            sessions.record_delivery(&address, id(3)),
            Err(ProtocolStateError::InvalidStateBinding { address: actual, reason })
                if actual == address && reason == "session is not kept for its peer"
        ));
    }

    #[test]
    fn a_sessions_records_are_stored_under_its_session_id() {
        let [session, pending] = session_record_addresses(id(9));
        assert_eq!(session.kind(), ProtocolStateKind::RatchetSession);
        assert_eq!(pending.kind(), ProtocolStateKind::PendingAcknowledgments);
        for address in [session, pending] {
            assert_eq!(address.key().as_bytes(), id(9).as_bytes());
        }
    }

    #[test]
    fn a_peers_session_list_is_stored_under_the_peers_identity_key() {
        let identity_key = IdentityKey {
            x25519_public_key: [7; PUBLIC_KEY_LEN],
            ed25519_verifying_key: [8; PUBLIC_KEY_LEN],
        };
        let address = peer_sessions_address(identity_key);
        assert_eq!(address.kind(), ProtocolStateKind::PeerSessions);
        assert_eq!(address.key().as_bytes(), identity_key.canonical_encoding());
    }
}
