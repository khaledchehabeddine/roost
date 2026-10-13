//! Session state, and the Sessions Roost keeps with each peer and which one it sends on.

use super::{
    ContactIdentityKeyWire, ProtocolStateAddress, ProtocolStateBlob, ProtocolStateError,
    ProtocolStateKey, ProtocolStateKind, ProtocolStateSnapshot, SessionUnrecoverableReason,
    blob_body, encode_blob, encode_zeroizing, validate_session_contact_identity_key,
};
use crate::contact::ContactIdentityKey;
use crate::hardening::ProtocolHardeningLimits;
use roost_crypto::{Handshake, PublicKey, RatchetState, SealedFramePreKeyReference};
use roost_protocol::{PUBLIC_KEY_LEN, SessionId, is_valid_x25519_public_key};
use serde::{Deserialize, Serialize};

/// Most Sessions kept per peer besides the one Roost sends on.
const MAX_OLDER_SESSIONS: usize = 5;
/// Most deleted SessionIDs remembered per peer.
const MAX_DELETED_SESSIONS: usize = 5;

pub(super) fn session_address(session_id: SessionId) -> ProtocolStateAddress {
    ProtocolStateAddress::new(ProtocolStateKind::RatchetSession, session_id.into())
}

pub(super) fn pending_acknowledgment_address(session_id: SessionId) -> ProtocolStateAddress {
    ProtocolStateAddress::new(ProtocolStateKind::PendingAcknowledgments, session_id.into())
}

/// Returns the addresses of the records a Session keeps.
pub(super) fn session_record_addresses(session_id: SessionId) -> [ProtocolStateAddress; 2] {
    [
        session_address(session_id),
        pending_acknowledgment_address(session_id),
    ]
}

pub(super) fn peer_sessions_address(identity_key: ContactIdentityKey) -> ProtocolStateAddress {
    ProtocolStateAddress::new(ProtocolStateKind::PeerSessions, identity_key.into())
}

impl From<SessionId> for ProtocolStateKey {
    fn from(value: SessionId) -> Self {
        Self(value.as_bytes().to_vec())
    }
}

/// A decoded Session blob.
pub(super) struct LoadedSession {
    /// The peer the handshake authenticated, fixed for the Session's life.
    pub(super) peer_identity_key: ContactIdentityKey,
    pub(super) status: SessionStatus,
}

pub(super) enum SessionStatus {
    Active {
        state: Box<RatchetState>,
        /// The handshake this side started, which its Messages carry until the peer replies, or for
        /// a Contact Request until the peer accepts.
        pending_handshake: Option<PendingHandshake>,
    },
    Unrecoverable {
        reason: SessionUnrecoverableReason,
        event_emitted: bool,
    },
}

/// A handshake this side started, and the signed prekey ID its route names.
#[derive(Clone, Copy)]
pub(super) struct PendingHandshake {
    pub(super) handshake: Handshake,
    pub(super) signed_prekey_id: u64,
}

/// Returns the Session at `address`, or `None` when the snapshot has none.
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

pub(super) fn encode_active_session(
    address: &ProtocolStateAddress,
    peer_identity_key: ContactIdentityKey,
    state: &RatchetState,
    pending_handshake: Option<&PendingHandshake>,
    limits: ProtocolHardeningLimits,
) -> Result<ProtocolStateBlob, ProtocolStateError> {
    let ratchet_state = state.to_bytes()?;
    encode_session_wire(
        address,
        &SessionWire {
            peer_identity_key: peer_identity_key.into(),
            status: SessionStatusWire::Active {
                ratchet_state: &ratchet_state,
                pending_handshake: pending_handshake.map(HandshakeWire::from),
            },
        },
        limits,
    )
}

pub(super) fn encode_unrecoverable_session(
    address: &ProtocolStateAddress,
    peer_identity_key: ContactIdentityKey,
    reason: SessionUnrecoverableReason,
    event_emitted: bool,
    limits: ProtocolHardeningLimits,
) -> Result<ProtocolStateBlob, ProtocolStateError> {
    encode_session_wire(
        address,
        &SessionWire {
            peer_identity_key: peer_identity_key.into(),
            status: SessionStatusWire::Unrecoverable {
                reason,
                event_emitted,
            },
        },
        limits,
    )
}

fn encode_session_wire(
    address: &ProtocolStateAddress,
    wire: &SessionWire<'_>,
    limits: ProtocolHardeningLimits,
) -> Result<ProtocolStateBlob, ProtocolStateError> {
    let body = encode_zeroizing(wire).map_err(|_| ProtocolStateError::BlobEncode {
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
    let body = blob_body(address, blob, limits.max_protocol_state_blob_len)?;
    // Borrow ratchet bytes so a failed decode or key validation leaves no unsanitized heap copy.
    let (wire, trailing): (SessionWire<'_>, &[u8]) = postcard::take_from_bytes(body)
        .map_err(|_| decode_error(address, "ratchet/session state failed to decode"))?;
    if !trailing.is_empty() {
        return Err(decode_error(
            address,
            "ratchet/session state has trailing bytes",
        ));
    }
    let peer_identity_key =
        validate_session_contact_identity_key(address, wire.peer_identity_key.into())?;
    let status = match wire.status {
        SessionStatusWire::Active {
            ratchet_state,
            pending_handshake,
        } => SessionStatus::Active {
            state: Box::new(
                RatchetState::from_bytes(ratchet_state)
                    .map_err(|_| decode_error(address, "ratchet/session state failed to decode"))?,
            ),
            pending_handshake: pending_handshake
                .map(|handshake| handshake.to_handshake(address))
                .transpose()?,
        },
        SessionStatusWire::Unrecoverable {
            reason,
            event_emitted,
        } => SessionStatus::Unrecoverable {
            reason,
            event_emitted,
        },
    };
    Ok(LoadedSession {
        peer_identity_key,
        status,
    })
}

/// Where a responder's Session came from, so its SessionID can be refused while the prekey that
/// could recreate it still exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SignedPreKeyUse {
    pub(super) epoch: u32,
    pub(super) public_key: [u8; PUBLIC_KEY_LEN],
}

/// Which side started a Session with its handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Starter {
    Local,
    Peer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SessionEntry {
    pub(super) session_id: SessionId,
    /// The signed prekey this side accepted the Session with, or `None` if this side started it.
    accepted_with: Option<SignedPreKeyUse>,
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

/// The Sessions kept with one peer: the one Roost sends on, older ones that still receive, and
/// deleted SessionIDs a replayed first Message must not bring back.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct PeerSessions {
    current: SessionEntry,
    /// Oldest first.
    older: Vec<SessionEntry>,
    /// Oldest first.
    deleted: Vec<DeletedSession>,
}

impl PeerSessions {
    /// Starts the list with its first Session.
    pub(super) fn new(session_id: SessionId, accepted_with: Option<SignedPreKeyUse>) -> Self {
        Self {
            current: SessionEntry {
                session_id,
                accepted_with,
            },
            older: Vec::new(),
            deleted: Vec::new(),
        }
    }

    /// Returns the Session Roost sends on.
    pub(super) fn current(&self) -> SessionId {
        self.current.session_id
    }

    /// Returns which side started the Session Roost sends on.
    pub(super) fn current_starter(&self) -> Starter {
        self.current.starter()
    }

    /// Returns which side started `session_id`, or `None` when it isn't one of this peer's
    /// Sessions.
    pub(super) fn starter(&self, session_id: SessionId) -> Option<Starter> {
        std::iter::once(&self.current)
            .chain(&self.older)
            .find(|entry| entry.session_id == session_id)
            .map(SessionEntry::starter)
    }

    /// Returns whether `session_id` is one of this peer's Sessions.
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

    /// Forgets deleted SessionIDs whose signed prekey is gone, since no handshake can recreate them.
    pub(super) fn forget_deletions_unless(&mut self, is_held: impl Fn(&SignedPreKeyUse) -> bool) {
        self.deleted
            .retain(|deleted| is_held(&deleted.signed_prekey));
    }

    /// Returns the Sessions starting one more would evict, whichever Session it makes current.
    pub(super) fn evicted_by_next_start(&self) -> &[SessionEntry] {
        let excess = (self.older.len() + 1).saturating_sub(MAX_OLDER_SESSIONS);
        &self.older[..excess]
    }

    /// Makes a new Session the one Roost sends on, and returns the Sessions this evicts.
    pub(super) fn start(
        &mut self,
        session_id: SessionId,
        accepted_with: Option<SignedPreKeyUse>,
    ) -> Vec<SessionId> {
        let previous = std::mem::replace(
            &mut self.current,
            SessionEntry {
                session_id,
                accepted_with,
            },
        );
        self.older.push(previous);
        self.evict()
    }

    /// Adds a Session the peer started while this side's own start still awaits a reply, and
    /// returns the Sessions this evicts.
    ///
    /// Both peers keep the lower SessionID, so they converge when they start at once.
    pub(super) fn start_alongside(
        &mut self,
        session_id: SessionId,
        accepted_with: Option<SignedPreKeyUse>,
    ) -> Vec<SessionId> {
        if session_id < self.current.session_id {
            return self.start(session_id, accepted_with);
        }
        self.older.push(SessionEntry {
            session_id,
            accepted_with,
        });
        self.evict()
    }

    /// Makes `session_id` the one Roost sends on because it just delivered a Message, and returns
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

    // Deletes the oldest Sessions beyond the limit, remembering the ones this side accepted.
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
    let body = blob_body(address, blob, limits.max_protocol_state_blob_len)?;
    let (wire, trailing): (PeerSessionsWire, &[u8]) = postcard::take_from_bytes(body)
        .map_err(|_| decode_error(address, "peer sessions failed to decode"))?;
    if !trailing.is_empty() {
        return Err(decode_error(address, "peer sessions have trailing bytes"));
    }
    if wire.older.len() > MAX_OLDER_SESSIONS || wire.deleted.len() > MAX_DELETED_SESSIONS {
        return Err(decode_error(address, "peer sessions exceed their limit"));
    }
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

fn decode_error(address: &ProtocolStateAddress, reason: &str) -> ProtocolStateError {
    ProtocolStateError::BlobDecode {
        address: address.clone(),
        reason: reason.into(),
    }
}

#[derive(Deserialize, Serialize)]
struct SessionWire<'a> {
    peer_identity_key: ContactIdentityKeyWire,
    #[serde(borrow)]
    status: SessionStatusWire<'a>,
}

#[derive(Deserialize, Serialize)]
enum SessionStatusWire<'a> {
    Active {
        #[serde(borrow)]
        ratchet_state: &'a [u8],
        pending_handshake: Option<HandshakeWire>,
    },
    Unrecoverable {
        reason: SessionUnrecoverableReason,
        event_emitted: bool,
    },
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
                .one_time_prekey_id
                .zip(reference.one_time_prekey_public_key),
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
                    one_time_prekey_id: self.one_time_prekey.map(|(id, _)| id),
                    one_time_prekey_public_key: self.one_time_prekey.map(|(_, key)| key),
                },
            },
            signed_prekey_id: self.signed_prekey_id,
        })
    }
}

#[derive(Deserialize, Serialize)]
struct PeerSessionsWire {
    current: SessionEntryWire,
    older: Vec<SessionEntryWire>,
    deleted: Vec<DeletedSessionWire>,
}

#[derive(Deserialize, Serialize)]
struct SessionEntryWire {
    session_id: [u8; 16],
    accepted_with: Option<SignedPreKeyUseWire>,
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
        }
    }
}

impl From<SessionEntryWire> for SessionEntry {
    fn from(value: SessionEntryWire) -> Self {
        Self {
            session_id: SessionId::from_bytes(value.session_id),
            accepted_with: value.accepted_with.map(Into::into),
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
        let peer_identity_key = ContactIdentityKey {
            x25519_public_key: [9; 32],
            ed25519_verifying_key: [9; 32],
        };
        let mut bytes = vec![super::super::PROTOCOL_STATE_BLOB_VERSION];
        bytes.extend(
            postcard::to_stdvec(&SessionWire {
                peer_identity_key: peer_identity_key.into(),
                status: SessionStatusWire::Active {
                    ratchet_state: &[0x42],
                    pending_handshake: None,
                },
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
    fn starting_sessions_keeps_five_older_and_remembers_evicted_accepted_ones() {
        let mut sessions = PeerSessions::new(id(1), accepted(1));
        let mut evicted = Vec::new();
        for byte in 2..=8 {
            let accepted_with = if byte % 2 == 0 { None } else { accepted(byte) };
            evicted.extend(sessions.start(id(byte), accepted_with));
        }

        assert_eq!(sessions.current(), id(8));
        assert_eq!(evicted, vec![id(1), id(2)]);
        assert!(sessions.was_deleted(id(1)));
        assert!(!sessions.was_deleted(id(2)));
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
    fn simultaneous_start_keeps_the_lower_session_current() {
        let mut lower_first = PeerSessions::new(id(1), None);
        lower_first.start_alongside(id(2), accepted(2));
        let mut higher_first = PeerSessions::new(id(2), None);
        higher_first.start_alongside(id(1), accepted(1));

        assert_eq!(lower_first.current(), id(1));
        assert_eq!(higher_first.current(), id(1));
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
        let address = peer_sessions_address(ContactIdentityKey {
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
            Err(ProtocolStateError::InvalidStateBinding { .. })
        ));
    }
}
