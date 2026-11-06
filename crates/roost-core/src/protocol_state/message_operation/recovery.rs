//! Recovery: finding the messages a contact hasn't acknowledged, and encrypting them again on a
//! newer session after a delivery check signals it.

use super::super::contact_record::{
    ContactRecord, RecoveryProgress, contact_address, load_contact,
};
use super::super::pending_acknowledgment::{
    LoadedPendingAcknowledgment, LoadedPendingAcknowledgments, decode_pending_acknowledgments,
    encode_pending_acknowledgments,
};
use super::super::session::{
    PeerSessions, Starter, load_peer_sessions, load_session, peer_sessions_address,
    pending_acknowledgment_address, session_address, session_record_addresses,
};
use super::super::{
    ProtocolHardeningLimits, ProtocolStateAddress, ProtocolStateBlob, ProtocolStateEngine,
    ProtocolStateError, ProtocolStateSnapshot, ProtocolStateUpdate, StateChanges,
    validate_contact_identity_key,
};
use super::{
    DiscoveryKeyCheck, Encrypting, LocalIdentityKeys, MessageDestination, MessageEncryptionStep,
    MessageOperationError, OutboundMessageResult, OutgoingMessage, PeerPreKeyBundle, Planned,
    RotatedContact, SendIntent, SignedSenderCertificate, StateReads, changes, contact_update,
    content_kind, supply_state,
};
use crate::TransportBinding;
use crate::contact::{ContactDiscoveryKey, ContactIdentityKey};
use rand::{CryptoRng, RngCore};
use roost_protocol::{MessageId, PayloadKind, SessionId, to_unix_millis};
use std::time::{Duration, SystemTime};
use zeroize::Zeroizing;

/// How long a message waits for an acknowledgment before Roost signals a recovery. A contact who
/// is only offline looks the same as one that lost its session, so the wait is long.
const QUIET_PERIOD: Duration = Duration::from_secs(24 * 60 * 60);
/// How long after a recovery Roost may signal another one for messages still unacknowledged.
const RECHECK_PERIOD: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// How long the relay holds a message. An unacknowledged one shows as not delivered this long after
/// its first send, even if a resend can still arrive.
const UNDELIVERED_AFTER: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// What a delivery check found.
pub struct DeliveryCheckResult {
    /// Whether a recovery starts. The app commits its recovery job with the check's changes.
    pub starts_recovery: bool,
}

/// What a [`DeliveryCheck`] needs next, or its result.
pub enum DeliveryCheckStep {
    /// The records to supply through [`DeliveryCheck::supply_state`].
    NeedsState(Vec<ProtocolStateAddress>),
    /// What the check found, and the state changes to commit with the app's work for it. The
    /// check has ended.
    Ready {
        /// What the check found.
        result: DeliveryCheckResult,
        /// The state changes to commit with the recovery job. They list the messages whose first
        /// copy the relay would have dropped by now as undelivered.
        changes: StateChanges,
    },
}

/// A check, at a time the app passes, of the messages this identity sent one contact that the
/// contact hasn't acknowledged.
///
/// The check gives up on messages 30 days after their first send. It signals a recovery after a day
/// without an acknowledgment, or as soon as the contact sends an inbox grant newer than the one a
/// waiting message went to, delivers on a newer session, or acknowledges a recovery's probe, and
/// once signaled, a recovery comes back only after a week, after an unblock, or when the contact
/// proves a newer grant or session. Call [`Self::step`] until it returns
/// [`DeliveryCheckStep::Ready`], supplying the records each other step asks for. Dropping the check
/// commits nothing.
pub struct DeliveryCheck(Option<Box<Checking>>);

struct Checking {
    engine: ProtocolStateEngine,
    contact: ContactIdentityKey,
    now_millis: u64,
    reads: StateReads,
    phase: CheckPhase,
}

enum CheckPhase {
    Started,
    ContactRequested,
    SessionsRequested(Box<AcceptedContact>),
    Taken,
}

// An accepted contact's record and the sessions kept with it, which every step after the first
// reads.
struct AcceptedContact {
    contact: ContactRecord,
    sessions: PeerSessions,
}

impl ProtocolStateEngine {
    /// Starts checking the messages this identity sent `contact` that it hasn't acknowledged, at
    /// `now`.
    pub fn start_delivery_check(
        &self,
        contact: ContactIdentityKey,
        now: SystemTime,
    ) -> Result<DeliveryCheck, ProtocolStateError> {
        validate_contact_identity_key(&contact_address(contact), &contact)?;
        let now_millis = to_unix_millis(now).ok_or(ProtocolStateError::TimeOutOfRange)?;
        Ok(DeliveryCheck(Some(Box::new(Checking {
            engine: *self,
            contact,
            now_millis,
            reads: StateReads::default(),
            phase: CheckPhase::Started,
        }))))
    }
}

impl DeliveryCheck {
    /// Advances the check and returns what it needs next, or its result.
    ///
    /// Returning [`DeliveryCheckStep::Ready`] or an error ends the check.
    pub fn step(&mut self) -> Result<DeliveryCheckStep, MessageOperationError> {
        let checking = self.0.as_mut().ok_or(MessageOperationError::Finished)?;
        let step = checking.advance();
        if !matches!(step, Ok(DeliveryCheckStep::NeedsState(_))) {
            self.0 = None;
        }
        step
    }

    /// Supplies one entry for each record the pending [`DeliveryCheckStep::NeedsState`] named, in
    /// any order, with `None` for an absent record.
    pub fn supply_state(
        &mut self,
        entries: Vec<(ProtocolStateAddress, Option<ProtocolStateBlob>)>,
    ) -> Result<(), MessageOperationError> {
        let checking = self.0.as_mut().ok_or(MessageOperationError::Finished)?;
        let supplied = supply_state(&mut checking.reads, entries);
        if supplied.is_err() {
            self.0 = None;
        }
        supplied
    }
}

impl Checking {
    fn advance(&mut self) -> Result<DeliveryCheckStep, MessageOperationError> {
        if let Some(pending) = self.reads.pending() {
            return Ok(DeliveryCheckStep::NeedsState(pending.to_vec()));
        }
        match std::mem::replace(&mut self.phase, CheckPhase::Taken) {
            CheckPhase::Started => {
                self.phase = CheckPhase::ContactRequested;
                Ok(DeliveryCheckStep::NeedsState(request_contact_records(
                    &mut self.reads,
                    self.contact,
                )))
            }
            CheckPhase::ContactRequested => {
                let Some(accepted) =
                    load_accepted_contact(&self.reads, self.contact, self.engine.limits)?
                else {
                    return Ok(self.ready(Checked::default()));
                };
                let mut addresses = vec![session_address(accepted.sessions.current())];
                addresses.extend(
                    accepted
                        .sessions
                        .session_ids()
                        .map(pending_acknowledgment_address),
                );
                self.phase = CheckPhase::SessionsRequested(Box::new(accepted));
                Ok(DeliveryCheckStep::NeedsState(self.reads.request(addresses)))
            }
            CheckPhase::SessionsRequested(accepted) => {
                let result = self.check(*accepted)?;
                Ok(self.ready(result))
            }
            CheckPhase::Taken => Err(MessageOperationError::Finished),
        }
    }

    fn ready(&self, checked: Checked) -> DeliveryCheckStep {
        DeliveryCheckStep::Ready {
            result: DeliveryCheckResult {
                starts_recovery: checked.starts_recovery,
            },
            changes: changes(&self.reads, checked.updates).with_undelivered(checked.undelivered),
        }
    }

    // Gives up on messages whose first copy the relay has dropped, and signals a recovery of the
    // rest when the contact has been quiet too long, granted a newer inbox than one a message went
    // to, or delivered on a newer session. A blocked contact gets none.
    fn check(&self, accepted: AcceptedContact) -> Result<Checked, ProtocolStateError> {
        let AcceptedContact {
            mut contact,
            sessions,
        } = accepted;
        let limits = self.engine.limits;
        let snapshot = self.reads.snapshot();
        let now_millis = self.now_millis;
        let mut records = load_pending_by_session(snapshot, &sessions, limits)?;
        let mut undelivered = Vec::new();
        let mut updates = Vec::new();
        for (session_id, pending) in &mut records {
            let before = pending.pending.len();
            pending.pending.retain(|message_id, entry| {
                let expired = waited(entry.first_sent_at_millis, now_millis) >= UNDELIVERED_AFTER;
                if expired {
                    undelivered.push((
                        entry.first_sent_at_millis,
                        MessageId::from_bytes(*message_id),
                    ));
                }
                !expired
            });
            if pending.pending.len() != before {
                updates.push(pending_update(snapshot, *session_id, pending, limits)?);
            }
        }
        undelivered.sort_by_key(|(first_sent_at_millis, message_id)| {
            (*first_sent_at_millis, *message_id.as_bytes())
        });
        let waiting = unacknowledged(&records);
        let outstanding = Outstanding::new(&waiting, &sessions, snapshot, limits)?;
        let sent_to_dead_inbox = outstanding
            .recoverable
            .iter()
            .any(|message| contact.has_newer_grant_than(message.entry.sent_to));
        let starts_recovery = match outstanding.oldest() {
            None => {
                contact.forget_recovery();
                false
            }
            Some(_) if contact.blocked => false,
            Some(oldest) => {
                let left_behind = outstanding.left_behind().is_some();
                let may_signal = contact.recovery().is_none_or(|recovery| {
                    waited(recovery.signaled_at_millis, now_millis) >= RECHECK_PERIOD
                        // The contact acknowledged the probe, so the rest go out on its session.
                        || (matches!(recovery.progress, RecoveryProgress::Probed(_)) && left_behind)
                });
                let quiet = waited(oldest.entry.first_sent_at_millis, now_millis) >= QUIET_PERIOD;
                may_signal && (quiet || sent_to_dead_inbox || left_behind)
            }
        };
        if starts_recovery {
            contact.signal_recovery(now_millis);
        }
        updates.extend(contact_update(snapshot, &contact, limits)?);
        Ok(Checked {
            starts_recovery,
            undelivered: undelivered.into_iter().map(|(_, id)| id).collect(),
            updates,
        })
    }
}

// What a check found, before its updates become state changes.
#[derive(Default)]
struct Checked {
    starts_recovery: bool,
    undelivered: Vec<MessageId>,
    updates: Vec<ProtocolStateUpdate>,
}

// A message this side sent that the contact hasn't acknowledged, and the session it waits on.
struct Unacknowledged<'a> {
    session_id: SessionId,
    message_id: MessageId,
    entry: &'a LoadedPendingAcknowledgment,
}

// The messages a recovery may resend, and where they wait relative to the session Roost sends on.
struct Outstanding<'a, 'b> {
    // Every unacknowledged message except grant updates, which recovered messages replace, oldest
    // first.
    recoverable: Vec<&'b Unacknowledged<'a>>,
    current: SessionId,
    // Whether the current session's records exist.
    current_is_kept: bool,
    // Whether the contact delivered on the current session, so it awaits no reply.
    current_is_replied: bool,
    // The sessions kept with the contact that started before the current one.
    before_current: Vec<SessionId>,
}

impl<'a, 'b> Outstanding<'a, 'b> {
    fn new(
        waiting: &'b [Unacknowledged<'a>],
        sessions: &PeerSessions,
        snapshot: &ProtocolStateSnapshot,
        limits: ProtocolHardeningLimits,
    ) -> Result<Self, ProtocolStateError> {
        let current = sessions.current();
        let current_session = load_session(snapshot, &session_address(current), limits)?;
        Ok(Self {
            recoverable: waiting
                .iter()
                .filter(|message| message.entry.payload_kind != PayloadKind::GrantUpdate)
                .collect(),
            current,
            current_is_kept: current_session.is_some(),
            current_is_replied: current_session
                .is_some_and(|session| session.pending_handshake.is_none()),
            before_current: sessions
                .session_ids()
                .filter(|session_id| sessions.started_before(*session_id, current))
                .collect(),
        })
    }

    fn oldest(&self) -> Option<&'b Unacknowledged<'a>> {
        self.recoverable.first().copied()
    }

    // Returns the oldest message waiting on a session older than the one the contact delivered on
    // since, which may have lost it, or held behind a probe with no copy on its way. The newer
    // session holds nothing sent before the message, so the contact misses no message on it.
    fn left_behind(&self) -> Option<&'b Unacknowledged<'a>> {
        if !self.current_is_replied {
            return None;
        }
        self.recoverable
            .iter()
            .find(|message| message.entry.held || self.before_current.contains(&message.session_id))
            .copied()
    }
}

// Asks for a contact's record and session list, which a check or recovery reads first.
fn request_contact_records(
    reads: &mut StateReads,
    contact: ContactIdentityKey,
) -> Vec<ProtocolStateAddress> {
    reads.request(vec![
        contact_address(contact),
        peer_sessions_address(contact),
    ])
}

// Returns the contact's record and sessions, when it's an accepted contact with sessions. Only an
// accepted contact acknowledges, so only its messages wait for an acknowledgment.
fn load_accepted_contact(
    reads: &StateReads,
    contact: ContactIdentityKey,
    limits: ProtocolHardeningLimits,
) -> Result<Option<AcceptedContact>, ProtocolStateError> {
    let snapshot = reads.snapshot();
    let record = load_contact(snapshot, &contact_address(contact), limits)?;
    let sessions = load_peer_sessions(snapshot, &peer_sessions_address(contact), limits)?;
    Ok(match (record, sessions) {
        (Some(contact), Some(sessions)) if contact.is_accepted() => {
            Some(AcceptedContact { contact, sessions })
        }
        _ => None,
    })
}

// Returns the pending acknowledgments of each session kept with a peer that has any.
fn load_pending_by_session(
    snapshot: &ProtocolStateSnapshot,
    sessions: &PeerSessions,
    limits: ProtocolHardeningLimits,
) -> Result<Vec<(SessionId, LoadedPendingAcknowledgments)>, ProtocolStateError> {
    sessions
        .session_ids()
        .filter_map(|session_id| {
            let address = pending_acknowledgment_address(session_id);
            snapshot.get(&address).map(|blob| {
                decode_pending_acknowledgments(&address, blob, limits)
                    .map(|pending| (session_id, pending))
            })
        })
        .collect()
}

// Returns the update that stores `pending` as `session_id`'s pending acknowledgments.
pub(super) fn pending_update(
    snapshot: &ProtocolStateSnapshot,
    session_id: SessionId,
    pending: &LoadedPendingAcknowledgments,
    limits: ProtocolHardeningLimits,
) -> Result<ProtocolStateUpdate, ProtocolStateError> {
    let address = pending_acknowledgment_address(session_id);
    Ok(ProtocolStateUpdate::set(
        address.clone(),
        encode_pending_acknowledgments(&address, pending, limits)?,
    )
    .with_snapshot(snapshot))
}

// Returns every message still waiting in `records`, oldest first.
fn unacknowledged(
    records: &[(SessionId, LoadedPendingAcknowledgments)],
) -> Vec<Unacknowledged<'_>> {
    let mut waiting: Vec<Unacknowledged<'_>> = records
        .iter()
        .flat_map(|(session_id, pending)| {
            pending
                .pending
                .iter()
                .map(|(message_id, entry)| Unacknowledged {
                    session_id: *session_id,
                    message_id: MessageId::from_bytes(*message_id),
                    entry,
                })
        })
        .collect();
    waiting.sort_by_key(|message| {
        (
            message.entry.first_sent_at_millis,
            *message.message_id.as_bytes(),
        )
    });
    waiting
}

// Returns how long has passed from `since_millis` to `now_millis`, or nothing for a time ahead.
fn waited(since_millis: u64, now_millis: u64) -> Duration {
    Duration::from_millis(now_millis.saturating_sub(since_millis))
}

/// What the app passes to resend a contact's unacknowledged messages on a newer session.
pub struct OutgoingRecovery {
    /// The contact's identity key.
    pub recipient: ContactIdentityKey,
    /// The local identity's certificate sealed into the resent message.
    pub sender_certificate: SignedSenderCertificate,
    /// The bundle the app fetched after [`MessageRecoveryStep::NeedsPreKeyBundle`], kept with the
    /// recovery job until a session uses it or the job ends.
    pub prekey_bundle: Option<PeerPreKeyBundle>,
}

/// What a [`MessageRecovery`] needs next, or its result.
pub enum MessageRecoveryStep {
    /// The records to supply through [`MessageRecovery::supply_state`].
    NeedsState(Vec<ProtocolStateAddress>),
    /// The content the app sent under this message ID, to supply through
    /// [`MessageRecovery::supply_content`].
    NeedsContent(MessageId),
    /// The destination whose transport binding to supply through
    /// [`MessageRecovery::supply_transport_binding`].
    NeedsTransport(MessageDestination),
    /// A new session, or the first resend after an unblock, needs this contact's prekey bundle, and
    /// the given one is missing or older than the contact's discovery key. The recovery has ended:
    /// fetch the bundle and start again.
    NeedsPreKeyBundle(ContactIdentityKey),
    /// The first message this recovery resent on a new session isn't acknowledged yet, and the
    /// rest wait for it. The recovery has ended and nothing changed, and a delivery check signals
    /// it again once the contact acknowledges the probe.
    AwaitingProbe(MessageId),
    /// Nothing is left to resend. The recovery has ended and nothing changed.
    Finished,
    /// One message encrypted again under its message ID, and the state changes to commit with it.
    /// The recovery has ended.
    Ready {
        /// The message encrypted again.
        result: Box<OutboundMessageResult>,
        /// The state changes to commit with the message.
        changes: StateChanges,
    },
}

/// One step of a recovery, which encrypts one unacknowledged message again on a newer session and
/// returns its result once.
///
/// Roost picks the message and the session. When the contact delivered on a session newer than the
/// one holding the message, the message goes there, so the contact misses no message on it, unless
/// the app's bundle names a newer discovery key, which starts a new session instead. Otherwise,
/// under a signaled recovery, the oldest message starts a new session from the contact's prekey
/// bundle, and the rest wait until the contact acknowledges it or delivers on another session. Call
/// [`Self::step`] until it returns [`MessageRecoveryStep::Ready`],
/// [`MessageRecoveryStep::NeedsPreKeyBundle`], [`MessageRecoveryStep::AwaitingProbe`], or
/// [`MessageRecoveryStep::Finished`], supplying what each other step asks for. Dropping the
/// recovery commits nothing.
pub struct MessageRecovery(Option<Box<Recovering>>);

struct Recovering {
    encrypting: Encrypting,
    phase: RecoveryPhase,
}

enum RecoveryPhase {
    Started,
    ContactRequested,
    SessionsRequested(Box<AcceptedContact>),
    ContentRequested(Box<Resend>, Option<Zeroizing<Vec<u8>>>),
    Encrypting,
    Taken,
}

// The message a recovery resends, and where.
struct Resend {
    contact: ContactRecord,
    session_id: SessionId,
    message_id: MessageId,
    first_sent_at_millis: u64,
    payload_kind: PayloadKind,
    target: Target,
}

enum Target {
    // The session the contact delivered on last.
    Current {
        session_id: SessionId,
        starter: Starter,
    },
    // A new session from the contact's bundle.
    New {
        bundle: Box<PeerPreKeyBundle>,
        bundle_discovery_key: ContactDiscoveryKey,
    },
}

impl ProtocolStateEngine {
    // Starts one step of recovering the messages sent to `recovery.recipient`, sealing with the
    // local identity's `keys`.
    pub(crate) fn start_recovery(
        &self,
        keys: LocalIdentityKeys,
        recovery: OutgoingRecovery,
    ) -> Result<MessageRecovery, ProtocolStateError> {
        // Roost picks the message, whose ID, send time, and content replace these.
        let message = OutgoingMessage {
            recipient: recovery.recipient,
            message_id: MessageId::from_bytes([0; 16]),
            sent_at_millis: 0,
            sender_certificate: recovery.sender_certificate,
            plaintext: Zeroizing::new(Vec::new()),
            prekey_bundle: recovery.prekey_bundle,
        };
        Ok(MessageRecovery(Some(Box::new(Recovering {
            encrypting: self.encrypting(keys, message, SendIntent::Message)?,
            phase: RecoveryPhase::Started,
        }))))
    }
}

impl MessageRecovery {
    /// Advances the recovery and returns what it needs next, or its result.
    ///
    /// Sealing happens here, never in the supply calls. Returning a step other than
    /// [`MessageRecoveryStep::NeedsState`], [`MessageRecoveryStep::NeedsContent`], or
    /// [`MessageRecoveryStep::NeedsTransport`], or an error, ends the recovery.
    pub fn step<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<MessageRecoveryStep, MessageOperationError> {
        let recovering = self.0.as_mut().ok_or(MessageOperationError::Finished)?;
        let step = recovering.advance(rng);
        if !matches!(
            step,
            Ok(MessageRecoveryStep::NeedsState(_)
                | MessageRecoveryStep::NeedsContent(_)
                | MessageRecoveryStep::NeedsTransport(_))
        ) {
            self.0 = None;
        }
        step
    }

    /// Supplies one entry for each record the pending [`MessageRecoveryStep::NeedsState`] named,
    /// in any order, with `None` for an absent record.
    pub fn supply_state(
        &mut self,
        entries: Vec<(ProtocolStateAddress, Option<ProtocolStateBlob>)>,
    ) -> Result<(), MessageOperationError> {
        let recovering = self.0.as_mut().ok_or(MessageOperationError::Finished)?;
        let supplied = supply_state(&mut recovering.encrypting.reads, entries);
        if supplied.is_err() {
            self.0 = None;
        }
        supplied
    }

    /// Supplies the content the pending [`MessageRecoveryStep::NeedsContent`] asked for.
    pub fn supply_content(
        &mut self,
        content: Zeroizing<Vec<u8>>,
    ) -> Result<(), MessageOperationError> {
        let recovering = self.0.as_mut().ok_or(MessageOperationError::Finished)?;
        if let RecoveryPhase::ContentRequested(_, supplied @ None) = &mut recovering.phase {
            *supplied = Some(content);
            return Ok(());
        }
        self.0 = None;
        Err(MessageOperationError::NotAwaitingContent)
    }

    /// Supplies the transport binding for the pending [`MessageRecoveryStep::NeedsTransport`].
    pub fn supply_transport_binding(
        &mut self,
        transport_binding: TransportBinding,
    ) -> Result<(), MessageOperationError> {
        let recovering = self.0.as_mut().ok_or(MessageOperationError::Finished)?;
        let supplied = recovering
            .encrypting
            .supply_transport_binding(transport_binding);
        if supplied.is_err() {
            self.0 = None;
        }
        supplied
    }
}

impl Recovering {
    fn advance<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<MessageRecoveryStep, MessageOperationError> {
        if let Some(pending) = self.encrypting.reads.pending() {
            return Ok(MessageRecoveryStep::NeedsState(pending.to_vec()));
        }
        let recipient = self.encrypting.recipient;
        match std::mem::replace(&mut self.phase, RecoveryPhase::Taken) {
            RecoveryPhase::Started => {
                self.phase = RecoveryPhase::ContactRequested;
                Ok(MessageRecoveryStep::NeedsState(request_contact_records(
                    &mut self.encrypting.reads,
                    recipient,
                )))
            }
            RecoveryPhase::ContactRequested => {
                let Some(accepted) = load_accepted_contact(
                    &self.encrypting.reads,
                    recipient,
                    self.encrypting.engine.limits,
                )?
                else {
                    return Ok(MessageRecoveryStep::Finished);
                };
                if accepted.contact.blocked {
                    return Err(ProtocolStateError::BlockedContact.into());
                }
                let addresses = accepted
                    .sessions
                    .session_ids()
                    .flat_map(session_record_addresses)
                    .collect();
                self.phase = RecoveryPhase::SessionsRequested(Box::new(accepted));
                Ok(MessageRecoveryStep::NeedsState(
                    self.encrypting.reads.request(addresses),
                ))
            }
            RecoveryPhase::SessionsRequested(accepted) => match self.select(*accepted)? {
                Selected::Resend(resend) => {
                    let message_id = resend.message_id;
                    self.phase = RecoveryPhase::ContentRequested(resend, None);
                    Ok(MessageRecoveryStep::NeedsContent(message_id))
                }
                Selected::Ended(step) => Ok(step),
            },
            RecoveryPhase::ContentRequested(resend, None) => {
                let message_id = resend.message_id;
                self.phase = RecoveryPhase::ContentRequested(resend, None);
                Ok(MessageRecoveryStep::NeedsContent(message_id))
            }
            RecoveryPhase::ContentRequested(resend, Some(content)) => {
                self.phase = RecoveryPhase::Encrypting;
                self.encrypt(rng, *resend, content)
            }
            RecoveryPhase::Encrypting => {
                self.phase = RecoveryPhase::Encrypting;
                let step = self.encrypting.advance(rng)?;
                Ok(recovery_step(step))
            }
            RecoveryPhase::Taken => Err(MessageOperationError::Finished),
        }
    }

    // Picks the message to resend and where, or ends the recovery.
    fn select(&mut self, accepted: AcceptedContact) -> Result<Selected, ProtocolStateError> {
        let AcceptedContact { contact, sessions } = accepted;
        let limits = self.encrypting.engine.limits;
        let snapshot = self.encrypting.reads.snapshot();
        let records = load_pending_by_session(snapshot, &sessions, limits)?;
        let waiting = unacknowledged(&records);
        let outstanding = Outstanding::new(&waiting, &sessions, snapshot, limits)?;
        // The contact delivered on a newer session, so the message goes there, with no fetch unless
        // an unblock needs a check. A bundle naming a newer key starts a new session instead, since
        // the relay silently drops messages sent to a rotated inbox.
        if let Some(message) = outstanding.left_behind() {
            let (contact, message, target) = match self.encrypting.check_discovery_key(contact)? {
                DiscoveryKeyCheck::NeedsBundle => {
                    return Ok(Selected::Ended(MessageRecoveryStep::NeedsPreKeyBundle(
                        self.encrypting.recipient,
                    )));
                }
                DiscoveryKeyCheck::Rotated(rotated) => {
                    let RotatedContact {
                        contact,
                        bundle,
                        bundle_discovery_key,
                    } = *rotated;
                    let target = Target::New {
                        bundle: Box::new(bundle),
                        bundle_discovery_key,
                    };
                    (contact, outstanding.oldest().unwrap_or(message), target)
                }
                DiscoveryKeyCheck::Checked(contact) => {
                    let target = Target::Current {
                        session_id: outstanding.current,
                        starter: sessions.current_starter(),
                    };
                    (*contact, message, target)
                }
            };
            return Ok(Selected::Resend(Box::new(Resend::of(
                contact, message, target,
            ))));
        }
        let (Some(oldest), Some(recovery)) = (outstanding.oldest(), contact.recovery()) else {
            return Ok(Selected::Ended(MessageRecoveryStep::Finished));
        };
        // What's left already went out under this signal, so it waits for the next one.
        match recovery.progress {
            RecoveryProgress::Probed(probe)
                if outstanding.current_is_kept && !outstanding.current_is_replied =>
            {
                return Ok(Selected::Ended(MessageRecoveryStep::AwaitingProbe(probe)));
            }
            RecoveryProgress::Probed(_) | RecoveryProgress::Resent => {
                return Ok(Selected::Ended(MessageRecoveryStep::Finished));
            }
            RecoveryProgress::Signaled => {}
        }
        let Some(bundle) = self.encrypting.prekey_bundle.take() else {
            return Ok(Selected::Ended(MessageRecoveryStep::NeedsPreKeyBundle(
                contact.identity_key,
            )));
        };
        let bundle_discovery_key = self.encrypting.verify_bundle(&bundle)?;
        if contact.has_newer_discovery_key_than(&bundle_discovery_key) {
            return Ok(Selected::Ended(MessageRecoveryStep::NeedsPreKeyBundle(
                contact.identity_key,
            )));
        }
        let target = Target::New {
            bundle: Box::new(bundle),
            bundle_discovery_key,
        };
        Ok(Selected::Resend(Box::new(Resend::of(
            contact, oldest, target,
        ))))
    }

    // Encrypts the selected message again with the content the app sent.
    fn encrypt<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        resend: Resend,
        content: Zeroizing<Vec<u8>>,
    ) -> Result<MessageRecoveryStep, MessageOperationError> {
        let Resend {
            mut contact,
            session_id,
            message_id,
            first_sent_at_millis,
            payload_kind,
            target,
        } = resend;
        self.encrypting
            .resend(session_id, message_id, first_sent_at_millis, content);
        match target {
            Target::Current {
                session_id,
                starter,
            } => {
                contact.record_resend(None);
                // An acceptance counts only on the requester's session.
                let payload_kind =
                    if payload_kind == PayloadKind::ContactAcceptance && starter == Starter::Peer {
                        payload_kind
                    } else {
                        let local_grant = self.encrypting.sender.grant().stamp();
                        content_kind(contact.receives_grant(starter, local_grant))
                    };
                let prepared = self.encrypting.prepare_seal(Planned {
                    contact,
                    payload_kind,
                    session_id,
                })?;
                Ok(recovery_step(self.encrypting.request_transport(prepared)))
            }
            Target::New {
                bundle,
                bundle_discovery_key,
            } => {
                contact.record_resend(Some(message_id));
                let step = self.encrypting.start_session_from(
                    rng,
                    contact,
                    *bundle,
                    bundle_discovery_key,
                )?;
                Ok(recovery_step(step))
            }
        }
    }
}

// What a recovery decided after reading the contact's sessions.
enum Selected {
    Resend(Box<Resend>),
    Ended(MessageRecoveryStep),
}

impl Resend {
    fn of(contact: ContactRecord, message: &Unacknowledged<'_>, target: Target) -> Self {
        Self {
            contact,
            session_id: message.session_id,
            message_id: message.message_id,
            first_sent_at_millis: message.entry.first_sent_at_millis,
            payload_kind: message.entry.payload_kind,
            target,
        }
    }
}

// Returns an encryption's step as a recovery's. A resend never asks for a bundle or has nothing
// to send, since the recovery picked its session first.
fn recovery_step(step: MessageEncryptionStep) -> MessageRecoveryStep {
    match step {
        MessageEncryptionStep::NeedsState(addresses) => MessageRecoveryStep::NeedsState(addresses),
        MessageEncryptionStep::NeedsTransport(destination) => {
            MessageRecoveryStep::NeedsTransport(destination)
        }
        MessageEncryptionStep::NeedsPreKeyBundle(identity_key) => {
            MessageRecoveryStep::NeedsPreKeyBundle(identity_key)
        }
        MessageEncryptionStep::NothingToSend => MessageRecoveryStep::Finished,
        MessageEncryptionStep::Ready { result, changes } => {
            MessageRecoveryStep::Ready { result, changes }
        }
    }
}
