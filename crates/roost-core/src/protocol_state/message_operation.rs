mod recovery;

pub use recovery::{
    DeliveryCheck, DeliveryCheckResult, DeliveryCheckStep, MessageRecovery, MessageRecoveryStep,
    OutgoingRecovery,
};

use super::contact_record::{ContactRecord, ReceivedCount, contact_address, load_contact};
use super::deduplication::{
    LoadedDeduplicationSet, deduplication_address, encode_deduplication_set,
    receiving_deduplication_set,
};
use super::envelope::{
    LocalSender, OpenedMessage, OutboundContent, SignedRecipient, authenticate_first_message,
    authenticate_session_message, certified_sender_identity_key, decode_acknowledgment_plaintext,
    encode_acknowledgment_plaintext, open_message, seal_proved, seal_signed,
    validate_sender_identity, verify_recipient_keys,
};
use super::grant::{
    DiscoveryKeyStamp, InboxGrant, LocalGrant, MAX_ENCODED_GRANT_LEN, encode_granted_payload,
    open_granted_payload,
};
use super::pending_acknowledgment::{
    LoadedPendingAcknowledgment, LoadedPendingAcknowledgments, StrandedMessage,
    acknowledgment_digest, decode_pending_acknowledgments, encode_pending_acknowledgments,
    evict_sessions, has_seen_acknowledgment, load_pending_acknowledgments,
};
use super::session::{
    LoadedSession, PeerSessions, PendingHandshake, SignedPreKeyUse, Starter, encode_peer_sessions,
    encode_session, load_peer_sessions, load_required_session, load_session, peer_sessions_address,
    pending_acknowledgment_address, session_address, session_record_addresses,
};
use super::{
    AcknowledgmentResult, BlockedContactAcknowledgmentPolicy, BlockedInboundMessageResult,
    DIGEST_LEN, GrantUpdateResult, InboundMessageOutcome, InboundMessageResult,
    InboundSenderCertificateValidation, OutboundMessageResult, ProtocolHardeningLimits,
    ProtocolStateAddress, ProtocolStateBlob, ProtocolStateCommitCondition, ProtocolStateEngine,
    ProtocolStateError, ProtocolStateSnapshot, ProtocolStateUpdate, ReceiveSettings,
    SenderIdentityMaterial, StateChanges, WithheldInboundMessageResult,
    contact_identity_keys_match, match_state_entries, validate_contact_identity_key,
};
use crate::TransportBinding;
use crate::contact::{ContactDiscoveryKey, ContactIdentityKey};
use crate::key_store::{KeyStore, KeyStoreError};
use rand::{CryptoRng, RngCore};
use roost_crypto::{
    DiscoveryKey, Handshake, KeyPair, PreKeyBundle, PublicDiscoveryKey, PublicIdentityKey,
    PublicKey, PublicSignedPreKey, RatchetState, RecipientDeliveryCapability, SealedFrame,
    SealedFramePreKeyReference, Signature, SigningKeyPair, accept_handshake, initiate_handshake,
    sign_identity_key_binding, verify_discovery_to_identity_binding,
};
use roost_protocol::{MAX_SEALED_PLAINTEXT_LEN, MessageId, PUBLIC_KEY_LEN, PayloadKind, SessionId};
use std::collections::BTreeMap;
use std::time::SystemTime;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

// Longest content a Message holds. A resend after a Recovery carries the Inbox Grant even when the
// original didn't, so every Message leaves room for it.
const MAX_CONTENT_LEN: usize = MAX_SEALED_PLAINTEXT_LEN - MAX_ENCODED_GRANT_LEN;

/// The local Identity's secret keys a Message Operation uses.
pub(crate) struct LocalIdentityKeys {
    /// Identity Key agreement half, which proves Messages that carry a handshake.
    pub(crate) agreement_key: KeyPair,
    /// Identity Key signing half, which signs Messages sent after the peer replies.
    pub(crate) signing_key: SigningKeyPair,
    /// Current Discovery Key, which opens received Messages.
    pub(crate) discovery_key: DiscoveryKey,
    /// The current inbox's Delivery Capability, which Roost shares only inside Inbox Grants.
    pub(crate) delivery_capability: RecipientDeliveryCapability,
}

/// What the app asked an encryption to do, which the contact's current state may change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SendIntent {
    /// An ordinary Message to a contact.
    Message,
    /// A Contact Request, which becomes an acceptance when the peer already asked.
    Request,
    /// A Contact Acceptance, which becomes an ordinary Message once the contact is accepted.
    Acceptance,
    /// A Grant Update, which carries only the local Inbox Grant.
    GrantUpdate,
}

/// A domain-signed sender certificate and the domain's signature over it.
pub struct SignedSenderCertificate {
    /// Domain-signed sender certificate bytes.
    pub certificate: Vec<u8>,
    /// Domain signature over the certificate.
    pub signature: Vec<u8>,
}

/// A contact's published keys as the app fetched them from the Relay.
pub struct PeerPreKeyBundle {
    /// The contact's Identity Key.
    pub identity_key: PublicIdentityKey,
    /// The contact Discovery Key's signature over the Identity Key.
    pub discovery_to_identity: Signature,
    /// The contact's Discovery Key, signed prekey, and one-time prekey when one was left.
    pub bundle: PreKeyBundle,
}

/// What the app sends: a recipient, a stable draft MessageID, and the plaintext.
pub struct OutgoingMessage {
    /// The contact's Identity Key, which selects the Session and the destination.
    pub recipient: ContactIdentityKey,
    /// The MessageID the app allocated for this draft, kept across retries.
    pub message_id: MessageId,
    /// Sender-observed Unix timestamp in milliseconds.
    pub sent_at_millis: u64,
    /// The local Identity's certificate sealed into the Message.
    pub sender_certificate: SignedSenderCertificate,
    /// Plaintext bytes to encrypt, at most 65,291.
    pub plaintext: Zeroizing<Vec<u8>>,
    /// The bundle the app fetched after [`MessageEncryptionStep::NeedsPreKeyBundle`], kept with
    /// the draft until a send uses it.
    pub prekey_bundle: Option<PeerPreKeyBundle>,
}

/// What the app sends to give a contact the current Inbox Grant: a recipient and a MessageID.
pub struct OutgoingGrantUpdate {
    /// The contact's Identity Key, which selects the Session and the destination.
    pub recipient: ContactIdentityKey,
    /// The MessageID the app allocated for this Grant Update, kept across retries.
    pub message_id: MessageId,
    /// Sender-observed Unix timestamp in milliseconds.
    pub sent_at_millis: u64,
    /// The local Identity's certificate sealed into the Message.
    pub sender_certificate: SignedSenderCertificate,
    /// The bundle the app fetched after [`MessageEncryptionStep::NeedsPreKeyBundle`], kept with
    /// the Grant Update until a send uses it.
    pub prekey_bundle: Option<PeerPreKeyBundle>,
}

impl OutgoingGrantUpdate {
    // Returns the Grant Update as a Message with no content.
    pub(crate) fn into_message(self) -> OutgoingMessage {
        OutgoingMessage {
            recipient: self.recipient,
            message_id: self.message_id,
            sent_at_millis: self.sent_at_millis,
            sender_certificate: self.sender_certificate,
            plaintext: Zeroizing::new(Vec::new()),
            prekey_bundle: self.prekey_bundle,
        }
    }
}

/// What the app received, with the inputs Roost needs to check and acknowledge it.
pub struct IncomingMessage {
    /// The received Message.
    pub message: SealedFrame,
    /// The exact Transport Binding the Message arrived with.
    pub transport_binding: TransportBinding,
    /// The app's settings for this receive.
    pub settings: ReceiveSettings,
    /// Trust, revocation, and time inputs for the sender's certificate.
    pub sender_certificate_validation: InboundSenderCertificateValidation,
    /// Unix timestamp in milliseconds sealed into the acknowledgment.
    pub acknowledgment_sent_at_millis: u64,
    /// The local Identity's certificate sealed into the acknowledgment.
    pub acknowledgment_sender_certificate: SignedSenderCertificate,
}

/// Where Roost sends a Message, so the app can supply a Transport Binding that reaches it.
pub enum MessageDestination {
    /// A first Message, which the Relay admits against the recipient's current prekeys.
    FirstMessage {
        /// The recipient's Identity Key.
        identity_key: ContactIdentityKey,
        /// The recipient Discovery Key's X25519 public key the Message is sealed to.
        discovery_key: [u8; PUBLIC_KEY_LEN],
        /// The recipient signed prekey the handshake used.
        signed_prekey_id: u64,
        /// The recipient one-time prekey the handshake used, if one was left.
        one_time_prekey_id: Option<u64>,
    },
    /// An established Message, which the Relay admits with the recipient's Delivery Capability.
    Established {
        /// The recipient's Identity Key.
        identity_key: ContactIdentityKey,
        /// The recipient Discovery Key's X25519 public key the Message is sealed to.
        discovery_key: [u8; PUBLIC_KEY_LEN],
        /// The recipient's Delivery Capability, a secret the app passes only to the Relay.
        delivery_capability: RecipientDeliveryCapability,
    },
}

/// The signed prekey a first Message names, which the app must prove the Relay admitted it
/// against before Roost uses it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionRequest {
    /// The local Discovery Key epoch the signed prekey belongs to.
    pub discovery_epoch: u32,
    /// The signed prekey's ID, which the Relay's admission proof must name.
    pub signed_prekey_id: u64,
}

/// What a [`MessageEncryption`] needs next, or its result.
pub enum MessageEncryptionStep {
    /// The records to supply through [`MessageEncryption::supply_state`].
    NeedsState(Vec<ProtocolStateAddress>),
    /// The destination whose Transport Binding to supply through
    /// [`MessageEncryption::supply_transport_binding`].
    NeedsTransport(MessageDestination),
    /// A new Session, or the first send after an unblock, needs this contact's prekey bundle, and
    /// the given one is missing or older than the contact's Discovery Key. A send to an accepted
    /// contact, or an acceptance of a request, whose Session records are missing starts a new
    /// Session too. The operation has ended: fetch the bundle and start again with the same draft.
    NeedsPreKeyBundle(ContactIdentityKey),
    /// The contact already acknowledged a Message carrying the current Inbox Grant, so a Grant
    /// Update has nothing to carry. The operation has ended and nothing changed.
    NothingToSend,
    /// The sealed Message, and the state changes to commit with it. The operation has ended.
    Ready {
        /// The sealed Message.
        result: Box<OutboundMessageResult>,
        /// The state changes to commit with the Message.
        changes: StateChanges,
    },
}

/// What a [`MessageDecryption`] needs next, or its result.
pub enum MessageDecryptionStep {
    /// The records to supply through [`MessageDecryption::supply_state`].
    NeedsState(Vec<ProtocolStateAddress>),
    /// A first Message names a signed prekey kept after a rotation. Confirm through
    /// [`MessageDecryption::confirm_admission`] once the Relay's proof shows it admitted this
    /// Message against that prekey, or drop the operation.
    NeedsAdmission(AdmissionRequest),
    /// The destination whose Transport Binding the acknowledgment needs, to supply through
    /// [`MessageDecryption::supply_acknowledgment_transport_binding`].
    NeedsAcknowledgmentTransport(MessageDestination),
    /// What the Message turned out to be, and the state changes to commit with its effects. The
    /// operation has ended.
    Ready {
        /// What the Message turned out to be.
        outcome: InboundMessageOutcome,
        /// The state changes to commit with the outcome's effects, empty when it has none.
        changes: StateChanges,
    },
}

/// Errors returned by a Message Operation's calls.
///
/// Every error ends the operation, so later calls return [`Self::Finished`].
#[derive(Debug, thiserror::Error)]
pub enum MessageOperationError {
    /// The operation returned its result or failed, and accepts no more calls.
    #[error("message operation has finished")]
    Finished,
    /// Admission was confirmed while the operation wasn't waiting for it.
    #[error("message operation isn't waiting for admission")]
    NotAwaitingAdmission,
    /// State was supplied while the operation wasn't waiting for any.
    #[error("message operation isn't waiting for state")]
    NotAwaitingState,
    /// A Transport Binding was supplied while the operation wasn't waiting for one.
    #[error("message operation isn't waiting for a transport binding")]
    NotAwaitingTransportBinding,
    /// A Message's content was supplied while a recovery wasn't waiting for it.
    #[error("message recovery isn't waiting for content")]
    NotAwaitingContent,
    /// Reading the prekeys a first Message names, or staging the use of a one-time prekey,
    /// failed.
    #[error(transparent)]
    KeyStore(#[from] KeyStoreError),
    /// Checking or processing the Message failed.
    #[error(transparent)]
    ProtocolState(#[from] ProtocolStateError),
}

/// One attempt to encrypt a Message to a contact, which asks for the records it needs and returns
/// its result once.
///
/// Call [`Self::step`] until it returns [`MessageEncryptionStep::Ready`],
/// [`MessageEncryptionStep::NeedsPreKeyBundle`], or [`MessageEncryptionStep::NothingToSend`],
/// supplying what each other step asks for. Calling [`Self::step`] again before supplying it
/// returns the same request without repeating work. Dropping the operation commits nothing.
pub struct MessageEncryption(Option<Box<Encrypting>>);

struct Encrypting {
    engine: ProtocolStateEngine,
    sender: LocalSenderKeys,
    intent: SendIntent,
    recipient: ContactIdentityKey,
    message_id: MessageId,
    sent_at_millis: u64,
    plaintext: Zeroizing<Vec<u8>>,
    prekey_bundle: Option<PeerPreKeyBundle>,
    reads: StateReads,
    phase: EncryptionPhase,
    // The Session whose copy of this Message a recovery replaces, which sealing deletes.
    replaces: Option<SessionId>,
}

enum EncryptionPhase {
    Started,
    ContactRequested,
    SessionRequested(Box<Planned>),
    NewSessionRequested(Box<NewSession>),
    TransportRequested(Box<PreparedSeal>),
    Taken,
}

// What the bundle the app passed says about the contact's Discovery Key.
enum DiscoveryKeyCheck {
    // The first send after an unblock has no bundle, or one older than the contact's Discovery
    // Key.
    NeedsBundle,
    // The contact rotated, and this send starts a Session from the bundle.
    Rotated(Box<RotatedContact>),
    // The send continues as usual with the checked contact.
    Checked(Box<ContactRecord>),
}

// A contact that rotated its inbox, and the bundle that names its new Discovery Key.
struct RotatedContact {
    contact: ContactRecord,
    bundle: PeerPreKeyBundle,
    bundle_discovery_key: ContactDiscoveryKey,
}

// What a send turned out to be, and the contact record after it.
struct Planned {
    contact: ContactRecord,
    payload_kind: PayloadKind,
    session_id: SessionId,
}

// A Session this send starts, waiting to confirm its records don't exist yet.
struct NewSession {
    planned: Planned,
    state: Box<RatchetState>,
    pending_handshake: PendingHandshake,
    peer_sessions: PeerSessions,
    evicted: Vec<SessionId>,
}

// How the Relay admits a Message, kept so Roost can describe the destination again.
enum Route {
    FirstMessage {
        discovery_key: [u8; PUBLIC_KEY_LEN],
        signed_prekey_id: u64,
        one_time_prekey_id: Option<u64>,
    },
    Established {
        discovery_key: [u8; PUBLIC_KEY_LEN],
        delivery_capability: Zeroizing<[u8; 32]>,
    },
}

impl Route {
    fn first_message(pending_handshake: &PendingHandshake) -> Self {
        Self::FirstMessage {
            discovery_key: *pending_handshake
                .handshake
                .responder_discovery_key
                .as_bytes(),
            signed_prekey_id: pending_handshake.signed_prekey_id,
            one_time_prekey_id: pending_handshake
                .handshake
                .prekey_reference
                .one_time_prekey
                .map(|prekey| prekey.id),
        }
    }

    fn established(contact: &ContactRecord) -> Result<Self, ProtocolStateError> {
        let (discovery_key, capability) = contact.established_route()?;
        Ok(Self::Established {
            discovery_key,
            delivery_capability: capability.to_bytes(),
        })
    }

    fn discovery_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        match self {
            Self::FirstMessage { discovery_key, .. } | Self::Established { discovery_key, .. } => {
                *discovery_key
            }
        }
    }

    fn destination(&self, identity_key: ContactIdentityKey) -> MessageDestination {
        match self {
            Self::FirstMessage {
                discovery_key,
                signed_prekey_id,
                one_time_prekey_id,
            } => MessageDestination::FirstMessage {
                identity_key,
                discovery_key: *discovery_key,
                signed_prekey_id: *signed_prekey_id,
                one_time_prekey_id: *one_time_prekey_id,
            },
            Self::Established {
                discovery_key,
                delivery_capability,
            } => MessageDestination::Established {
                identity_key,
                discovery_key: *discovery_key,
                delivery_capability: RecipientDeliveryCapability::from_bytes(**delivery_capability),
            },
        }
    }
}

// Everything sealing needs once Roost knows the Session and the destination.
struct PreparedSeal {
    planned: Planned,
    state: Box<RatchetState>,
    pending_handshake: Option<PendingHandshake>,
    pending: LoadedPendingAcknowledgments,
    // The peer's Session list when this send starts a Session, and the Sessions that evicts.
    started: Option<(PeerSessions, Vec<SessionId>)>,
    route: Route,
    transport_binding: Option<TransportBinding>,
}

impl ProtocolStateEngine {
    // Starts encrypting `message` with the local Identity's `keys`.
    pub(crate) fn start_encryption(
        &self,
        keys: LocalIdentityKeys,
        message: OutgoingMessage,
        intent: SendIntent,
    ) -> Result<MessageEncryption, ProtocolStateError> {
        Ok(MessageEncryption(Some(Box::new(
            self.encrypting(keys, message, intent)?,
        ))))
    }

    fn encrypting(
        &self,
        keys: LocalIdentityKeys,
        message: OutgoingMessage,
        intent: SendIntent,
    ) -> Result<Encrypting, ProtocolStateError> {
        validate_contact_identity_key(&contact_address(message.recipient), &message.recipient)?;
        if message.plaintext.len() > MAX_CONTENT_LEN {
            return Err(ProtocolStateError::ContentTooLong {
                len: message.plaintext.len(),
                max: MAX_CONTENT_LEN,
            });
        }
        let sender = LocalSenderKeys::new(keys, message.sender_certificate)?;
        validate_sender_identity(&sender.identity, self.limits)?;
        Ok(Encrypting {
            engine: *self,
            sender,
            intent,
            recipient: message.recipient,
            message_id: message.message_id,
            sent_at_millis: message.sent_at_millis,
            plaintext: message.plaintext,
            prekey_bundle: message.prekey_bundle,
            reads: StateReads::default(),
            phase: EncryptionPhase::Started,
            replaces: None,
        })
    }

    // Starts decrypting `message` with the local Identity's `keys`, reading prekeys and previous
    // Discovery Keys from `store` as they stand at `now`.
    pub(crate) fn start_decryption(
        &self,
        store: KeyStore,
        now: SystemTime,
        keys: LocalIdentityKeys,
        message: IncomingMessage,
    ) -> Result<MessageDecryption, ProtocolStateError> {
        let encoded = message.message.to_bytes()?;
        let local = LocalSenderKeys::new(keys, message.acknowledgment_sender_certificate)?;
        validate_sender_identity(&local.identity, self.limits)?;
        Ok(MessageDecryption(Some(Box::new(Decrypting {
            engine: *self,
            store,
            now,
            local,
            message: message.message,
            encoded,
            transport_binding: message.transport_binding,
            settings: message.settings,
            validation: message.sender_certificate_validation,
            acknowledgment_sent_at_millis: message.acknowledgment_sent_at_millis,
            reads: StateReads::default(),
            phase: DecryptionPhase::Started,
        }))))
    }
}

impl MessageEncryption {
    /// Advances the operation and returns what it needs next, or its result.
    ///
    /// Sealing happens here, never in the supply calls. Returning
    /// [`MessageEncryptionStep::Ready`], [`MessageEncryptionStep::NeedsPreKeyBundle`],
    /// [`MessageEncryptionStep::NothingToSend`], or an error ends the operation.
    pub fn step<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<MessageEncryptionStep, MessageOperationError> {
        let encrypting = self.0.as_mut().ok_or(MessageOperationError::Finished)?;
        let step = encrypting.advance(rng);
        if !matches!(
            step,
            Ok(MessageEncryptionStep::NeedsState(_) | MessageEncryptionStep::NeedsTransport(_))
        ) {
            self.0 = None;
        }
        step
    }

    /// Supplies one entry for each record the pending [`MessageEncryptionStep::NeedsState`]
    /// named, in any order, with `None` for an absent record.
    pub fn supply_state(
        &mut self,
        entries: Vec<(ProtocolStateAddress, Option<ProtocolStateBlob>)>,
    ) -> Result<(), MessageOperationError> {
        let encrypting = self.0.as_mut().ok_or(MessageOperationError::Finished)?;
        let supplied = supply_state(&mut encrypting.reads, entries);
        if supplied.is_err() {
            self.0 = None;
        }
        supplied
    }

    /// Supplies the Transport Binding for the pending [`MessageEncryptionStep::NeedsTransport`].
    pub fn supply_transport_binding(
        &mut self,
        transport_binding: TransportBinding,
    ) -> Result<(), MessageOperationError> {
        let encrypting = self.0.as_mut().ok_or(MessageOperationError::Finished)?;
        let supplied = encrypting.supply_transport_binding(transport_binding);
        if supplied.is_err() {
            self.0 = None;
        }
        supplied
    }
}

impl Encrypting {
    fn supply_transport_binding(
        &mut self,
        transport_binding: TransportBinding,
    ) -> Result<(), MessageOperationError> {
        if let EncryptionPhase::TransportRequested(prepared) = &mut self.phase
            && prepared.transport_binding.is_none()
        {
            prepared.transport_binding = Some(transport_binding);
            return Ok(());
        }
        Err(MessageOperationError::NotAwaitingTransportBinding)
    }

    // Makes this an encryption of a Message sent earlier on `session_id`, keeping its MessageID
    // and send time, whose sealing replaces that copy.
    fn resend(
        &mut self,
        session_id: SessionId,
        message_id: MessageId,
        sent_at_millis: u64,
        plaintext: Zeroizing<Vec<u8>>,
    ) {
        self.message_id = message_id;
        self.sent_at_millis = sent_at_millis;
        self.plaintext = plaintext;
        self.replaces = Some(session_id);
    }

    fn advance<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<MessageEncryptionStep, MessageOperationError> {
        if let Some(pending) = self.reads.pending() {
            return Ok(MessageEncryptionStep::NeedsState(pending.to_vec()));
        }
        match std::mem::replace(&mut self.phase, EncryptionPhase::Taken) {
            EncryptionPhase::Started => {
                self.phase = EncryptionPhase::ContactRequested;
                Ok(MessageEncryptionStep::NeedsState(self.reads.request(vec![
                    contact_address(self.recipient),
                    peer_sessions_address(self.recipient),
                ])))
            }
            EncryptionPhase::ContactRequested => self.plan(rng),
            EncryptionPhase::SessionRequested(planned) => {
                let lost = self
                    .reads
                    .snapshot()
                    .get(&session_address(planned.session_id))
                    .is_none();
                if lost && planned.contact.is_accepted() {
                    return self.start_session(rng, Some(planned.contact));
                }
                let prepared = self.prepare_seal(*planned)?;
                Ok(self.request_transport(prepared))
            }
            EncryptionPhase::NewSessionRequested(new_session) => {
                let prepared = self.prepare_new_session(*new_session)?;
                Ok(self.request_transport(prepared))
            }
            EncryptionPhase::TransportRequested(mut prepared) => {
                match prepared.transport_binding.take() {
                    Some(transport_binding) => Ok(self.seal(rng, *prepared, &transport_binding)?),
                    None => Ok(self.request_transport(*prepared)),
                }
            }
            EncryptionPhase::Taken => Err(MessageOperationError::Finished),
        }
    }

    fn request_transport(&mut self, prepared: PreparedSeal) -> MessageEncryptionStep {
        let destination = prepared.route.destination(self.recipient);
        self.phase = EncryptionPhase::TransportRequested(Box::new(prepared));
        MessageEncryptionStep::NeedsTransport(destination)
    }

    // Decides what this send is from the contact's record and Sessions, and asks for what it
    // needs next.
    fn plan<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<MessageEncryptionStep, MessageOperationError> {
        let limits = self.engine.limits;
        let snapshot = self.reads.snapshot();
        let address = contact_address(self.recipient);
        let contact = load_contact(snapshot, &address, limits)?;
        let sessions =
            load_peer_sessions(snapshot, &peer_sessions_address(self.recipient), limits)?;
        if contact.as_ref().is_some_and(|contact| contact.blocked) {
            return Err(ProtocolStateError::BlockedContact.into());
        }
        let contact = match contact {
            // A contact with no Session and no consent has no Session for a bundle to replace.
            Some(contact) if contact.is_accepted() || sessions.is_some() => {
                match self.check_discovery_key(contact)? {
                    DiscoveryKeyCheck::NeedsBundle => {
                        return Ok(MessageEncryptionStep::NeedsPreKeyBundle(self.recipient));
                    }
                    DiscoveryKeyCheck::Rotated(rotated) => {
                        return self.start_rotated_session(rng, *rotated, sessions.as_ref());
                    }
                    DiscoveryKeyCheck::Checked(contact) => Some(*contact),
                }
            }
            contact => contact,
        };
        let local_grant = self.sender.grant().stamp();
        let (mut contact, sessions) = match (contact, sessions) {
            (contact, None) | (contact @ None, Some(_)) if self.intent == SendIntent::Request => {
                return self.start_session(rng, contact);
            }
            // An accepted contact has a Session unless the host lost its records.
            (Some(contact), None) if contact.is_accepted() => {
                return self.start_session(rng, Some(contact));
            }
            // The requester's Session is gone, such as after a restore, so the acceptance starts
            // a new one, and its Contact Request crosses the requester's, which accepts both sides.
            // A contact that never wrote never asked.
            (Some(mut contact), None)
                if self.intent == SendIntent::Acceptance
                    && contact.has_written_before_acceptance() =>
            {
                contact.accept();
                return self.start_session(rng, Some(contact));
            }
            (Some(contact), Some(sessions)) if contact.is_accepted() => {
                let session_id = sessions.current();
                let carries_grant = contact.receives_grant(Starter::Local, local_grant);
                let Some(payload_kind) = self.payload_kind(carries_grant) else {
                    return Ok(MessageEncryptionStep::NothingToSend);
                };
                return Ok(self.request_session(Planned {
                    payload_kind,
                    contact,
                    session_id,
                }));
            }
            (Some(contact), Some(sessions)) => (contact, sessions),
            (None, _) if self.intent != SendIntent::Acceptance => {
                return Err(ProtocolStateError::MissingRequiredState { address }.into());
            }
            (Some(_), None)
                if matches!(self.intent, SendIntent::Message | SendIntent::GrantUpdate) =>
            {
                return Err(ProtocolStateError::ContactNotAccepted.into());
            }
            (None | Some(_), _) => return Err(ProtocolStateError::NoContactRequest.into()),
        };
        let starter = sessions.current_starter();
        let payload_kind = match (self.intent, starter) {
            (SendIntent::Request | SendIntent::Acceptance, Starter::Peer) => {
                contact.accept();
                PayloadKind::ContactAcceptance
            }
            (SendIntent::Acceptance, Starter::Local) => {
                return Err(ProtocolStateError::NoContactRequest.into());
            }
            // The asked side keeps its grant private until it accepts.
            (SendIntent::GrantUpdate, Starter::Peer) => {
                return Err(ProtocolStateError::ContactNotAccepted.into());
            }
            // A Grant Update carries no content, so it doesn't count toward the limit.
            (SendIntent::GrantUpdate, Starter::Local) => {
                match self.payload_kind(contact.receives_grant(starter, local_grant)) {
                    Some(payload_kind) => {
                        contact.record_grant_update(self.message_id, local_grant);
                        payload_kind
                    }
                    None => return Ok(MessageEncryptionStep::NothingToSend),
                }
            }
            (SendIntent::Message | SendIntent::Request, _) => {
                let carries_grant = contact.receives_grant(starter, local_grant);
                contact.count_sent(self.message_id, carries_grant.then_some(local_grant))?;
                text_kind(carries_grant)
            }
        };
        Ok(self.request_session(Planned {
            contact,
            payload_kind,
            session_id: sessions.current(),
        }))
    }

    // Returns what this send carries, or `None` for a Grant Update with no grant to carry.
    fn payload_kind(&self, carries_grant: bool) -> Option<PayloadKind> {
        match self.intent {
            SendIntent::GrantUpdate => carries_grant.then_some(PayloadKind::GrantUpdate),
            SendIntent::Message | SendIntent::Request | SendIntent::Acceptance => {
                Some(text_kind(carries_grant))
            }
        }
    }

    fn request_session(&mut self, planned: Planned) -> MessageEncryptionStep {
        let session_id = planned.session_id;
        self.phase = EncryptionPhase::SessionRequested(Box::new(planned));
        MessageEncryptionStep::NeedsState(self.reads.request(vec![
            session_address(session_id),
            pending_acknowledgment_address(session_id),
        ]))
    }

    // Starts a Session from the bundle the app fetched, after checking it against the contact.
    fn start_session<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        contact: Option<ContactRecord>,
    ) -> Result<MessageEncryptionStep, MessageOperationError> {
        let Some(bundle) = self.prekey_bundle.take() else {
            return Ok(MessageEncryptionStep::NeedsPreKeyBundle(self.recipient));
        };
        let bundle_discovery_key = self.verify_bundle(&bundle)?;
        if contact
            .as_ref()
            .is_some_and(|contact| contact.has_newer_discovery_key_than(&bundle_discovery_key))
        {
            return Ok(MessageEncryptionStep::NeedsPreKeyBundle(self.recipient));
        }
        let contact = contact.unwrap_or_else(|| ContactRecord::pending(self.recipient, None));
        self.start_session_from(rng, contact, bundle, bundle_discovery_key)
    }

    // Returns the bundle's Discovery Key once the bundle proves it belongs to the recipient.
    fn verify_bundle(
        &self,
        bundle: &PeerPreKeyBundle,
    ) -> Result<ContactDiscoveryKey, ProtocolStateError> {
        let bundle_identity_key = ContactIdentityKey {
            x25519_public_key: *bundle.identity_key.public_key.as_bytes(),
            ed25519_verifying_key: bundle.identity_key.verifying_key.to_bytes(),
        };
        if !contact_identity_keys_match(&bundle_identity_key, &self.recipient) {
            return Err(ProtocolStateError::InvalidMessage {
                reason: "prekey bundle belongs to another identity".into(),
            });
        }
        verify_discovery_to_identity_binding(
            &bundle.identity_key,
            &bundle.bundle.discovery_key.verifying_key,
            &bundle.discovery_to_identity,
        )
        .map_err(roost_crypto::HandshakeError::from)?;
        Ok(ContactDiscoveryKey::from(&bundle.bundle.discovery_key))
    }

    // Checks the bundle the app passed against the contact. A bundle naming a newer Discovery Key,
    // such as one from a fresh contact link, starts a new Session, since the Relay silently drops
    // Messages sent with the old capability. The first send after an unblock needs a bundle, since
    // the contact may have rotated during the block.
    fn check_discovery_key(
        &mut self,
        mut contact: ContactRecord,
    ) -> Result<DiscoveryKeyCheck, ProtocolStateError> {
        let Some(bundle) = self.prekey_bundle.take() else {
            return Ok(if contact.needs_discovery_key_check {
                DiscoveryKeyCheck::NeedsBundle
            } else {
                DiscoveryKeyCheck::Checked(Box::new(contact))
            });
        };
        let bundle_discovery_key = self.verify_bundle(&bundle)?;
        if contact.has_newer_discovery_key_than(&bundle_discovery_key) {
            if contact.needs_discovery_key_check {
                return Ok(DiscoveryKeyCheck::NeedsBundle);
            }
        } else {
            contact.needs_discovery_key_check = false;
            if contact.discovery_key != Some(bundle_discovery_key) {
                return Ok(DiscoveryKeyCheck::Rotated(Box::new(RotatedContact {
                    contact,
                    bundle,
                    bundle_discovery_key,
                })));
            }
        }
        self.prekey_bundle = Some(bundle);
        Ok(DiscoveryKeyCheck::Checked(Box::new(contact)))
    }

    // Starts a Session with a contact that rotated its inbox. The asked side's acceptance counts
    // only on the requester's Session, whose inbox is gone, so a send to a requester asks again,
    // and the requests cross, which accepts both sides.
    fn start_rotated_session<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        rotated: RotatedContact,
        sessions: Option<&PeerSessions>,
    ) -> Result<MessageEncryptionStep, MessageOperationError> {
        let RotatedContact {
            mut contact,
            bundle,
            bundle_discovery_key,
        } = rotated;
        let peer_asked =
            sessions.is_some_and(|sessions| sessions.current_starter() == Starter::Peer);
        if !contact.is_accepted() {
            match (self.intent, peer_asked) {
                (SendIntent::GrantUpdate, true) => {
                    return Err(ProtocolStateError::ContactNotAccepted.into());
                }
                (SendIntent::Acceptance, false) => {
                    return Err(ProtocolStateError::NoContactRequest.into());
                }
                (_, true) => contact.accept(),
                (_, false) => {}
            }
        }
        self.start_session_from(rng, contact, bundle, bundle_discovery_key)
    }

    // Starts a Session with `contact` from a bundle already checked against it.
    fn start_session_from<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        mut contact: ContactRecord,
        bundle: PeerPreKeyBundle,
        bundle_discovery_key: ContactDiscoveryKey,
    ) -> Result<MessageEncryptionStep, MessageOperationError> {
        let local_grant = self.sender.grant().stamp();
        let carries_grant = contact.receives_grant(Starter::Local, local_grant);
        let Some(payload_kind) = self.payload_kind(carries_grant) else {
            return Ok(MessageEncryptionStep::NothingToSend);
        };
        if !contact.is_accepted() {
            if counts_toward_limit(payload_kind) {
                contact.count_sent(self.message_id, carries_grant.then_some(local_grant))?;
            } else {
                contact.record_grant_update(self.message_id, local_grant);
            }
        }
        let (state, session_id, handshake) =
            initiate_handshake(rng, &bundle.identity_key, &bundle.bundle)
                .map_err(ProtocolStateError::from)?;
        contact.record_discovery_key(bundle_discovery_key);
        let (peer_sessions, evicted) = match load_peer_sessions(
            self.reads.snapshot(),
            &peer_sessions_address(self.recipient),
            self.engine.limits,
        )? {
            Some(mut sessions) => {
                let evicted = sessions.start(session_id, None);
                (sessions, evicted)
            }
            None => (PeerSessions::new(session_id, None), Vec::new()),
        };
        let mut addresses = session_record_addresses(session_id).to_vec();
        for evicted in &evicted {
            addresses.extend(session_record_addresses(*evicted));
        }
        self.phase = EncryptionPhase::NewSessionRequested(Box::new(NewSession {
            planned: Planned {
                payload_kind,
                contact,
                session_id,
            },
            state: Box::new(state),
            pending_handshake: PendingHandshake {
                handshake,
                signed_prekey_id: bundle.bundle.signed_prekey.id,
            },
            peer_sessions,
            evicted,
        }));
        Ok(MessageEncryptionStep::NeedsState(
            self.reads.request(addresses),
        ))
    }

    // Checks that the new Session's records don't exist yet.
    fn prepare_new_session(
        &self,
        new_session: NewSession,
    ) -> Result<PreparedSeal, ProtocolStateError> {
        let session_id = new_session.planned.session_id;
        for address in session_record_addresses(session_id) {
            if self.reads.snapshot().get(&address).is_some() {
                return Err(ProtocolStateError::InvalidStateBinding {
                    address,
                    reason: "session already exists".into(),
                });
            }
        }
        Ok(PreparedSeal {
            route: Route::first_message(&new_session.pending_handshake),
            planned: new_session.planned,
            state: new_session.state,
            pending_handshake: Some(new_session.pending_handshake),
            pending: LoadedPendingAcknowledgments::empty(),
            started: Some((new_session.peer_sessions, new_session.evicted)),
            transport_binding: None,
        })
    }

    // Checks the Session Roost selected and finds where the Message goes.
    fn prepare_seal(&self, planned: Planned) -> Result<PreparedSeal, ProtocolStateError> {
        let limits = self.engine.limits;
        let snapshot = self.reads.snapshot();
        let address = session_address(planned.session_id);
        let LoadedSession {
            peer_identity_key,
            state,
            pending_handshake,
        } = load_required_session(snapshot, &address, limits)?;
        if !contact_identity_keys_match(&peer_identity_key, &self.recipient) {
            return Err(ProtocolStateError::InvalidStateBinding {
                address,
                reason: "session belongs to another peer".into(),
            });
        }
        let pending = load_pending_acknowledgments(
            snapshot,
            &pending_acknowledgment_address(planned.session_id),
            limits,
        )?;
        let route = match &pending_handshake {
            Some(pending_handshake) => Route::first_message(pending_handshake),
            None => Route::established(&planned.contact)?,
        };
        Ok(PreparedSeal {
            planned,
            state,
            pending_handshake,
            pending,
            started: None,
            route,
            transport_binding: None,
        })
    }

    fn seal<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        prepared: PreparedSeal,
        transport_binding: &TransportBinding,
    ) -> Result<MessageEncryptionStep, ProtocolStateError> {
        let limits = self.engine.limits;
        let PreparedSeal {
            planned,
            mut state,
            pending_handshake,
            mut pending,
            started,
            route,
            ..
        } = prepared;
        let Planned {
            contact,
            payload_kind,
            session_id,
        } = planned;
        let grant = self.sender.grant();
        let granted;
        let payload: &[u8] = if payload_kind.carries_grant() {
            granted = encode_granted_payload(&grant, &self.plaintext)?;
            &granted
        } else {
            &self.plaintext
        };
        let content = OutboundContent {
            session_id,
            id: self.message_id,
            sent_at_millis: self.sent_at_millis,
            payload_kind,
            payload,
        };
        let sender = self.sender.local_sender();
        let message = match &pending_handshake {
            Some(pending_handshake) => seal_proved(
                rng,
                &mut state,
                content,
                &pending_handshake.handshake,
                &sender,
                transport_binding,
                limits,
            )?,
            None => seal_signed(
                rng,
                &mut state,
                content,
                SignedRecipient {
                    discovery_key: route.discovery_key(),
                    identity_verifying_key: &self.recipient.ed25519_verifying_key,
                },
                &sender,
                transport_binding,
                limits,
            )?,
        };
        let pending_address = pending_acknowledgment_address(session_id);
        // A contact that hasn't accepted acknowledges nothing yet, so nothing waits for it.
        if contact.is_accepted() {
            pending.record(
                self.message_id,
                LoadedPendingAcknowledgment {
                    first_sent_at_millis: self.sent_at_millis,
                    payload_kind,
                    grant: payload_kind.carries_grant().then(|| grant.stamp()),
                    sent_to: contact.discovery_key.as_ref().map(DiscoveryKeyStamp::of),
                    held: false,
                },
            )?;
        }
        let snapshot = self.reads.snapshot();
        let (deletions, stranded) = match &started {
            Some((_, evicted)) => evict_sessions(snapshot, evicted, limits)?,
            None => (Vec::new(), Vec::new()),
        };
        let mut undelivered = Vec::new();
        for StrandedMessage {
            message_id,
            mut entry,
        } in stranded
        {
            // A resend's new copy waits on the new Session instead.
            if message_id == self.message_id {
                continue;
            }
            // The rest of a recovery wait behind its probe on the probe's Session, except Grant
            // Updates, which recovered Messages replace.
            if self.replaces.is_some() && entry.payload_kind != PayloadKind::GrantUpdate {
                entry.held = true;
                pending.record(message_id, entry)?;
            } else {
                undelivered.push(message_id);
            }
        }
        let mut updates = vec![
            session_update(
                snapshot,
                session_id,
                self.recipient,
                &state,
                pending_handshake.as_ref(),
                limits,
            )?,
            ProtocolStateUpdate::set(
                pending_address.clone(),
                encode_pending_acknowledgments(&pending_address, &pending, limits)?,
            )
            .with_snapshot(snapshot),
        ];
        updates.extend(contact_update(snapshot, &contact, limits)?);
        let mut evicted = Vec::new();
        if let Some((peer_sessions, started_evicted)) = started {
            let peer_address = peer_sessions_address(self.recipient);
            updates.push(
                ProtocolStateUpdate::set(
                    peer_address.clone(),
                    encode_peer_sessions(&peer_address, &peer_sessions, limits)?,
                )
                .with_snapshot(snapshot),
            );
            updates.extend(deletions);
            evicted = started_evicted;
        }
        // A Session this send evicts takes its copy with it, and a held copy on this Session was
        // replaced above.
        if let Some(replaced) = self
            .replaces
            .filter(|replaced| *replaced != session_id && !evicted.contains(replaced))
        {
            let address = pending_acknowledgment_address(replaced);
            let mut replaced_pending = load_pending_acknowledgments(snapshot, &address, limits)?;
            replaced_pending.pending.remove(self.message_id.as_bytes());
            updates.push(recovery::pending_update(
                snapshot,
                replaced,
                &replaced_pending,
                limits,
            )?);
        }
        Ok(MessageEncryptionStep::Ready {
            result: Box::new(OutboundMessageResult {
                session_id,
                message_id: self.message_id,
                sent_at_millis: self.sent_at_millis,
                payload_kind,
                message,
            }),
            changes: changes(&self.reads, updates).with_undelivered(undelivered),
        })
    }
}

// A Grant Update carries no content, so it doesn't count toward the limit before acceptance.
fn counts_toward_limit(payload_kind: PayloadKind) -> bool {
    payload_kind != PayloadKind::GrantUpdate
}

fn text_kind(carries_grant: bool) -> PayloadKind {
    if carries_grant {
        PayloadKind::EncryptedTextWithGrant
    } else {
        PayloadKind::EncryptedText
    }
}

/// One attempt to decrypt a received Message, which asks for the records it needs and returns
/// its result once.
///
/// Call [`Self::step`] until it returns [`MessageDecryptionStep::Ready`], supplying what each
/// other step asks for. A first Message on a signed prekey kept after a rotation asks for proof of
/// admission before Roost uses that prekey. A Message that needs an acknowledgment asks for that
/// acknowledgment's Transport Binding only after its sender authenticates and Roost decides to
/// reply. Calling [`Self::step`] again before supplying input returns the same request without
/// repeating work. Dropping the operation commits nothing.
pub struct MessageDecryption(Option<Box<Decrypting>>);

struct Decrypting {
    engine: ProtocolStateEngine,
    store: KeyStore,
    // When the operation started, the one time it reads for every key lookup.
    now: SystemTime,
    local: LocalSenderKeys,
    message: SealedFrame,
    encoded: Vec<u8>,
    transport_binding: TransportBinding,
    settings: ReceiveSettings,
    validation: InboundSenderCertificateValidation,
    acknowledgment_sent_at_millis: u64,
    reads: StateReads,
    phase: DecryptionPhase,
}

enum DecryptionPhase {
    Started,
    DeduplicationRequested,
    SessionRequested(Box<Opened>),
    PeerRequested(Box<KnownSession>),
    OtherSessionsRequested(Box<UnmatchedAcknowledgment>),
    AdmissionRequested(Box<FirstMessage>),
    FirstMessagePeerRequested(Box<AcceptedFirstMessage>),
    FirstMessageCurrentRequested(Box<AcceptedFirstMessage>, PeerSessions),
    AcknowledgmentTransportRequested(Box<Acknowledging>),
    Taken,
}

// A Message that passed deduplication and opened under the local Discovery Key.
struct Opened {
    deduplication: LoadedDeduplicationSet,
    digest: [u8; DIGEST_LEN],
    message: OpenedMessage,
}

// A Message on a Session this identity has, waiting for its peer's records.
struct KnownSession {
    opened: Opened,
    session_id: SessionId,
    peer_identity_key: ContactIdentityKey,
    state: Box<RatchetState>,
    pending_handshake: Option<PendingHandshake>,
}

// An authenticated acknowledgment that matched nothing on its own Session, waiting for the
// Pending Acknowledgments of the peer's other Sessions.
struct UnmatchedAcknowledgment {
    result: Box<AcknowledgmentResult>,
    updates: Vec<ProtocolStateUpdate>,
    others: Vec<SessionId>,
}

// A first Message whose signed prekey needs proof of admission.
struct FirstMessage {
    opened: Opened,
    reference: SealedFramePreKeyReference,
    admission: AdmissionRequest,
    admitted: bool,
}

// A first Message that authenticated and created a Session, waiting for its sender's records.
struct AcceptedFirstMessage {
    deduplication: LoadedDeduplicationSet,
    digest: [u8; DIGEST_LEN],
    session_id: SessionId,
    state: Box<RatchetState>,
    sender_identity_key: ContactIdentityKey,
    sender_discovery_key: ContactDiscoveryKey,
    grant: Option<InboxGrant>,
    message_id: MessageId,
    sent_at_millis: u64,
    payload_kind: PayloadKind,
    plaintext: Zeroizing<Vec<u8>>,
    sender_identity: SenderIdentityMaterial,
    accepted_with: SignedPreKeyUse,
    held_signed_prekeys: Vec<PublicSignedPreKey>,
    one_time_prekey: Option<OneTimePreKeyUse>,
}

// The one-time prekey a new Session used, by its Epoch and ID.
#[derive(Clone, Copy)]
struct OneTimePreKeyUse {
    epoch: u32,
    id: u64,
}

// What an authenticated Message turned out to be.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Delivered {
    Accepted,
    ContactRequest,
    Blocked,
}

// An authenticated Message and the state changes it makes, before any acknowledgment.
struct Delivery {
    session_id: SessionId,
    peer_identity_key: ContactIdentityKey,
    state: Box<RatchetState>,
    pending_handshake: Option<PendingHandshake>,
    message_id: MessageId,
    sent_at_millis: u64,
    payload_kind: PayloadKind,
    plaintext: Zeroizing<Vec<u8>>,
    sender_identity: SenderIdentityMaterial,
    delivered: Delivered,
    // Whether an acknowledgment carries the local Inbox Grant.
    acknowledgment_carries_grant: bool,
    // Every update except the Session's, which sealing an acknowledgment advances.
    updates: Vec<ProtocolStateUpdate>,
    // Sent Messages whose Session the new one evicted.
    undelivered: Vec<MessageId>,
    one_time_prekey: Option<OneTimePreKeyUse>,
}

// A delivered Message waiting only for its acknowledgment's Transport Binding.
struct Acknowledging {
    delivery: Delivery,
    route: Route,
    transport_binding: Option<TransportBinding>,
}

impl MessageDecryption {
    /// Advances the operation and returns what it needs next, or its result.
    ///
    /// Decryption and the acknowledgment's sealing happen here, never in the supply calls.
    /// Returning [`MessageDecryptionStep::Ready`] or an error ends the operation.
    pub fn step<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<MessageDecryptionStep, MessageOperationError> {
        let decrypting = self.0.as_mut().ok_or(MessageOperationError::Finished)?;
        let step = decrypting.advance(rng);
        if !matches!(
            step,
            Ok(MessageDecryptionStep::NeedsState(_)
                | MessageDecryptionStep::NeedsAdmission(_)
                | MessageDecryptionStep::NeedsAcknowledgmentTransport(_))
        ) {
            self.0 = None;
        }
        step
    }

    /// Supplies one entry for each record the pending [`MessageDecryptionStep::NeedsState`]
    /// named, in any order, with `None` for an absent record.
    pub fn supply_state(
        &mut self,
        entries: Vec<(ProtocolStateAddress, Option<ProtocolStateBlob>)>,
    ) -> Result<(), MessageOperationError> {
        let decrypting = self.0.as_mut().ok_or(MessageOperationError::Finished)?;
        let supplied = supply_state(&mut decrypting.reads, entries);
        if supplied.is_err() {
            self.0 = None;
        }
        supplied
    }

    /// Confirms the pending [`MessageDecryptionStep::NeedsAdmission`]: the Relay's proof shows it
    /// admitted this exact Message as a first Message against the named signed prekey.
    pub fn confirm_admission(&mut self) -> Result<(), MessageOperationError> {
        let decrypting = self.0.as_mut().ok_or(MessageOperationError::Finished)?;
        if let DecryptionPhase::AdmissionRequested(first) = &mut decrypting.phase
            && !first.admitted
        {
            first.admitted = true;
            return Ok(());
        }
        self.0 = None;
        Err(MessageOperationError::NotAwaitingAdmission)
    }

    /// Supplies the Transport Binding for the pending
    /// [`MessageDecryptionStep::NeedsAcknowledgmentTransport`].
    pub fn supply_acknowledgment_transport_binding(
        &mut self,
        transport_binding: TransportBinding,
    ) -> Result<(), MessageOperationError> {
        let decrypting = self.0.as_mut().ok_or(MessageOperationError::Finished)?;
        if let DecryptionPhase::AcknowledgmentTransportRequested(acknowledging) =
            &mut decrypting.phase
            && acknowledging.transport_binding.is_none()
        {
            acknowledging.transport_binding = Some(transport_binding);
            return Ok(());
        }
        self.0 = None;
        Err(MessageOperationError::NotAwaitingTransportBinding)
    }
}

impl Decrypting {
    fn advance<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<MessageDecryptionStep, MessageOperationError> {
        if let Some(pending) = self.reads.pending() {
            return Ok(MessageDecryptionStep::NeedsState(pending.to_vec()));
        }
        match std::mem::replace(&mut self.phase, DecryptionPhase::Taken) {
            DecryptionPhase::Started => {
                self.phase = DecryptionPhase::DeduplicationRequested;
                Ok(MessageDecryptionStep::NeedsState(
                    self.reads.request(vec![deduplication_address()]),
                ))
            }
            DecryptionPhase::DeduplicationRequested => self.open(rng),
            DecryptionPhase::SessionRequested(opened) => self.load_session(rng, *opened),
            DecryptionPhase::PeerRequested(known) => self.authenticate(rng, *known),
            DecryptionPhase::OtherSessionsRequested(unmatched) => self.match_elsewhere(*unmatched),
            DecryptionPhase::AdmissionRequested(first) => {
                if first.admitted {
                    let FirstMessage {
                        opened, reference, ..
                    } = *first;
                    self.accept_first_message(rng, opened, reference)
                } else {
                    let admission = first.admission;
                    self.phase = DecryptionPhase::AdmissionRequested(first);
                    Ok(MessageDecryptionStep::NeedsAdmission(admission))
                }
            }
            DecryptionPhase::FirstMessagePeerRequested(first) => self.read_current_session(*first),
            DecryptionPhase::FirstMessageCurrentRequested(first, sessions) => {
                self.record_first_message(*first, Some(sessions))
            }
            DecryptionPhase::AcknowledgmentTransportRequested(mut acknowledging) => {
                match acknowledging.transport_binding.take() {
                    Some(transport_binding) => {
                        self.acknowledge(rng, *acknowledging, &transport_binding)
                    }
                    None => {
                        let destination = acknowledging
                            .route
                            .destination(acknowledging.delivery.peer_identity_key);
                        self.phase =
                            DecryptionPhase::AcknowledgmentTransportRequested(acknowledging);
                        Ok(MessageDecryptionStep::NeedsAcknowledgmentTransport(
                            destination,
                        ))
                    }
                }
            }
            DecryptionPhase::Taken => Err(MessageOperationError::Finished),
        }
    }

    // Drops a repeated delivery before decrypting anything, then opens the Message to learn which
    // Session it names.
    fn open<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<MessageDecryptionStep, MessageOperationError> {
        let deduplication = receiving_deduplication_set(
            rng,
            self.reads.snapshot(),
            self.settings,
            self.engine.limits,
        )?;
        let digest = deduplication.digest(self.transport_binding.as_bytes(), &self.encoded);
        if deduplication.contains(&digest) {
            return Ok(unchanged(InboundMessageOutcome::Duplicate));
        }
        let sealed_to = &self.message.recipient_public_key;
        // Only an established Message outlives a rotation, which deletes the prekeys a first
        // Message names.
        let previous = if self.message.prekey_reference.is_none()
            && sealed_to != self.local.keys.discovery_key.public_key().as_bytes()
        {
            self.store.previous_discovery_key(sealed_to, self.now)?
        } else {
            None
        };
        let discovery_key = previous.as_ref().unwrap_or(&self.local.keys.discovery_key);
        let message = open_message(&self.message, discovery_key, &self.transport_binding)?;
        let session_id = message.metadata.session_id;
        let mut addresses = vec![session_address(session_id)];
        if message.metadata.payload_kind.is_acknowledgment() {
            addresses.push(pending_acknowledgment_address(session_id));
        }
        self.phase = DecryptionPhase::SessionRequested(Box::new(Opened {
            deduplication,
            digest,
            message,
        }));
        Ok(MessageDecryptionStep::NeedsState(
            self.reads.request(addresses),
        ))
    }

    // Finds the Session the Message names, then asks for its peer's records. A Message that names
    // no Session this identity has may start one when it carries a handshake.
    fn load_session<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        opened: Opened,
    ) -> Result<MessageDecryptionStep, MessageOperationError> {
        let limits = self.engine.limits;
        let session_id = opened.message.metadata.session_id;
        let snapshot = self.reads.snapshot();
        let Some(session) = load_session(snapshot, &session_address(session_id), limits)? else {
            return match self.message.prekey_reference {
                Some(reference) => self.check_admission(rng, opened, reference),
                None => Ok(unchanged(InboundMessageOutcome::UnknownSession)),
            };
        };
        let is_acknowledgment = opened.message.metadata.payload_kind.is_acknowledgment();
        if is_acknowledgment
            && has_seen_acknowledgment(
                snapshot,
                &pending_acknowledgment_address(session_id),
                acknowledgment_digest(self.transport_binding.as_bytes(), &self.encoded),
                limits,
            )?
        {
            return Ok(unchanged(InboundMessageOutcome::Duplicate));
        }
        let LoadedSession {
            peer_identity_key,
            state,
            pending_handshake,
        } = session;
        let addresses = vec![
            contact_address(peer_identity_key),
            peer_sessions_address(peer_identity_key),
        ];
        self.phase = DecryptionPhase::PeerRequested(Box::new(KnownSession {
            opened,
            session_id,
            peer_identity_key,
            state,
            pending_handshake,
        }));
        Ok(MessageDecryptionStep::NeedsState(
            self.reads.request(addresses),
        ))
    }

    // Asks for proof of admission when the first Message names a signed prekey kept after a
    // rotation, since the Relay admits first Messages only against the current one.
    fn check_admission<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        opened: Opened,
        reference: SealedFramePreKeyReference,
    ) -> Result<MessageDecryptionStep, MessageOperationError> {
        let Some(signed_prekey_id) = self.store.signed_prekey_needing_admission(
            reference.discovery_epoch,
            &reference.signed_prekey_public_key,
            self.now,
        )?
        else {
            return self.accept_first_message(rng, opened, reference);
        };
        let admission = AdmissionRequest {
            discovery_epoch: reference.discovery_epoch,
            signed_prekey_id,
        };
        self.phase = DecryptionPhase::AdmissionRequested(Box::new(FirstMessage {
            opened,
            reference,
            admission,
            admitted: false,
        }));
        Ok(MessageDecryptionStep::NeedsAdmission(admission))
    }

    // Runs the handshake a first Message carries, decrypts it, and authenticates its sender, then
    // asks for the sender's records.
    fn accept_first_message<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        opened: Opened,
        reference: SealedFramePreKeyReference,
    ) -> Result<MessageDecryptionStep, MessageOperationError> {
        let limits = self.engine.limits;
        let Opened {
            deduplication,
            digest,
            message,
        } = opened;
        let prekeys = self.store.first_message_prekeys(&reference, self.now)?;
        let session_id = message.metadata.session_id;
        let base_key =
            message
                .metadata
                .base_key
                .ok_or_else(|| ProtocolStateError::InvalidMessage {
                    reason: "message carries no handshake".into(),
                })?;
        let handshake = Handshake {
            base_key: PublicKey::from(base_key),
            responder_discovery_key: PublicKey::from(self.message.recipient_public_key),
            prekey_reference: reference,
        };
        let (mut state, derived_session_id) = accept_handshake(
            &handshake,
            &self.local.keys.discovery_key,
            &prekeys.signed_prekey,
            prekeys.one_time_prekey,
        )
        .map_err(ProtocolStateError::from)?;
        if !bool::from(derived_session_id.as_bytes().ct_eq(session_id.as_bytes())) {
            return Err(ProtocolStateError::InvalidMessage {
                reason: "session id does not match its handshake".into(),
            }
            .into());
        }
        let payload_kind = message.metadata.payload_kind;
        if payload_kind.is_acknowledgment() {
            return Err(ProtocolStateError::InvalidMessage {
                reason: "an acknowledgment cannot start a session".into(),
            }
            .into());
        }
        let decoded = message.decrypt(rng, &mut state, limits)?;
        let (sender, sender_discovery_key) =
            authenticate_first_message(&decoded, &handshake, &prekeys.signed_prekey)?;
        let sender_identity_key = certified_sender_identity_key(
            &self.validation,
            self.settings.certificate_grace,
            &decoded.sender_identity,
        )?;
        // The sender started this Session, so it can't be accepting a request this side made.
        if payload_kind == PayloadKind::ContactAcceptance {
            return Err(ProtocolStateError::UnsolicitedAcceptance.into());
        }
        let (grant, plaintext) = open_payload(payload_kind, decoded.plaintext, &sender)?;
        let accepted = AcceptedFirstMessage {
            deduplication,
            digest,
            session_id,
            state: Box::new(state),
            sender_identity_key,
            sender_discovery_key,
            grant,
            message_id: message.metadata.id,
            sent_at_millis: message.metadata.sent_at_millis,
            payload_kind,
            plaintext,
            sender_identity: decoded.sender_identity,
            accepted_with: SignedPreKeyUse {
                epoch: reference.discovery_epoch,
                public_key: reference.signed_prekey_public_key,
            },
            held_signed_prekeys: prekeys.held_signed_prekeys,
            one_time_prekey: reference.one_time_prekey.map(|prekey| OneTimePreKeyUse {
                epoch: reference.discovery_epoch,
                id: prekey.id,
            }),
        };
        let addresses = vec![
            contact_address(sender_identity_key),
            peer_sessions_address(sender_identity_key),
        ];
        self.phase = DecryptionPhase::FirstMessagePeerRequested(Box::new(accepted));
        Ok(MessageDecryptionStep::NeedsState(
            self.reads.request(addresses),
        ))
    }

    // Asks for the records the new Session's start touches: the Session this side sends on when
    // this side started it, since the new one replaces it only once it no longer awaits a reply,
    // and the records of the Sessions it evicts.
    fn read_current_session(
        &mut self,
        first: AcceptedFirstMessage,
    ) -> Result<MessageDecryptionStep, MessageOperationError> {
        let sessions = load_peer_sessions(
            self.reads.snapshot(),
            &peer_sessions_address(first.sender_identity_key),
            self.engine.limits,
        )?;
        let sessions = match sessions {
            Some(sessions)
                if !sessions.was_deleted(first.session_id)
                    && !sessions.contains(first.session_id) =>
            {
                sessions
            }
            sessions => return self.record_first_message(first, sessions),
        };
        let mut addresses: Vec<ProtocolStateAddress> = sessions
            .evicted_by_next_start()
            .iter()
            .flat_map(|entry| session_record_addresses(entry.session_id))
            .collect();
        if sessions.current_starter() == Starter::Local {
            addresses.push(session_address(sessions.current()));
        }
        if addresses.is_empty() {
            return self.record_first_message(first, Some(sessions));
        }
        self.phase = DecryptionPhase::FirstMessageCurrentRequested(Box::new(first), sessions);
        Ok(MessageDecryptionStep::NeedsState(
            self.reads.request(addresses),
        ))
    }

    // Records the new Session and what the first Message means for the sender's contact record.
    fn record_first_message(
        &mut self,
        first: AcceptedFirstMessage,
        sessions: Option<PeerSessions>,
    ) -> Result<MessageDecryptionStep, MessageOperationError> {
        let limits = self.engine.limits;
        let AcceptedFirstMessage {
            mut deduplication,
            digest,
            session_id,
            state,
            sender_identity_key,
            sender_discovery_key,
            grant,
            message_id,
            sent_at_millis,
            payload_kind,
            plaintext,
            sender_identity,
            accepted_with,
            held_signed_prekeys,
            one_time_prekey,
        } = first;
        let snapshot = self.reads.snapshot();
        let previous = load_contact(snapshot, &contact_address(sender_identity_key), limits)?;
        let local_asked = sessions
            .as_ref()
            .is_some_and(|sessions| sessions.current_starter() == Starter::Local);
        let (peer_sessions, evicted) = match sessions {
            // The Session's blob is gone by now, so one the list still names was wiped by the
            // host.
            Some(sessions) if sessions.was_deleted(session_id) || sessions.contains(session_id) => {
                return Ok(unchanged(InboundMessageOutcome::DeletedSession));
            }
            Some(mut sessions) => {
                sessions.forget_deletions_unless(|signed_prekey| {
                    held_signed_prekeys.iter().any(|held| {
                        held.epoch == signed_prekey.epoch
                            && held.public_key.as_bytes() == &signed_prekey.public_key
                    })
                });
                let evicted = if self.engine.awaits_reply(
                    snapshot,
                    sessions.current(),
                    &sender_discovery_key,
                )? {
                    sessions.start_alongside(session_id, Some(accepted_with))
                } else {
                    sessions.start(session_id, Some(accepted_with))
                };
                (sessions, evicted)
            }
            None => (
                PeerSessions::new(session_id, Some(accepted_with)),
                Vec::new(),
            ),
        };
        let created = previous.is_none();
        let mut contact = match previous {
            // A new Session proves the contact may have lost the old ones, and with them the local
            // grant, as a restore does.
            Some(mut contact) => {
                contact.forget_recovery();
                contact.forget_acknowledged_grant();
                contact
            }
            // Only a Contact Request creates a record, so a stranger can't skip showing one.
            None if payload_kind == PayloadKind::GrantUpdate => {
                return Err(ProtocolStateError::InvalidMessage {
                    reason: "a grant update cannot start a contact".into(),
                }
                .into());
            }
            // A Contact Request carries the requester's grant, which the asked side's replies use.
            None if grant.is_some() => ContactRecord::pending(sender_identity_key, None),
            None => {
                return Err(ProtocolStateError::InvalidMessage {
                    reason: "contact request carries no inbox grant".into(),
                }
                .into());
            }
        };
        contact.record_discovery_key(sender_discovery_key);
        if let Some(grant) = grant {
            contact.record_grant(grant);
        }
        let delivered = if contact.blocked {
            Some(Delivered::Blocked)
        } else if created {
            contact.count_received(message_id);
            Some(Delivered::ContactRequest)
        } else if contact.is_accepted() {
            Some(Delivered::Accepted)
        } else if local_asked {
            // Requests that cross count as both consents.
            contact.accept();
            Some(Delivered::Accepted)
        } else if !counts_toward_limit(payload_kind)
            || contact.count_received(message_id) == ReceivedCount::WithinLimit
        {
            Some(Delivered::Accepted)
        } else {
            None
        };
        // The sender started the new Session.
        let acknowledges = self.should_acknowledge(&contact, Starter::Peer);
        deduplication.record(digest);
        let peer_address = peer_sessions_address(sender_identity_key);
        let pending_address = pending_acknowledgment_address(session_id);
        let mut updates = vec![
            ProtocolStateUpdate::set(
                pending_address.clone(),
                encode_pending_acknowledgments(
                    &pending_address,
                    &LoadedPendingAcknowledgments::empty(),
                    limits,
                )?,
            )
            .with_snapshot(snapshot),
            ProtocolStateUpdate::set(
                peer_address.clone(),
                encode_peer_sessions(&peer_address, &peer_sessions, limits)?,
            )
            .with_snapshot(snapshot),
            deduplication_update(snapshot, &deduplication, limits)?,
        ];
        updates.extend(contact_update(snapshot, &contact, limits)?);
        let (deletions, stranded) = evict_sessions(snapshot, &evicted, limits)?;
        updates.extend(deletions);
        let undelivered = stranded
            .into_iter()
            .map(|message| message.message_id)
            .collect();
        let Some(delivered) = delivered else {
            updates.insert(
                0,
                session_update(
                    snapshot,
                    session_id,
                    sender_identity_key,
                    &state,
                    None,
                    limits,
                )?,
            );
            return self.withhold(
                session_id,
                message_id,
                updates,
                undelivered,
                one_time_prekey,
            );
        };
        let route = acknowledges
            .then(|| Route::established(&contact))
            .transpose()?;
        self.deliver(
            Delivery {
                session_id,
                peer_identity_key: sender_identity_key,
                state,
                pending_handshake: None,
                message_id,
                sent_at_millis,
                payload_kind,
                plaintext,
                sender_identity,
                delivered,
                acknowledgment_carries_grant: contact
                    .receives_grant(Starter::Peer, self.local.grant().stamp()),
                updates,
                undelivered,
                one_time_prekey,
            },
            route,
        )
    }

    // Decrypts a Message on a known Session and authenticates its sender and certificate before
    // any result.
    fn authenticate<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        known: KnownSession,
    ) -> Result<MessageDecryptionStep, MessageOperationError> {
        let limits = self.engine.limits;
        let KnownSession {
            opened:
                Opened {
                    mut deduplication,
                    digest,
                    message,
                },
            session_id,
            peer_identity_key,
            mut state,
            pending_handshake,
        } = known;
        let payload_kind = message.metadata.payload_kind;
        let decoded = message.decrypt(rng, &mut state, limits)?;
        authenticate_session_message(
            &decoded,
            &message,
            peer_identity_key,
            &self.local.identity.identity_verifying_key,
        )?;
        certified_sender_identity_key(
            &self.validation,
            self.settings.certificate_grace,
            &decoded.sender_identity,
        )?;
        let snapshot = self.reads.snapshot();
        let contact_address = contact_address(peer_identity_key);
        let mut contact = load_contact(snapshot, &contact_address, limits)?.ok_or_else(|| {
            ProtocolStateError::MissingRequiredState {
                address: contact_address.clone(),
            }
        })?;
        let mut updates: Vec<ProtocolStateUpdate> = self
            .engine
            .delivery_update(snapshot, session_id, peer_identity_key)?
            .into_iter()
            .collect();
        let peer_address = peer_sessions_address(peer_identity_key);
        // The delivery update already refused a Session the peer's list doesn't keep.
        let sessions = load_peer_sessions(snapshot, &peer_address, limits)?;
        let starter = sessions
            .as_ref()
            .and_then(|sessions| sessions.starter(session_id))
            .ok_or_else(|| ProtocolStateError::MissingRequiredState {
                address: peer_address,
            })?;
        let sender = decoded.sender_identity.public_identity_key()?;
        let (grant, plaintext) = open_payload(payload_kind, decoded.plaintext, &sender)?;
        if let Some(grant) = grant {
            contact.record_grant(grant);
        }
        if payload_kind.is_acknowledgment() {
            let acknowledged_message_id = decode_acknowledgment_plaintext(&plaintext)?;
            let pending_address = pending_acknowledgment_address(session_id);
            let mut pending = load_pending_acknowledgments(snapshot, &pending_address, limits)?;
            pending.record_acknowledgment(acknowledgment_digest(
                self.transport_binding.as_bytes(),
                &self.encoded,
            ));
            let matched = pending.pending.remove(acknowledged_message_id.as_bytes());
            if let Some(stamp) = matched.as_ref().and_then(|entry| entry.grant) {
                contact.acknowledge_grant(stamp);
            }
            // Messages sent before acceptance wait in the contact record instead, which acceptance
            // clears.
            contact.acknowledge_sent_before_acceptance(acknowledged_message_id);
            if payload_kind.carries_grant() {
                contact.accept_by_grant(starter);
            }
            updates.extend(contact_update(snapshot, &contact, limits)?);
            let pending_handshake = pending_handshake.filter(|_| !contact.is_accepted());
            updates.insert(
                0,
                session_update(
                    snapshot,
                    session_id,
                    peer_identity_key,
                    &state,
                    pending_handshake.as_ref(),
                    limits,
                )?,
            );
            updates.insert(
                1,
                ProtocolStateUpdate::set(
                    pending_address.clone(),
                    encode_pending_acknowledgments(&pending_address, &pending, limits)?,
                )
                .with_snapshot(snapshot),
            );
            let result = Box::new(AcknowledgmentResult {
                session_id,
                message_id: message.metadata.id,
                sent_at_millis: message.metadata.sent_at_millis,
                acknowledged_message_id,
                sender_identity: decoded.sender_identity,
            });
            // A recovery moves a Message's wait to the Session of its new copy, while the contact
            // may still acknowledge the original.
            let others: Vec<SessionId> = sessions
                .iter()
                .flat_map(PeerSessions::session_ids)
                .filter(|other| *other != session_id)
                .collect();
            if matched.is_some() || others.is_empty() {
                return Ok(MessageDecryptionStep::Ready {
                    outcome: if matched.is_some() {
                        InboundMessageOutcome::AcknowledgmentMatched(result)
                    } else {
                        InboundMessageOutcome::AcknowledgmentUnmatched(result)
                    },
                    changes: changes(&self.reads, updates),
                });
            }
            let addresses = others
                .iter()
                .copied()
                .map(pending_acknowledgment_address)
                .collect();
            self.phase =
                DecryptionPhase::OtherSessionsRequested(Box::new(UnmatchedAcknowledgment {
                    result,
                    updates,
                    others,
                }));
            return Ok(MessageDecryptionStep::NeedsState(
                self.reads.request(addresses),
            ));
        }
        // Only the asked side accepts, on the Session the requester started.
        if payload_kind == PayloadKind::ContactAcceptance
            && starter != Starter::Local
            && !contact.is_accepted()
        {
            return Err(ProtocolStateError::UnsolicitedAcceptance.into());
        }
        if payload_kind.carries_grant() {
            contact.accept_by_grant(starter);
        }
        let within_limit = contact.is_accepted()
            || contact.blocked
            || !counts_toward_limit(payload_kind)
            || contact.count_received(message.metadata.id) == ReceivedCount::WithinLimit;
        // The requester's Messages keep carrying the handshake until the peer accepts.
        let pending_handshake = pending_handshake.filter(|_| !contact.is_accepted());
        deduplication.record(digest);
        updates.insert(0, deduplication_update(snapshot, &deduplication, limits)?);
        updates.extend(contact_update(snapshot, &contact, limits)?);
        if !within_limit {
            updates.insert(
                0,
                session_update(
                    snapshot,
                    session_id,
                    peer_identity_key,
                    &state,
                    pending_handshake.as_ref(),
                    limits,
                )?,
            );
            return self.withhold(session_id, message.metadata.id, updates, Vec::new(), None);
        }
        let delivered = if contact.blocked {
            Delivered::Blocked
        } else {
            Delivered::Accepted
        };
        let acknowledges = self.should_acknowledge(&contact, starter);
        let route = acknowledges
            .then(|| Route::established(&contact))
            .transpose()?;
        self.deliver(
            Delivery {
                session_id,
                peer_identity_key,
                state,
                pending_handshake,
                message_id: message.metadata.id,
                sent_at_millis: message.metadata.sent_at_millis,
                payload_kind,
                plaintext,
                sender_identity: decoded.sender_identity,
                delivered,
                acknowledgment_carries_grant: contact
                    .receives_grant(starter, self.local.grant().stamp()),
                updates,
                undelivered: Vec::new(),
                one_time_prekey: None,
            },
            route,
        )
    }

    // Clears the acknowledged Message from whichever of the peer's other Sessions it waits on. That
    // copy isn't the one acknowledged, so the grant it carried still counts as unconfirmed.
    fn match_elsewhere(
        &mut self,
        unmatched: UnmatchedAcknowledgment,
    ) -> Result<MessageDecryptionStep, MessageOperationError> {
        let limits = self.engine.limits;
        let snapshot = self.reads.snapshot();
        let UnmatchedAcknowledgment {
            result,
            mut updates,
            others,
        } = unmatched;
        for session_id in others {
            let address = pending_acknowledgment_address(session_id);
            let Some(blob) = snapshot.get(&address) else {
                continue;
            };
            let mut pending = decode_pending_acknowledgments(&address, blob, limits)?;
            if pending
                .pending
                .remove(result.acknowledged_message_id.as_bytes())
                .is_some()
            {
                updates.push(recovery::pending_update(
                    snapshot, session_id, &pending, limits,
                )?);
                return Ok(MessageDecryptionStep::Ready {
                    outcome: InboundMessageOutcome::AcknowledgmentMatched(result),
                    changes: changes(&self.reads, updates),
                });
            }
        }
        Ok(MessageDecryptionStep::Ready {
            outcome: InboundMessageOutcome::AcknowledgmentUnmatched(result),
            changes: changes(&self.reads, updates),
        })
    }

    // Returns whether a Message from `contact` on a Session `starter` started gets an
    // acknowledgment. A blocked contact gets one only under the silent-receipt choice, and even
    // then a stranger whose request is open doesn't learn it arrived.
    fn should_acknowledge(&self, contact: &ContactRecord, starter: Starter) -> bool {
        contact.should_acknowledge(starter)
            && (!contact.blocked
                || self.settings.blocked_contact_acknowledgment_policy
                    == BlockedContactAcknowledgmentPolicy::SilentReceipt)
    }

    // Returns a Message past the limit before acceptance without its plaintext.
    fn withhold(
        &self,
        session_id: SessionId,
        message_id: MessageId,
        updates: Vec<ProtocolStateUpdate>,
        undelivered: Vec<MessageId>,
        one_time_prekey: Option<OneTimePreKeyUse>,
    ) -> Result<MessageDecryptionStep, MessageOperationError> {
        let changes = self.with_one_time_prekey(
            changes(&self.reads, updates).with_undelivered(undelivered),
            one_time_prekey,
        )?;
        Ok(MessageDecryptionStep::Ready {
            outcome: InboundMessageOutcome::Withheld(Box::new(WithheldInboundMessageResult {
                session_id,
                message_id,
            })),
            changes,
        })
    }

    // Returns the delivered Message, or first asks where its acknowledgment goes.
    fn deliver(
        &mut self,
        delivery: Delivery,
        acknowledgment_route: Option<Route>,
    ) -> Result<MessageDecryptionStep, MessageOperationError> {
        let Some(route) = acknowledgment_route else {
            let session = session_update(
                self.reads.snapshot(),
                delivery.session_id,
                delivery.peer_identity_key,
                &delivery.state,
                delivery.pending_handshake.as_ref(),
                self.engine.limits,
            )?;
            return self.outcome(delivery, session, None);
        };
        let destination = route.destination(delivery.peer_identity_key);
        self.phase = DecryptionPhase::AcknowledgmentTransportRequested(Box::new(Acknowledging {
            delivery,
            route,
            transport_binding: None,
        }));
        Ok(MessageDecryptionStep::NeedsAcknowledgmentTransport(
            destination,
        ))
    }

    // Seals the acknowledgment and returns the received Message with it.
    fn acknowledge<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        acknowledging: Acknowledging,
        transport_binding: &TransportBinding,
    ) -> Result<MessageDecryptionStep, MessageOperationError> {
        let limits = self.engine.limits;
        let Acknowledging {
            mut delivery,
            route,
            ..
        } = acknowledging;
        let mut acknowledgment_id = [0u8; 16];
        rng.try_fill_bytes(&mut acknowledgment_id)
            .map_err(ProtocolStateError::Randomness)?;
        let plaintext = encode_acknowledgment_plaintext(delivery.message_id)?;
        let (payload_kind, payload) = if delivery.acknowledgment_carries_grant {
            (
                PayloadKind::AcknowledgmentWithGrant,
                encode_granted_payload(&self.local.grant(), &plaintext)?,
            )
        } else {
            (PayloadKind::Acknowledgment, plaintext)
        };
        let acknowledgment = seal_signed(
            rng,
            &mut delivery.state,
            OutboundContent {
                session_id: delivery.session_id,
                id: MessageId::from_bytes(acknowledgment_id),
                sent_at_millis: self.acknowledgment_sent_at_millis,
                payload_kind,
                payload: &payload,
            },
            SignedRecipient {
                discovery_key: route.discovery_key(),
                identity_verifying_key: &delivery.sender_identity.identity_verifying_key,
            },
            &self.local.local_sender(),
            transport_binding,
            limits,
        )?;
        let session = session_update(
            self.reads.snapshot(),
            delivery.session_id,
            delivery.peer_identity_key,
            &delivery.state,
            delivery.pending_handshake.as_ref(),
            limits,
        )?;
        self.outcome(delivery, session, Some(acknowledgment))
    }

    fn outcome(
        &self,
        delivery: Delivery,
        session: ProtocolStateUpdate,
        acknowledgment: Option<SealedFrame>,
    ) -> Result<MessageDecryptionStep, MessageOperationError> {
        let Delivery {
            session_id,
            message_id,
            sent_at_millis,
            payload_kind,
            plaintext,
            sender_identity,
            delivered,
            mut updates,
            undelivered,
            one_time_prekey,
            ..
        } = delivery;
        updates.insert(0, session);
        let changes = self.with_one_time_prekey(
            changes(&self.reads, updates).with_undelivered(undelivered),
            one_time_prekey,
        )?;
        let outcome = match delivered {
            Delivered::Blocked => {
                InboundMessageOutcome::Blocked(Box::new(BlockedInboundMessageResult {
                    acknowledgment,
                }))
            }
            Delivered::Accepted if payload_kind == PayloadKind::GrantUpdate => {
                InboundMessageOutcome::GrantUpdate(Box::new(GrantUpdateResult {
                    session_id,
                    message_id,
                    acknowledgment,
                }))
            }
            Delivered::Accepted | Delivered::ContactRequest => {
                let result = Box::new(InboundMessageResult {
                    session_id,
                    message_id,
                    sent_at_millis,
                    payload_kind,
                    plaintext,
                    sender_identity,
                    acknowledgment,
                });
                if delivered == Delivered::ContactRequest {
                    InboundMessageOutcome::ContactRequest(result)
                } else {
                    InboundMessageOutcome::Accepted(result)
                }
            }
        };
        Ok(MessageDecryptionStep::Ready { outcome, changes })
    }

    // Stages the use of the one-time prekey a new Session consumed, so it commits with `changes`.
    fn with_one_time_prekey(
        &self,
        changes: StateChanges,
        one_time_prekey: Option<OneTimePreKeyUse>,
    ) -> Result<StateChanges, MessageOperationError> {
        Ok(match one_time_prekey {
            Some(OneTimePreKeyUse { epoch, id }) => {
                changes.with_operation(self.store.prepare_one_time_prekey_use(epoch, id)?)
            }
            None => changes,
        })
    }
}

// Returns an outcome that changes nothing, such as a duplicate.
fn unchanged(outcome: InboundMessageOutcome) -> MessageDecryptionStep {
    MessageDecryptionStep::Ready {
        outcome,
        changes: StateChanges::empty(),
    }
}

// Splits a payload into the Inbox Grant its kind carries, verified against `sender`, and the
// plaintext.
fn open_payload(
    payload_kind: PayloadKind,
    payload: Zeroizing<Vec<u8>>,
    sender: &PublicIdentityKey,
) -> Result<(Option<InboxGrant>, Zeroizing<Vec<u8>>), ProtocolStateError> {
    if !payload_kind.carries_grant() {
        return Ok((None, payload));
    }
    let (grant, plaintext) = open_granted_payload(&payload, sender)?;
    if payload_kind == PayloadKind::GrantUpdate && !plaintext.is_empty() {
        return Err(ProtocolStateError::InvalidMessage {
            reason: "grant update carries content".into(),
        });
    }
    Ok((Some(grant), plaintext))
}

fn session_update(
    snapshot: &ProtocolStateSnapshot,
    session_id: SessionId,
    peer_identity_key: ContactIdentityKey,
    state: &RatchetState,
    pending_handshake: Option<&PendingHandshake>,
    limits: ProtocolHardeningLimits,
) -> Result<ProtocolStateUpdate, ProtocolStateError> {
    let address = session_address(session_id);
    Ok(ProtocolStateUpdate::set(
        address.clone(),
        encode_session(
            &address,
            peer_identity_key,
            state,
            pending_handshake,
            limits,
        )?,
    )
    .with_snapshot(snapshot))
}

// Returns the update that stores `contact`, or `None` when the record read holds it already.
fn contact_update(
    snapshot: &ProtocolStateSnapshot,
    contact: &ContactRecord,
    limits: ProtocolHardeningLimits,
) -> Result<Option<ProtocolStateUpdate>, ProtocolStateError> {
    let address = contact_address(contact.identity_key);
    let blob = contact.encode(&address, limits)?;
    if snapshot
        .get(&address)
        .is_some_and(|current| current.as_bytes() == blob.as_bytes())
    {
        return Ok(None);
    }
    Ok(Some(
        ProtocolStateUpdate::set(address, blob).with_snapshot(snapshot),
    ))
}

fn deduplication_update(
    snapshot: &ProtocolStateSnapshot,
    deduplication: &LoadedDeduplicationSet,
    limits: ProtocolHardeningLimits,
) -> Result<ProtocolStateUpdate, ProtocolStateError> {
    let address = deduplication_address();
    Ok(ProtocolStateUpdate::set(
        address.clone(),
        encode_deduplication_set(&address, deduplication, limits)?,
    )
    .with_snapshot(snapshot))
}

fn supply_state(
    reads: &mut StateReads,
    entries: Vec<(ProtocolStateAddress, Option<ProtocolStateBlob>)>,
) -> Result<(), MessageOperationError> {
    if reads.pending().is_none() {
        return Err(MessageOperationError::NotAwaitingState);
    }
    Ok(reads.supply(entries)?)
}

// The local keys and credentials that authenticate what one operation seals.
struct LocalSenderKeys {
    keys: LocalIdentityKeys,
    identity: SenderIdentityMaterial,
    discovery_key: PublicDiscoveryKey,
    discovery_to_identity: Signature,
}

impl LocalSenderKeys {
    fn new(
        keys: LocalIdentityKeys,
        certificate: SignedSenderCertificate,
    ) -> Result<Self, ProtocolStateError> {
        let identity_key = PublicIdentityKey {
            public_key: keys.agreement_key.public,
            verifying_key: keys.signing_key.verifying,
            binding_signature: sign_identity_key_binding(
                &keys.signing_key,
                &keys.agreement_key.public,
            )?,
        };
        let identity_verifying_key = identity_key.verifying_key.to_bytes();
        verify_recipient_keys(&keys.discovery_key, &identity_verifying_key)?;
        let discovery_to_identity = keys.discovery_key.sign_identity_binding(&identity_key)?;
        Ok(Self {
            identity: SenderIdentityMaterial {
                identity_key: *identity_key.public_key.as_bytes(),
                identity_verifying_key,
                identity_binding_signature: identity_key.binding_signature.to_bytes().to_vec(),
                certificate: certificate.certificate,
                signature: certificate.signature,
            },
            discovery_key: keys.discovery_key.public(),
            discovery_to_identity,
            keys,
        })
    }

    fn local_sender(&self) -> LocalSender<'_> {
        LocalSender {
            identity: &self.identity,
            signing_key: &self.keys.signing_key,
            agreement_key: &self.keys.agreement_key,
            discovery_key: &self.discovery_key,
            discovery_to_identity: &self.discovery_to_identity,
        }
    }

    fn grant(&self) -> LocalGrant<'_> {
        LocalGrant {
            discovery_key: &self.discovery_key,
            discovery_to_identity: &self.discovery_to_identity,
            delivery_capability: &self.keys.delivery_capability,
        }
    }
}

// Conditions cover every record `reads` holds, present or absent, and every written record.
fn changes(reads: &StateReads, updates: Vec<ProtocolStateUpdate>) -> StateChanges {
    let mut conditions = reads.conditions();
    for update in &updates {
        conditions
            .entry(update.address.clone())
            .or_insert(update.condition);
    }
    StateChanges {
        conditions: conditions.into_iter().collect(),
        updates,
        operation: None,
        undelivered: Vec::new(),
    }
}

/// The records a Message Operation has read: each one present or absent, and the read it awaits.
#[derive(Default)]
struct StateReads {
    present: ProtocolStateSnapshot,
    absent: Vec<ProtocolStateAddress>,
    pending: Option<Vec<ProtocolStateAddress>>,
}

impl StateReads {
    // Starts a read of `addresses` and returns them as the request.
    fn request(&mut self, addresses: Vec<ProtocolStateAddress>) -> Vec<ProtocolStateAddress> {
        self.pending = Some(addresses.clone());
        addresses
    }

    fn pending(&self) -> Option<&[ProtocolStateAddress]> {
        self.pending.as_deref()
    }

    // Records the host's entries for the pending read, which must match it exactly.
    fn supply(
        &mut self,
        entries: Vec<(ProtocolStateAddress, Option<ProtocolStateBlob>)>,
    ) -> Result<(), ProtocolStateError> {
        let pending = self.pending.as_deref().unwrap_or_default();
        let expected: Vec<&ProtocolStateAddress> = pending.iter().collect();
        match_state_entries(&expected, &entries)?;
        for (address, blob) in entries {
            match blob {
                Some(blob) => self.present.set(address, blob)?,
                None => self.absent.push(address),
            }
        }
        self.pending = None;
        Ok(())
    }

    fn snapshot(&self) -> &ProtocolStateSnapshot {
        &self.present
    }

    fn conditions(&self) -> BTreeMap<ProtocolStateAddress, ProtocolStateCommitCondition> {
        let present = self.present.blobs.iter().map(|(address, blob)| {
            (
                address.clone(),
                ProtocolStateCommitCondition::from_blob(Some(blob)),
            )
        });
        let absent = self
            .absent
            .iter()
            .map(|address| (address.clone(), ProtocolStateCommitCondition::Absent));
        present.chain(absent).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::InMemorySecureStorage;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use roost_crypto::generate_discovery_key;

    #[test]
    fn local_keys_whose_discovery_key_another_identity_signed_are_refused() {
        let other = SigningKeyPair::from_signing_bytes([2; 32]);
        let keys = LocalIdentityKeys {
            agreement_key: KeyPair::from_secret_bytes([1; 32]),
            signing_key: SigningKeyPair::from_signing_bytes([1; 32]),
            discovery_key: generate_discovery_key(
                &mut ChaCha20Rng::from_seed([3; 32]),
                &other,
                1,
                1_700_000_000,
            )
            .unwrap(),
            delivery_capability: RecipientDeliveryCapability::from_bytes([4; 32]),
        };

        assert!(matches!(
            LocalSenderKeys::new(
                keys,
                SignedSenderCertificate {
                    certificate: Vec::new(),
                    signature: Vec::new(),
                },
            ),
            Err(ProtocolStateError::InvalidMessage { reason })
                if reason == "recipient discovery key does not match recipient identity key"
        ));
    }

    // Returns a KeyStore holding an identity and a signed prekey, as an app sets one up.
    fn key_store() -> (KeyStore, PublicIdentityKey) {
        let store = KeyStore::new(Box::new(InMemorySecureStorage::new()));
        let created = store.prepare_identity_creation().unwrap();
        store.reserve_operation(created.id).unwrap();
        store.finalize_operation(created.id).unwrap();
        let rotated = store.prepare_signed_prekey_rotation().unwrap();
        store.reserve_operation(rotated.id).unwrap();
        store.finalize_operation(rotated.id).unwrap();
        (store, created.output.public().unwrap())
    }

    // Runs `store`'s decryption of `message` over a host that holds no records.
    fn decrypt_over_no_records(
        store: &KeyStore,
        message: SealedFrame,
    ) -> Result<MessageDecryptionStep, MessageOperationError> {
        let mut decryption = store
            .start_decryption(IncomingMessage {
                message,
                transport_binding: TransportBinding::new(b"route".to_vec()).unwrap(),
                settings: ReceiveSettings::default(),
                sender_certificate_validation: InboundSenderCertificateValidation {
                    domain_signing_keys: Vec::new(),
                    expected_relay_domain: b"relay.test".to_vec(),
                    revoked_identity_keys: Some(Vec::new()),
                    reference_time: SystemTime::UNIX_EPOCH,
                },
                acknowledgment_sent_at_millis: 0,
                acknowledgment_sender_certificate: SignedSenderCertificate {
                    certificate: Vec::new(),
                    signature: Vec::new(),
                },
            })
            .unwrap();
        let mut rng = ChaCha20Rng::from_seed([0x40; 32]);
        loop {
            match decryption.step(&mut rng)? {
                MessageDecryptionStep::NeedsState(addresses) => decryption.supply_state(
                    addresses
                        .into_iter()
                        .map(|address| (address, None))
                        .collect(),
                )?,
                step @ (MessageDecryptionStep::NeedsAdmission(_)
                | MessageDecryptionStep::NeedsAcknowledgmentTransport(_)
                | MessageDecryptionStep::Ready { .. }) => return Ok(step),
            }
        }
    }

    #[test]
    fn a_first_message_whose_session_id_does_not_match_its_handshake_is_rejected() {
        let (bob, bob_identity) = key_store();
        let publication = bob.current_publication().unwrap();
        let bundle = PreKeyBundle {
            version: publication.version,
            discovery_key: publication.discovery_key,
            signed_prekey: publication.signed_prekey,
            one_time_prekey: None,
        };
        let mut rng = ChaCha20Rng::from_seed([0x41; 32]);
        let (mut state, session_id, handshake) =
            initiate_handshake(&mut rng, &bob_identity, &bundle).unwrap();
        let signing_key = SigningKeyPair::from_signing_bytes([0x10; 32]);
        let agreement_key = KeyPair::from_secret_bytes([0x11; 32]);
        let identity_key = PublicIdentityKey {
            public_key: agreement_key.public,
            verifying_key: signing_key.verifying,
            binding_signature: sign_identity_key_binding(&signing_key, &agreement_key.public)
                .unwrap(),
        };
        let discovery_key = generate_discovery_key(
            &mut ChaCha20Rng::from_seed([0x12; 32]),
            &signing_key,
            1,
            1_700_000_000,
        )
        .unwrap();
        let identity = SenderIdentityMaterial {
            identity_key: *identity_key.public_key.as_bytes(),
            identity_verifying_key: identity_key.verifying_key.to_bytes(),
            identity_binding_signature: identity_key.binding_signature.to_bytes().to_vec(),
            certificate: Vec::new(),
            signature: Vec::new(),
        };
        let public_discovery_key = discovery_key.public();
        let discovery_to_identity = discovery_key.sign_identity_binding(&identity_key).unwrap();
        let sender = LocalSender {
            identity: &identity,
            signing_key: &signing_key,
            agreement_key: &agreement_key,
            discovery_key: &public_discovery_key,
            discovery_to_identity: &discovery_to_identity,
        };
        let mut seal = |session_id| {
            seal_proved(
                &mut rng,
                &mut state,
                OutboundContent {
                    session_id,
                    id: MessageId::from_bytes([3; 16]),
                    sent_at_millis: 4,
                    payload_kind: PayloadKind::EncryptedTextWithGrant,
                    payload: b"hi bob",
                },
                &handshake,
                &sender,
                &TransportBinding::new(b"route".to_vec()).unwrap(),
                ProtocolHardeningLimits::default(),
            )
            .unwrap()
        };
        let substituted = seal(SessionId::from_bytes([0x75; 16]));
        let genuine = seal(session_id);

        assert!(matches!(
            decrypt_over_no_records(&bob, substituted),
            Err(MessageOperationError::ProtocolState(ProtocolStateError::InvalidMessage { reason }))
                if reason == "session id does not match its handshake"
        ));
        // The genuine Message gets past the handshake, as far as its sender's empty certificate.
        assert!(matches!(
            decrypt_over_no_records(&bob, genuine),
            Err(MessageOperationError::ProtocolState(
                ProtocolStateError::SenderCertificateValidation(_)
            ))
        ));
    }
}
