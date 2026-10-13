use super::contact_record::{ContactRecord, ReceivedCount, contact_address, load_contact};
use super::grant::{
    DiscoveryKeyStamp, InboxGrant, LocalGrant, encode_granted_payload, open_granted_payload,
};
use super::session::{
    LoadedSession, PeerSessions, PendingHandshake, SessionStatus, SignedPreKeyUse, Starter,
    encode_active_session, encode_peer_sessions, encode_unrecoverable_session, load_peer_sessions,
    load_session, peer_sessions_address, pending_acknowledgment_address, session_address,
    session_record_addresses,
};
use super::{
    AcknowledgmentResult, BlockedContactAcknowledgmentPolicy, BlockedInboundMessageResult,
    InboundMessageOutcome, InboundMessageResult, InboundSenderCertificateValidation,
    LoadedDeduplicationSet, LoadedPendingAcknowledgments, LocalSender, OpenedMessage,
    OutboundContent, OutboundMessageResult, ProtocolHardeningLimits, ProtocolStateAddress,
    ProtocolStateBlob, ProtocolStateCommitCondition, ProtocolStateEngine, ProtocolStateError,
    ProtocolStateSnapshot, ProtocolStateUpdate, ReceiveSettings, SenderIdentityMaterial,
    SessionEvent, SessionUnrecoverableReason, SessionUnrecoverableResult, SignedRecipient,
    StateChanges, WithheldInboundMessageResult, acknowledgment_digest, authenticate_first_message,
    authenticate_session_message, contact_identity_keys_match, contains_digest,
    decode_acknowledgment_plaintext, deduplication_address, deduplication_digest,
    encode_acknowledgment_plaintext, encode_deduplication_set, encode_pending_acknowledgments,
    ensure_supported_payload_kind, inbound_contact_identity_key, load_pending_acknowledgments,
    load_required_session, match_state_entries, open_message, pending_acknowledgment_digest_seen,
    receiving_deduplication_set, record_acknowledgment_digest, record_deduplication_digest,
    record_pending_acknowledgment, seal_proved, seal_signed, session_deletions,
    validate_contact_identity_key, validate_sender_identity, verify_recipient_keys,
};
use crate::contact::{ContactDiscoveryKey, ContactIdentityKey};
use crate::key_store::{KeyStore, KeyStoreError};
use crate::{Message, MessageId, PayloadKind, TransportBinding};
use rand::{CryptoRng, RngCore};
use roost_crypto::{
    DiscoveryKey, Handshake, KeyPair, PreKeyBundle, PublicDiscoveryKey, PublicIdentityKey,
    PublicKey, PublicSignedPreKey, RatchetState, RecipientDeliveryCapability,
    SealedFramePreKeyReference, Signature, SigningKeyPair, accept_handshake, initiate_handshake,
    sign_identity_key_binding, verify_discovery_to_identity_binding,
};
use roost_protocol::{PUBLIC_KEY_LEN, SessionId};
use std::collections::BTreeMap;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

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
    /// Plaintext bytes to encrypt.
    pub plaintext: Zeroizing<Vec<u8>>,
    /// The bundle the app fetched after [`MessageEncryptionStep::NeedsPreKeyBundle`], kept with
    /// the draft until a Session uses it.
    pub prekey_bundle: Option<PeerPreKeyBundle>,
}

/// What the app received, with the inputs Roost needs to check and acknowledge it.
pub struct IncomingMessage {
    /// The received Message.
    pub message: Message,
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
    /// A new Session needs this contact's prekey bundle, and the given one is missing or older
    /// than the contact's Discovery Key. The operation has ended: fetch the bundle and start again
    /// with the same draft.
    NeedsPreKeyBundle(ContactIdentityKey),
    /// The sealed Message and its state changes. The operation has ended.
    Ready(Box<OutboundMessageResult>),
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
    /// What the Message turned out to be. The operation has ended.
    Ready(Box<InboundMessageOutcome>),
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
/// Call [`Self::step`] until it returns [`MessageEncryptionStep::Ready`] or
/// [`MessageEncryptionStep::NeedsPreKeyBundle`], supplying what each other step asks for. Calling
/// [`Self::step`] again before supplying it returns the same request without repeating work.
/// Dropping the operation commits nothing.
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
}

enum EncryptionPhase {
    Started,
    ContactRequested,
    SessionRequested(Box<Planned>),
    NewSessionRequested(Box<NewSession>),
    TransportRequested(Box<PreparedSeal>),
    Taken,
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
                .one_time_prekey_id,
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
        validate_contact_identity_key(&contact_address(message.recipient), &message.recipient)?;
        let sender = LocalSenderKeys::new(keys, message.sender_certificate)?;
        validate_sender_identity(&sender.identity, self.limits)?;
        Ok(MessageEncryption(Some(Box::new(Encrypting {
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
        }))))
    }

    // Starts decrypting `message` with the local Identity's `keys`, reading prekeys from `store`.
    pub(crate) fn start_decryption(
        &self,
        store: KeyStore,
        keys: LocalIdentityKeys,
        message: IncomingMessage,
    ) -> Result<MessageDecryption, ProtocolStateError> {
        let encoded = message
            .message
            .to_bytes()
            .map_err(ProtocolStateError::MessageEncode)?;
        let local = LocalSenderKeys::new(keys, message.acknowledgment_sender_certificate)?;
        validate_sender_identity(&local.identity, self.limits)?;
        Ok(MessageDecryption(Some(Box::new(Decrypting {
            engine: *self,
            store,
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
    /// [`MessageEncryptionStep::Ready`], [`MessageEncryptionStep::NeedsPreKeyBundle`], or an error
    /// ends the operation.
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
        if let EncryptionPhase::TransportRequested(prepared) = &mut encrypting.phase
            && prepared.transport_binding.is_none()
        {
            prepared.transport_binding = Some(transport_binding);
            return Ok(());
        }
        self.0 = None;
        Err(MessageOperationError::NotAwaitingTransportBinding)
    }
}

impl Encrypting {
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
                let prepared = self.prepare_seal(*planned)?;
                Ok(self.request_transport(prepared))
            }
            EncryptionPhase::NewSessionRequested(new_session) => {
                let prepared = self.prepare_new_session(*new_session)?;
                Ok(self.request_transport(prepared))
            }
            EncryptionPhase::TransportRequested(mut prepared) => {
                match prepared.transport_binding.take() {
                    Some(transport_binding) => Ok(MessageEncryptionStep::Ready(Box::new(
                        self.seal(rng, *prepared, &transport_binding)?,
                    ))),
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
        let local_grant = self.sender.grant().stamp();
        let (mut contact, sessions) = match (contact, sessions) {
            (contact, None) | (contact @ None, Some(_)) if self.intent == SendIntent::Request => {
                return self.start_session(rng, contact);
            }
            (Some(contact), sessions) if contact.is_accepted() => {
                let session_id = sessions.ok_or(ProtocolStateError::NoSession)?.current();
                return Ok(self.request_session(Planned {
                    payload_kind: text_kind(contact.needs_grant(local_grant)),
                    contact,
                    session_id,
                }));
            }
            (Some(contact), Some(sessions)) => (contact, sessions),
            (None, _) if self.intent != SendIntent::Acceptance => {
                return Err(ProtocolStateError::MissingRequiredState { address }.into());
            }
            (Some(_), None) if self.intent == SendIntent::Message => {
                return Err(ProtocolStateError::NoSession.into());
            }
            (None | Some(_), _) => return Err(ProtocolStateError::NoContactRequest.into()),
        };
        let peer_asked = sessions.current_starter() == Starter::Peer;
        let payload_kind = match (self.intent, peer_asked) {
            (SendIntent::Request | SendIntent::Acceptance, true) => {
                contact.accept();
                PayloadKind::ContactAcceptance
            }
            (SendIntent::Acceptance, false) => {
                return Err(ProtocolStateError::NoContactRequest.into());
            }
            // The asked side keeps its grant private until it accepts.
            (SendIntent::Message | SendIntent::Request, _) => {
                let carries_grant = !peer_asked && contact.needs_grant(local_grant);
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
        let limits = self.engine.limits;
        let Some(bundle) = self.prekey_bundle.take() else {
            return Ok(MessageEncryptionStep::NeedsPreKeyBundle(self.recipient));
        };
        let bundle_identity_key = ContactIdentityKey {
            x25519_public_key: *bundle.identity_key.public_key.as_bytes(),
            ed25519_verifying_key: bundle.identity_key.verifying_key.to_bytes(),
        };
        if !contact_identity_keys_match(&bundle_identity_key, &self.recipient) {
            return Err(ProtocolStateError::InvalidMessage {
                reason: "prekey bundle belongs to another identity".into(),
            }
            .into());
        }
        verify_discovery_to_identity_binding(
            &bundle.identity_key,
            &bundle.bundle.discovery_key.verifying_key,
            &bundle.discovery_to_identity,
        )
        .map_err(roost_crypto::HandshakeError::from)
        .map_err(ProtocolStateError::from)?;
        let bundle_discovery_key = ContactDiscoveryKey::from(&bundle.bundle.discovery_key);
        if contact
            .as_ref()
            .and_then(|contact| contact.discovery_key)
            .is_some_and(|current| {
                DiscoveryKeyStamp::of(&bundle_discovery_key) < DiscoveryKeyStamp::of(&current)
            })
        {
            return Ok(MessageEncryptionStep::NeedsPreKeyBundle(self.recipient));
        }
        let (state, session_id, handshake) =
            initiate_handshake(rng, &bundle.identity_key, &bundle.bundle)
                .map_err(ProtocolStateError::from)?;
        let mut contact = contact.unwrap_or_else(|| ContactRecord::pending(self.recipient, None));
        contact.record_discovery_key(bundle_discovery_key);
        let local_grant = self.sender.grant().stamp();
        let carries_grant = contact.needs_grant(local_grant);
        if !contact.is_accepted() {
            contact.count_sent(self.message_id, carries_grant.then_some(local_grant))?;
        }
        let (peer_sessions, evicted) = match load_peer_sessions(
            self.reads.snapshot(),
            &peer_sessions_address(self.recipient),
            limits,
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
                payload_kind: text_kind(carries_grant),
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
            status,
        } = load_required_session(snapshot, &address, limits)?;
        if !contact_identity_keys_match(&peer_identity_key, &self.recipient) {
            return Err(ProtocolStateError::InvalidStateBinding {
                address,
                reason: "session belongs to another peer".into(),
            });
        }
        let SessionStatus::Active {
            state,
            pending_handshake,
        } = status
        else {
            return Err(ProtocolStateError::SessionUnrecoverable);
        };
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
    ) -> Result<OutboundMessageResult, ProtocolStateError> {
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
                sender.identity,
                sender.signing_key,
                transport_binding,
                limits,
            )?,
        };
        let pending_address = pending_acknowledgment_address(session_id);
        // A contact that hasn't accepted acknowledges nothing yet, so nothing waits for it.
        if contact.is_accepted() {
            record_pending_acknowledgment(
                &pending_address,
                &mut pending,
                self.message_id,
                self.sent_at_millis,
                &message,
                payload_kind.carries_grant().then(|| grant.stamp()),
                limits,
            )?;
        }
        let snapshot = self.reads.snapshot();
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
        if let Some((peer_sessions, evicted)) = started {
            let peer_address = peer_sessions_address(self.recipient);
            updates.push(
                ProtocolStateUpdate::set(
                    peer_address.clone(),
                    encode_peer_sessions(&peer_address, &peer_sessions, limits)?,
                )
                .with_snapshot(snapshot),
            );
            updates.extend(session_deletions(snapshot, &evicted));
        }
        Ok(OutboundMessageResult {
            session_id,
            message_id: self.message_id,
            sent_at_millis: self.sent_at_millis,
            payload_kind,
            message,
            changes: changes(&self.reads, updates),
        })
    }
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
    local: LocalSenderKeys,
    message: Message,
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
    AdmissionRequested(Box<FirstMessage>),
    FirstMessagePeerRequested(Box<AcceptedFirstMessage>),
    FirstMessageCurrentRequested(Box<AcceptedFirstMessage>, PeerSessions),
    AcknowledgmentTransportRequested(Box<Acknowledging>),
    Taken,
}

// A Message that passed deduplication and opened under the local Discovery Key.
struct Opened {
    deduplication: LoadedDeduplicationSet,
    digest: [u8; super::DEDUPLICATION_DIGEST_LEN],
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
    digest: [u8; super::DEDUPLICATION_DIGEST_LEN],
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
    // Every update except the Session's, which sealing an acknowledgment advances.
    updates: Vec<ProtocolStateUpdate>,
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
                    Some(transport_binding) => Ok(MessageDecryptionStep::Ready(Box::new(
                        self.acknowledge(rng, *acknowledging, &transport_binding)?,
                    ))),
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
        let digest = deduplication_digest(
            &deduplication.digest_key,
            self.transport_binding.as_bytes(),
            &self.encoded,
        );
        if contains_digest(&deduplication.digests, &digest) {
            return Ok(MessageDecryptionStep::Ready(Box::new(
                InboundMessageOutcome::Duplicate,
            )));
        }
        let message = open_message(
            &self.message,
            &self.local.keys.discovery_key,
            &self.transport_binding,
        )?;
        ensure_supported_payload_kind(&message)?;
        let session_id = message.metadata.session_id;
        let mut addresses = vec![session_address(session_id)];
        if message.metadata.payload_kind == PayloadKind::Acknowledgment {
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
                None => Ok(MessageDecryptionStep::Ready(Box::new(
                    InboundMessageOutcome::UnknownSession,
                ))),
            };
        };
        let is_acknowledgment = opened.message.metadata.payload_kind == PayloadKind::Acknowledgment;
        if is_acknowledgment
            && pending_acknowledgment_digest_seen(
                snapshot,
                &pending_acknowledgment_address(session_id),
                acknowledgment_digest(self.transport_binding.as_bytes(), &self.encoded),
                limits,
            )?
        {
            return Ok(MessageDecryptionStep::Ready(Box::new(
                InboundMessageOutcome::Duplicate,
            )));
        }
        let peer_identity_key = session.peer_identity_key;
        let (state, pending_handshake) = match session.status {
            SessionStatus::Active {
                state,
                pending_handshake,
            } => (state, pending_handshake),
            SessionStatus::Unrecoverable {
                reason,
                event_emitted,
            } => {
                return Ok(MessageDecryptionStep::Ready(Box::new(
                    InboundMessageOutcome::SessionUnrecoverable(Box::new(
                        session_unrecoverable_result(
                            &self.reads,
                            session_id,
                            peer_identity_key,
                            reason,
                            event_emitted,
                            limits,
                        )?,
                    )),
                )));
            }
        };
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
        let prekeys = self.store.first_message_prekeys(&reference)?;
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
        if payload_kind == PayloadKind::Acknowledgment {
            return Err(ProtocolStateError::InvalidMessage {
                reason: "an acknowledgment cannot start a session".into(),
            }
            .into());
        }
        let decoded = message.decrypt(rng, &mut state, limits)?;
        let (sender, sender_discovery_key) =
            authenticate_first_message(&decoded, &handshake, &prekeys.signed_prekey)?;
        let sender_identity_key = inbound_contact_identity_key(
            &self.validation,
            self.settings.certificate_grace(),
            &decoded.sender_identity,
            Some(decoded.sender_identity.contact_identity_key()),
            limits,
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
            one_time_prekey: reference.one_time_prekey_id.map(|id| OneTimePreKeyUse {
                epoch: reference.discovery_epoch,
                id,
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
                return Ok(MessageDecryptionStep::Ready(Box::new(
                    InboundMessageOutcome::DeletedSession,
                )));
            }
            Some(mut sessions) => {
                sessions.forget_deletions_unless(|signed_prekey| {
                    held_signed_prekeys.iter().any(|held| {
                        held.epoch == signed_prekey.epoch
                            && held.public_key.as_bytes() == &signed_prekey.public_key
                    })
                });
                let evicted = if self.engine.awaits_reply(snapshot, sessions.current())? {
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
            Some(contact) => contact,
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
        } else if contact.count_received(message_id) == ReceivedCount::WithinLimit {
            Some(Delivered::Accepted)
        } else {
            None
        };
        // The sender started the new Session.
        let acknowledges = self.should_acknowledge(&contact, Starter::Peer);
        record_deduplication_digest(&mut deduplication, digest);
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
        updates.extend(session_deletions(snapshot, &evicted));
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
            return self.withhold(session_id, message_id, updates, one_time_prekey);
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
                updates,
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
        inbound_contact_identity_key(
            &self.validation,
            self.settings.certificate_grace(),
            &decoded.sender_identity,
            Some(peer_identity_key),
            limits,
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
        if payload_kind == PayloadKind::Acknowledgment {
            let acknowledged_message_id = decode_acknowledgment_plaintext(&decoded.plaintext)?;
            let pending_address = pending_acknowledgment_address(session_id);
            let mut pending = load_pending_acknowledgments(snapshot, &pending_address, limits)?;
            record_acknowledgment_digest(
                &mut pending,
                acknowledgment_digest(self.transport_binding.as_bytes(), &self.encoded),
                limits,
            );
            let matched = pending.pending.remove(acknowledged_message_id.as_bytes());
            if let Some(stamp) = matched.as_ref().and_then(|entry| entry.grant) {
                contact.acknowledge_grant(stamp);
            }
            // Messages sent before acceptance wait in the contact record instead.
            contact.acknowledge_sent_before_acceptance(acknowledged_message_id);
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
                changes: changes(&self.reads, updates),
            });
            return Ok(MessageDecryptionStep::Ready(Box::new(
                if matched.is_some() {
                    InboundMessageOutcome::AcknowledgmentMatched(result)
                } else {
                    InboundMessageOutcome::AcknowledgmentUnmatched(result)
                },
            )));
        }
        let sender = decoded.sender_identity.public_identity_key()?;
        let (grant, plaintext) = open_payload(payload_kind, decoded.plaintext, &sender)?;
        if let Some(grant) = grant {
            contact.record_grant(grant);
        }
        let peer_address = peer_sessions_address(peer_identity_key);
        // The delivery update already refused a Session the peer's list doesn't keep.
        let starter = load_peer_sessions(snapshot, &peer_address, limits)?
            .and_then(|sessions| sessions.starter(session_id))
            .ok_or_else(|| ProtocolStateError::MissingRequiredState {
                address: peer_address,
            })?;
        if payload_kind == PayloadKind::ContactAcceptance && !contact.is_accepted() {
            // Only the asked side accepts, on the Session the requester started.
            if starter != Starter::Local {
                return Err(ProtocolStateError::UnsolicitedAcceptance.into());
            }
            contact.accept();
        }
        let within_limit = contact.is_accepted()
            || contact.blocked
            || contact.count_received(message.metadata.id) == ReceivedCount::WithinLimit;
        // The requester's Messages keep carrying the handshake until the peer accepts.
        let pending_handshake = pending_handshake.filter(|_| !contact.is_accepted());
        record_deduplication_digest(&mut deduplication, digest);
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
            return self.withhold(session_id, message.metadata.id, updates, None);
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
                updates,
                one_time_prekey: None,
            },
            route,
        )
    }

    // Returns whether a Message from `contact` on a Session `starter` started gets an
    // acknowledgment. A blocked contact gets one only under the silent-receipt choice, and even
    // then a stranger whose request is open doesn't learn it arrived.
    fn should_acknowledge(&self, contact: &ContactRecord, starter: Starter) -> bool {
        contact.should_acknowledge(starter)
            && (!contact.blocked
                || self.settings.blocked_contact_acknowledgment_policy()
                    == BlockedContactAcknowledgmentPolicy::SilentReceipt)
    }

    // Returns a Message past the limit before acceptance without its plaintext.
    fn withhold(
        &self,
        session_id: SessionId,
        message_id: MessageId,
        updates: Vec<ProtocolStateUpdate>,
        one_time_prekey: Option<OneTimePreKeyUse>,
    ) -> Result<MessageDecryptionStep, MessageOperationError> {
        let changes = self.with_one_time_prekey(changes(&self.reads, updates), one_time_prekey)?;
        Ok(MessageDecryptionStep::Ready(Box::new(
            InboundMessageOutcome::Withheld(Box::new(WithheldInboundMessageResult {
                session_id,
                message_id,
                changes,
            })),
        )))
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
            return Ok(MessageDecryptionStep::Ready(Box::new(
                self.outcome(delivery, session, None)?,
            )));
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
    ) -> Result<InboundMessageOutcome, MessageOperationError> {
        let limits = self.engine.limits;
        let Acknowledging {
            mut delivery,
            route,
            ..
        } = acknowledging;
        let mut acknowledgment_id = [0u8; 16];
        rng.try_fill_bytes(&mut acknowledgment_id)
            .map_err(ProtocolStateError::Randomness)?;
        let acknowledgment = seal_signed(
            rng,
            &mut delivery.state,
            OutboundContent {
                session_id: delivery.session_id,
                id: MessageId::from_bytes(acknowledgment_id),
                sent_at_millis: self.acknowledgment_sent_at_millis,
                payload_kind: PayloadKind::Acknowledgment,
                payload: &encode_acknowledgment_plaintext(delivery.message_id)?,
            },
            SignedRecipient {
                discovery_key: route.discovery_key(),
                identity_verifying_key: &delivery.sender_identity.identity_verifying_key,
            },
            &self.local.identity,
            &self.local.keys.signing_key,
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
        acknowledgment: Option<Message>,
    ) -> Result<InboundMessageOutcome, MessageOperationError> {
        let Delivery {
            session_id,
            message_id,
            sent_at_millis,
            payload_kind,
            plaintext,
            sender_identity,
            delivered,
            mut updates,
            one_time_prekey,
            ..
        } = delivery;
        updates.insert(0, session);
        let changes = self.with_one_time_prekey(changes(&self.reads, updates), one_time_prekey)?;
        Ok(match delivered {
            Delivered::Blocked => {
                InboundMessageOutcome::Blocked(Box::new(BlockedInboundMessageResult {
                    acknowledgment,
                    changes,
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
                    changes,
                });
                if delivered == Delivered::ContactRequest {
                    InboundMessageOutcome::ContactRequest(result)
                } else {
                    InboundMessageOutcome::Accepted(result)
                }
            }
        })
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
        encode_active_session(
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

fn session_unrecoverable_result(
    reads: &StateReads,
    session_id: SessionId,
    peer_identity_key: ContactIdentityKey,
    reason: SessionUnrecoverableReason,
    event_emitted: bool,
    limits: ProtocolHardeningLimits,
) -> Result<SessionUnrecoverableResult, ProtocolStateError> {
    let (event, state_updates) = if event_emitted {
        (None, Vec::new())
    } else {
        let address = session_address(session_id);
        let update = ProtocolStateUpdate::set(
            address.clone(),
            encode_unrecoverable_session(&address, peer_identity_key, reason, true, limits)?,
        )
        .with_snapshot(reads.snapshot());
        (
            Some(SessionEvent::Unrecoverable { session_id, reason }),
            vec![update],
        )
    };
    Ok(SessionUnrecoverableResult {
        session_id,
        reason,
        event,
        changes: changes(reads, state_updates),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
