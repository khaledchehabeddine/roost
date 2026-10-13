use super::session::{
    LoadedSession, SessionStatus, encode_active_session, encode_unrecoverable_session,
    load_peer_sessions, load_session, peer_sessions_address, pending_acknowledgment_address,
    session_address,
};
use super::{
    AcknowledgmentResult, BlockedContactAcknowledgmentPolicy, BlockedInboundMessageResult,
    InboundMessageOutcome, InboundMessageResult, InboundSenderCertificateValidation,
    LoadedDeduplicationSet, LoadedPendingAcknowledgments, LocalSender, OpenedMessage,
    OutboundContent, OutboundMessageResult, ProtocolHardeningLimits, ProtocolStateAddress,
    ProtocolStateBlob, ProtocolStateCommitCondition, ProtocolStateEngine, ProtocolStateError,
    ProtocolStateSnapshot, ProtocolStateUpdate, ReceiveSettings, SenderIdentityMaterial,
    SessionEvent, SessionUnrecoverableReason, SessionUnrecoverableResult, SignedRecipient,
    StateChanges, acknowledgment_digest, authenticate_session_message, contact_address,
    contact_identity_keys_match, contains_digest, decode_acknowledgment_plaintext,
    deduplication_address, deduplication_digest, encode_acknowledgment_plaintext,
    encode_deduplication_set, encode_pending_acknowledgments, ensure_payload_kind,
    inbound_contact_identity_key, load_contact_state, load_pending_acknowledgments,
    load_required_session, match_state_entries, open_message, outbound_contact,
    pending_acknowledgment_digest_seen, receiving_deduplication_set, record_acknowledgment_digest,
    record_deduplication_digest, record_pending_acknowledgment, seal_proved, seal_signed,
    validate_contact_identity_key, validate_sender_identity, verify_recipient_keys,
};
use crate::contact::ContactIdentityKey;
use crate::{Message, MessageId, PayloadKind, TransportBinding};
use rand::{CryptoRng, RngCore};
use roost_crypto::{
    DiscoveryKey, Handshake, KeyPair, PublicDiscoveryKey, PublicIdentityKey, RatchetState,
    Signature, SigningKeyPair, sign_identity_key_binding,
};
use roost_protocol::{PUBLIC_KEY_LEN, SessionId};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// The local Identity's secret keys a Message Operation uses.
pub struct LocalIdentityKeys {
    /// Identity Key agreement half, which proves Messages that carry a handshake.
    pub agreement_key: KeyPair,
    /// Identity Key signing half, which signs Messages sent after the peer replies.
    pub signing_key: SigningKeyPair,
    /// Current Discovery Key, which opens received Messages.
    pub discovery_key: DiscoveryKey,
}

/// A domain-signed sender certificate and the domain's signature over it.
pub struct SignedSenderCertificate {
    /// Domain-signed sender certificate bytes.
    pub certificate: Vec<u8>,
    /// Domain signature over the certificate.
    pub signature: Vec<u8>,
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageDestination {
    /// The recipient's Identity Key.
    pub identity_key: ContactIdentityKey,
    /// The recipient Discovery Key's X25519 public key the Message is sealed to.
    pub discovery_key: [u8; PUBLIC_KEY_LEN],
}

/// What a [`MessageEncryption`] needs next, or its result.
pub enum MessageEncryptionStep {
    /// The records to supply through [`MessageEncryption::supply_state`].
    NeedsState(Vec<ProtocolStateAddress>),
    /// The destination whose Transport Binding to supply through
    /// [`MessageEncryption::supply_transport_binding`].
    NeedsTransport(MessageDestination),
    /// The sealed Message and its state changes. The operation has ended.
    Ready(Box<OutboundMessageResult>),
}

/// What a [`MessageDecryption`] needs next, or its result.
pub enum MessageDecryptionStep {
    /// The records to supply through [`MessageDecryption::supply_state`].
    NeedsState(Vec<ProtocolStateAddress>),
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
    /// State was supplied while the operation wasn't waiting for any.
    #[error("message operation isn't waiting for state")]
    NotAwaitingState,
    /// A Transport Binding was supplied while the operation wasn't waiting for one.
    #[error("message operation isn't waiting for a transport binding")]
    NotAwaitingTransportBinding,
    /// Checking or processing the Message failed.
    #[error(transparent)]
    ProtocolState(#[from] ProtocolStateError),
}

/// One attempt to encrypt a Message to a contact, which asks for the records it needs and returns
/// its result once.
///
/// Call [`Self::step`] until it returns [`MessageEncryptionStep::Ready`], supplying what each
/// other step asks for. Calling [`Self::step`] again before supplying it returns the same request
/// without repeating work. Dropping the operation commits nothing.
pub struct MessageEncryption(Option<Box<Encrypting>>);

struct Encrypting {
    engine: ProtocolStateEngine,
    sender: LocalSenderKeys,
    recipient: ContactIdentityKey,
    message_id: MessageId,
    sent_at_millis: u64,
    plaintext: Zeroizing<Vec<u8>>,
    reads: StateReads,
    phase: EncryptionPhase,
}

enum EncryptionPhase {
    Started,
    ContactRequested,
    SessionRequested {
        discovery_key: [u8; PUBLIC_KEY_LEN],
        session_id: SessionId,
    },
    TransportRequested(Box<PreparedSeal>),
    Taken,
}

// Everything sealing needs once Roost knows the Session and the destination.
struct PreparedSeal {
    session_id: SessionId,
    state: Box<RatchetState>,
    pending_handshake: Option<Handshake>,
    pending: LoadedPendingAcknowledgments,
    destination: MessageDestination,
    transport_binding: Option<TransportBinding>,
}

impl ProtocolStateEngine {
    /// Starts encrypting `message` with the local Identity's `keys`.
    pub fn start_encryption(
        &self,
        keys: LocalIdentityKeys,
        message: OutgoingMessage,
    ) -> Result<MessageEncryption, ProtocolStateError> {
        validate_contact_identity_key(&contact_address(message.recipient), &message.recipient)?;
        let sender = LocalSenderKeys::new(keys, message.sender_certificate)?;
        validate_sender_identity(&sender.identity, self.limits)?;
        Ok(MessageEncryption(Some(Box::new(Encrypting {
            engine: *self,
            sender,
            recipient: message.recipient,
            message_id: message.message_id,
            sent_at_millis: message.sent_at_millis,
            plaintext: message.plaintext,
            reads: StateReads::default(),
            phase: EncryptionPhase::Started,
        }))))
    }

    /// Starts decrypting `message` with the local Identity's `keys`.
    pub fn start_decryption(
        &self,
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
    /// [`MessageEncryptionStep::Ready`] or an error ends the operation.
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
        let limits = self.engine.limits;
        match std::mem::replace(&mut self.phase, EncryptionPhase::Taken) {
            EncryptionPhase::Started => {
                self.phase = EncryptionPhase::ContactRequested;
                Ok(MessageEncryptionStep::NeedsState(self.reads.request(vec![
                    contact_address(self.recipient),
                    peer_sessions_address(self.recipient),
                ])))
            }
            EncryptionPhase::ContactRequested => {
                let snapshot = self.reads.snapshot();
                let contact = outbound_contact(snapshot, self.recipient, limits)?;
                let session_id =
                    load_peer_sessions(snapshot, &peer_sessions_address(self.recipient), limits)?
                        .ok_or(ProtocolStateError::NoSession)?
                        .current();
                self.phase = EncryptionPhase::SessionRequested {
                    discovery_key: contact.identity.discovery_key.x25519_public_key,
                    session_id,
                };
                Ok(MessageEncryptionStep::NeedsState(self.reads.request(vec![
                    session_address(session_id),
                    pending_acknowledgment_address(session_id),
                ])))
            }
            EncryptionPhase::SessionRequested {
                discovery_key,
                session_id,
            } => {
                let prepared = self.prepare_seal(discovery_key, session_id)?;
                let destination = prepared.destination;
                self.phase = EncryptionPhase::TransportRequested(Box::new(prepared));
                Ok(MessageEncryptionStep::NeedsTransport(destination))
            }
            EncryptionPhase::TransportRequested(mut prepared) => {
                match prepared.transport_binding.take() {
                    Some(transport_binding) => Ok(MessageEncryptionStep::Ready(Box::new(
                        self.seal(rng, *prepared, &transport_binding)?,
                    ))),
                    None => {
                        let destination = prepared.destination;
                        self.phase = EncryptionPhase::TransportRequested(prepared);
                        Ok(MessageEncryptionStep::NeedsTransport(destination))
                    }
                }
            }
            EncryptionPhase::Taken => Err(MessageOperationError::Finished),
        }
    }

    // Checks the Session Roost selected and finds where the Message goes.
    fn prepare_seal(
        &self,
        contact_discovery_key: [u8; PUBLIC_KEY_LEN],
        session_id: SessionId,
    ) -> Result<PreparedSeal, ProtocolStateError> {
        let limits = self.engine.limits;
        let snapshot = self.reads.snapshot();
        let address = session_address(session_id);
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
            &pending_acknowledgment_address(session_id),
            limits,
        )?;
        let discovery_key = match &pending_handshake {
            Some(handshake) => *handshake.responder_discovery_key.as_bytes(),
            None => contact_discovery_key,
        };
        Ok(PreparedSeal {
            session_id,
            state,
            pending_handshake,
            pending,
            destination: MessageDestination {
                identity_key: self.recipient,
                discovery_key,
            },
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
            session_id,
            mut state,
            pending_handshake,
            mut pending,
            destination,
            ..
        } = prepared;
        let content = OutboundContent {
            session_id,
            id: self.message_id,
            sent_at_millis: self.sent_at_millis,
            plaintext: &self.plaintext,
        };
        let sender = self.sender.local_sender();
        let message = match &pending_handshake {
            Some(handshake) => seal_proved(
                rng,
                &mut state,
                content,
                handshake,
                &sender,
                transport_binding,
                limits,
            )?,
            None => seal_signed(
                rng,
                &mut state,
                content,
                PayloadKind::EncryptedText,
                SignedRecipient {
                    discovery_key: destination.discovery_key,
                    identity_verifying_key: &self.recipient.ed25519_verifying_key,
                },
                sender.identity,
                sender.signing_key,
                transport_binding,
                limits,
            )?,
        };
        let pending_address = pending_acknowledgment_address(session_id);
        record_pending_acknowledgment(
            &pending_address,
            &mut pending,
            self.message_id,
            self.sent_at_millis,
            &message,
            limits,
        )?;
        let address = session_address(session_id);
        let snapshot = self.reads.snapshot();
        let updates = vec![
            ProtocolStateUpdate::set(
                address.clone(),
                encode_active_session(
                    &address,
                    self.recipient,
                    &state,
                    pending_handshake.as_ref(),
                    limits,
                )?,
            )
            .with_snapshot(snapshot),
            ProtocolStateUpdate::set(
                pending_address.clone(),
                encode_pending_acknowledgments(&pending_address, &pending, limits)?,
            )
            .with_snapshot(snapshot),
        ];
        Ok(OutboundMessageResult {
            session_id,
            message_id: self.message_id,
            sent_at_millis: self.sent_at_millis,
            payload_kind: PayloadKind::EncryptedText,
            message,
            changes: changes(&self.reads, updates),
        })
    }
}

/// One attempt to decrypt a received Message, which asks for the records it needs and returns
/// its result once.
///
/// Call [`Self::step`] until it returns [`MessageDecryptionStep::Ready`], supplying what each
/// other step asks for. A Message that needs an acknowledgment asks for that acknowledgment's
/// Transport Binding only after its sender authenticates and block policy allows a reply. Calling
/// [`Self::step`] again before supplying input returns the same request without repeating work.
/// Dropping the operation commits nothing.
pub struct MessageDecryption(Option<Box<Decrypting>>);

struct Decrypting {
    engine: ProtocolStateEngine,
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
    PeerRequested(
        Box<Opened>,
        SessionId,
        ContactIdentityKey,
        Box<RatchetState>,
    ),
    AcknowledgmentTransportRequested(Box<Acknowledging>),
    Taken,
}

// A Message that passed deduplication and opened under the local Discovery Key.
struct Opened {
    deduplication: LoadedDeduplicationSet,
    digest: [u8; super::DEDUPLICATION_DIGEST_LEN],
    message: OpenedMessage,
}

// An authenticated Message waiting only for its acknowledgment's Transport Binding.
struct Acknowledging {
    session_id: SessionId,
    peer_identity_key: ContactIdentityKey,
    state: Box<RatchetState>,
    message_id: MessageId,
    sent_at_millis: u64,
    payload_kind: PayloadKind,
    plaintext: Zeroizing<Vec<u8>>,
    sender_identity: SenderIdentityMaterial,
    blocked: bool,
    updates: Vec<ProtocolStateUpdate>,
    destination: MessageDestination,
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
            DecryptionPhase::SessionRequested(opened) => self.load_session(*opened),
            DecryptionPhase::PeerRequested(opened, session_id, peer_identity_key, state) => {
                self.authenticate(rng, *opened, session_id, peer_identity_key, *state)
            }
            DecryptionPhase::AcknowledgmentTransportRequested(mut acknowledging) => {
                match acknowledging.transport_binding.take() {
                    Some(transport_binding) => Ok(MessageDecryptionStep::Ready(Box::new(
                        self.acknowledge(rng, *acknowledging, &transport_binding)?,
                    ))),
                    None => {
                        let destination = acknowledging.destination;
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

    // Finds the Session the Message names, then asks for its peer's records.
    fn load_session(
        &mut self,
        opened: Opened,
    ) -> Result<MessageDecryptionStep, MessageOperationError> {
        let limits = self.engine.limits;
        let session_id = opened.message.metadata.session_id;
        let snapshot = self.reads.snapshot();
        let Some(session) = load_session(snapshot, &session_address(session_id), limits)? else {
            return Ok(MessageDecryptionStep::Ready(Box::new(
                InboundMessageOutcome::UnknownSession,
            )));
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
        let state = match session.status {
            SessionStatus::Active { state, .. } => state,
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
        self.phase =
            DecryptionPhase::PeerRequested(Box::new(opened), session_id, peer_identity_key, state);
        Ok(MessageDecryptionStep::NeedsState(
            self.reads.request(addresses),
        ))
    }

    // Decrypts the Message and authenticates its sender and certificate before any result.
    fn authenticate<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        opened: Opened,
        session_id: SessionId,
        peer_identity_key: ContactIdentityKey,
        mut state: RatchetState,
    ) -> Result<MessageDecryptionStep, MessageOperationError> {
        let limits = self.engine.limits;
        let Opened {
            mut deduplication,
            digest,
            message,
        } = opened;
        let payload_kind = message.metadata.payload_kind;
        if payload_kind != PayloadKind::Acknowledgment {
            ensure_payload_kind(&message, PayloadKind::EncryptedText)?;
        }
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
        let session_update =
            |state: &RatchetState| -> Result<ProtocolStateUpdate, ProtocolStateError> {
                let address = session_address(session_id);
                Ok(ProtocolStateUpdate::set(
                    address.clone(),
                    encode_active_session(&address, peer_identity_key, state, None, limits)?,
                )
                .with_snapshot(snapshot))
            };
        let delivery_update =
            self.engine
                .delivery_update(snapshot, session_id, peer_identity_key)?;
        let contact = load_contact_state(snapshot, &contact_address(peer_identity_key), limits)?;
        if payload_kind == PayloadKind::Acknowledgment {
            let acknowledged_message_id = decode_acknowledgment_plaintext(&decoded.plaintext)?;
            let pending_address = pending_acknowledgment_address(session_id);
            let mut pending = load_pending_acknowledgments(snapshot, &pending_address, limits)?;
            record_acknowledgment_digest(
                &mut pending,
                acknowledgment_digest(self.transport_binding.as_bytes(), &self.encoded),
                limits,
            );
            let matched = pending
                .pending
                .remove(acknowledged_message_id.as_bytes())
                .is_some();
            let mut updates = vec![
                session_update(&state)?,
                ProtocolStateUpdate::set(
                    pending_address.clone(),
                    encode_pending_acknowledgments(&pending_address, &pending, limits)?,
                )
                .with_snapshot(snapshot),
            ];
            updates.extend(delivery_update);
            let result = Box::new(AcknowledgmentResult {
                session_id,
                message_id: message.metadata.id,
                sent_at_millis: message.metadata.sent_at_millis,
                acknowledged_message_id,
                sender_identity: decoded.sender_identity,
                changes: changes(&self.reads, updates),
            });
            return Ok(MessageDecryptionStep::Ready(Box::new(if matched {
                InboundMessageOutcome::AcknowledgmentMatched(result)
            } else {
                InboundMessageOutcome::AcknowledgmentUnmatched(result)
            })));
        }
        record_deduplication_digest(&mut deduplication, digest);
        let deduplication_address = deduplication_address();
        let mut updates = vec![
            ProtocolStateUpdate::set(
                deduplication_address.clone(),
                encode_deduplication_set(&deduplication_address, &deduplication, limits)?,
            )
            .with_snapshot(snapshot),
        ];
        updates.extend(delivery_update);
        if contact.blocked
            && self.settings.blocked_contact_acknowledgment_policy()
                == BlockedContactAcknowledgmentPolicy::Unreachable
        {
            // No acknowledgment, so the sending chain stays where it was while the receiving
            // chain's advance and the recorded digest still commit.
            updates.insert(0, session_update(&state)?);
            return Ok(MessageDecryptionStep::Ready(Box::new(
                InboundMessageOutcome::Blocked(Box::new(BlockedInboundMessageResult {
                    acknowledgment: None,
                    changes: changes(&self.reads, updates),
                })),
            )));
        }
        let destination = MessageDestination {
            identity_key: peer_identity_key,
            discovery_key: contact.identity.discovery_key.x25519_public_key,
        };
        self.phase = DecryptionPhase::AcknowledgmentTransportRequested(Box::new(Acknowledging {
            session_id,
            peer_identity_key,
            state: Box::new(state),
            message_id: message.metadata.id,
            sent_at_millis: message.metadata.sent_at_millis,
            payload_kind,
            plaintext: decoded.plaintext,
            sender_identity: decoded.sender_identity,
            blocked: contact.blocked,
            updates,
            destination,
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
    ) -> Result<InboundMessageOutcome, ProtocolStateError> {
        let limits = self.engine.limits;
        let Acknowledging {
            session_id,
            peer_identity_key,
            mut state,
            message_id,
            sent_at_millis,
            payload_kind,
            plaintext,
            sender_identity,
            blocked,
            mut updates,
            destination,
            ..
        } = acknowledging;
        let mut acknowledgment_id = [0u8; 16];
        rng.try_fill_bytes(&mut acknowledgment_id)
            .map_err(ProtocolStateError::Randomness)?;
        let acknowledgment = seal_signed(
            rng,
            &mut state,
            OutboundContent {
                session_id,
                id: MessageId::from_bytes(acknowledgment_id),
                sent_at_millis: self.acknowledgment_sent_at_millis,
                plaintext: &encode_acknowledgment_plaintext(message_id)?,
            },
            PayloadKind::Acknowledgment,
            SignedRecipient {
                discovery_key: destination.discovery_key,
                identity_verifying_key: &sender_identity.identity_verifying_key,
            },
            &self.local.identity,
            &self.local.keys.signing_key,
            transport_binding,
            limits,
        )?;
        let address = session_address(session_id);
        updates.insert(
            0,
            ProtocolStateUpdate::set(
                address.clone(),
                encode_active_session(&address, peer_identity_key, &state, None, limits)?,
            )
            .with_snapshot(self.reads.snapshot()),
        );
        let changes = changes(&self.reads, updates);
        Ok(if blocked {
            InboundMessageOutcome::Blocked(Box::new(BlockedInboundMessageResult {
                acknowledgment: Some(acknowledgment),
                changes,
            }))
        } else {
            InboundMessageOutcome::Accepted(Box::new(InboundMessageResult {
                session_id,
                message_id,
                sent_at_millis,
                payload_kind,
                plaintext,
                sender_identity,
                acknowledgment,
                changes,
            }))
        })
    }
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

/// The local keys and credentials that authenticate what one operation seals.
pub(crate) struct LocalSenderKeys {
    keys: LocalIdentityKeys,
    identity: SenderIdentityMaterial,
    discovery_key: PublicDiscoveryKey,
    discovery_to_identity: Signature,
}

impl LocalSenderKeys {
    pub(crate) fn new(
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

    pub(crate) fn local_sender(&self) -> LocalSender<'_> {
        LocalSender {
            identity: &self.identity,
            signing_key: &self.keys.signing_key,
            agreement_key: &self.keys.agreement_key,
            discovery_key: &self.discovery_key,
            discovery_to_identity: &self.discovery_to_identity,
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
