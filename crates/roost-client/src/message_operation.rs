use crate::certificate::SenderCertificateValidation;
use crate::context::{Contacts, Messaging};
use crate::encoding::fixed_64;
use crate::error::{RoostError, reason_from_chain};
use crate::identity::IdentityKey;
use crate::message::{Message, MessageId, PayloadKind, SenderIdentityMaterial, SessionId};
use crate::publication::PreKeyBundle;
use crate::state::{StateChanges, StateEntry, StateKey, entries_to_core, state_keys};
use crate::transport_binding::TransportBinding;
use rand::RngCore;
use rand::rngs::OsRng;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::Zeroizing;

/// A domain-signed sender certificate and the domain's signature over it.
#[derive(uniffi::Record)]
pub struct SignedSenderCertificate {
    /// The certificate bytes the relay issued.
    pub certificate: Vec<u8>,
    /// The relay domain's signature over the certificate. Always 64 bytes.
    pub signature: Vec<u8>,
}

/// What the app sends: a recipient, the draft's message ID, and the plaintext.
#[derive(uniffi::Record)]
pub struct OutgoingMessage {
    /// The contact's identity key. Roost picks the session and the contact's discovery key.
    pub recipient: IdentityKey,
    /// The message ID from [`Messaging::create_message`], saved with the draft and kept across
    /// retries.
    pub message_id: MessageId,
    /// When the app sent the message, in Unix milliseconds.
    pub sent_at_millis: u64,
    /// The local identity's certificate, sealed into the message.
    pub sender_certificate: SignedSenderCertificate,
    /// The plaintext to encrypt, at most 65,293 bytes.
    pub plaintext: Vec<u8>,
    /// The contact's bundle, fetched after a [`MessageEncryptionStep::NeedsPreKeyBundle`] step or
    /// for the discovery key in a fresh contact link, and saved with the draft until a session uses
    /// it. A bundle whose discovery key is newer than the contact's starts a new session, and Roost
    /// ignores any other bundle when no new session is needed. A message to a requester through
    /// their newer bundle accepts them.
    pub prekey_bundle: Option<PreKeyBundle>,
}

/// What the app sends to give a contact this identity's current inbox grant.
#[derive(uniffi::Record)]
pub struct OutgoingGrantUpdate {
    /// The contact's identity key. Roost picks the session and the contact's discovery key.
    pub recipient: IdentityKey,
    /// A message ID from [`Messaging::create_message`], kept across retries.
    pub message_id: MessageId,
    /// When the app sent the grant update, in Unix milliseconds.
    pub sent_at_millis: u64,
    /// The local identity's certificate, sealed into the message.
    pub sender_certificate: SignedSenderCertificate,
    /// The contact's bundle, fetched after a [`MessageEncryptionStep::NeedsPreKeyBundle`] step and
    /// kept until a send uses it. Roost ignores it when no check or new session needs it.
    pub prekey_bundle: Option<PreKeyBundle>,
}

/// What the app received, with what Roost needs to check and acknowledge it.
#[derive(uniffi::Record)]
pub struct IncomingMessage {
    /// The received message.
    pub message: Message,
    /// The exact transport binding the message arrived with.
    pub transport_binding: TransportBinding,
    /// The settings for this receive.
    pub settings: ReceiveSettings,
    /// Trust, revocation, and time inputs for the sender's certificate.
    pub sender_certificate_validation: SenderCertificateValidation,
    /// When the app sends the acknowledgment, in Unix milliseconds.
    pub acknowledgment_sent_at_millis: u64,
    /// The local identity's certificate, sealed into the acknowledgment.
    pub acknowledgment_sender_certificate: SignedSenderCertificate,
}

/// The settings the app passes with each receive.
///
/// Roost holds no settings, so the app and its extensions apply whatever each receive passes.
/// Read the value the app should use from one place, such as its own settings or its relay.
#[derive(uniffi::Record)]
pub struct ReceiveSettings {
    /// How many received-message digests the deduplication set keeps, within
    /// [`ProtocolHardeningLimits`](crate::ProtocolHardeningLimits)'s range. Roost resizes the set
    /// when this changes, dropping the oldest digests first.
    pub deduplication_capacity: u32,
    /// Whether a blocked contact's messages get an acknowledgment.
    pub blocked_contact_acknowledgment_policy: BlockedContactAcknowledgmentPolicy,
    /// How long after expiry a sender certificate still validates, in milliseconds, at most
    /// 300,000.
    ///
    /// A grace covers clock differences between devices, at the cost of accepting a certificate
    /// the relay has stopped vouching for.
    pub certificate_grace_millis: u64,
}

/// Blocked-contact acknowledgment policy.
#[derive(uniffi::Enum)]
pub enum BlockedContactAcknowledgmentPolicy {
    /// Suppress acknowledgments so blocks look like unreachable recipients.
    Unreachable,
    /// Return the acknowledgments an unblocked sender would get, while hiding plaintext.
    Acknowledge,
}

/// Where Roost sends a message, and how the relay admits it, so the app can supply a transport
/// binding that reaches it.
#[derive(uniffi::Enum)]
pub enum MessageDestination {
    /// A first message, which the relay admits against the recipient's current prekeys.
    FirstMessage {
        /// The recipient's identity key.
        identity_key: IdentityKey,
        /// The X25519 public key of the recipient discovery key the message is sealed to. Always
        /// 32 bytes.
        discovery_key: Vec<u8>,
        /// The recipient signed prekey the handshake used.
        signed_prekey_id: u64,
        /// The recipient one-time prekey the handshake used, absent when none was left.
        one_time_prekey_id: Option<u64>,
    },
    /// An established message, which the relay admits with the recipient's delivery capability.
    Established {
        /// The recipient's identity key.
        identity_key: IdentityKey,
        /// The X25519 public key of the recipient discovery key the message is sealed to. Always
        /// 32 bytes.
        discovery_key: Vec<u8>,
        /// The recipient's 32-byte delivery capability. It's a secret, so pass it only to the relay
        /// in this message's submission, and don't store or log it.
        delivery_capability: Vec<u8>,
    },
}

/// The signed prekey a first message names, kept after a rotation, which the app must prove the
/// relay admitted the message against.
#[derive(uniffi::Record)]
pub struct AdmissionRequest {
    /// The local discovery key epoch the signed prekey belongs to.
    pub discovery_epoch: u32,
    /// The signed prekey's ID, which the relay's admission proof must name.
    pub signed_prekey_id: u64,
}

/// What a [`MessageEncryption`] needs next, or its result.
#[derive(uniffi::Enum)]
pub enum MessageEncryptionStep {
    /// Supply one entry for each key through [`MessageEncryption::supply_state`].
    NeedsState {
        /// The records to read.
        keys: Vec<StateKey>,
    },
    /// Supply the transport binding that reaches `destination` through
    /// [`MessageEncryption::supply_transport_binding`].
    NeedsTransport {
        /// Where the message goes.
        destination: MessageDestination,
    },
    /// A new session, or the first send after an unblock, needs the contact's prekey bundle, and
    /// the draft has none or one older than the contact's discovery key. A send to an accepted
    /// contact, or an acceptance of a request, whose session records are missing starts a new
    /// session too. The operation has ended, so release the identity lock, fetch the bundle, save
    /// it with the draft, and start again with the same draft.
    NeedsPreKeyBundle {
        /// The contact whose bundle to fetch.
        identity_key: IdentityKey,
    },
    /// The contact already acknowledged a message carrying the current inbox grant, so a grant
    /// update has nothing to carry. The operation has ended and there is nothing to commit.
    NothingToSend,
    /// The sealed message, and the state changes to commit with it. The operation has ended.
    Ready {
        /// The sealed message.
        result: OutboundMessageResult,
        /// The state changes to commit with the message.
        changes: StateChanges,
    },
}

/// What a [`MessageDecryption`] needs next, or its result.
#[derive(uniffi::Enum)]
#[expect(
    clippy::large_enum_variant,
    reason = "UniFFI enum payloads are generated records, which can't be boxed"
)]
pub enum MessageDecryptionStep {
    /// Supply one entry for each key through [`MessageDecryption::supply_state`].
    NeedsState {
        /// The records to read.
        keys: Vec<StateKey>,
    },
    /// The first message names a signed prekey kept after a rotation. Check the relay's
    /// admission proof for this message: its signature, the frame's digest, the first-message
    /// route, and `admission.signed_prekey_id`. Then call
    /// [`MessageDecryption::confirm_admission`], or drop the operation and the message.
    NeedsAdmission {
        /// The signed prekey the proof must name.
        admission: AdmissionRequest,
    },
    /// Supply the transport binding that reaches `destination` through
    /// [`MessageDecryption::supply_acknowledgment_transport_binding`].
    NeedsAcknowledgmentTransport {
        /// Where the acknowledgment goes: the sender, after it authenticated.
        destination: MessageDestination,
    },
    /// What the message turned out to be, and the state changes to commit with its effects. The
    /// operation has ended.
    Ready {
        /// What the message turned out to be.
        outcome: InboundMessageOutcome,
        /// The state changes to commit with the outcome's effects, empty when it has none.
        changes: StateChanges,
    },
}

/// An outbound message from one message operation.
#[derive(uniffi::Record)]
pub struct OutboundMessageResult {
    /// The session Roost selected for the message.
    pub session_id: SessionId,
    /// The draft's message ID, sealed inside the message.
    pub message_id: MessageId,
    /// Sender-observed Unix timestamp in milliseconds.
    pub sent_at_millis: u64,
    /// Payload kind sealed in the message.
    pub payload_kind: PayloadKind,
    /// Message to send after durable commit.
    pub message: Message,
}

/// A provisional receive result. Commit it atomically with the changes that come beside it before
/// use.
///
/// Switch on the outcome to obtain only the fields that case permits. The app's transaction must
/// check the changes with [`StateChanges::matches`] and persist the outcome's effects before
/// plaintext is displayed or an acknowledgment is sent.
#[derive(uniffi::Enum)]
pub enum InboundMessageOutcome {
    /// Authenticated plaintext, and an acknowledgment when this side acknowledges, for a unique
    /// message.
    Accepted {
        /// Payload for this outcome.
        result: InboundMessageResult,
    },
    /// A contact request: the first message from an identity with no contact record, which the
    /// changes record as a pending contact. Nothing is acknowledged until this side replies.
    ContactRequest {
        /// Payload for this outcome.
        result: InboundMessageResult,
    },
    /// A blocked message with state changes and the acknowledgment its receive allows.
    Blocked {
        /// Payload for this outcome.
        result: BlockedInboundMessageResult,
    },
    /// A message past the limit before acceptance, whose plaintext Roost withholds.
    Withheld {
        /// Payload for this outcome.
        result: WithheldInboundMessageResult,
    },
    /// A grant update, whose inbox grant Roost kept. There is nothing to show.
    GrantUpdate {
        /// Payload for this outcome.
        result: GrantUpdateResult,
    },
    /// An already accepted encrypted message. No effects are produced, and its changes are empty.
    Duplicate,
    /// The message names a session this identity doesn't keep and carries no handshake, such as
    /// one whose records it lost. No effects are produced, and its changes are empty.
    UnknownSession,
    /// The first message names a session this identity deleted, so nothing was created. No
    /// effects are produced, and its changes are empty.
    DeletedSession,
    /// An acknowledgment cleared one of this identity's pending acknowledgments. Commit it before
    /// treating the acknowledged message as delivered. Roost sends no reply to an acknowledgment.
    AcknowledgmentMatched {
        /// Payload for this outcome.
        result: AcknowledgmentResult,
    },
    /// An authenticated acknowledgment named no pending acknowledgment, such as one already
    /// cleared. Commit it anyway, so the advanced state recognizes a retry as a duplicate. If it
    /// names a message Roost reported as not delivered, a later copy arrived, so correct that
    /// status.
    AcknowledgmentUnmatched {
        /// Payload for this outcome.
        result: AcknowledgmentResult,
    },
}

/// Authenticated message data that remains provisional until the app's transaction commits.
///
/// The app commits the message, acknowledgment, and state changes in one transaction. When the
/// changes carry an operation, the app finalizes it before showing the plaintext. The plaintext is
/// secret, so clear each copy once the app is done with it.
///
/// A sender's recovery resends a message under its original message ID with new bytes, so show one
/// message per sender and message ID, and check before notifying, including in a notification
/// extension. When one is already shown, still commit the changes and send the acknowledgment.
#[derive(uniffi::Record)]
pub struct InboundMessageResult {
    /// The session the message arrived on.
    pub session_id: SessionId,
    /// Authenticated message ID.
    pub message_id: MessageId,
    /// Authenticated sender timestamp in milliseconds.
    pub sent_at_millis: u64,
    /// Authenticated payload kind.
    pub payload_kind: PayloadKind,
    /// Plaintext for the app to protect and clear after use.
    pub plaintext: Vec<u8>,
    /// Authenticated sender material.
    pub sender_identity: SenderIdentityMaterial,
    /// Encrypted acknowledgment to commit with the transport binding the app supplied for it,
    /// absent while the contact isn't accepted and this side doesn't acknowledge yet, or while no
    /// inbox grant has supplied the contact's current delivery capability.
    pub acknowledgment: Option<Message>,
}

/// A message from a contact who hasn't accepted, past the limit on messages before acceptance.
///
/// Roost withholds its plaintext and sends no acknowledgment. Commit the changes so the session
/// keeps up.
#[derive(uniffi::Record)]
pub struct WithheldInboundMessageResult {
    /// The session the message arrived on.
    pub session_id: SessionId,
    /// Authenticated message ID.
    pub message_id: MessageId,
}

/// A grant update whose inbox grant Roost kept, so later messages reach the contact's current
/// inbox.
///
/// Commit the changes, and the acknowledgment when present, but show nothing.
#[derive(uniffi::Record)]
pub struct GrantUpdateResult {
    /// The session the grant update arrived on.
    pub session_id: SessionId,
    /// Authenticated message ID.
    pub message_id: MessageId,
    /// Encrypted acknowledgment to commit with the transport binding the app supplied for it,
    /// absent while this side doesn't acknowledge the contact yet.
    pub acknowledgment: Option<Message>,
}

/// A blocked receive with no plaintext available to the app.
///
/// The acknowledgment is present only under [`BlockedContactAcknowledgmentPolicy::Acknowledge`].
/// Commit it with the changes before sending it. Under
/// [`BlockedContactAcknowledgmentPolicy::Unreachable`], the app commits only the changes.
#[derive(uniffi::Record)]
pub struct BlockedInboundMessageResult {
    /// Acknowledgment when the receive's policy permits one.
    pub acknowledgment: Option<Message>,
}

/// An authenticated acknowledgment.
///
/// Commit its changes before clearing the app's own delivery state.
#[derive(uniffi::Record)]
pub struct AcknowledgmentResult {
    /// The session the acknowledgment arrived on.
    pub session_id: SessionId,
    /// The acknowledgment's own message ID.
    pub message_id: MessageId,
    /// Authenticated sender timestamp in milliseconds.
    pub sent_at_millis: u64,
    /// The outbound message ID the acknowledgment names.
    pub acknowledged_message_id: MessageId,
    /// Authenticated sender material.
    pub sender_identity: SenderIdentityMaterial,
}

/// One attempt to encrypt a message to a contact.
///
/// Call [`Self::step`] until it returns [`MessageEncryptionStep::Ready`],
/// [`MessageEncryptionStep::NeedsPreKeyBundle`], or [`MessageEncryptionStep::NothingToSend`],
/// supplying what each other step asks for. For [`MessageEncryptionStep::NeedsState`], return
/// exactly one entry per key, in any order, with no bytes for a record the app doesn't have. The
/// operation does its cryptography in [`Self::step`], so asking again before supplying returns the
/// same request without repeating it.
///
/// The destination says how the relay admits the message: a first message by the recipient's
/// prekey IDs, or an established one by the recipient's delivery capability.
///
/// The operation returns its result once. After that, and after any error, every call returns
/// [`RoostError::OperationFinished`], so start a new operation from fresh reads. Releasing an
/// operation commits nothing. Calls from two threads take turns.
///
/// ```swift
/// var sealed: (OutboundMessageResult, StateChanges)?
/// while sealed == nil {
///     let encryption = try contacts.requestContact(message: draft)
///     steps: while true {
///         switch try encryption.step() {
///         case .needsState(let keys):
///             try encryption.supplyState(entries: try database.entries(for: keys))
///         case .needsTransport(let destination):
///             try encryption.supplyTransportBinding(transportBinding: router.binding(to: destination))
///         case .needsPreKeyBundle(let identityKey):
///             // Fetch outside the identity lock, keep the bundle with the draft, and restart.
///             draft.prekeyBundle = try await relay.prekeyBundle(for: identityKey)
///             try drafts.save(draft)
///             break steps
///         case .nothingToSend:
///             return // Only a grant update ends here.
///         case .ready(let result, let changes):
///             sealed = (result, changes)
///             break steps
///         }
///     }
/// }
/// let (result, changes) = sealed!
/// try database.transaction { db in
///     guard try changes.matches(current: db.entries(for: changes.conditions.map(\.key))) else {
///         throw CommitError.conflict // Start again from fresh reads.
///     }
///     try db.write(changes.updates)
///     try db.markNotDelivered(changes.undelivered)
///     try db.queue(result.message, messageId: result.messageId)
/// }
/// ```
///
/// ```kotlin
/// var ready: MessageEncryptionStep.Ready? = null
/// while (ready == null) {
///     val encryption = contacts.requestContact(draft)
///     steps@ while (true) {
///         when (val step = encryption.step()) {
///             is MessageEncryptionStep.NeedsState ->
///                 encryption.supplyState(database.entries(step.keys))
///             is MessageEncryptionStep.NeedsTransport ->
///                 encryption.supplyTransportBinding(router.bindingTo(step.destination))
///             is MessageEncryptionStep.NeedsPreKeyBundle -> {
///                 // Fetch outside the identity lock, keep the bundle with the draft, and restart.
///                 draft = draft.copy(prekeyBundle = relay.prekeyBundle(step.identityKey))
///                 drafts.save(draft)
///                 break@steps
///             }
///             is MessageEncryptionStep.NothingToSend -> return // Only a grant update ends here.
///             is MessageEncryptionStep.Ready -> {
///                 ready = step
///                 break@steps
///             }
///         }
///     }
/// }
/// val (result, changes) = ready
/// database.transaction { db ->
///     if (!changes.matches(db.entries(changes.conditions.map { it.key }))) {
///         throw CommitConflict() // Start again from fresh reads.
///     }
///     db.write(changes.updates)
///     db.markNotDelivered(changes.undelivered)
///     db.queue(result.message, result.messageId)
/// }
/// ```
#[derive(uniffi::Object)]
pub struct MessageEncryption(Mutex<Option<roost_core::MessageEncryption>>);

/// One attempt to decrypt a received message.
///
/// Drive it as [`MessageEncryption`] describes. A first message on a signed prekey kept after a
/// rotation asks for proof that the relay admitted it before Roost uses that prekey. A message
/// that needs an acknowledgment asks for the acknowledgment's transport binding only after its
/// sender authenticates and Roost decides to reply, because the route the message arrived on may
/// not reach the sender. An acknowledgment the app receives decrypts here too and never asks for
/// one.
///
/// The result comes with the state changes beside the outcome. Commit the changes and the
/// outcome's effects in one transaction, as [`StateChanges`] describes. When the changes carry an
/// operation, such as one that uses up a one-time prekey, show the plaintext or send the
/// acknowledgment only after finalizing it.
///
/// The operation returns its result once. After that, and after any error, every call returns
/// [`RoostError::OperationFinished`]. Releasing an operation commits nothing. Calls from two
/// threads take turns.
#[derive(uniffi::Object)]
pub struct MessageDecryption(Mutex<Option<roost_core::MessageDecryption>>);

#[uniffi::export]
impl Messaging {
    /// Returns a new random message ID for a draft.
    ///
    /// Save it with the draft before the first send attempt, and pass the same message ID to every
    /// retry, so the recipient sees one message however many attempts it takes.
    pub fn create_message(&self) -> Result<MessageId, RoostError> {
        let mut bytes = [0u8; 16];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|error| RoostError::InternalError {
                reason: format!(
                    "message id randomness failed: {}",
                    reason_from_chain(&error)
                ),
            })?;
        Ok(MessageId::from_core(roost_protocol::MessageId::from_bytes(
            bytes,
        )))
    }

    /// Starts encrypting a message to a contact.
    ///
    /// The operation reads the local identity's keys now and touches SecureStorage no more. A
    /// contact that hasn't accepted gets a few messages before refusing more, and an accepted
    /// contact gets this identity's inbox grant attached until it acknowledges one.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if a key, message ID, certificate, or the plaintext is
    ///   malformed or too long.
    /// - [`RoostError::NotFound`] if no identity or discovery key is stored.
    /// - [`RoostError::Corrupt`] if the stored discovery key fails its binding checks, or the
    ///   operation journal is corrupt.
    /// - [`RoostError::UnfinishedReservation`] if a reserved operation is unfinished.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn start_encryption(
        &self,
        message: OutgoingMessage,
    ) -> Result<Arc<MessageEncryption>, RoostError> {
        let operation = self.inner.start_encryption(message.into_core()?)?;
        Ok(Arc::new(MessageEncryption(Mutex::new(Some(operation)))))
    }

    /// Starts decrypting a received message, including a first message that starts a session.
    ///
    /// The operation reads the local identity's keys now. It reads SecureStorage again only for
    /// the prekeys a first message names. When the first message uses a one-time prekey, the
    /// result's changes carry the operation that uses it up.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if the message, transport binding, settings, validation inputs,
    ///   or acknowledgment certificate are malformed or outside Roost's limits.
    /// - [`RoostError::NotFound`] if no identity or discovery key is stored.
    /// - [`RoostError::Corrupt`] if the stored discovery key fails its binding checks, or the
    ///   operation journal is corrupt.
    /// - [`RoostError::UnfinishedReservation`] if a reserved operation is unfinished.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn start_decryption(
        &self,
        message: IncomingMessage,
    ) -> Result<Arc<MessageDecryption>, RoostError> {
        let operation = self.inner.start_decryption(roost_core::IncomingMessage {
            message: message.message.into_core()?,
            transport_binding: message.transport_binding.into_core()?,
            settings: message.settings.into_core()?,
            sender_certificate_validation: message.sender_certificate_validation.into_core()?,
            acknowledgment_sent_at_millis: message.acknowledgment_sent_at_millis,
            acknowledgment_sender_certificate: message
                .acknowledgment_sender_certificate
                .into_core()?,
        })?;
        Ok(Arc::new(MessageDecryption(Mutex::new(Some(operation)))))
    }
}

#[uniffi::export]
impl Contacts {
    /// Starts encrypting a contact request, whose commit creates the contact's pending record.
    ///
    /// A new contact needs a session, so without a usable bundle in the draft the operation ends
    /// with [`MessageEncryptionStep::NeedsPreKeyBundle`]. Each restart reads fresh state. When the
    /// contact asked meanwhile, the request becomes a contact acceptance, and when the contact
    /// already accepted, an ordinary message. The draft keeps one message ID across restarts. A
    /// request counts toward the limit on messages before acceptance, and once a restore drops the
    /// contact's sessions, the count starts over with the next request.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if a key, message ID, certificate, or bundle is malformed, or
    ///   the plaintext is too long.
    /// - [`RoostError::NotFound`] if no identity or discovery key is stored.
    /// - [`RoostError::Corrupt`] if the stored discovery key fails its binding checks, or the
    ///   operation journal is corrupt.
    /// - [`RoostError::UnfinishedReservation`] if a reserved operation is unfinished.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn request_contact(
        &self,
        message: OutgoingMessage,
    ) -> Result<Arc<MessageEncryption>, RoostError> {
        let operation = self.inner.request_contact(message.into_core()?)?;
        Ok(Arc::new(MessageEncryption(Mutex::new(Some(operation)))))
    }

    /// Starts encrypting a grant update, which carries only this identity's current inbox grant.
    ///
    /// After an inbox rotation, send one to each contact that should stay able to reach this
    /// identity, after registering the new inbox with the relay. Roost decides who may hold the
    /// grant, so the app can send one to every contact without checking. When stepping, a blocked
    /// contact fails with [`RoostError::BlockedContact`], a requester this side hasn't accepted
    /// fails with [`RoostError::ContactNotAccepted`], and a contact that already acknowledged the
    /// current grant ends with [`MessageEncryptionStep::NothingToSend`]. A requester's grant
    /// updates don't count toward the limit on messages before acceptance. The recipient shows
    /// nothing.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if a key, message ID, certificate, or bundle is malformed.
    /// - [`RoostError::NotFound`] if no identity or discovery key is stored.
    /// - [`RoostError::Corrupt`] if the stored discovery key fails its binding checks, or the
    ///   operation journal is corrupt.
    /// - [`RoostError::UnfinishedReservation`] if a reserved operation is unfinished.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn start_grant_update(
        &self,
        update: OutgoingGrantUpdate,
    ) -> Result<Arc<MessageEncryption>, RoostError> {
        let operation = self.inner.start_grant_update(update.into_core()?)?;
        Ok(Arc::new(MessageEncryption(Mutex::new(Some(operation)))))
    }

    /// Starts encrypting a contact acceptance, which carries this identity's inbox grant and
    /// whose commit accepts the contact.
    ///
    /// Only the side a contact asked accepts. When the contact is already accepted, the
    /// acceptance becomes an ordinary message. When the request's session is gone, such as after a
    /// backup restore, the acceptance starts a new session from the contact's bundle, and its
    /// first message is a contact request that accepts both sides when it arrives. Roost then
    /// refuses only a contact that never wrote, so accept only a request the contact sent.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if a key, message ID, or certificate is malformed, the
    ///   plaintext is too long, or when stepping, if no contact request from the contact is open.
    /// - [`RoostError::NotFound`] if no identity or discovery key is stored.
    /// - [`RoostError::Corrupt`] if the stored discovery key fails its binding checks, or the
    ///   operation journal is corrupt.
    /// - [`RoostError::UnfinishedReservation`] if a reserved operation is unfinished.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn accept_contact(
        &self,
        message: OutgoingMessage,
    ) -> Result<Arc<MessageEncryption>, RoostError> {
        let operation = self.inner.accept_contact(message.into_core()?)?;
        Ok(Arc::new(MessageEncryption(Mutex::new(Some(operation)))))
    }
}

#[uniffi::export]
impl MessageEncryption {
    /// Advances the operation and returns what it needs next, or its result.
    ///
    /// # Errors
    /// - [`RoostError::OperationFinished`] if the operation already returned its result or failed.
    /// - [`RoostError::BlockedContact`] if the contact is blocked.
    /// - [`RoostError::ContactNotAccepted`] if the contact hasn't accepted and this side already
    ///   sent the most messages allowed before acceptance, no session exists to send on, or a
    ///   grant update would give a requester this side hasn't accepted its inbox grant.
    /// - [`RoostError::NoDeliveryCapability`] if an established message needs the contact's
    ///   delivery capability and no inbox grant has supplied one.
    /// - [`RoostError::TooManyPendingAcknowledgments`] if the most messages allowed already wait
    ///   for the contact's acknowledgment on the session.
    /// - [`RoostError::AuthenticationFailed`] if a bundle's signatures don't bind its discovery key
    ///   and the contact's identity in both directions.
    /// - [`RoostError::ProtocolStateFault`] if a record is missing or malformed.
    /// - [`RoostError::UnsupportedVersion`] if a record uses an unknown format version.
    /// - [`RoostError::InvalidData`] if the message is too large to seal.
    pub fn step(&self) -> Result<MessageEncryptionStep, RoostError> {
        with_operation(&self.0, |encryption| {
            Ok(MessageEncryptionStep::from_core(
                encryption.step(&mut OsRng)?,
            ))
        })
    }

    /// Supplies one entry for each key the pending [`MessageEncryptionStep::NeedsState`] named.
    ///
    /// # Errors
    /// - [`RoostError::OperationFinished`] if the operation already returned its result or failed.
    /// - [`RoostError::InvalidData`] if the entries miss, repeat, or add a key, a key is malformed,
    ///   or the operation isn't waiting for state.
    pub fn supply_state(&self, entries: Vec<StateEntry>) -> Result<(), RoostError> {
        let entries = entries_to_core(entries);
        with_operation(&self.0, |encryption| Ok(encryption.supply_state(entries?)?))
    }

    /// Supplies the transport binding the pending [`MessageEncryptionStep::NeedsTransport`] asked
    /// for.
    ///
    /// Retain the exact binding with the message for sending and retransmission.
    ///
    /// # Errors
    /// - [`RoostError::OperationFinished`] if the operation already returned its result or failed.
    /// - [`RoostError::InvalidData`] if the binding is empty or too long, or the operation isn't
    ///   waiting for one.
    pub fn supply_transport_binding(
        &self,
        transport_binding: TransportBinding,
    ) -> Result<(), RoostError> {
        with_operation(&self.0, |encryption| {
            Ok(encryption.supply_transport_binding(transport_binding.into_core()?)?)
        })
    }
}

#[uniffi::export]
impl MessageDecryption {
    /// Advances the operation and returns what it needs next, or its result.
    ///
    /// # Errors
    /// - [`RoostError::OperationFinished`] if the operation already returned its result or failed.
    /// - [`RoostError::AuthenticationFailed`] if the message fails to decrypt, its sender fails to
    ///   authenticate, or an inbox grant it carries fails its signatures.
    /// - [`RoostError::CertificateRejected`] if the sender's certificate fails validation.
    /// - [`RoostError::OneTimePreKeyUsed`] if a different first message already used the one-time
    ///   prekey this one names. A repeat of the same message is a duplicate instead.
    /// - [`RoostError::Corrupt`] if the operation journal is corrupt, when a first message uses a
    ///   one-time prekey.
    /// - [`RoostError::UnfinishedReservation`] if a reserved operation is unfinished, when a first
    ///   message uses a one-time prekey.
    /// - [`RoostError::TooManyUnfinishedOperations`] if too many operations are unfinished, when a
    ///   first message uses a one-time prekey.
    /// - [`RoostError::Storage`] if SecureStorage fails while reading the prekeys a first message
    ///   names.
    /// - [`RoostError::ProtocolStateFault`] if a record is missing or malformed, including the
    ///   sender's contact record.
    /// - [`RoostError::UnsupportedVersion`] if the message, the sender's certificate, or a record
    ///   uses an unknown version.
    /// - [`RoostError::InvalidData`] if the message is malformed.
    pub fn step(&self) -> Result<MessageDecryptionStep, RoostError> {
        with_operation(&self.0, |decryption| {
            Ok(MessageDecryptionStep::from_core(
                decryption.step(&mut OsRng)?,
            ))
        })
    }

    /// Supplies one entry for each key the pending [`MessageDecryptionStep::NeedsState`] named.
    ///
    /// # Errors
    /// - [`RoostError::OperationFinished`] if the operation already returned its result or failed.
    /// - [`RoostError::InvalidData`] if the entries miss, repeat, or add a key, a key is malformed,
    ///   or the operation isn't waiting for state.
    pub fn supply_state(&self, entries: Vec<StateEntry>) -> Result<(), RoostError> {
        let entries = entries_to_core(entries);
        with_operation(&self.0, |decryption| Ok(decryption.supply_state(entries?)?))
    }

    /// Confirms the pending [`MessageDecryptionStep::NeedsAdmission`], once the relay's proof shows
    /// it admitted this exact message as a first message against the named signed prekey.
    ///
    /// # Errors
    /// - [`RoostError::OperationFinished`] if the operation already returned its result or failed.
    /// - [`RoostError::InvalidData`] if the operation isn't waiting for admission.
    pub fn confirm_admission(&self) -> Result<(), RoostError> {
        with_operation(&self.0, |decryption| Ok(decryption.confirm_admission()?))
    }

    /// Supplies the transport binding the pending
    /// [`MessageDecryptionStep::NeedsAcknowledgmentTransport`] asked for.
    ///
    /// Retain the exact binding with the acknowledgment for sending and retransmission.
    ///
    /// # Errors
    /// - [`RoostError::OperationFinished`] if the operation already returned its result or failed.
    /// - [`RoostError::InvalidData`] if the binding is empty or too long, or the operation isn't
    ///   waiting for one.
    pub fn supply_acknowledgment_transport_binding(
        &self,
        transport_binding: TransportBinding,
    ) -> Result<(), RoostError> {
        with_operation(&self.0, |decryption| {
            Ok(decryption
                .supply_acknowledgment_transport_binding(transport_binding.into_core()?)?)
        })
    }
}

// Runs `call` on an unfinished operation and ends the operation if the call fails, which also
// covers input that fails to convert before the call. A call that panicked while holding the lock
// ends the operation too.
pub(crate) fn with_operation<T, R>(
    operation: &Mutex<Option<T>>,
    call: impl FnOnce(&mut T) -> Result<R, RoostError>,
) -> Result<R, RoostError> {
    let mut operation = operation.lock().unwrap_or_else(|poisoned| {
        let mut operation = poisoned.into_inner();
        *operation = None;
        operation
    });
    let unfinished = operation.as_mut().ok_or(RoostError::OperationFinished)?;
    let result = call(unfinished);
    if result.is_err() {
        *operation = None;
    }
    result
}

impl SignedSenderCertificate {
    pub(crate) fn into_core(self) -> Result<roost_core::SignedSenderCertificate, RoostError> {
        Ok(roost_core::SignedSenderCertificate {
            certificate: self.certificate,
            signature: fixed_64(&self.signature, "sender certificate signature")?,
        })
    }
}

impl OutgoingMessage {
    fn into_core(self) -> Result<roost_core::OutgoingMessage, RoostError> {
        let plaintext = Zeroizing::new(self.plaintext);
        Ok(roost_core::OutgoingMessage {
            recipient: self.recipient.to_core()?,
            message_id: self.message_id.to_core()?,
            sent_at_millis: self.sent_at_millis,
            sender_certificate: self.sender_certificate.into_core()?,
            plaintext,
            prekey_bundle: self
                .prekey_bundle
                .as_ref()
                .map(PreKeyBundle::to_core)
                .transpose()?,
        })
    }
}

impl OutgoingGrantUpdate {
    fn into_core(self) -> Result<roost_core::OutgoingGrantUpdate, RoostError> {
        Ok(roost_core::OutgoingGrantUpdate {
            recipient: self.recipient.to_core()?,
            message_id: self.message_id.to_core()?,
            sent_at_millis: self.sent_at_millis,
            sender_certificate: self.sender_certificate.into_core()?,
            prekey_bundle: self
                .prekey_bundle
                .as_ref()
                .map(PreKeyBundle::to_core)
                .transpose()?,
        })
    }
}

impl MessageDestination {
    pub(crate) fn from_core(destination: roost_core::MessageDestination) -> Self {
        match destination {
            roost_core::MessageDestination::FirstMessage {
                identity_key,
                discovery_key,
                signed_prekey_id,
                one_time_prekey_id,
            } => Self::FirstMessage {
                identity_key: IdentityKey::from_core(identity_key),
                discovery_key: discovery_key.to_vec(),
                signed_prekey_id,
                one_time_prekey_id,
            },
            roost_core::MessageDestination::Established {
                identity_key,
                discovery_key,
                delivery_capability,
            } => Self::Established {
                identity_key: IdentityKey::from_core(identity_key),
                discovery_key: discovery_key.to_vec(),
                delivery_capability: delivery_capability.to_bytes().to_vec(),
            },
        }
    }
}

impl MessageEncryptionStep {
    fn from_core(step: roost_core::MessageEncryptionStep) -> Self {
        match step {
            roost_core::MessageEncryptionStep::NeedsState(addresses) => Self::NeedsState {
                keys: state_keys(&addresses),
            },
            roost_core::MessageEncryptionStep::NeedsTransport(destination) => {
                Self::NeedsTransport {
                    destination: MessageDestination::from_core(destination),
                }
            }
            roost_core::MessageEncryptionStep::NeedsPreKeyBundle(identity_key) => {
                Self::NeedsPreKeyBundle {
                    identity_key: IdentityKey::from_core(identity_key),
                }
            }
            roost_core::MessageEncryptionStep::NothingToSend => Self::NothingToSend,
            roost_core::MessageEncryptionStep::Ready { result, changes } => Self::Ready {
                result: OutboundMessageResult::from_core(*result),
                changes: StateChanges::from_core(changes),
            },
        }
    }
}

impl MessageDecryptionStep {
    fn from_core(step: roost_core::MessageDecryptionStep) -> Self {
        match step {
            roost_core::MessageDecryptionStep::NeedsState(addresses) => Self::NeedsState {
                keys: state_keys(&addresses),
            },
            roost_core::MessageDecryptionStep::NeedsAdmission(admission) => Self::NeedsAdmission {
                admission: AdmissionRequest {
                    discovery_epoch: admission.discovery_epoch,
                    signed_prekey_id: admission.signed_prekey_id,
                },
            },
            roost_core::MessageDecryptionStep::NeedsAcknowledgmentTransport(destination) => {
                Self::NeedsAcknowledgmentTransport {
                    destination: MessageDestination::from_core(destination),
                }
            }
            roost_core::MessageDecryptionStep::Ready { outcome, changes } => Self::Ready {
                outcome: InboundMessageOutcome::from_core(outcome),
                changes: StateChanges::from_core(changes),
            },
        }
    }
}

impl ReceiveSettings {
    fn into_core(self) -> Result<roost_core::ReceiveSettings, RoostError> {
        // A `u32` fits in `usize` on every target Roost builds for.
        Ok(roost_core::ReceiveSettings::new(
            self.deduplication_capacity as usize,
            self.blocked_contact_acknowledgment_policy.into_core(),
            Duration::from_millis(self.certificate_grace_millis),
        )?)
    }
}

impl BlockedContactAcknowledgmentPolicy {
    fn into_core(self) -> roost_core::BlockedContactAcknowledgmentPolicy {
        match self {
            Self::Unreachable => roost_core::BlockedContactAcknowledgmentPolicy::Unreachable,
            Self::Acknowledge => roost_core::BlockedContactAcknowledgmentPolicy::Acknowledge,
        }
    }
}

impl OutboundMessageResult {
    pub(crate) fn from_core(value: roost_core::OutboundMessageResult) -> Self {
        Self {
            session_id: SessionId::from_core(value.session_id),
            message_id: MessageId::from_core(value.message_id),
            sent_at_millis: value.sent_at_millis,
            payload_kind: PayloadKind::from_protocol(value.payload_kind),
            message: Message::from_core(value.message),
        }
    }
}

impl InboundMessageResult {
    fn from_core(value: roost_core::InboundMessageResult) -> Self {
        Self {
            session_id: SessionId::from_core(value.session_id),
            message_id: MessageId::from_core(value.message_id),
            sent_at_millis: value.sent_at_millis,
            payload_kind: PayloadKind::from_protocol(value.payload_kind),
            plaintext: value.plaintext.to_vec(),
            sender_identity: SenderIdentityMaterial::from_core(value.sender_identity),
            acknowledgment: value.acknowledgment.map(Message::from_core),
        }
    }
}

impl InboundMessageOutcome {
    fn from_core(value: roost_core::InboundMessageOutcome) -> Self {
        match value {
            roost_core::InboundMessageOutcome::Accepted(result) => Self::Accepted {
                result: InboundMessageResult::from_core(*result),
            },
            roost_core::InboundMessageOutcome::ContactRequest(result) => Self::ContactRequest {
                result: InboundMessageResult::from_core(*result),
            },
            roost_core::InboundMessageOutcome::Withheld(result) => Self::Withheld {
                result: WithheldInboundMessageResult {
                    session_id: SessionId::from_core(result.session_id),
                    message_id: MessageId::from_core(result.message_id),
                },
            },
            roost_core::InboundMessageOutcome::GrantUpdate(result) => Self::GrantUpdate {
                result: GrantUpdateResult {
                    session_id: SessionId::from_core(result.session_id),
                    message_id: MessageId::from_core(result.message_id),
                    acknowledgment: result.acknowledgment.map(Message::from_core),
                },
            },
            roost_core::InboundMessageOutcome::Blocked(result) => Self::Blocked {
                result: BlockedInboundMessageResult {
                    acknowledgment: result.acknowledgment.map(Message::from_core),
                },
            },
            roost_core::InboundMessageOutcome::Duplicate => Self::Duplicate,
            roost_core::InboundMessageOutcome::UnknownSession => Self::UnknownSession,
            roost_core::InboundMessageOutcome::DeletedSession => Self::DeletedSession,
            roost_core::InboundMessageOutcome::AcknowledgmentMatched(result) => {
                Self::AcknowledgmentMatched {
                    result: AcknowledgmentResult::from_core(*result),
                }
            }
            roost_core::InboundMessageOutcome::AcknowledgmentUnmatched(result) => {
                Self::AcknowledgmentUnmatched {
                    result: AcknowledgmentResult::from_core(*result),
                }
            }
        }
    }
}

impl AcknowledgmentResult {
    fn from_core(result: roost_core::AcknowledgmentResult) -> Self {
        Self {
            session_id: SessionId::from_core(result.session_id),
            message_id: MessageId::from_core(result.message_id),
            sent_at_millis: result.sent_at_millis,
            acknowledged_message_id: MessageId::from_core(result.acknowledged_message_id),
            sender_identity: SenderIdentityMaterial::from_core(result.sender_identity),
        }
    }
}
