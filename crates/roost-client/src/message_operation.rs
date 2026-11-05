use crate::certificate::SenderCertificateValidation;
use crate::context::{Contacts, Messaging};
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
    /// The relay domain's signature over the certificate.
    pub signature: Vec<u8>,
}

/// What the app sends: a recipient, the draft's MessageID, and the plaintext.
#[derive(uniffi::Record)]
pub struct OutgoingMessage {
    /// The contact's Identity Key. Roost picks the Session and the contact's Discovery Key.
    pub recipient: IdentityKey,
    /// The MessageID from [`Messaging::create_message`], saved with the draft and kept across
    /// retries.
    pub message_id: MessageId,
    /// When the app sent the Message, in Unix milliseconds.
    pub sent_at_millis: u64,
    /// The local identity's certificate, sealed into the Message.
    pub sender_certificate: SignedSenderCertificate,
    /// The plaintext to encrypt, at most 65,291 bytes.
    pub plaintext: Vec<u8>,
    /// The contact's bundle, fetched after a [`MessageEncryptionStep::NeedsPreKeyBundle`] step or
    /// for the Discovery Key in a fresh contact link, and saved with the draft until a Session uses
    /// it. A bundle whose Discovery Key is newer than the contact's starts a new Session, and Roost
    /// ignores any other bundle when no new Session is needed.
    pub prekey_bundle: Option<PreKeyBundle>,
}

/// What the app sends to give a contact this identity's current Inbox Grant.
#[derive(uniffi::Record)]
pub struct OutgoingGrantUpdate {
    /// The contact's Identity Key. Roost picks the Session and the contact's Discovery Key.
    pub recipient: IdentityKey,
    /// A MessageID from [`Messaging::create_message`], kept across retries.
    pub message_id: MessageId,
    /// When the app sent the Grant Update, in Unix milliseconds.
    pub sent_at_millis: u64,
    /// The local identity's certificate, sealed into the Message.
    pub sender_certificate: SignedSenderCertificate,
    /// The contact's bundle, fetched after a [`MessageEncryptionStep::NeedsPreKeyBundle`] step and
    /// kept until a send uses it. Roost ignores it when no check or new Session needs it.
    pub prekey_bundle: Option<PreKeyBundle>,
}

/// What the app received, with what Roost needs to check and acknowledge it.
#[derive(uniffi::Record)]
pub struct IncomingMessage {
    /// The received Message.
    pub message: Message,
    /// The exact Transport Binding the Message arrived with.
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
/// Read the value the app should use from one place, such as its own settings or its Relay.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Record)]
pub struct ReceiveSettings {
    /// How many received-Message digests the Deduplication Set keeps, within
    /// [`ProtocolHardeningLimits`](crate::ProtocolHardeningLimits)'s range. Roost resizes the set
    /// when this changes, dropping the oldest digests first.
    pub deduplication_capacity: u32,
    /// Whether a blocked contact's Messages get an acknowledgment.
    pub blocked_contact_acknowledgment_policy: BlockedContactAcknowledgmentPolicy,
    /// How long after expiry a sender certificate still validates, in milliseconds, at most
    /// 300,000.
    ///
    /// A grace covers clock differences between devices, at the cost of accepting a certificate
    /// the relay has stopped vouching for.
    pub certificate_grace_millis: u64,
}

/// Blocked-contact acknowledgment policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum BlockedContactAcknowledgmentPolicy {
    /// Suppress acknowledgments so blocks look like unreachable recipients.
    Unreachable,
    /// Return the acknowledgments an unblocked sender would get, while hiding plaintext.
    SilentReceipt,
}

/// Where Roost sends a Message, and how the Relay admits it, so the app can supply a Transport
/// Binding that reaches it.
#[derive(uniffi::Enum)]
pub enum MessageDestination {
    /// A first Message, which the Relay admits against the recipient's current prekeys.
    FirstMessage {
        /// The recipient's Identity Key.
        identity_key: IdentityKey,
        /// The X25519 public key of the recipient Discovery Key the Message is sealed to. Always
        /// 32 bytes.
        discovery_key: Vec<u8>,
        /// The recipient signed prekey the handshake used.
        signed_prekey_id: u64,
        /// The recipient one-time prekey the handshake used, absent when none was left.
        one_time_prekey_id: Option<u64>,
    },
    /// An established Message, which the Relay admits with the recipient's Delivery Capability.
    Established {
        /// The recipient's Identity Key.
        identity_key: IdentityKey,
        /// The X25519 public key of the recipient Discovery Key the Message is sealed to. Always
        /// 32 bytes.
        discovery_key: Vec<u8>,
        /// The recipient's 32-byte Delivery Capability. It is a secret: pass it only to the Relay
        /// in this Message's submission, and don't store or log it.
        delivery_capability: Vec<u8>,
    },
}

/// The signed prekey a first Message names, kept after a rotation, which the app must prove the
/// Relay admitted the Message against.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Record)]
pub struct AdmissionRequest {
    /// The local Discovery Key epoch the signed prekey belongs to.
    pub discovery_epoch: u32,
    /// The signed prekey's ID, which the Relay's admission proof must name.
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
    /// Supply the Transport Binding that reaches `destination` through
    /// [`MessageEncryption::supply_transport_binding`].
    NeedsTransport {
        /// Where the Message goes.
        destination: MessageDestination,
    },
    /// A new Session, or the first send after an unblock, needs the contact's prekey bundle, and
    /// the draft has none or one older than the contact's Discovery Key. A send to an accepted
    /// contact, or an acceptance of a request, whose Session records are missing starts a new
    /// Session too. The operation has ended: release the Identity Lock, fetch the bundle, save it
    /// with the draft, and start again with the same draft.
    NeedsPreKeyBundle {
        /// The contact whose bundle to fetch.
        identity_key: IdentityKey,
    },
    /// The contact already acknowledged a Message carrying the current Inbox Grant, so a Grant
    /// Update has nothing to carry. The operation has ended and there is nothing to commit.
    NothingToSend,
    /// The sealed Message, and the state changes to commit with it. The operation has ended.
    Ready {
        /// The sealed Message.
        result: OutboundMessageResult,
        /// The state changes to commit with the Message.
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
    /// The first Message names a signed prekey kept after a rotation. Check the Relay's
    /// admission proof for this Message: its signature, the frame's digest, the first-message
    /// route, and `admission.signed_prekey_id`. Then call
    /// [`MessageDecryption::confirm_admission`], or drop the operation and the Message.
    NeedsAdmission {
        /// The signed prekey the proof must name.
        admission: AdmissionRequest,
    },
    /// Supply the Transport Binding that reaches `destination` through
    /// [`MessageDecryption::supply_acknowledgment_transport_binding`].
    NeedsAcknowledgmentTransport {
        /// Where the acknowledgment goes: the sender, after it authenticated.
        destination: MessageDestination,
    },
    /// What the Message turned out to be, and the state changes to commit with its effects. The
    /// operation has ended.
    Ready {
        /// What the Message turned out to be.
        outcome: InboundMessageOutcome,
        /// The state changes to commit with the outcome's effects, empty when it has none.
        changes: StateChanges,
    },
}

/// An outbound Message from one Message Operation.
#[derive(uniffi::Record)]
pub struct OutboundMessageResult {
    /// The Session Roost selected for the Message.
    pub session_id: SessionId,
    /// The draft's MessageID, sealed inside the Message.
    pub message_id: MessageId,
    /// Sender-observed Unix timestamp in milliseconds.
    pub sent_at_millis: u64,
    /// Payload kind sealed in the Message.
    pub payload_kind: PayloadKind,
    /// Message to send after durable commit.
    pub message: Message,
}

/// A provisional receive result. Commit it atomically with the changes that come beside it before
/// use.
///
/// Switch on the outcome to obtain only the fields that case permits. The host transaction must
/// check the changes with [`StateChanges::matches`] and persist the outcome's effects before
/// plaintext is displayed or an acknowledgment is sent.
#[derive(uniffi::Enum)]
pub enum InboundMessageOutcome {
    /// Authenticated plaintext, and an acknowledgment when this side acknowledges, for a unique
    /// Message.
    Accepted {
        /// Payload for this outcome.
        result: InboundMessageResult,
    },
    /// A Contact Request: the first Message from an identity with no contact record, which the
    /// changes record as a Pending contact. Nothing is acknowledged until this side replies.
    ContactRequest {
        /// Payload for this outcome.
        result: InboundMessageResult,
    },
    /// A blocked Message with state changes and the acknowledgment its receive allows.
    Blocked {
        /// Payload for this outcome.
        result: BlockedInboundMessageResult,
    },
    /// A Message past the limit before acceptance, whose plaintext Roost withholds.
    Withheld {
        /// Payload for this outcome.
        result: WithheldInboundMessageResult,
    },
    /// A Grant Update: Roost kept the contact's new Inbox Grant, and there is nothing to show.
    GrantUpdate {
        /// Payload for this outcome.
        result: GrantUpdateResult,
    },
    /// An already accepted encrypted Message. No effects are produced, and its changes are empty.
    Duplicate,
    /// The Message names a Session this identity doesn't keep and carries no handshake, such as
    /// one whose records it lost. No effects are produced, and its changes are empty.
    UnknownSession,
    /// The first Message names a Session this identity deleted, so nothing was created. No
    /// effects are produced, and its changes are empty.
    DeletedSession,
    /// An acknowledgment cleared one of this identity's Pending Acknowledgments. Commit it before
    /// treating the acknowledged Message as delivered. Roost sends no reply to an acknowledgment.
    AcknowledgmentMatched {
        /// Payload for this outcome.
        result: AcknowledgmentResult,
    },
    /// An authenticated acknowledgment named no Pending Acknowledgment, such as one already
    /// cleared. Commit it anyway, so the advanced state recognizes a retry as a duplicate. If it
    /// names a Message Roost reported as not delivered, a later copy arrived, so correct that
    /// status.
    AcknowledgmentUnmatched {
        /// Payload for this outcome.
        result: AcknowledgmentResult,
    },
}

/// Authenticated Message data that remains provisional until the host transaction commits.
///
/// The host commits the Message, acknowledgment, and state changes in one transaction. When the
/// changes carry an operation, the host finalizes it before showing the plaintext. Plaintext is
/// host-owned secret bytes; clear discarded copies promptly.
///
/// A sender's recovery resends a Message under its original MessageID with new bytes, so show one
/// Message per sender and MessageID, and check before notifying, including in a notification
/// extension. When one is already shown, still commit the changes and send the acknowledgment.
#[derive(uniffi::Record)]
pub struct InboundMessageResult {
    /// The Session the Message arrived on.
    pub session_id: SessionId,
    /// Authenticated MessageID.
    pub message_id: MessageId,
    /// Authenticated sender timestamp in milliseconds.
    pub sent_at_millis: u64,
    /// Authenticated payload kind.
    pub payload_kind: PayloadKind,
    /// Plaintext for the host to protect and clear after use.
    pub plaintext: Vec<u8>,
    /// Authenticated sender material.
    pub sender_identity: SenderIdentityMaterial,
    /// Encrypted acknowledgment to commit with the Transport Binding the host supplied for it,
    /// absent while the contact isn't accepted and this side doesn't acknowledge yet, or while no
    /// Inbox Grant has supplied the contact's current Delivery Capability.
    pub acknowledgment: Option<Message>,
}

/// A Message from a contact who hasn't accepted, past the limit on Messages before acceptance.
///
/// Roost withholds its plaintext and sends no acknowledgment. Commit the changes so the Session
/// keeps up.
#[derive(uniffi::Record)]
pub struct WithheldInboundMessageResult {
    /// The Session the Message arrived on.
    pub session_id: SessionId,
    /// Authenticated MessageID.
    pub message_id: MessageId,
}

/// A Grant Update whose Inbox Grant Roost kept, so later Messages reach the contact's current
/// inbox.
///
/// Commit the changes, and the acknowledgment when present, but show nothing.
#[derive(uniffi::Record)]
pub struct GrantUpdateResult {
    /// The Session the Grant Update arrived on.
    pub session_id: SessionId,
    /// Authenticated MessageID.
    pub message_id: MessageId,
    /// Encrypted acknowledgment to commit with the Transport Binding the host supplied for it,
    /// absent while this side doesn't acknowledge the contact yet.
    pub acknowledgment: Option<Message>,
}

/// A blocked receive with no plaintext available to the caller.
///
/// The acknowledgment is present only under the silent-receipt policy. Commit it with the changes
/// before sending; under the default policy the host persists only the processed state.
#[derive(uniffi::Record)]
pub struct BlockedInboundMessageResult {
    /// Acknowledgment when the receive's policy permits one.
    pub acknowledgment: Option<Message>,
}

/// An authenticated acknowledgment.
///
/// Commit its changes before clearing the host's own delivery state.
#[derive(uniffi::Record)]
pub struct AcknowledgmentResult {
    /// The Session the acknowledgment arrived on.
    pub session_id: SessionId,
    /// The acknowledgment's own MessageID.
    pub message_id: MessageId,
    /// Authenticated sender timestamp in milliseconds.
    pub sent_at_millis: u64,
    /// The outbound MessageID the acknowledgment names.
    pub acknowledged_message_id: MessageId,
    /// Authenticated sender material.
    pub sender_identity: SenderIdentityMaterial,
}

/// One attempt to encrypt a Message to a contact.
///
/// Call [`Self::step`] until it returns [`MessageEncryptionStep::Ready`],
/// [`MessageEncryptionStep::NeedsPreKeyBundle`], or [`MessageEncryptionStep::NothingToSend`],
/// supplying what each other step asks for. For [`MessageEncryptionStep::NeedsState`], return
/// exactly one entry per key, in any order, with no bytes for a record the host doesn't have. The
/// operation does its cryptography in [`Self::step`], so asking again before supplying returns the
/// same request without repeating it.
///
/// The destination says how the Relay admits the Message: a first Message by the recipient's
/// prekey IDs, or an established one by the recipient's Delivery Capability.
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
///             // Fetch outside the Identity Lock, keep the bundle with the draft, and restart.
///             draft.prekeyBundle = try await relay.prekeyBundle(for: identityKey)
///             try drafts.save(draft)
///             break steps
///         case .nothingToSend:
///             return // Only a Grant Update ends here.
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
///                 // Fetch outside the Identity Lock, keep the bundle with the draft, and restart.
///                 draft = draft.copy(prekeyBundle = relay.prekeyBundle(step.identityKey))
///                 drafts.save(draft)
///                 break@steps
///             }
///             is MessageEncryptionStep.NothingToSend -> return // Only a Grant Update ends here.
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

/// One attempt to decrypt a received Message.
///
/// Drive it as [`MessageEncryption`] describes. A first Message on a signed prekey kept after a
/// rotation asks for proof that the Relay admitted it before Roost uses that prekey. A Message
/// that needs an acknowledgment asks for the acknowledgment's Transport Binding only after its
/// sender authenticates and Roost decides to reply, because the route the Message arrived on may
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
    /// Returns a new random MessageID for a draft.
    ///
    /// Save it with the draft before the first send attempt, and pass the same MessageID to every
    /// retry, so the recipient sees one Message however many attempts it takes.
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

    /// Starts encrypting a Message to a contact.
    ///
    /// The operation reads the local identity's keys now and touches SecureStorage no more. A
    /// contact that hasn't accepted gets a few Messages before refusing more, and an accepted
    /// contact gets this identity's Inbox Grant attached until it acknowledges one.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if a key, MessageID, certificate, or the plaintext is
    ///   malformed or too long.
    /// - [`RoostError::NotFound`] if no identity or Discovery Key is stored.
    /// - [`RoostError::Corrupt`] if the stored Discovery Key fails its binding checks.
    /// - [`RoostError::OperationRecoveryRequired`] if a reserved operation needs recovery.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn start_encryption(
        &self,
        message: OutgoingMessage,
    ) -> Result<Arc<MessageEncryption>, RoostError> {
        let operation = self.inner.start_encryption(message.into_core()?)?;
        Ok(Arc::new(MessageEncryption(Mutex::new(Some(operation)))))
    }

    /// Starts decrypting a received Message, including a first Message that starts a Session.
    ///
    /// The operation reads the local identity's keys now. It reads SecureStorage again only for
    /// the prekeys a first Message names. When the first Message uses a one-time prekey, the
    /// result's changes carry the operation that uses it up.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if the Message, Transport Binding, settings, or validation
    ///   inputs are malformed or outside Roost's limits.
    /// - [`RoostError::NotFound`] if no identity or Discovery Key is stored.
    /// - [`RoostError::Corrupt`] if the stored Discovery Key fails its binding checks.
    /// - [`RoostError::OperationRecoveryRequired`] if a reserved operation needs recovery.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn start_decryption(
        &self,
        message: IncomingMessage,
    ) -> Result<Arc<MessageDecryption>, RoostError> {
        let operation = self.inner.start_decryption(roost_core::IncomingMessage {
            message: message.message.into_core()?,
            transport_binding: message.transport_binding.into_core()?,
            settings: message.settings.to_core()?,
            sender_certificate_validation: message.sender_certificate_validation.to_core()?,
            acknowledgment_sent_at_millis: message.acknowledgment_sent_at_millis,
            acknowledgment_sender_certificate: message
                .acknowledgment_sender_certificate
                .into_core(),
        })?;
        Ok(Arc::new(MessageDecryption(Mutex::new(Some(operation)))))
    }
}

#[uniffi::export]
impl Contacts {
    /// Starts encrypting a Contact Request, whose commit creates the contact's Pending record.
    ///
    /// A new contact needs a Session, so without a usable bundle in the draft the operation ends
    /// with [`MessageEncryptionStep::NeedsPreKeyBundle`]. Each restart reads fresh state: when the
    /// contact asked meanwhile, the request becomes a Contact Acceptance, and when the contact
    /// already accepted, an ordinary Message. The draft keeps one MessageID across restarts. A
    /// request counts toward the limit on Messages before acceptance, and once a restore drops the
    /// contact's Sessions, the count starts over with the next request.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if a key, MessageID, certificate, or bundle is malformed, or
    ///   the plaintext is too long.
    /// - [`RoostError::NotFound`] if no identity or Discovery Key is stored.
    /// - [`RoostError::Corrupt`] if the stored Discovery Key fails its binding checks.
    /// - [`RoostError::OperationRecoveryRequired`] if a reserved operation needs recovery.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn request_contact(
        &self,
        message: OutgoingMessage,
    ) -> Result<Arc<MessageEncryption>, RoostError> {
        let operation = self.inner.request_contact(message.into_core()?)?;
        Ok(Arc::new(MessageEncryption(Mutex::new(Some(operation)))))
    }

    /// Starts encrypting a Grant Update, which carries only this identity's current Inbox Grant.
    ///
    /// After an inbox rotation, send one to each contact that should stay able to reach this
    /// identity, after registering the new inbox with the Relay. Roost decides who may hold the
    /// grant, so the app can send one to every contact without checking: when stepping, a blocked
    /// contact fails with [`RoostError::BlockedContact`], a requester this side hasn't accepted
    /// fails with [`RoostError::ContactNotAccepted`], and a contact that already acknowledged the
    /// current grant ends with [`MessageEncryptionStep::NothingToSend`]. A requester's Grant
    /// Updates don't count toward the limit on Messages before acceptance. The recipient shows
    /// nothing.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if a key, MessageID, certificate, or bundle is malformed.
    /// - [`RoostError::NotFound`] if no identity or Discovery Key is stored.
    /// - [`RoostError::Corrupt`] if the stored Discovery Key fails its binding checks.
    /// - [`RoostError::OperationRecoveryRequired`] if a reserved operation needs recovery.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn start_grant_update(
        &self,
        update: OutgoingGrantUpdate,
    ) -> Result<Arc<MessageEncryption>, RoostError> {
        let operation = self.inner.start_grant_update(update.into_core()?)?;
        Ok(Arc::new(MessageEncryption(Mutex::new(Some(operation)))))
    }

    /// Starts encrypting a Contact Acceptance, which carries this identity's Inbox Grant and
    /// whose commit accepts the contact.
    ///
    /// Only the side a contact asked accepts. When the contact is already accepted, the
    /// acceptance becomes an ordinary Message. When the request's Session is gone, such as after a
    /// backup restore, the acceptance starts a new Session from the contact's bundle, and its
    /// first Message is a Contact Request that accepts both sides when it arrives. Roost then
    /// refuses only a contact that never wrote, so accept only a request the contact sent.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if a key, MessageID, or certificate is malformed, the
    ///   plaintext is too long, or when stepping, if no Contact Request from the contact is open.
    /// - [`RoostError::NotFound`] if no identity or Discovery Key is stored.
    /// - [`RoostError::Corrupt`] if the stored Discovery Key fails its binding checks.
    /// - [`RoostError::OperationRecoveryRequired`] if a reserved operation needs recovery.
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
    ///   sent the most Messages allowed before acceptance, no Session exists to send on, or a
    ///   Grant Update would give a requester this side hasn't accepted its Inbox Grant.
    /// - [`RoostError::NoDeliveryCapability`] if an established Message needs the contact's
    ///   Delivery Capability and no Inbox Grant has supplied one.
    /// - [`RoostError::TooManyPendingAcknowledgments`] if the most Messages allowed already wait
    ///   for the contact's acknowledgment on the Session.
    /// - [`RoostError::AuthenticationFailed`] if a bundle's signatures don't bind its Discovery Key
    ///   and the contact's identity in both directions.
    /// - [`RoostError::ProtocolStateFault`] if a record is missing or malformed.
    /// - [`RoostError::UnsupportedVersion`] if a record uses an unknown format version.
    /// - [`RoostError::InvalidData`] if the Message is too large to seal.
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

    /// Supplies the Transport Binding the pending [`MessageEncryptionStep::NeedsTransport`] asked
    /// for.
    ///
    /// Retain the exact binding with the Message for sending and retransmission.
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
    /// - [`RoostError::AuthenticationFailed`] if the Message fails to decrypt, its sender fails to
    ///   authenticate, or an Inbox Grant it carries fails its signatures.
    /// - [`RoostError::CertificateRejected`] if the sender's certificate fails validation.
    /// - [`RoostError::OneTimePreKeyUsed`] if a different first Message already used the one-time
    ///   prekey this one names. A repeat of the same Message is a duplicate instead.
    /// - [`RoostError::ProtocolStateFault`] if a record is missing or malformed, including the
    ///   sender's contact record.
    /// - [`RoostError::UnsupportedVersion`] if the Message or a record uses an unknown version.
    /// - [`RoostError::InvalidData`] if the Message is malformed.
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

    /// Confirms the pending [`MessageDecryptionStep::NeedsAdmission`]: the Relay's proof shows it
    /// admitted this exact Message as a first Message against the named signed prekey.
    ///
    /// # Errors
    /// - [`RoostError::OperationFinished`] if the operation already returned its result or failed.
    /// - [`RoostError::InvalidData`] if the operation isn't waiting for admission.
    pub fn confirm_admission(&self) -> Result<(), RoostError> {
        with_operation(&self.0, |decryption| Ok(decryption.confirm_admission()?))
    }

    /// Supplies the Transport Binding the pending
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
// covers input that fails before Core sees it. A call that panicked while holding the lock ends
// the operation too.
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
    pub(crate) fn into_core(self) -> roost_core::SignedSenderCertificate {
        roost_core::SignedSenderCertificate {
            certificate: self.certificate,
            signature: self.signature,
        }
    }
}

impl OutgoingMessage {
    fn into_core(self) -> Result<roost_core::OutgoingMessage, RoostError> {
        let plaintext = Zeroizing::new(self.plaintext);
        Ok(roost_core::OutgoingMessage {
            recipient: self.recipient.to_core()?,
            message_id: self.message_id.to_core()?,
            sent_at_millis: self.sent_at_millis,
            sender_certificate: self.sender_certificate.into_core(),
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
            sender_certificate: self.sender_certificate.into_core(),
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
    fn to_core(self) -> Result<roost_core::ReceiveSettings, RoostError> {
        let deduplication_capacity =
            usize::try_from(self.deduplication_capacity).map_err(|_| RoostError::InvalidData {
                reason: "deduplication capacity exceeds platform range".into(),
            })?;
        Ok(roost_core::ReceiveSettings::new(
            deduplication_capacity,
            self.blocked_contact_acknowledgment_policy.to_core(),
            Duration::from_millis(self.certificate_grace_millis),
        )?)
    }
}

impl BlockedContactAcknowledgmentPolicy {
    fn to_core(self) -> roost_core::BlockedContactAcknowledgmentPolicy {
        match self {
            Self::Unreachable => roost_core::BlockedContactAcknowledgmentPolicy::Unreachable,
            Self::SilentReceipt => roost_core::BlockedContactAcknowledgmentPolicy::SilentReceipt,
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
