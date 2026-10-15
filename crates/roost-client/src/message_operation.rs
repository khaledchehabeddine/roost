use crate::certificate::SenderCertificateValidation;
use crate::context::{Contacts, Messaging};
use crate::error::RoostError;
use crate::message::{Message, MessageId};
use crate::protocol::{
    IdentityKey, InboundMessageOutcome, OutboundMessageResult, ReceiveSettings, StateEntry,
    StateKey, entries_to_core,
};
use crate::records::PreKeyBundle;
use crate::transport_binding::TransportBinding;
use rand::RngCore;
use rand::rngs::OsRng;
use std::sync::{Arc, Mutex, MutexGuard};
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
    /// The plaintext to encrypt.
    pub plaintext: Vec<u8>,
    /// The contact's bundle, fetched after a `NeedsPreKeyBundle` step and saved with the draft
    /// until a Session uses it. Roost ignores it when no new Session is needed.
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
    /// The contact's bundle, fetched after a `NeedsPreKeyBundle` step and kept until a send uses
    /// it. Roost ignores it when no check or new Session needs it.
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
    /// the draft has none or one older than the contact's Discovery Key. The operation has ended:
    /// release the identity's lock, fetch the bundle, save it with the draft, and start again
    /// with the same draft.
    NeedsPreKeyBundle {
        /// The contact whose bundle to fetch.
        identity_key: IdentityKey,
    },
    /// The contact already acknowledged a Message carrying the current Inbox Grant, so a Grant
    /// Update has nothing to carry. The operation has ended and there is nothing to commit.
    NothingToSend,
    /// The sealed Message. The operation has ended.
    Ready {
        /// The Message and the state changes to commit with it.
        result: OutboundMessageResult,
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
    /// What the Message turned out to be. The operation has ended.
    Ready {
        /// The outcome and any state changes to commit.
        outcome: InboundMessageOutcome,
    },
}

/// One attempt to encrypt a Message to a contact.
///
/// Call [`Self::step`] until it returns `Ready`, `NeedsPreKeyBundle`, or `NothingToSend`,
/// supplying what each other step asks for. For `NeedsState`, return exactly one entry per key,
/// in any order, with no bytes for a record the host doesn't have. The operation does its
/// cryptography in [`Self::step`], so asking again before supplying returns the same request
/// without repeating it.
///
/// The destination says how the Relay admits the Message: a first Message by the recipient's
/// prekey IDs, or an established one by the recipient's Delivery Capability.
///
/// The operation returns its result once. After that, and after any error, every call returns
/// [`RoostError::OperationFinished`], so start a new operation from fresh reads. Releasing an
/// operation commits nothing. Calls from two threads take turns.
///
/// ```swift
/// var result: OutboundMessageResult?
/// while result == nil {
///     let encryption = try contacts.requestContact(message: draft)
///     steps: while true {
///         switch try encryption.step() {
///         case .needsState(let keys):
///             try encryption.supplyState(entries: try database.entries(for: keys))
///         case .needsTransport(let destination):
///             try encryption.supplyTransportBinding(transportBinding: router.binding(to: destination))
///         case .needsPreKeyBundle(let identityKey):
///             // Fetch outside the identity's lock, keep the bundle with the draft, and restart.
///             draft.prekeyBundle = try await relay.prekeyBundle(for: identityKey)
///             try drafts.save(draft)
///             break steps
///         case .nothingToSend:
///             return // Only a Grant Update ends here.
///         case .ready(let ready):
///             result = ready
///             break steps
///         }
///     }
/// }
/// try database.transaction { db in
///     let changes = result!.changes
///     guard try changes.matches(current: db.entries(for: changes.conditions.map(\.key))) else {
///         throw CommitError.conflict // Start again from fresh reads.
///     }
///     try db.write(changes.updates)
///     try db.queue(result!.message, messageId: result!.messageId)
/// }
/// ```
///
/// ```kotlin
/// var result: OutboundMessageResult? = null
/// while (result == null) {
///     val encryption = contacts.requestContact(draft)
///     steps@ while (true) {
///         when (val step = encryption.step()) {
///             is MessageEncryptionStep.NeedsState ->
///                 encryption.supplyState(database.entries(step.keys))
///             is MessageEncryptionStep.NeedsTransport ->
///                 encryption.supplyTransportBinding(router.bindingTo(step.destination))
///             is MessageEncryptionStep.NeedsPreKeyBundle -> {
///                 // Fetch outside the identity's lock, keep the bundle with the draft, and restart.
///                 draft = draft.copy(prekeyBundle = relay.prekeyBundle(step.identityKey))
///                 drafts.save(draft)
///                 break@steps
///             }
///             is MessageEncryptionStep.NothingToSend -> return // Only a Grant Update ends here.
///             is MessageEncryptionStep.Ready -> {
///                 result = step.result
///                 break@steps
///             }
///         }
///     }
/// }
/// database.transaction { db ->
///     val changes = result.changes
///     if (!changes.matches(db.entries(changes.conditions.map { it.key }))) {
///         throw CommitConflict() // Start again from fresh reads.
///     }
///     db.write(changes.updates)
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
/// When the result's changes carry an operation, such as one that uses up a one-time prekey,
/// commit them as [`StateChanges`](crate::StateChanges) describes, and show the plaintext or send
/// the acknowledgment only after finalizing it.
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
    ///
    /// # Errors
    /// - [`RoostError::InternalError`] if the system's randomness fails.
    pub fn create_message(&self) -> Result<MessageId, RoostError> {
        let mut bytes = [0u8; 16];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|error| RoostError::InternalError {
                reason: format!("message id randomness failed: {error}"),
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
    /// - [`RoostError::InvalidData`] if a key, MessageID, or certificate is malformed or too long.
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
            message: message.message.to_core()?,
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
    /// with `NeedsPreKeyBundle`. Each restart reads fresh state: when the contact asked meanwhile,
    /// the request becomes a Contact Acceptance, and when the contact already accepted, an ordinary
    /// Message. The draft keeps one MessageID across restarts, and a request counts toward the
    /// limit on Messages before acceptance.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if a key, MessageID, certificate, or bundle is malformed.
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
    /// current grant ends with `NothingToSend`. A requester's Grant Updates don't count toward the
    /// limit on Messages before acceptance. The recipient shows nothing.
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
    /// acceptance becomes an ordinary Message.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if a key, MessageID, or certificate is malformed, or when
    ///   stepping, if no Contact Request from the contact is open.
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
    ///   sent the most Messages allowed before acceptance, or a Grant Update would give a
    ///   requester this side hasn't accepted its Inbox Grant.
    /// - [`RoostError::NoDeliveryCapability`] if an established Message needs the contact's
    ///   Delivery Capability and no Inbox Grant has supplied one.
    /// - [`RoostError::TerminalSessionRecovery`] if no live Session exists with the contact, so a
    ///   fresh handshake must start one.
    /// - [`RoostError::AuthenticationFailed`] if a bundle's signatures don't bind its Discovery Key
    ///   and the contact's identity in both directions.
    /// - [`RoostError::ProtocolStateFault`] if a record is missing or malformed.
    /// - [`RoostError::UnsupportedVersion`] if a record uses an unknown format version.
    /// - [`RoostError::InvalidData`] if the Message is too large to seal.
    pub fn step(&self) -> Result<MessageEncryptionStep, RoostError> {
        let mut operation = lock(&self.0);
        let encryption = operation.as_mut().ok_or(RoostError::OperationFinished)?;
        // Core ends the operation itself once it returns its result or fails.
        Ok(MessageEncryptionStep::from_core(
            encryption.step(&mut OsRng)?,
        ))
    }

    /// Supplies one entry for each key the pending `NeedsState` step named.
    ///
    /// # Errors
    /// - [`RoostError::OperationFinished`] if the operation already returned its result or failed.
    /// - [`RoostError::InvalidData`] if the entries miss, repeat, or add a key, a key is malformed,
    ///   or the operation isn't waiting for state.
    pub fn supply_state(&self, entries: Vec<StateEntry>) -> Result<(), RoostError> {
        let mut operation = lock(&self.0);
        let encryption = operation.as_mut().ok_or(RoostError::OperationFinished)?;
        let supplied =
            entries_to_core(entries).and_then(|entries| Ok(encryption.supply_state(entries)?));
        if supplied.is_err() {
            *operation = None;
        }
        supplied
    }

    /// Supplies the Transport Binding the pending `NeedsTransport` step asked for.
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
        let mut operation = lock(&self.0);
        let encryption = operation.as_mut().ok_or(RoostError::OperationFinished)?;
        let supplied = transport_binding
            .into_core()
            .and_then(|binding| Ok(encryption.supply_transport_binding(binding)?));
        if supplied.is_err() {
            *operation = None;
        }
        supplied
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
    /// - [`RoostError::NoDeliveryCapability`] if the acknowledgment needs the sender's Delivery
    ///   Capability and no Inbox Grant has supplied one.
    /// - [`RoostError::ProtocolStateFault`] if a record is missing or malformed, including the
    ///   sender's contact record.
    /// - [`RoostError::UnsupportedVersion`] if the Message or a record uses an unknown version.
    /// - [`RoostError::InvalidData`] if the Message is malformed.
    pub fn step(&self) -> Result<MessageDecryptionStep, RoostError> {
        let mut operation = lock(&self.0);
        let decryption = operation.as_mut().ok_or(RoostError::OperationFinished)?;
        // Core ends the operation itself once it returns its result or fails.
        Ok(MessageDecryptionStep::from_core(
            decryption.step(&mut OsRng)?,
        ))
    }

    /// Supplies one entry for each key the pending `NeedsState` step named.
    ///
    /// # Errors
    /// - [`RoostError::OperationFinished`] if the operation already returned its result or failed.
    /// - [`RoostError::InvalidData`] if the entries miss, repeat, or add a key, a key is malformed,
    ///   or the operation isn't waiting for state.
    pub fn supply_state(&self, entries: Vec<StateEntry>) -> Result<(), RoostError> {
        let mut operation = lock(&self.0);
        let decryption = operation.as_mut().ok_or(RoostError::OperationFinished)?;
        let supplied =
            entries_to_core(entries).and_then(|entries| Ok(decryption.supply_state(entries)?));
        if supplied.is_err() {
            *operation = None;
        }
        supplied
    }

    /// Confirms the pending `NeedsAdmission` step: the Relay's proof shows it admitted this exact
    /// Message as a first Message against the named signed prekey.
    ///
    /// # Errors
    /// - [`RoostError::OperationFinished`] if the operation already returned its result or failed.
    /// - [`RoostError::InvalidData`] if the operation isn't waiting for admission.
    pub fn confirm_admission(&self) -> Result<(), RoostError> {
        let mut operation = lock(&self.0);
        let decryption = operation.as_mut().ok_or(RoostError::OperationFinished)?;
        let confirmed = decryption.confirm_admission();
        if confirmed.is_err() {
            *operation = None;
        }
        Ok(confirmed?)
    }

    /// Supplies the Transport Binding the pending `NeedsAcknowledgmentTransport` step asked for.
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
        let mut operation = lock(&self.0);
        let decryption = operation.as_mut().ok_or(RoostError::OperationFinished)?;
        let supplied = transport_binding
            .into_core()
            .and_then(|binding| Ok(decryption.supply_acknowledgment_transport_binding(binding)?));
        if supplied.is_err() {
            *operation = None;
        }
        supplied
    }
}

// A call that panicked while holding the lock ends the operation, as any error does.
fn lock<T>(operation: &Mutex<Option<T>>) -> MutexGuard<'_, Option<T>> {
    operation.lock().unwrap_or_else(|poisoned| {
        let mut operation = poisoned.into_inner();
        *operation = None;
        operation
    })
}

impl SignedSenderCertificate {
    fn into_core(self) -> roost_core::SignedSenderCertificate {
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
    fn from_core(destination: roost_core::MessageDestination) -> Self {
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

fn state_keys(addresses: &[roost_core::ProtocolStateAddress]) -> Vec<StateKey> {
    addresses.iter().map(StateKey::from_core).collect()
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
            roost_core::MessageEncryptionStep::Ready(result) => Self::Ready {
                result: OutboundMessageResult::from_core(*result),
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
            roost_core::MessageDecryptionStep::Ready(outcome) => Self::Ready {
                outcome: InboundMessageOutcome::from_core(*outcome),
            },
        }
    }
}
