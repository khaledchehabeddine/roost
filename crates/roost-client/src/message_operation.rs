use crate::certificate::SenderCertificateValidation;
use crate::context::Messaging;
use crate::error::RoostError;
use crate::message::{Message, MessageId};
use crate::protocol::{
    IdentityKey, InboundMessageOutcome, OutboundMessageResult, ReceiveSettings, StateEntry,
    StateKey, entries_to_core,
};
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

/// Where Roost sends a Message, so the app can supply a Transport Binding that reaches it.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct MessageDestination {
    /// The recipient's Identity Key.
    pub identity_key: IdentityKey,
    /// The X25519 public key of the recipient Discovery Key the Message is sealed to. Always 32
    /// bytes.
    pub discovery_key: Vec<u8>,
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
/// Call [`Self::step`] until it returns `Ready`, supplying what each other step asks for. For
/// `NeedsState`, return exactly one entry per key, in any order, with no bytes for a record the
/// host doesn't have. The operation does its cryptography in [`Self::step`], so asking again
/// before supplying returns the same request without repeating it.
///
/// The operation returns its result once. After that, and after any error, every call returns
/// [`RoostError::OperationFinished`], so start a new operation from fresh reads. Releasing an
/// operation commits nothing. Calls from two threads take turns.
///
/// ```swift
/// let encryption = try messaging.startEncryption(message: outgoing)
/// var result: OutboundMessageResult?
/// while result == nil {
///     switch try encryption.step() {
///     case .needsState(let keys):
///         try encryption.supplyState(entries: try database.entries(for: keys))
///     case .needsTransport(let destination):
///         try encryption.supplyTransportBinding(transportBinding: router.binding(to: destination))
///     case .ready(let ready):
///         result = ready
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
/// val encryption = messaging.startEncryption(outgoing)
/// var result: OutboundMessageResult? = null
/// while (result == null) {
///     when (val step = encryption.step()) {
///         is MessageEncryptionStep.NeedsState ->
///             encryption.supplyState(database.entries(step.keys))
///         is MessageEncryptionStep.NeedsTransport ->
///             encryption.supplyTransportBinding(router.bindingTo(step.destination))
///         is MessageEncryptionStep.Ready -> result = step.result
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
/// Drive it as [`MessageEncryption`] describes. A Message that needs an acknowledgment asks for
/// the acknowledgment's Transport Binding only after its sender authenticates and block policy
/// allows a reply, because the route the Message arrived on may not reach the sender. An
/// acknowledgment the app receives decrypts here too and never asks for one.
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
    /// The operation reads the local identity's keys now and touches SecureStorage no more.
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
        let plaintext = Zeroizing::new(message.plaintext);
        let operation = self.inner.start_encryption(roost_core::OutgoingMessage {
            recipient: message.recipient.to_core()?,
            message_id: message.message_id.to_core()?,
            sent_at_millis: message.sent_at_millis,
            sender_certificate: message.sender_certificate.into_core(),
            plaintext,
        })?;
        Ok(Arc::new(MessageEncryption(Mutex::new(Some(operation)))))
    }

    /// Starts decrypting a received Message.
    ///
    /// The operation reads the local identity's keys now and touches SecureStorage no more.
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
impl MessageEncryption {
    /// Advances the operation and returns what it needs next, or its result.
    ///
    /// # Errors
    /// - [`RoostError::OperationFinished`] if the operation already returned its result or failed.
    /// - [`RoostError::BlockedContact`] or [`RoostError::ContactNotAccepted`] if the contact can't
    ///   receive Messages.
    /// - [`RoostError::TerminalSessionRecovery`] if no live Session exists with the contact, so a
    ///   fresh handshake must start one.
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
    /// - [`RoostError::AuthenticationFailed`] if the Message fails to decrypt or its sender fails to
    ///   authenticate.
    /// - [`RoostError::CertificateRejected`] if the sender's certificate fails validation.
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

impl MessageDestination {
    fn from_core(destination: roost_core::MessageDestination) -> Self {
        Self {
            identity_key: IdentityKey::from_core(destination.identity_key),
            discovery_key: destination.discovery_key.to_vec(),
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
