use crate::context::Messaging;
use crate::error::RoostError;
use crate::message::{Message, MessageId};
use crate::message_operation::{MessageDestination, SignedSenderCertificate, lock, state_keys};
use crate::protocol::{
    IdentityKey, OutboundMessageResult, StateChanges, StateEntry, StateKey, entries_to_core,
};
use crate::records::PreKeyBundle;
use crate::time::time_from_millis;
use crate::transport_binding::TransportBinding;
use rand::rngs::OsRng;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

/// A Message to send again, unchanged, because the contact sent a newer Inbox Grant.
#[derive(uniffi::Record)]
pub struct RetryInstruction {
    /// The Message's ID.
    pub message_id: MessageId,
    /// The Message as first sent, which the contact can still open.
    pub message: Message,
    /// The contact's current inbox.
    pub destination: MessageDestination,
}

/// What a delivery check found, and the state changes to commit with the app's work for it.
#[derive(uniffi::Record)]
pub struct DeliveryCheckResult {
    /// Messages to send again, unchanged, to the contact's newer inbox. Send each with the
    /// Transport Binding it was first sent with.
    pub retries: Vec<RetryInstruction>,
    /// Whether a recovery starts. Create a recovery job for the contact in the same transaction
    /// as the changes, and run it with [`Messaging::start_recovery`].
    pub starts_recovery: bool,
    /// State changes to commit with the retries and the recovery job. They list the Messages the
    /// Relay would have dropped by now as undelivered.
    pub changes: StateChanges,
}

/// What a [`DeliveryCheck`] needs next, or its result.
#[derive(uniffi::Enum)]
pub enum DeliveryCheckStep {
    /// Supply one entry for each key through [`DeliveryCheck::supply_state`].
    NeedsState {
        /// The records to read.
        keys: Vec<StateKey>,
    },
    /// What the check found. The check has ended.
    Ready {
        /// The retries and the recovery signal, with their changes.
        result: DeliveryCheckResult,
    },
}

/// A check of the Messages this identity sent one contact that the contact hasn't acknowledged.
///
/// Drive it as [`MessageEncryption`](crate::MessageEncryption) describes. The check returns its
/// result once, and every call after that, or after any error, returns
/// [`RoostError::OperationFinished`]. Releasing a check commits nothing.
#[derive(uniffi::Object)]
pub struct DeliveryCheck(Mutex<Option<roost_core::DeliveryCheck>>);

/// What the app passes to resend a contact's unacknowledged Messages on a newer Session.
#[derive(uniffi::Record)]
pub struct OutgoingRecovery {
    /// The contact's Identity Key.
    pub recipient: IdentityKey,
    /// The local identity's certificate, sealed into the resent Message.
    pub sender_certificate: SignedSenderCertificate,
    /// The contact's bundle, fetched after a `NeedsPreKeyBundle` step and kept with the recovery
    /// job until a Session uses it.
    pub prekey_bundle: Option<PreKeyBundle>,
}

/// What a [`MessageRecovery`] needs next, or its result.
#[derive(uniffi::Enum)]
pub enum MessageRecoveryStep {
    /// Supply one entry for each key through [`MessageRecovery::supply_state`].
    NeedsState {
        /// The records to read.
        keys: Vec<StateKey>,
    },
    /// Supply the content the app sent under `message_id` through
    /// [`MessageRecovery::supply_content`].
    NeedsContent {
        /// The Message to encrypt again.
        message_id: MessageId,
    },
    /// Supply the Transport Binding that reaches `destination` through
    /// [`MessageRecovery::supply_transport_binding`].
    NeedsTransport {
        /// Where the Message goes.
        destination: MessageDestination,
    },
    /// A new Session needs the contact's prekey bundle. The recovery has ended: release the
    /// identity's lock, fetch the bundle by the contact's stored Discovery Key, keep it with the
    /// job, and start again. When the Relay answers that it doesn't know that key, the contact
    /// rotated: end the job, and a later check signals again once the contact's newer grant or
    /// Session arrives.
    NeedsPreKeyBundle {
        /// The contact whose bundle to fetch.
        identity_key: IdentityKey,
    },
    /// The first Message the recovery resent on a new Session isn't acknowledged yet, and the
    /// rest wait for it. The recovery has ended and there is nothing to commit: end the job. A
    /// delivery check after the contact acknowledges `message_id` starts the recovery again.
    AwaitingProbe {
        /// The Message whose acknowledgment the rest wait for.
        message_id: MessageId,
    },
    /// Nothing is left to resend. The recovery has ended and there is nothing to commit: end the
    /// job.
    Finished,
    /// One Message encrypted again. The recovery has ended: commit it, then start again.
    Ready {
        /// The Message under its original MessageID, send time, and kind, and the state changes
        /// to commit with it.
        result: OutboundMessageResult,
    },
}

/// One step of a recovery job, which encrypts one Message the contact hasn't acknowledged again
/// on a newer Session.
///
/// Roost keeps only the encrypted copy of a sent Message, so the app supplies its content, and
/// the copy keeps its MessageID, send time, and kind, so the contact shows it once. Roost picks
/// the Message and the Session: one the contact delivered on since, or else a new Session from
/// the contact's bundle, where the oldest Message goes first as a probe and the rest wait for a
/// delivery check after the contact acknowledges it. Each `Ready` result replaces the Message's
/// earlier copy, so commit it in one transaction with replacing the app's send work for that
/// MessageID, and never send the old copy again.
///
/// Track each recovery as its own job, apart from the Message's original send, whose record
/// already says it's done. Drive each step as [`MessageEncryption`](crate::MessageEncryption)
/// describes, and start a new one until a step ends the job.
///
/// ```swift
/// func run(_ job: RecoveryJob) async throws {
///     while true {
///         let recovery = try messaging.startRecovery(recovery: job.outgoing)
///         steps: while true {
///             switch try recovery.step() {
///             case .needsState(let keys):
///                 try recovery.supplyState(entries: try database.entries(for: keys))
///             case .needsContent(let messageId):
///                 try recovery.supplyContent(content: try database.content(of: messageId))
///             case .needsTransport(let destination):
///                 try recovery.supplyTransportBinding(transportBinding: router.binding(to: destination))
///             case .needsPreKeyBundle(let identityKey):
///                 // Fetch outside the identity's lock. An unknown Discovery Key ends the job.
///                 job.outgoing.prekeyBundle = try await relay.prekeyBundle(for: identityKey)
///                 try jobs.save(job)
///                 break steps
///             case .awaitingProbe, .finished:
///                 return try jobs.end(job)
///             case .ready(let result):
///                 try database.commitResend(result) // Replaces the send work for its MessageID.
///                 break steps
///             }
///         }
///     }
/// }
/// ```
///
/// ```kotlin
/// suspend fun run(job: RecoveryJob) {
///     while (true) {
///         val recovery = messaging.startRecovery(job.outgoing)
///         steps@ while (true) {
///             when (val step = recovery.step()) {
///                 is MessageRecoveryStep.NeedsState ->
///                     recovery.supplyState(database.entries(step.keys))
///                 is MessageRecoveryStep.NeedsContent ->
///                     recovery.supplyContent(database.content(step.messageId))
///                 is MessageRecoveryStep.NeedsTransport ->
///                     recovery.supplyTransportBinding(router.bindingTo(step.destination))
///                 is MessageRecoveryStep.NeedsPreKeyBundle -> {
///                     // Fetch outside the identity's lock. An unknown Discovery Key ends the job.
///                     job.outgoing = job.outgoing.copy(prekeyBundle = relay.prekeyBundle(step.identityKey))
///                     jobs.save(job)
///                     break@steps
///                 }
///                 is MessageRecoveryStep.AwaitingProbe, is MessageRecoveryStep.Finished ->
///                     return jobs.end(job)
///                 is MessageRecoveryStep.Ready -> {
///                     database.commitResend(step.result) // Replaces the send work for its MessageID.
///                     break@steps
///                 }
///             }
///         }
///     }
/// }
/// ```
#[derive(uniffi::Object)]
pub struct MessageRecovery(Mutex<Option<roost_core::MessageRecovery>>);

#[uniffi::export]
impl Messaging {
    /// Starts checking the Messages this identity sent a contact that the contact hasn't
    /// acknowledged, at `now_millis`.
    ///
    /// Run a check for each contact with unacknowledged Messages after committing anything
    /// received from them, and at least once a day. The app never resends a Message the Relay
    /// accepted on a timer, since the Relay redelivers it until the contact saves it. The check
    /// says instead when to send Messages again to the contact's newer inbox, when a recovery
    /// starts, and which Messages the Relay would have dropped by now. Roost sets the waits: a
    /// recovery starts after a day without an acknowledgment, or as soon as the contact delivers
    /// on a newer Session or acknowledges a recovery's probe, and once started, comes back only
    /// after a week or once the contact sends a newer Inbox Grant or starts a new Session.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if `contact` or `now_millis` is out of range.
    /// - [`RoostError::ProtocolStateFault`] if `contact` isn't canonical.
    pub fn start_delivery_check(
        &self,
        contact: IdentityKey,
        now_millis: u64,
    ) -> Result<Arc<DeliveryCheck>, RoostError> {
        let check = self.inner.protocol_engine().start_delivery_check(
            contact.to_core()?,
            time_from_millis(now_millis, "now_millis")?,
        )?;
        Ok(Arc::new(DeliveryCheck(Mutex::new(Some(check)))))
    }

    /// Starts one step of a recovery job, which a delivery check started for a contact.
    ///
    /// The operation reads the local identity's keys now and touches SecureStorage no more.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if a key, certificate, or bundle is malformed.
    /// - [`RoostError::NotFound`] if no identity or Discovery Key is stored.
    /// - [`RoostError::Corrupt`] if the stored Discovery Key fails its binding checks.
    /// - [`RoostError::OperationRecoveryRequired`] if a reserved operation needs recovery.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn start_recovery(
        &self,
        recovery: OutgoingRecovery,
    ) -> Result<Arc<MessageRecovery>, RoostError> {
        let recovery = self.inner.start_recovery(recovery.into_core()?)?;
        Ok(Arc::new(MessageRecovery(Mutex::new(Some(recovery)))))
    }
}

#[uniffi::export]
impl DeliveryCheck {
    /// Advances the check and returns what it needs next, or its result.
    ///
    /// # Errors
    /// - [`RoostError::OperationFinished`] if the check already returned its result or failed.
    /// - [`RoostError::ProtocolStateFault`] if a record is malformed.
    /// - [`RoostError::UnsupportedVersion`] if a record uses an unknown format version.
    pub fn step(&self) -> Result<DeliveryCheckStep, RoostError> {
        let mut check = lock(&self.0);
        let checking = check.as_mut().ok_or(RoostError::OperationFinished)?;
        // Core ends the check itself once it returns its result or fails.
        Ok(DeliveryCheckStep::from_core(checking.step()?))
    }

    /// Supplies one entry for each key the pending `NeedsState` step named.
    ///
    /// # Errors
    /// - [`RoostError::OperationFinished`] if the check already returned its result or failed.
    /// - [`RoostError::InvalidData`] if the entries miss, repeat, or add a key, a key is malformed,
    ///   or the check isn't waiting for state.
    pub fn supply_state(&self, entries: Vec<StateEntry>) -> Result<(), RoostError> {
        let mut check = lock(&self.0);
        let checking = check.as_mut().ok_or(RoostError::OperationFinished)?;
        let supplied =
            entries_to_core(entries).and_then(|entries| Ok(checking.supply_state(entries)?));
        if supplied.is_err() {
            *check = None;
        }
        supplied
    }
}

#[uniffi::export]
impl MessageRecovery {
    /// Advances the recovery and returns what it needs next, or its result.
    ///
    /// # Errors
    /// - [`RoostError::OperationFinished`] if the recovery already returned its result or failed.
    /// - [`RoostError::BlockedContact`] if the contact is blocked.
    /// - [`RoostError::NoDeliveryCapability`] if the Message goes to a Session the contact
    ///   delivered on, and no Inbox Grant has supplied the contact's Delivery Capability.
    /// - [`RoostError::AuthenticationFailed`] if a bundle's signatures don't bind its Discovery Key
    ///   and the contact's identity in both directions.
    /// - [`RoostError::ProtocolStateFault`] if a record is missing or malformed.
    /// - [`RoostError::UnsupportedVersion`] if a record uses an unknown format version.
    /// - [`RoostError::InvalidData`] if the content is too large to seal.
    pub fn step(&self) -> Result<MessageRecoveryStep, RoostError> {
        let mut recovery = lock(&self.0);
        let recovering = recovery.as_mut().ok_or(RoostError::OperationFinished)?;
        // Core ends the recovery itself once it returns its result or fails.
        Ok(MessageRecoveryStep::from_core(recovering.step(&mut OsRng)?))
    }

    /// Supplies one entry for each key the pending `NeedsState` step named.
    ///
    /// # Errors
    /// - [`RoostError::OperationFinished`] if the recovery already returned its result or failed.
    /// - [`RoostError::InvalidData`] if the entries miss, repeat, or add a key, a key is malformed,
    ///   or the recovery isn't waiting for state.
    pub fn supply_state(&self, entries: Vec<StateEntry>) -> Result<(), RoostError> {
        let mut recovery = lock(&self.0);
        let recovering = recovery.as_mut().ok_or(RoostError::OperationFinished)?;
        let supplied =
            entries_to_core(entries).and_then(|entries| Ok(recovering.supply_state(entries)?));
        if supplied.is_err() {
            *recovery = None;
        }
        supplied
    }

    /// Supplies the content the app sent under the MessageID the pending `NeedsContent` step
    /// named.
    ///
    /// # Errors
    /// - [`RoostError::OperationFinished`] if the recovery already returned its result or failed.
    /// - [`RoostError::InvalidData`] if the recovery isn't waiting for content.
    pub fn supply_content(&self, content: Vec<u8>) -> Result<(), RoostError> {
        let content = Zeroizing::new(content);
        let mut recovery = lock(&self.0);
        let recovering = recovery.as_mut().ok_or(RoostError::OperationFinished)?;
        let supplied = recovering.supply_content(content);
        if supplied.is_err() {
            *recovery = None;
        }
        Ok(supplied?)
    }

    /// Supplies the Transport Binding the pending `NeedsTransport` step asked for.
    ///
    /// Retain the exact binding with the Message for sending.
    ///
    /// # Errors
    /// - [`RoostError::OperationFinished`] if the recovery already returned its result or failed.
    /// - [`RoostError::InvalidData`] if the binding is empty or too long, or the recovery isn't
    ///   waiting for one.
    pub fn supply_transport_binding(
        &self,
        transport_binding: TransportBinding,
    ) -> Result<(), RoostError> {
        let mut recovery = lock(&self.0);
        let recovering = recovery.as_mut().ok_or(RoostError::OperationFinished)?;
        let supplied = transport_binding
            .into_core()
            .and_then(|binding| Ok(recovering.supply_transport_binding(binding)?));
        if supplied.is_err() {
            *recovery = None;
        }
        supplied
    }
}

impl OutgoingRecovery {
    fn into_core(self) -> Result<roost_core::OutgoingRecovery, RoostError> {
        Ok(roost_core::OutgoingRecovery {
            recipient: self.recipient.to_core()?,
            sender_certificate: self.sender_certificate.into_core(),
            prekey_bundle: self
                .prekey_bundle
                .as_ref()
                .map(PreKeyBundle::to_core)
                .transpose()?,
        })
    }
}

impl DeliveryCheckStep {
    fn from_core(step: roost_core::DeliveryCheckStep) -> Self {
        match step {
            roost_core::DeliveryCheckStep::NeedsState(addresses) => Self::NeedsState {
                keys: state_keys(&addresses),
            },
            roost_core::DeliveryCheckStep::Ready(result) => Self::Ready {
                result: DeliveryCheckResult::from_core(*result),
            },
        }
    }
}

impl DeliveryCheckResult {
    fn from_core(result: roost_core::DeliveryCheckResult) -> Self {
        Self {
            retries: result
                .retries
                .into_iter()
                .map(|retry| RetryInstruction {
                    message_id: MessageId::from_core(retry.message_id),
                    message: Message::from_core(retry.message),
                    destination: MessageDestination::from_core(retry.destination),
                })
                .collect(),
            starts_recovery: result.starts_recovery,
            changes: StateChanges::from_core(result.changes),
        }
    }
}

impl MessageRecoveryStep {
    fn from_core(step: roost_core::MessageRecoveryStep) -> Self {
        match step {
            roost_core::MessageRecoveryStep::NeedsState(addresses) => Self::NeedsState {
                keys: state_keys(&addresses),
            },
            roost_core::MessageRecoveryStep::NeedsContent(message_id) => Self::NeedsContent {
                message_id: MessageId::from_core(message_id),
            },
            roost_core::MessageRecoveryStep::NeedsTransport(destination) => Self::NeedsTransport {
                destination: MessageDestination::from_core(destination),
            },
            roost_core::MessageRecoveryStep::NeedsPreKeyBundle(identity_key) => {
                Self::NeedsPreKeyBundle {
                    identity_key: IdentityKey::from_core(identity_key),
                }
            }
            roost_core::MessageRecoveryStep::AwaitingProbe(message_id) => Self::AwaitingProbe {
                message_id: MessageId::from_core(message_id),
            },
            roost_core::MessageRecoveryStep::Finished => Self::Finished,
            roost_core::MessageRecoveryStep::Ready(result) => Self::Ready {
                result: OutboundMessageResult::from_core(*result),
            },
        }
    }
}
