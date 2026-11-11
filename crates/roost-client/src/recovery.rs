use crate::context::Messaging;
use crate::error::RoostError;
use crate::identity::IdentityKey;
use crate::message::MessageId;
use crate::message_operation::{
    MessageDestination, OutboundMessageResult, SignedSenderCertificate, with_operation,
};
use crate::publication::PreKeyBundle;
use crate::state::{StateChanges, StateEntry, StateKey, entries_to_core, state_keys};
use crate::time::time_from_millis;
use crate::transport_binding::TransportBinding;
use rand::rngs::OsRng;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

/// What a delivery check found.
#[derive(uniffi::Record)]
pub struct DeliveryCheckResult {
    /// Whether a recovery starts. Create a recovery job for the contact in the same transaction
    /// as the check's changes, and run it with [`Messaging::start_recovery`].
    pub starts_recovery: bool,
}

/// What a [`DeliveryCheck`] needs next, or its result.
#[derive(uniffi::Enum)]
pub enum DeliveryCheckStep {
    /// Supply one entry for each key through [`DeliveryCheck::supply_state`].
    NeedsState {
        /// The records to read.
        keys: Vec<StateKey>,
    },
    /// What the check found, and the state changes to commit with the app's work for it. The
    /// check has ended.
    Ready {
        /// The recovery signal.
        result: DeliveryCheckResult,
        /// The state changes to commit with the recovery job. They list the messages whose first
        /// copy the relay would have dropped by now as undelivered.
        changes: StateChanges,
    },
}

/// A check of the messages this identity sent one contact that the contact hasn't acknowledged.
///
/// Drive it as [`MessageEncryption`](crate::MessageEncryption) describes. The check returns its
/// result once, and every call after that, or after any error, returns
/// [`RoostError::OperationFinished`]. Releasing a check commits nothing.
#[derive(uniffi::Object)]
pub struct DeliveryCheck(Mutex<Option<roost_core::DeliveryCheck>>);

/// What the app passes to resend a contact's unacknowledged messages on a newer session.
#[derive(uniffi::Record)]
pub struct OutgoingRecovery {
    /// The contact's identity key.
    pub recipient: IdentityKey,
    /// The local identity's certificate, sealed into the resent message.
    pub sender_certificate: SignedSenderCertificate,
    /// The contact's bundle, fetched after a [`MessageRecoveryStep::NeedsPreKeyBundle`] step and
    /// kept with the recovery job until a session uses it or the job ends.
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
        /// The message to encrypt again.
        message_id: MessageId,
    },
    /// Supply the transport binding that reaches `destination` through
    /// [`MessageRecovery::supply_transport_binding`].
    NeedsTransport {
        /// Where the message goes.
        destination: MessageDestination,
    },
    /// A new session, or the first resend after an unblock, needs the contact's prekey bundle. The
    /// recovery has ended, so release the identity lock, fetch the bundle by the contact's stored
    /// discovery key, keep it with the job, and start again. When the relay answers that it doesn't
    /// know that key, the contact rotated, so end the job. A later check signals again once the
    /// contact's newer grant or session arrives.
    NeedsPreKeyBundle {
        /// The contact whose bundle to fetch.
        identity_key: IdentityKey,
    },
    /// Nothing is left to resend until a delivery check starts the recovery again, such as after
    /// the contact acknowledges the probe. The recovery has ended and there is nothing to commit,
    /// so end the job.
    Finished,
    /// One message encrypted again, and the state changes to commit with it. The recovery has
    /// ended, so commit them, then start again.
    Ready {
        /// The message under its original message ID and send time. Its kind can differ from the
        /// original's, such as content that now carries the inbox grant.
        result: OutboundMessageResult,
        /// The state changes to commit with the message.
        changes: StateChanges,
    },
}

/// One step of a recovery job, which encrypts one message the contact hasn't acknowledged again
/// on a newer session.
///
/// Roost keeps no copy of a sent message, so the app supplies its content, and the new copy keeps
/// its message ID and send time, so the contact shows it once. Roost picks the message and a
/// session newer than the one it was sent on, so the contact never misses a message on it: a
/// session the contact delivered on since, or else a new session from the contact's bundle, where
/// the oldest message goes first as a probe and the rest wait for a delivery check after the
/// contact acknowledges it or delivers on another session. Each [`MessageRecoveryStep::Ready`]
/// result replaces the message's earlier copy, so commit it in one transaction with replacing the
/// app's send work for that message ID, and never send the old copy again.
///
/// Track each recovery as its own job, apart from the message's original send, whose record
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
///                 // Fetch outside the identity lock. An unknown discovery key ends the job.
///                 job.outgoing.prekeyBundle = try await relay.prekeyBundle(for: identityKey)
///                 try jobs.save(job)
///                 break steps
///             case .finished:
///                 return try jobs.end(job)
///             case .ready(let result, let changes):
///                 // Replaces the send work for its message ID.
///                 try database.commitResend(result, changes: changes)
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
///                     // Fetch outside the identity lock. An unknown discovery key ends the job.
///                     job.outgoing = job.outgoing.copy(prekeyBundle = relay.prekeyBundle(step.identityKey))
///                     jobs.save(job)
///                     break@steps
///                 }
///                 is MessageRecoveryStep.Finished ->
///                     return jobs.end(job)
///                 is MessageRecoveryStep.Ready -> {
///                     // Replaces the send work for its message ID.
///                     database.commitResend(step.result, step.changes)
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
    /// Starts checking the messages this identity sent a contact that the contact hasn't
    /// acknowledged, at `now_millis`.
    ///
    /// Run a check for each contact with unacknowledged messages after committing anything received
    /// from them, and at least once a day. The app never resends a message the relay accepted,
    /// since the relay redelivers it until the contact saves it. The check says instead when a
    /// recovery starts, which encrypts the messages again on a newer session, and which messages'
    /// first copies the relay would have dropped by now. A later copy of one can still arrive.
    /// Roost sets the waits, and grant updates never start a recovery. A recovery starts once
    /// another message waits a day without an acknowledgment, or as soon as the contact sends an
    /// inbox grant newer than the one a waiting message went to, delivers on a newer session, or
    /// acknowledges a recovery's probe. Once started, it comes back only after a week, after an
    /// unblock, or once the contact sends a newer inbox grant or starts a new session.
    ///
    /// Pass `now_millis` from the clock [`IdentityContext`](crate::IdentityContext) describes,
    /// the one that sets each message's send time.
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
    /// - [`RoostError::NotFound`] if no identity or discovery key is stored.
    /// - [`RoostError::Corrupt`] if the stored discovery key fails its binding checks, or the
    ///   operation journal is corrupt.
    /// - [`RoostError::UnfinishedReservation`] if a reserved operation is unfinished.
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
        with_operation(&self.0, |check| {
            Ok(DeliveryCheckStep::from_core(check.step()?))
        })
    }

    /// Supplies one entry for each key the pending [`DeliveryCheckStep::NeedsState`] named.
    ///
    /// # Errors
    /// - [`RoostError::OperationFinished`] if the check already returned its result or failed.
    /// - [`RoostError::InvalidData`] if the entries miss, repeat, or add a key, a key is malformed,
    ///   or the check isn't waiting for state.
    pub fn supply_state(&self, entries: Vec<StateEntry>) -> Result<(), RoostError> {
        let entries = entries_to_core(entries);
        with_operation(&self.0, |check| Ok(check.supply_state(entries?)?))
    }
}

#[uniffi::export]
impl MessageRecovery {
    /// Advances the recovery and returns what it needs next, or its result.
    ///
    /// # Errors
    /// - [`RoostError::OperationFinished`] if the recovery already returned its result or failed.
    /// - [`RoostError::BlockedContact`] if the contact is blocked.
    /// - [`RoostError::NoDeliveryCapability`] if the message goes to a session the contact
    ///   delivered on, and no inbox grant has supplied the contact's delivery capability.
    /// - [`RoostError::TooManyPendingAcknowledgments`] if the most messages allowed already wait
    ///   for the contact's acknowledgment on that session.
    /// - [`RoostError::AuthenticationFailed`] if a bundle's signatures don't bind its discovery key
    ///   and the contact's identity in both directions.
    /// - [`RoostError::ProtocolStateFault`] if a record is missing or malformed.
    /// - [`RoostError::UnsupportedVersion`] if a record uses an unknown format version.
    /// - [`RoostError::InvalidData`] if the content is too large to seal.
    pub fn step(&self) -> Result<MessageRecoveryStep, RoostError> {
        with_operation(&self.0, |recovery| {
            Ok(MessageRecoveryStep::from_core(recovery.step(&mut OsRng)?))
        })
    }

    /// Supplies one entry for each key the pending [`MessageRecoveryStep::NeedsState`] named.
    ///
    /// # Errors
    /// - [`RoostError::OperationFinished`] if the recovery already returned its result or failed.
    /// - [`RoostError::InvalidData`] if the entries miss, repeat, or add a key, a key is malformed,
    ///   or the recovery isn't waiting for state.
    pub fn supply_state(&self, entries: Vec<StateEntry>) -> Result<(), RoostError> {
        let entries = entries_to_core(entries);
        with_operation(&self.0, |recovery| Ok(recovery.supply_state(entries?)?))
    }

    /// Supplies the content the app sent under the message ID the pending
    /// [`MessageRecoveryStep::NeedsContent`] named.
    ///
    /// # Errors
    /// - [`RoostError::OperationFinished`] if the recovery already returned its result or failed.
    /// - [`RoostError::InvalidData`] if the recovery isn't waiting for content.
    pub fn supply_content(&self, content: Vec<u8>) -> Result<(), RoostError> {
        let content = Zeroizing::new(content);
        with_operation(&self.0, |recovery| Ok(recovery.supply_content(content)?))
    }

    /// Supplies the transport binding the pending [`MessageRecoveryStep::NeedsTransport`] asked
    /// for.
    ///
    /// Retain the exact binding with the message for sending.
    ///
    /// # Errors
    /// - [`RoostError::OperationFinished`] if the recovery already returned its result or failed.
    /// - [`RoostError::InvalidData`] if the binding is empty or too long, or the recovery isn't
    ///   waiting for one.
    pub fn supply_transport_binding(
        &self,
        transport_binding: TransportBinding,
    ) -> Result<(), RoostError> {
        with_operation(&self.0, |recovery| {
            Ok(recovery.supply_transport_binding(transport_binding.into_core()?)?)
        })
    }
}

impl OutgoingRecovery {
    fn into_core(self) -> Result<roost_core::OutgoingRecovery, RoostError> {
        Ok(roost_core::OutgoingRecovery {
            recipient: self.recipient.to_core()?,
            sender_certificate: self.sender_certificate.into_core()?,
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
            roost_core::DeliveryCheckStep::Ready { result, changes } => Self::Ready {
                result: DeliveryCheckResult::from_core(result),
                changes: StateChanges::from_core(changes),
            },
        }
    }
}

impl DeliveryCheckResult {
    fn from_core(result: roost_core::DeliveryCheckResult) -> Self {
        Self {
            starts_recovery: result.starts_recovery,
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
            roost_core::MessageRecoveryStep::Finished => Self::Finished,
            roost_core::MessageRecoveryStep::Ready { result, changes } => Self::Ready {
                result: OutboundMessageResult::from_core(*result),
                changes: StateChanges::from_core(changes),
            },
        }
    }
}
