//! The identity context and the messaging and contacts groups that share it.

use crate::SecureStorage;
use crate::certificate::{
    SenderCertificateValidation, domain_signing_keys_to_protocol, revocation_state_to_protocol,
    revoked_identity_keys_to_protocol,
};
use crate::error::RoostError;
use crate::message::{Message, SenderIdentityMaterial};
use crate::operation::{
    OperationId, OperationStatus, PreparedContactBlock, PreparedIdentity, PreparedInboxRotation,
    PreparedOneTimePreKeys, PreparedSessionAcceptance, PreparedSignedPreKeyRotation,
    UnfinishedOperation,
};
use crate::protocol::{
    AcknowledgmentOutcome, ContactStateChange, IdentityKey, InboundMessageOutcome,
    OutboundMessageResult, ProtocolStateEntry, ProtocolStateUpdate, protocol_key,
    snapshot_input_from_entries, updates_from_core,
};
use crate::records::{
    Identity, InboxRotation, PublicOneTimePreKey, PublicSignedPreKey, PublicationBundle, fixed_16,
    fixed_32,
};
use crate::storage::SecureStorageAdapter;
use crate::time::time_from_millis;
use crate::transport_binding::{PreKeySelection, TransportBinding};
use roost_core::{
    AcknowledgmentProcessing, InboundSenderCertificateValidation, KeyStore as CoreKeyStore,
    MessageDecryption, MessageEncryption,
    PreparedKeyStoreOperation as CorePreparedKeyStoreOperation,
    ProtocolStateEngine as CoreProtocolStateEngine, ProtocolStateKey, SessionAcceptance,
    SessionInitiation,
};
use roost_protocol::MessageId;
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

/// Largest authentication transcript the Identity Key will sign, in bytes.
///
/// A relay authentication transcript is 159 bytes for the HTTP form and 120 for the WebSocket
/// form, so this leaves room for long request targets while keeping the export from doubling as a
/// bulk document signer.
const MAX_AUTHENTICATION_TRANSCRIPT_LEN: usize = 4096;

/// ASCII prefixes reserved for preimages Roost signs or verifies itself.
///
/// Every signature context and domain tag Roost defines starts with one of these, so refusing
/// them keeps [`IdentityContext::sign_authentication_transcript`] disjoint from all of them.
/// Matched case-insensitively to cover the lowercase hash-domain convention as well.
const RESERVED_DOMAIN_PREFIXES: [&str; 2] = ["Aether", "Roost"];

/// One local identity namespace: its keys in SecureStorage and every operation that uses them.
///
/// Create one context for each namespace, before or after the identity exists. Its
/// [`Self::messaging`] and [`Self::contacts`] groups share its storage and configuration. The
/// context caches no protocol state, so several contexts, including ones in an app extension, can
/// serve the same identity.
///
/// Roost owns the identity's keys, backups, prekeys, and inbox rotations, the contents of
/// Protocol State Blobs, and the journal that makes key changes recoverable. It reads no clock
/// for certificate checks, does no networking, and keeps no copy of protocol state between calls.
///
/// The host owns the [`SecureStorage`] adapter, the database that stores Protocol State Blobs and
/// operation IDs, and its transactions. It stores the blobs without decoding them or keeping a
/// copy of its own, and calls Roost outside its database transactions, off the main thread. It
/// holds one lock that covers every process sharing the identity from preparing an operation until
/// its host commit is resolved.
///
/// # Key Changes
///
/// A method whose name starts with `prepare` stages a change in SecureStorage and returns its
/// output and an [`OperationId`]. Nothing is authoritative until the host:
///
/// 1. Calls [`Self::reserve_operation`].
/// 2. Commits the output with the operation ID in one transaction.
/// 3. Calls [`Self::finalize_operation`], then publishes the output.
///
/// When the commit definitely failed, call [`Self::abort_operation`] instead. When the outcome is
/// unknown, such as after a lost reply or a cancellation, neither finalize nor abort: recover
/// first. Releasing a context never aborts its operations.
///
/// At startup, and after any unknown outcome, resolve each of [`Self::unfinished_operations`]
/// against the host's records: finalize a reserved or finalizing operation whose ID the host
/// committed, abort a prepared or reserved one whose ID it didn't, and stop on anything else. A
/// host that records finalization itself also checks each committed operation it hasn't marked:
/// a crash between finalizing and marking leaves [`Self::operation_status`] reporting it
/// finalized. When SecureStorage has no identity but the host's records still hold one, stop
/// instead of creating a new identity.
///
/// ```swift
/// for operation in try context.unfinishedOperations() {
///     switch (operation.status, try database.hasCommitted(operation.id)) {
///     case (.reserved, true), (.finalizing, true):
///         try context.finalizeOperation(id: operation.id)
///     case (.prepared, false), (.reserved, false):
///         try context.abortOperation(id: operation.id)
///     default:
///         throw StartupError.inconsistentStorage
///     }
/// }
/// if try context.identity() == nil {
///     guard try database.isEmpty() else { throw StartupError.inconsistentStorage }
///     let prepared = try context.prepareIdentityCreation()
///     try context.reserveOperation(id: prepared.operationId)
///     switch try database.saveIdentity(prepared.identity, operationId: prepared.operationId) {
///     case .committed: try context.finalizeOperation(id: prepared.operationId)
///     case .conflict: try context.abortOperation(id: prepared.operationId)
///     case .unknown: throw StartupError.recoveryRequired
///     }
/// }
/// ```
///
/// ```kotlin
/// for (operation in context.unfinishedOperations()) {
///     val committed = database.hasCommitted(operation.id)
///     when {
///         committed && (operation.status == OperationStatus.RESERVED ||
///             operation.status == OperationStatus.FINALIZING) ->
///             context.finalizeOperation(operation.id)
///         !committed && (operation.status == OperationStatus.PREPARED ||
///             operation.status == OperationStatus.RESERVED) ->
///             context.abortOperation(operation.id)
///         else -> throw InconsistentStorage()
///     }
/// }
/// if (context.identity() == null) {
///     if (!database.isEmpty()) throw InconsistentStorage()
///     val prepared = context.prepareIdentityCreation()
///     context.reserveOperation(prepared.operationId)
///     when (database.saveIdentity(prepared.identity, prepared.operationId)) {
///         CommitResult.COMMITTED -> context.finalizeOperation(prepared.operationId)
///         CommitResult.CONFLICT -> context.abortOperation(prepared.operationId)
///         CommitResult.UNKNOWN -> throw RecoveryRequired()
///     }
/// }
/// ```
#[derive(uniffi::Object)]
pub struct IdentityContext {
    pub(crate) inner: Arc<CoreKeyStore>,
    revision: u64,
}

/// Session, Message, acknowledgment, and retry operations for one [`IdentityContext`].
///
/// The host supplies snapshots and exact Transport Binding bytes, then commits returned updates
/// together with their associated application effects.
#[derive(uniffi::Object)]
pub struct Messaging {
    pub(crate) inner: Arc<CoreKeyStore>,
}

/// Contact identity, trust, blocking, and inbox authorization for one [`IdentityContext`].
///
/// Queries read host-owned snapshots; state changes become visible when the host commits and
/// refreshes its store.
#[derive(uniffi::Object)]
pub struct Contacts {
    pub(crate) inner: Arc<CoreKeyStore>,
}

/// Protocol settings that every operation of an [`IdentityContext`] uses.
///
/// Every context serving one identity, in the app and its extensions, should use the same
/// configuration. The host bumps `revision` whenever it changes a setting, here or in its own
/// certificate trust inputs, so a commit can check that the work it saves used current settings.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct ContextConfiguration {
    /// Number of received Message digests kept for this identity, from 64 to 2048. Defaults to
    /// 1024.
    pub deduplication_capacity: u64,
    /// Whether a blocked sender receives an acknowledgment. Defaults to
    /// [`BlockedContactAcknowledgmentPolicy::Unreachable`](crate::BlockedContactAcknowledgmentPolicy::Unreachable).
    pub blocked_contact_acknowledgment_policy: crate::BlockedContactAcknowledgmentPolicy,
    /// How long after expiry a sender certificate still validates, in milliseconds, at most
    /// 300,000. Defaults to zero.
    ///
    /// A grace covers clock differences between devices, at the cost of accepting a certificate
    /// the relay has stopped vouching for.
    pub certificate_grace_millis: u64,
    /// The host's number for this configuration, which Roost returns unchanged. Defaults to zero.
    pub revision: u64,
}

/// Result of starting a Session through X3DH.
#[derive(uniffi::Record)]
pub struct SessionInitiationResult {
    /// X3DH first Message to send after host commit.
    pub message: Message,
    /// Opaque protocol-state updates to commit.
    pub state_updates: Vec<ProtocolStateUpdate>,
}

/// Result of blocking a contact.
#[derive(uniffi::Record)]
pub struct ContactBlock {
    /// Contact state change to commit durably, then emit.
    pub contact: ContactStateChange,
    /// The inbox rotation the block performed, absent when the contact was already blocked.
    ///
    /// Present means every remaining contact now holds a stale delivery capability and must be
    /// given the new one before it can reach this inbox again. The blocked contact is deliberately
    /// not among them — that is what makes the block bite at the relay rather than only locally.
    pub rotation: Option<InboxRotation>,
}

/// Result of accepting a Session through X3DH.
#[derive(uniffi::Record)]
pub struct SessionAcceptanceResult {
    /// Decrypted first-message plaintext.
    pub plaintext: Vec<u8>,
    /// Sender identity material decoded after authentication.
    pub sender_identity: SenderIdentityMaterial,
    /// Opaque protocol-state updates to commit.
    pub state_updates: Vec<ProtocolStateUpdate>,
}

#[uniffi::export]
impl IdentityContext {
    /// Creates a context over `secure_storage` with the default configuration.
    ///
    /// Creating a context reads and writes nothing.
    #[uniffi::constructor]
    pub fn new(secure_storage: Arc<dyn SecureStorage>) -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(CoreKeyStore::new(Box::new(SecureStorageAdapter::new(
                secure_storage,
            )))),
            revision: 0,
        })
    }

    /// Creates a context over `secure_storage` with `configuration`.
    ///
    /// Every context serving the same identity should use the same configuration.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if `deduplication_capacity` or `certificate_grace_millis` is
    ///   outside its range.
    #[uniffi::constructor]
    pub fn with_configuration(
        secure_storage: Arc<dyn SecureStorage>,
        configuration: ContextConfiguration,
    ) -> Result<Arc<Self>, RoostError> {
        let capacity = usize::try_from(configuration.deduplication_capacity).map_err(|_| {
            RoostError::InvalidData {
                reason: "deduplication capacity exceeds platform range".into(),
            }
        })?;
        let engine = CoreProtocolStateEngine::with_deduplication_capacity(capacity)?
            .with_blocked_contact_acknowledgment_policy(
                configuration
                    .blocked_contact_acknowledgment_policy
                    .to_core(),
            )
            .with_certificate_grace(Duration::from_millis(
                configuration.certificate_grace_millis,
            ))?;
        Ok(Arc::new(Self {
            inner: Arc::new(CoreKeyStore::with_protocol_engine(
                Box::new(SecureStorageAdapter::new(secure_storage)),
                engine,
            )),
            revision: configuration.revision,
        }))
    }

    /// Returns the configuration this context was created with.
    pub fn configuration(&self) -> ContextConfiguration {
        let engine = self.inner.protocol_engine();
        ContextConfiguration {
            deduplication_capacity: engine.hardening_limits().deduplication_capacity as u64,
            blocked_contact_acknowledgment_policy:
                crate::BlockedContactAcknowledgmentPolicy::from_core(
                    engine.blocked_contact_acknowledgment_policy(),
                ),
            // The engine accepts at most five minutes, which fits in u64 milliseconds.
            certificate_grace_millis: engine.certificate_grace().as_millis() as u64,
            revision: self.revision,
        }
    }

    /// Returns the messaging group, which shares this context's storage and configuration.
    pub fn messaging(&self) -> Arc<Messaging> {
        Arc::new(Messaging {
            inner: Arc::clone(&self.inner),
        })
    }

    /// Returns the contacts group, which shares this context's storage and configuration.
    pub fn contacts(&self) -> Arc<Contacts> {
        Arc::new(Contacts {
            inner: Arc::clone(&self.inner),
        })
    }

    /// Returns the stored identity's public keys, absent when no identity is stored.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if the stored identity is malformed.
    /// - [`RoostError::UnsupportedVersion`] if the stored identity uses an unknown format version.
    /// - [`RoostError::OperationRecoveryRequired`] if a reserved operation needs recovery.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn identity(&self) -> Result<Option<Identity>, RoostError> {
        self.inner
            .identity()?
            .map(|identity| Ok(Identity::from_core(identity)?))
            .transpose()
    }

    /// Prepares a new identity and its first Discovery Key.
    ///
    /// The host saves the identity with the operation ID, and publishes it only after
    /// finalization. Finalizing also completes an identity whose earlier creation stopped partway.
    ///
    /// # Errors
    /// - [`RoostError::AlreadyExists`] if an identity is already stored.
    /// - [`RoostError::OperationRecoveryRequired`] if a reserved operation needs recovery.
    /// - [`RoostError::TooManyUnfinishedOperations`] if too many operations are unfinished.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn prepare_identity_creation(&self) -> Result<PreparedIdentity, RoostError> {
        let (operation_id, identity) = convert_prepared(
            &self.inner,
            self.inner.prepare_identity_creation()?,
            |identity| Ok(Identity::from_core(identity)?),
        )?;
        Ok(PreparedIdentity {
            operation_id,
            identity,
        })
    }

    /// Prepares deletion of the identity and all of its keys.
    ///
    /// The host deletes its protocol state for the identity in the transaction that saves the
    /// operation ID. Preparing deletion with no identity stored still returns an operation.
    ///
    /// # Errors
    /// - [`RoostError::OperationRecoveryRequired`] if a reserved operation needs recovery.
    /// - [`RoostError::TooManyUnfinishedOperations`] if too many operations are unfinished.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn prepare_identity_deletion(&self) -> Result<OperationId, RoostError> {
        Ok(OperationId::from_core(
            self.inner.prepare_identity_deletion()?.operation.id,
        ))
    }

    /// Signs a host-built authentication transcript with the Identity Key and returns the
    /// 64-byte signature.
    ///
    /// The transcript is signed exactly as given, so the host puts its own domain separation inside
    /// it, as a relay authentication transcript does with its `Relay-HTTP-Auth-v1` prefix. Roost
    /// refuses a transcript that starts with `Aether` or `Roost`, in any letter case, because every
    /// preimage Roost signs starts with one of them: without the check, this method could sign an
    /// identity binding or a Message transcript chosen by whoever supplied the bytes. Signing is
    /// deterministic, so the same transcript always gives the same signature.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if the transcript is empty, longer than 4096 bytes, or starts
    ///   with a reserved prefix.
    /// - [`RoostError::NotFound`] if no identity is stored.
    /// - [`RoostError::OperationRecoveryRequired`] if a reserved operation needs recovery.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn sign_authentication_transcript(
        &self,
        transcript: Vec<u8>,
    ) -> Result<Vec<u8>, RoostError> {
        let transcript = Zeroizing::new(transcript);
        check_signable_transcript(&transcript)?;
        Ok(self
            .inner
            .load_identity()?
            .sign(&transcript)
            .to_bytes()
            .to_vec())
    }

    /// Returns a passphrase-encrypted backup of the identity and its current Discovery Key.
    ///
    /// Each call runs Argon2id with 64 MiB of memory, so call it off the main thread. The backup is
    /// about 274 bytes and restores on any device with [`Self::prepare_backup_import`].
    ///
    /// # Errors
    /// - [`RoostError::BackupFailed`] if key derivation or encryption fails.
    /// - [`RoostError::NotFound`] if no identity or Discovery Key is stored.
    /// - [`RoostError::OperationRecoveryRequired`] if a reserved operation needs recovery.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn export_encrypted_backup(&self, passphrase: String) -> Result<Vec<u8>, RoostError> {
        let passphrase = Zeroizing::new(passphrase);
        Ok(self.inner.export_encrypted_backup(&passphrase)?)
    }

    /// Prepares replacing this context's identity with the one in `backup`.
    ///
    /// A wrong passphrase or a damaged backup fails here and changes nothing. In the transaction
    /// that saves the operation ID, the host deletes or replaces all of its protocol state for the
    /// identity, since Sessions, acknowledgments, and deduplication from before the restore no
    /// longer apply. After finalization, prekeys and publication stay blocked until
    /// [`Self::prepare_inbox_rotation`] moves to the next Discovery Key epoch, so the restored
    /// identity never reuses prekey IDs already published under the backed-up one. Each call runs
    /// Argon2id with 64 MiB of memory.
    ///
    /// # Errors
    /// - [`RoostError::DecryptionFailed`] if the passphrase is wrong or the backup was altered.
    /// - [`RoostError::InvalidData`] or [`RoostError::UnsupportedVersion`] if the backup is
    ///   malformed.
    /// - [`RoostError::OperationRecoveryRequired`] if a reserved operation needs recovery.
    /// - [`RoostError::TooManyUnfinishedOperations`] if too many operations are unfinished.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn prepare_backup_import(
        &self,
        backup: Vec<u8>,
        passphrase: String,
    ) -> Result<OperationId, RoostError> {
        let backup = Zeroizing::new(backup);
        let passphrase = Zeroizing::new(passphrase);
        Ok(OperationId::from_core(
            self.inner
                .prepare_backup_import(backup.as_slice(), passphrase.as_str())?
                .operation
                .id,
        ))
    }

    /// Returns the current Discovery Key and signed prekey, which verify as one chain.
    ///
    /// Publish the two together: reading them separately could pair keys from different rotations,
    /// which peers reject.
    ///
    /// # Errors
    /// - [`RoostError::Corrupt`] if the stored keys don't verify as a chain.
    /// - [`RoostError::InboxRotationRequired`] after a backup restore, until an inbox rotation.
    /// - [`RoostError::NotFound`] if no identity, Discovery Key, or signed prekey is stored.
    /// - [`RoostError::OperationRecoveryRequired`] if a reserved operation needs recovery.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn current_publication(&self) -> Result<PublicationBundle, RoostError> {
        PublicationBundle::from_core(self.inner.current_publication()?)
    }

    /// Returns the current inbox's 32-byte delivery capability.
    ///
    /// The capability is a secret that lets a contact deliver to this inbox. Share it only with
    /// authorized contacts over an encrypted channel, keep it in secure storage, and register the
    /// publication's verifier with the relay instead.
    ///
    /// # Errors
    /// - [`RoostError::NotFound`] if no Discovery Key is stored.
    /// - [`RoostError::OperationRecoveryRequired`] if a reserved operation needs recovery.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn current_delivery_capability(&self) -> Result<Vec<u8>, RoostError> {
        Ok(self
            .inner
            .current_delivery_capability()?
            .to_bytes()
            .to_vec())
    }

    /// Prepares an inbox rotation: a Discovery Key at the next epoch, a signed prekey, and a
    /// delivery capability.
    ///
    /// Rotation clears the previous inbox's one-time prekeys and invalidates every contact's
    /// delivery capability, so the host shares the new capability with each contact that should
    /// keep delivering.
    ///
    /// # Errors
    /// - [`RoostError::NotFound`] if no identity is stored.
    /// - [`RoostError::OperationRecoveryRequired`] if a reserved operation needs recovery.
    /// - [`RoostError::TooManyUnfinishedOperations`] if too many operations are unfinished.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn prepare_inbox_rotation(&self) -> Result<PreparedInboxRotation, RoostError> {
        let (operation_id, rotation) = convert_prepared(
            &self.inner,
            self.inner.prepare_inbox_rotation()?,
            inbox_rotation_from_core,
        )?;
        Ok(PreparedInboxRotation {
            operation_id,
            rotation,
        })
    }

    /// Prepares a new signed prekey if the current one is missing or stale.
    ///
    /// Call this at launch. Finalize or abort the operation even when it returns no signed prekey.
    ///
    /// # Errors
    /// - [`RoostError::InboxRotationRequired`] after a backup restore, until an inbox rotation.
    /// - [`RoostError::NotFound`] if no identity or Discovery Key is stored.
    /// - [`RoostError::OperationRecoveryRequired`] if a reserved operation needs recovery.
    /// - [`RoostError::TooManyUnfinishedOperations`] if too many operations are unfinished.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn prepare_signed_prekey_rotation_if_stale(
        &self,
    ) -> Result<PreparedSignedPreKeyRotation, RoostError> {
        let (operation_id, signed_prekey) = convert_prepared(
            &self.inner,
            self.inner.prepare_signed_prekey_rotation_if_stale()?,
            |signed_prekey| signed_prekey.map(PublicSignedPreKey::from_core).transpose(),
        )?;
        Ok(PreparedSignedPreKeyRotation {
            operation_id,
            signed_prekey,
        })
    }

    /// Prepares a new signed prekey even if the current one is fresh.
    ///
    /// # Errors
    /// - [`RoostError::InboxRotationRequired`] after a backup restore, until an inbox rotation.
    /// - [`RoostError::NotFound`] if no identity or Discovery Key is stored.
    /// - [`RoostError::OperationRecoveryRequired`] if a reserved operation needs recovery.
    /// - [`RoostError::TooManyUnfinishedOperations`] if too many operations are unfinished.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn prepare_signed_prekey_rotation(
        &self,
    ) -> Result<PreparedSignedPreKeyRotation, RoostError> {
        let (operation_id, signed_prekey) = convert_prepared(
            &self.inner,
            self.inner.prepare_signed_prekey_rotation()?,
            |signed_prekey| PublicSignedPreKey::from_core(signed_prekey).map(Some),
        )?;
        Ok(PreparedSignedPreKeyRotation {
            operation_id,
            signed_prekey,
        })
    }

    /// Prepares exactly `count` one-time prekeys for the current Discovery Key.
    ///
    /// # Errors
    /// - [`RoostError::InboxRotationRequired`] after a backup restore, until an inbox rotation.
    /// - [`RoostError::InvalidData`] if the pool can't hold `count` more prekeys.
    /// - [`RoostError::NotFound`] if no identity or Discovery Key is stored.
    /// - [`RoostError::OperationRecoveryRequired`] if a reserved operation needs recovery.
    /// - [`RoostError::TooManyUnfinishedOperations`] if too many operations are unfinished.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn prepare_one_time_prekeys(
        &self,
        count: u32,
    ) -> Result<PreparedOneTimePreKeys, RoostError> {
        let count = usize::try_from(count).map_err(|_| RoostError::InvalidData {
            reason: "one-time prekey count exceeds platform range".into(),
        })?;
        let (operation_id, one_time_prekeys) = convert_prepared(
            &self.inner,
            self.inner.prepare_one_time_prekeys(count)?,
            public_one_time_prekeys_from_core,
        )?;
        Ok(PreparedOneTimePreKeys {
            operation_id,
            one_time_prekeys,
        })
    }

    /// Prepares one-time prekeys to refill the pool once it runs low.
    ///
    /// Returns no prekeys while the pool is above its threshold. Finalize or abort the operation
    /// either way.
    ///
    /// # Errors
    /// - [`RoostError::InboxRotationRequired`] after a backup restore, until an inbox rotation.
    /// - [`RoostError::NotFound`] if no identity or Discovery Key is stored.
    /// - [`RoostError::OperationRecoveryRequired`] if a reserved operation needs recovery.
    /// - [`RoostError::TooManyUnfinishedOperations`] if too many operations are unfinished.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn prepare_one_time_prekey_replenishment(
        &self,
    ) -> Result<PreparedOneTimePreKeys, RoostError> {
        let (operation_id, one_time_prekeys) = convert_prepared(
            &self.inner,
            self.inner.prepare_one_time_prekey_replenishment()?,
            public_one_time_prekeys_from_core,
        )?;
        Ok(PreparedOneTimePreKeys {
            operation_id,
            one_time_prekeys,
        })
    }

    /// Checks that SecureStorage still matches what a prepared operation read, and reserves it for
    /// the host's commit.
    ///
    /// Reserving again is harmless. Until the reserved operation is finalized or aborted, other
    /// calls return [`RoostError::OperationRecoveryRequired`].
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if `id` isn't a valid operation ID.
    /// - [`RoostError::NotFound`] if no recent operation has this ID.
    /// - [`RoostError::OperationConflict`] if the operation was aborted.
    /// - [`RoostError::OperationRecoveryRequired`] if another reserved operation needs recovery.
    /// - [`RoostError::SecureStoragePreconditionChanged`] if another operation changed the keys
    ///   this one read. Abort it and prepare again.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn reserve_operation(&self, id: OperationId) -> Result<(), RoostError> {
        self.inner.reserve_operation(id.to_core()?)?;
        Ok(())
    }

    /// Applies a reserved operation's staged changes after the host's commit.
    ///
    /// Finalizing again resumes an interrupted finalization, or does nothing once it's done.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if `id` isn't a valid operation ID.
    /// - [`RoostError::NotFound`] if no recent operation has this ID.
    /// - [`RoostError::OperationConflict`] if the operation isn't reserved or was aborted.
    /// - [`RoostError::Storage`] if SecureStorage fails. Finalize again to resume.
    pub fn finalize_operation(&self, id: OperationId) -> Result<(), RoostError> {
        self.inner.finalize_operation(id.to_core()?)?;
        Ok(())
    }

    /// Discards a prepared or reserved operation's staged changes.
    ///
    /// Abort a reserved operation only when the host's commit definitely didn't happen. Aborting
    /// again does nothing.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if `id` isn't a valid operation ID.
    /// - [`RoostError::NotFound`] if no recent operation has this ID.
    /// - [`RoostError::OperationConflict`] if finalization already started.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn abort_operation(&self, id: OperationId) -> Result<(), RoostError> {
        self.inner.abort_operation(id.to_core()?)?;
        Ok(())
    }

    /// Returns an operation's durable phase.
    ///
    /// Roost keeps only recent finalized and aborted operations, so an old one returns
    /// [`RoostError::NotFound`].
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if `id` isn't a valid operation ID.
    /// - [`RoostError::NotFound`] if no recent operation has this ID.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn operation_status(&self, id: OperationId) -> Result<OperationStatus, RoostError> {
        Ok(OperationStatus::from_core(
            self.inner.operation_status(id.to_core()?)?,
        ))
    }

    /// Returns every operation that is neither finalized nor aborted.
    ///
    /// # Errors
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn unfinished_operations(&self) -> Result<Vec<UnfinishedOperation>, RoostError> {
        Ok(self
            .inner
            .unfinished_operations()?
            .into_iter()
            .map(UnfinishedOperation::from_core)
            .collect())
    }
}

#[uniffi::export]
impl Messaging {
    /// Starts a new Session while authenticating a caller-owned Transport Binding.
    ///
    /// Commit the returned state updates atomically with the returned Message and retain the exact
    /// binding for transport retry. Aether does not interpret, transmit, or store the binding.
    ///
    /// # Errors
    /// - [`RoostError::AuthenticationFailed`] if X3DH, sealed-frame, sender-proof, or AEAD work
    ///   fails.
    /// - [`RoostError::Corrupt`] if the stored Discovery Key fails its binding checks.
    /// - [`RoostError::InternalError`] on storage lock poisoning.
    /// - [`RoostError::InvalidData`] if key, Message, certificate, prekey, or Transport Binding
    ///   inputs are malformed.
    /// - [`RoostError::NotFound`] if local Identity or Discovery Key material is missing.
    /// - [`RoostError::OperationRecoveryRequired`] if a reserved operation needs recovery.
    /// - [`RoostError::ProtocolStateFault`] if install state cannot be encoded.
    /// - [`RoostError::Storage`] on platform storage failure.
    /// - [`RoostError::UnsupportedVersion`] if a prekey bundle, Message, or stored key version is
    ///   unsupported.
    #[expect(
        clippy::too_many_arguments,
        reason = "flat UniFFI export preserves generated binding shape"
    )]
    pub fn initiate_session(
        &self,
        session_key: Vec<u8>,
        responder_identity: Identity,
        responder_publication: PublicationBundle,
        responder_one_time_prekey: Option<PublicOneTimePreKey>,
        sender_certificate: Vec<u8>,
        sender_signature: Vec<u8>,
        plaintext: Vec<u8>,
        transport_binding: TransportBinding,
    ) -> Result<SessionInitiationResult, RoostError> {
        let sender_certificate = Zeroizing::new(sender_certificate);
        let sender_signature = Zeroizing::new(sender_signature);
        let plaintext = Zeroizing::new(plaintext);
        let transport_binding = transport_binding.into_core()?;
        let result = self.inner.initiate_session_with_transport_binding(
            SessionInitiation {
                session_key: ProtocolStateKey::from_bytes(session_key)?,
                responder_identity_key: responder_identity.to_core()?,
                responder_discovery_to_identity: responder_publication
                    .discovery_to_identity_signature()?,
                responder_prekey_bundle: responder_publication
                    .to_prekey_bundle(responder_one_time_prekey)?,
                sender_certificate: &sender_certificate,
                sender_signature: &sender_signature,
                plaintext: &plaintext,
            },
            &transport_binding,
        )?;
        Ok(SessionInitiationResult {
            message: Message::from_core(result.message),
            state_updates: updates_from_core(result.state_updates),
        })
    }

    /// Reads who sent an X3DH first Message while authenticating its Transport Binding.
    ///
    /// This operation consumes no one-time prekey. Pass the same binding and prekey selection to
    /// [`Self::prepare_accept_session`] after deriving the host Session key.
    ///
    /// # Errors
    /// - [`RoostError::AuthenticationFailed`] if the frame is not sealed to this Discovery Key
    ///   and Transport Binding, the selected one-time-prekey identifier does not match the
    ///   Message, or the named identity's binding signature does not verify.
    /// - [`RoostError::Corrupt`] if the stored Discovery Key fails its binding checks.
    /// - [`RoostError::InboxRotationRequired`] after backup restore and before inbox rotation.
    /// - [`RoostError::InternalError`] on storage lock poisoning.
    /// - [`RoostError::InvalidData`] if the Message or Transport Binding is malformed.
    /// - [`RoostError::NotFound`] if local Discovery Key or referenced signed-prekey material is
    ///   missing.
    /// - [`RoostError::OperationRecoveryRequired`] if a reserved operation needs recovery.
    /// - [`RoostError::Storage`] on platform storage failure.
    /// - [`RoostError::UnsupportedVersion`] if the Message or stored prekey version is unsupported.
    pub fn initiator_identity_hint(
        &self,
        message: Message,
        transport_binding: TransportBinding,
        prekey_selection: PreKeySelection,
    ) -> Result<Identity, RoostError> {
        let core_message = message.to_core()?;
        let transport_binding = transport_binding.into_core()?;
        let bundle = self.inner.initiator_identity_hint_with_transport_binding(
            &core_message,
            &transport_binding,
            prekey_selection.to_core(),
        )?;
        Ok(Identity::from_public(bundle))
    }

    /// Prepares responder-side Session acceptance while authenticating a Transport Binding.
    ///
    /// For a retained superseded signed prekey, the host must first validate that its transport
    /// accepted the item before supersession. Reserve the operation, atomically persist the returned
    /// state updates and operation identifier, then finalize SecureStorage.
    ///
    /// # Errors
    /// - [`RoostError::AuthenticationFailed`] if X3DH, sealed-frame, sender-proof, or AEAD work
    ///   fails.
    /// - [`RoostError::Corrupt`] if the stored Discovery Key fails its binding checks.
    /// - [`RoostError::InboxRotationRequired`] after backup restore and before inbox rotation.
    /// - [`RoostError::InternalError`] on storage lock poisoning or operation identifier
    ///   generation failure.
    /// - [`RoostError::InvalidData`] if the Message, key, prekey, or Transport Binding inputs are
    ///   malformed.
    /// - [`RoostError::NotFound`] if required local Identity, Discovery Key, signed-prekey, or
    ///   one-time-prekey material is missing.
    /// - [`RoostError::TooManyUnfinishedOperations`] if the unfinished-operation limit is reached.
    /// - [`RoostError::OperationRecoveryRequired`] if a reserved operation needs recovery.
    /// - [`RoostError::ProtocolStateFault`] if install state cannot be encoded.
    /// - [`RoostError::Storage`] on platform storage failure.
    /// - [`RoostError::UnsupportedVersion`] if the Message, stored prekey, or protocol-state
    ///   version is unsupported.
    pub fn prepare_accept_session(
        &self,
        session_key: Vec<u8>,
        initiator_identity: Option<Identity>,
        message: Message,
        transport_binding: TransportBinding,
        prekey_selection: PreKeySelection,
    ) -> Result<PreparedSessionAcceptance, RoostError> {
        let core_message = message.to_core()?;
        let initiator_identity_key = initiator_identity
            .map(|identity| identity.to_core())
            .transpose()?;
        let transport_binding = transport_binding.into_core()?;
        let prepared = self.inner.prepare_accept_session_with_transport_binding(
            SessionAcceptance {
                session_key: ProtocolStateKey::from_bytes(session_key)?,
                initiator_identity_key,
                message: &core_message,
            },
            &transport_binding,
            prekey_selection.to_core(),
        )?;
        let (operation_id, acceptance) = convert_prepared(&self.inner, prepared, |result| {
            let state_updates = updates_from_core(result.state_updates);
            Ok(SessionAcceptanceResult {
                plaintext: result.plaintext.to_vec(),
                sender_identity: SenderIdentityMaterial::from_core(result.sender_identity),
                state_updates,
            })
        })?;
        Ok(PreparedSessionAcceptance {
            operation_id,
            acceptance,
        })
    }

    /// Encrypts an established-session Message while authenticating a Transport Binding.
    ///
    /// Commit the returned state updates atomically with the returned Message and retain the exact
    /// binding for retransmission.
    ///
    /// # Errors
    /// - [`RoostError::ContactNotAccepted`] if the peer contact is still pending.
    /// - [`RoostError::TerminalSessionRecovery`] if the Session requires replacement.
    /// - [`RoostError::BlockedContact`] if the contact is locally blocked.
    /// - [`RoostError::InternalError`] on storage lock poisoning.
    /// - [`RoostError::InvalidData`] if Message identifiers, keys, Message fields, the Transport
    ///   Binding, or the stored Identity are malformed.
    /// - [`RoostError::NotFound`] if local Identity material is missing.
    /// - [`RoostError::OperationRecoveryRequired`] if a reserved operation needs recovery.
    /// - [`RoostError::ProtocolStateFault`] if required blobs are missing or malformed.
    /// - [`RoostError::Storage`] on platform storage failure.
    /// - [`RoostError::UnsupportedVersion`] if a stored protocol-state version is unsupported.
    #[expect(
        clippy::too_many_arguments,
        reason = "flat UniFFI export preserves generated binding shape"
    )]
    pub fn encrypt_message(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        session_key: Vec<u8>,
        message_id: Vec<u8>,
        contact_identity_key: IdentityKey,
        recipient_public_key: Vec<u8>,
        sent_at_millis: u64,
        sender_certificate: Vec<u8>,
        sender_signature: Vec<u8>,
        plaintext: Vec<u8>,
        transport_binding: TransportBinding,
    ) -> Result<OutboundMessageResult, RoostError> {
        let sender_certificate = Zeroizing::new(sender_certificate);
        let sender_signature = Zeroizing::new(sender_signature);
        let plaintext = Zeroizing::new(plaintext);
        let snapshot = snapshot_input_from_entries(snapshot)?;
        let transport_binding = transport_binding.into_core()?;
        Ok(OutboundMessageResult::from_core(
            self.inner.encrypt_message_with_transport_binding(
                MessageEncryption {
                    snapshot: &snapshot,
                    session_key: protocol_key(session_key)?,
                    message_id: MessageId::from_bytes(fixed_16(&message_id, "message id")?),
                    contact_identity_key: contact_identity_key.to_core()?,
                    recipient_public_key: fixed_32(&recipient_public_key, "recipient public key")?,
                    sent_at_millis,
                    sender_certificate: &sender_certificate,
                    sender_signature: &sender_signature,
                    plaintext: &plaintext,
                },
                &transport_binding,
            )?,
        ))
    }

    /// Decrypts an established-session Message while authenticating its Transport Binding and the
    /// binding used for the returned acknowledgment.
    ///
    /// Unique Messages require `sender_certificate_validation`; duplicates can return before
    /// validation because they surface no plaintext. Retain `acknowledgment_transport_binding`
    /// with any returned acknowledgment Message.
    ///
    /// # Errors
    /// - [`RoostError::AuthenticationFailed`] if sealed-sender, ratchet, transcript, or AEAD
    ///   authentication fails.
    /// - [`RoostError::CertificateRejected`] if sender-certificate validation rejects the sender.
    /// - [`RoostError::Corrupt`] if the stored Discovery Key fails its binding checks.
    /// - [`RoostError::InternalError`] on storage lock poisoning.
    /// - [`RoostError::InvalidData`] if Message identifiers, keys, Message fields, or either
    ///   Transport Binding is malformed.
    /// - [`RoostError::NotFound`] if local Identity or Discovery Key material is missing.
    /// - [`RoostError::OperationRecoveryRequired`] if a reserved operation needs recovery.
    /// - [`RoostError::ProtocolStateFault`] if required blobs are missing or malformed.
    /// - [`RoostError::Storage`] on platform storage failure.
    /// - [`RoostError::UnsupportedVersion`] if the Message or a stored protocol-state version is
    ///   unsupported.
    #[expect(
        clippy::too_many_arguments,
        reason = "flat UniFFI export preserves generated binding shape"
    )]
    pub fn decrypt_message(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        session_key: Vec<u8>,
        deduplication_key: Vec<u8>,
        message: Message,
        acknowledgment_id: Vec<u8>,
        acknowledgment_recipient_public_key: Vec<u8>,
        acknowledgment_sent_at_millis: u64,
        acknowledgment_sender_certificate: Vec<u8>,
        acknowledgment_sender_signature: Vec<u8>,
        sender_certificate_validation: Option<SenderCertificateValidation>,
        message_transport_binding: TransportBinding,
        acknowledgment_transport_binding: TransportBinding,
    ) -> Result<InboundMessageOutcome, RoostError> {
        let acknowledgment_sender_certificate = Zeroizing::new(acknowledgment_sender_certificate);
        let acknowledgment_sender_signature = Zeroizing::new(acknowledgment_sender_signature);
        let snapshot = snapshot_input_from_entries(snapshot)?;
        let message = message.to_core()?;
        let message_transport_binding = message_transport_binding.into_core()?;
        let acknowledgment_transport_binding = acknowledgment_transport_binding.into_core()?;

        let validation_storage = if let Some(validation) = &sender_certificate_validation {
            Some((
                domain_signing_keys_to_protocol(&validation.domain_signing_keys)?,
                revoked_identity_keys_to_protocol(&validation.revocation_state)?,
                time_from_millis(validation.reference_time_millis, "reference_time_millis")?,
            ))
        } else {
            None
        };
        let core_validation = sender_certificate_validation
            .as_ref()
            .zip(validation_storage.as_ref())
            .map(
                |(validation, (domain_signing_keys, revoked_identity_keys, reference_time))| {
                    InboundSenderCertificateValidation {
                        domain_signing_keys,
                        expected_relay_domain: &validation.expected_relay_domain,
                        revocation_state: revocation_state_to_protocol(
                            &validation.revocation_state,
                            revoked_identity_keys,
                        ),
                        reference_time: *reference_time,
                    }
                },
            );

        Ok(InboundMessageOutcome::from_core(
            self.inner.decrypt_message_with_transport_bindings(
                MessageDecryption {
                    snapshot: &snapshot,
                    session_key: protocol_key(session_key)?,
                    deduplication_key: protocol_key(deduplication_key)?,
                    message: &message,
                    acknowledgment_id: MessageId::from_bytes(fixed_16(
                        &acknowledgment_id,
                        "acknowledgment id",
                    )?),
                    acknowledgment_recipient_public_key: fixed_32(
                        &acknowledgment_recipient_public_key,
                        "acknowledgment recipient public key",
                    )?,
                    acknowledgment_sent_at_millis,
                    acknowledgment_sender_certificate: &acknowledgment_sender_certificate,
                    acknowledgment_sender_signature: &acknowledgment_sender_signature,
                    sender_certificate_validation: core_validation,
                },
                &message_transport_binding,
                &acknowledgment_transport_binding,
            )?,
        ))
    }

    /// Processes an encrypted acknowledgment while authenticating its Transport Binding.
    ///
    /// Commit returned updates before clearing local transport retry state.
    ///
    /// # Errors
    /// - [`RoostError::AuthenticationFailed`] if sealed-sender, ratchet, transcript, or AEAD
    ///   authentication fails.
    /// - [`RoostError::Corrupt`] if the stored Discovery Key fails its binding checks.
    /// - [`RoostError::InternalError`] on storage lock poisoning.
    /// - [`RoostError::InvalidData`] if Message fields or the Transport Binding are malformed.
    /// - [`RoostError::NotFound`] if local Identity or Discovery Key material is missing.
    /// - [`RoostError::OperationRecoveryRequired`] if a reserved operation needs recovery.
    /// - [`RoostError::ProtocolStateFault`] if required blobs are missing or malformed.
    /// - [`RoostError::Storage`] on platform storage failure.
    /// - [`RoostError::UnsupportedVersion`] if the Message or a stored protocol-state version is
    ///   unsupported.
    pub fn process_acknowledgment(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        session_key: Vec<u8>,
        message: Message,
        transport_binding: TransportBinding,
    ) -> Result<AcknowledgmentOutcome, RoostError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        let message = message.to_core()?;
        let transport_binding = transport_binding.into_core()?;
        Ok(AcknowledgmentOutcome::from_core(
            self.inner.process_acknowledgment_with_transport_binding(
                AcknowledgmentProcessing {
                    snapshot: &snapshot,
                    session_key: protocol_key(session_key)?,
                    message: &message,
                },
                &transport_binding,
            )?,
        ))
    }
}

#[uniffi::export]
impl Contacts {
    /// Prepares a contact block and inbox rotation so both cross one host commit boundary.
    ///
    /// Blocking stops this device sending and surfacing the contact's messages and rotates the
    /// local inbox to invalidate the contact's delivery capability. Rotation also invalidates
    /// every other contact's copy:
    /// when `PreparedContactBlock.block.rotation` is present, each remaining contact must receive
    /// the new capability before it can deliver again.
    /// [`Self::contacts_needing_inbox_authorization`] returns that list and excludes the blocked
    /// contact.
    ///
    /// Blocking an already-blocked contact performs no rotation, so repeating the call does not
    /// churn every contact's capability. Its no-op operation must still be finalized or aborted.
    ///
    /// Reserve the operation, atomically persist `PreparedContactBlock.block.contact` and any
    /// host-owned publication work, then finalize the staged SecureStorage rotation. Abort only
    /// after proving the host transaction did not commit.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if `identity_key` has the wrong length.
    /// - [`RoostError::InternalError`] on storage lock poisoning or system clock anomaly.
    /// - [`RoostError::TooManyUnfinishedOperations`] if the unfinished-operation limit is reached.
    /// - [`RoostError::OperationRecoveryRequired`] if a reserved operation needs recovery.
    /// - [`RoostError::ProtocolStateFault`] if no contact is stored for `identity_key`, or its
    ///   blob is malformed.
    /// - [`RoostError::Storage`] on platform storage failure.
    pub fn prepare_block_contact(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        identity_key: IdentityKey,
    ) -> Result<PreparedContactBlock, RoostError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        let prepared = self
            .inner
            .prepare_block_contact(&snapshot, identity_key.to_core()?)?;
        let (operation_id, block) = convert_prepared(&self.inner, prepared, |blocked| {
            Ok(ContactBlock {
                contact: ContactStateChange::from_core(blocked.contact)?,
                rotation: blocked.rotation.map(inbox_rotation_from_core).transpose()?,
            })
        })?;
        Ok(PreparedContactBlock {
            operation_id,
            block,
        })
    }
}

fn convert_prepared<T, U>(
    store: &CoreKeyStore,
    prepared: CorePreparedKeyStoreOperation<T>,
    convert: impl FnOnce(T) -> Result<U, RoostError>,
) -> Result<(OperationId, U), RoostError> {
    let id = prepared.operation.id;
    match convert(prepared.output) {
        Ok(output) => Ok((OperationId::from_core(id), output)),
        // A conversion failure hides the prepared output from the host. Abort its journal record,
        // or return the identifier so the host can reconcile an uncertain cleanup after restart.
        Err(error) => match store.abort_operation(id) {
            Ok(_) => Err(error),
            Err(abort_error) => Err(RoostError::OperationRecoveryRequired {
                operation_id: OperationId::from_core(id),
                reason: format!(
                    "prepared output conversion failed and cleanup also failed: {}",
                    crate::error::reason_from_chain(&abort_error)
                ),
            }),
        },
    }
}

fn inbox_rotation_from_core(
    rotation: roost_core::InboxRotation,
) -> Result<InboxRotation, RoostError> {
    Ok(InboxRotation {
        publication: PublicationBundle::from_core(rotation.publication)?,
        capability: rotation.capability.to_bytes().to_vec(),
    })
}

fn public_one_time_prekeys_from_core(
    one_time_prekeys: Vec<roost_core::PublicOneTimePreKey>,
) -> Result<Vec<PublicOneTimePreKey>, RoostError> {
    one_time_prekeys
        .into_iter()
        .map(PublicOneTimePreKey::from_core)
        .collect()
}

// Bounds what the identity key will sign for a caller-defined purpose. The prefix rule is the
// security-relevant half: it keeps this export's preimages disjoint from every signature context
// Roost defines, so no signature it produces can satisfy a Roost verifier.
fn check_signable_transcript(transcript: &[u8]) -> Result<(), RoostError> {
    if transcript.is_empty() {
        return Err(RoostError::InvalidData {
            reason: "authentication transcript is empty".into(),
        });
    }
    if transcript.len() > MAX_AUTHENTICATION_TRANSCRIPT_LEN {
        return Err(RoostError::InvalidData {
            reason: format!(
                "authentication transcript exceeds {MAX_AUTHENTICATION_TRANSCRIPT_LEN} bytes"
            ),
        });
    }
    for prefix in RESERVED_DOMAIN_PREFIXES {
        if transcript
            .get(..prefix.len())
            .is_some_and(|start| start.eq_ignore_ascii_case(prefix.as_bytes()))
        {
            return Err(RoostError::InvalidData {
                reason: format!(
                    "authentication transcript starts with the reserved {prefix} domain prefix"
                ),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
impl IdentityContext {
    fn complete_prepared<T>(&self, id: OperationId, output: T) -> Result<T, RoostError> {
        self.reserve_operation(id.clone())?;
        self.finalize_operation(id)?;
        Ok(output)
    }

    pub(crate) fn generate_identity(&self) -> Result<Identity, RoostError> {
        let prepared = self.prepare_identity_creation()?;
        self.complete_prepared(prepared.operation_id, prepared.identity)
    }

    pub(crate) fn generate_one_time_prekeys(
        &self,
        batch_size: u32,
    ) -> Result<Vec<PublicOneTimePreKey>, RoostError> {
        let prepared = self.prepare_one_time_prekeys(batch_size)?;
        self.complete_prepared(prepared.operation_id, prepared.one_time_prekeys)
    }

    pub(crate) fn replenish_one_time_prekeys(
        &self,
    ) -> Result<Vec<PublicOneTimePreKey>, RoostError> {
        let prepared = self.prepare_one_time_prekey_replenishment()?;
        self.complete_prepared(prepared.operation_id, prepared.one_time_prekeys)
    }

    pub(crate) fn rotate_inbox_now(&self) -> Result<InboxRotation, RoostError> {
        let prepared = self.prepare_inbox_rotation()?;
        self.complete_prepared(prepared.operation_id, prepared.rotation)
    }

    pub(crate) fn rotate_signed_prekey_if_stale(
        &self,
    ) -> Result<Option<PublicSignedPreKey>, RoostError> {
        let prepared = self.prepare_signed_prekey_rotation_if_stale()?;
        self.complete_prepared(prepared.operation_id, prepared.signed_prekey)
    }

    pub(crate) fn rotate_signed_prekey_now(&self) -> Result<PublicSignedPreKey, RoostError> {
        let prepared = self.prepare_signed_prekey_rotation()?;
        let signed_prekey = prepared.signed_prekey.ok_or(RoostError::InternalError {
            reason: "forced signed-prekey rotation returned no bundle".into(),
        })?;
        self.complete_prepared(prepared.operation_id, signed_prekey)
    }

    pub(crate) fn accept_session(
        &self,
        session_key: Vec<u8>,
        initiator_identity: Option<Identity>,
        message: Message,
    ) -> Result<SessionAcceptanceResult, RoostError> {
        let selection = crate::PreKeySelection {
            signed_prekey_id: self.current_publication()?.signed_prekey.id,
            one_time_prekey_id: message
                .prekey_reference
                .as_ref()
                .and_then(|p| p.one_time_prekey_id),
        };
        let prepared = self.messaging().prepare_accept_session(
            session_key,
            initiator_identity,
            message,
            crate::TransportBinding {
                bytes: b"test-route".to_vec(),
            },
            selection,
        )?;
        self.complete_prepared(prepared.operation_id, prepared.acceptance)
    }
}

#[cfg(test)]
mod tests {
    use super::{IdentityContext, MAX_AUTHENTICATION_TRANSCRIPT_LEN};
    use crate::storage::MemoryStorage;
    use crate::{
        RoostError, SecureStorage,
        protocol::{
            ContactDiscoveryKey, ContactIdentity, IdentityKey, ProtocolStateEntry,
            ProtocolStateKind, ProtocolStateUpdate,
        },
        records::{
            Identity as FfiIdentity, PublicDiscoveryKey as FfiPublicDiscoveryKey,
            PublicOneTimePreKey as FfiPublicOneTimePreKey,
            PublicSignedPreKey as FfiPublicSignedPreKey, PublicationBundle as FfiPublicationBundle,
        },
    };
    use roost_crypto::{
        PublicDiscoveryKey as CryptoPublicDiscoveryKey,
        PublicIdentityKey as CryptoPublicIdentityKey, PublicKey,
        PublicSignedPreKey as CryptoPublicSignedPreKey,
        RecipientDeliveryCapability as CryptoCapability, Signature, VerifyingKey,
        verify_discovery_to_identity_binding, verify_public_discovery_key,
        verify_public_identity_key, verify_public_signed_prekey,
    };
    use roost_protocol::SignatureError;
    use roost_protocol::verify_with_context;
    use std::sync::Arc;

    /// Every Ed25519 signature context and canonical-encoding domain tag Roost defines, plus the
    /// protocol-state commit and lowercase hash domains.
    const DOMAIN_REGISTRY: [&str; 10] = [
        "AetherIKBinding-v1:",
        "AetherDK-v1:",
        "AetherDKToIK-v1:",
        "AetherSPK-v1:",
        "AetherMessageTranscript-v1:",
        "AetherIK-v1:",
        "AetherSafetyNumber-v1:",
        "AetherSenderCertificate-v2:",
        "RoostProtocolStateCommit-v1:",
        "aether-recipient-delivery-capability-v1",
    ];

    const RELAY_HTTP_AUTH_CONTEXT: &[u8] = b"Relay-HTTP-Auth-v1";
    const RELAY_PROTOCOL_VERSION: u16 = 1;
    const RELAY_CHALLENGE_NONCE: [u8; 32] = [0x22; 32];
    const RELAY_DOMAIN: &[u8] = b"relay.example";
    const RELAY_METHOD: &[u8] = b"POST";
    const RELAY_REQUEST_TARGET: &[u8] = b"/v1/prekeys?count=10";
    const RELAY_BODY_DIGEST: [u8; 32] = [0x33; 32];

    fn push_length_prefixed(transcript: &mut Vec<u8>, field: &[u8]) {
        transcript.extend_from_slice(&(field.len() as u16).to_be_bytes());
        transcript.extend_from_slice(field);
    }

    // Relay's authentication transcript: concat("Relay-HTTP-Auth-v1", protocol_version_u16_be, challenge_nonce,
    // identity_signing_key, len_u16_be(relay_domain), relay_domain, len_u16_be(method), method,
    // len_u16_be(request_target), request_target, SHA-256(request_body)). Fixed-width fields and
    // the context itself carry no length prefix, and nothing separates the context from what
    // follows it.
    fn relay_http_transcript(identity_signing_key: &[u8], body_digest: &[u8; 32]) -> Vec<u8> {
        let mut transcript = RELAY_HTTP_AUTH_CONTEXT.to_vec();
        transcript.extend_from_slice(&RELAY_PROTOCOL_VERSION.to_be_bytes());
        transcript.extend_from_slice(&RELAY_CHALLENGE_NONCE);
        transcript.extend_from_slice(identity_signing_key);
        push_length_prefixed(&mut transcript, RELAY_DOMAIN);
        push_length_prefixed(&mut transcript, RELAY_METHOD);
        push_length_prefixed(&mut transcript, RELAY_REQUEST_TARGET);
        transcript.extend_from_slice(body_digest);
        transcript
    }

    fn signature_from(bytes: &[u8]) -> Signature {
        Signature::from_bytes(&<[u8; 64]>::try_from(bytes).unwrap())
    }

    /// The signature must cover the transcript bytes and nothing else.
    ///
    /// The relay rebuilds the transcript alone and calls bare Ed25519 verify, so a context
    /// prepended on this side — what `sign_with_context` would do — yields a preimage the relay
    /// never reconstructs. That failure is silent at the boundary and only shows up as a signature
    /// that verifies nowhere, which is why it is pinned here rather than left to the caller.
    #[test]
    fn signed_authentication_transcript_verifies_bare_and_is_not_context_prefixed() {
        let store = key_store();
        let identity = store.generate_identity().unwrap();
        let transcript = relay_http_transcript(&identity.key.signing_key, &RELAY_BODY_DIGEST);

        let signature_bytes = store
            .sign_authentication_transcript(transcript.clone())
            .unwrap();

        assert_eq!(signature_bytes.len(), 64);
        let signature = signature_from(&signature_bytes);
        let verifying = verifying_key(&identity);
        assert!(verifying.verify_strict(&transcript, &signature).is_ok());
        // Re-prepending the transcript's own context is the exact shape a contextual signature
        // would have had. It must not verify, or this export would be signing the wrong preimage.
        assert!(matches!(
            verify_with_context(&verifying, RELAY_HTTP_AUTH_CONTEXT, &transcript, &signature),
            Err(SignatureError::SignatureInvalid)
        ));
        for context in DOMAIN_REGISTRY {
            assert!(matches!(
                verify_with_context(&verifying, context.as_bytes(), &transcript, &signature),
                Err(SignatureError::SignatureInvalid)
            ));
        }
        // Ed25519 is deterministic, so a host retrying the same challenge resends the same proof.
        assert_eq!(
            store.sign_authentication_transcript(transcript).unwrap(),
            signature_bytes
        );
    }

    /// An unrestricted "sign these bytes with the identity key" export would be a signing oracle
    /// over Roost's own preimages: the identity key is what signs identity bindings,
    /// discovery-key bindings, and message transcripts. Every context Roost signs or verifies
    /// under starts with `Aether` or `Roost`, so refusing those prefixes makes the two preimage
    /// sets disjoint.
    #[test]
    fn sign_authentication_transcript_refuses_reserved_preimages() {
        let store = key_store();
        let identity = store.generate_identity().unwrap();

        for context in DOMAIN_REGISTRY {
            let mut preimage = context.as_bytes().to_vec();
            preimage.extend_from_slice(&identity.key.agreement_key);
            preimage.extend_from_slice(&identity.key.signing_key);
            match store.sign_authentication_transcript(preimage) {
                Err(RoostError::InvalidData { .. }) => {}
                Err(error) => panic!("expected InvalidData for {context}, got {error}"),
                Ok(_) => panic!("expected InvalidData for {context}"),
            }
        }
    }

    /// Roost names its labels with an `Aether` or `Roost` prefix, and both are refused in any
    /// letter case.
    #[test]
    fn sign_authentication_transcript_refuses_reserved_prefixes_in_any_case() {
        let store = key_store();
        store.generate_identity().unwrap();

        for prefix in ["Aether", "aether", "AETHER", "Roost", "roost", "ROOST"] {
            let mut transcript = prefix.as_bytes().to_vec();
            transcript.extend_from_slice(&[0x41; 32]);
            match store.sign_authentication_transcript(transcript) {
                Err(RoostError::InvalidData { .. }) => {}
                other => panic!("expected InvalidData for {prefix}, got {other:?}"),
            }
        }
    }

    #[test]
    fn sign_authentication_transcript_bounds_transcript_length() {
        let store = key_store();
        store.generate_identity().unwrap();

        match store.sign_authentication_transcript(Vec::new()) {
            Err(RoostError::InvalidData { .. }) => {}
            other => panic!("expected InvalidData for an empty transcript, got {other:?}"),
        }
        match store
            .sign_authentication_transcript(vec![0x41; MAX_AUTHENTICATION_TRANSCRIPT_LEN + 1])
        {
            Err(RoostError::InvalidData { .. }) => {}
            other => panic!("expected InvalidData past the length cap, got {other:?}"),
        }
        assert!(
            store
                .sign_authentication_transcript(vec![0x41; MAX_AUTHENTICATION_TRANSCRIPT_LEN])
                .is_ok()
        );
    }

    #[test]
    fn sign_authentication_transcript_requires_a_stored_identity() {
        let store = key_store();

        match store.sign_authentication_transcript(b"Relay-HTTP-Auth-v1".to_vec()) {
            Err(RoostError::NotFound) => {}
            other => panic!("expected NotFound without an identity, got {other:?}"),
        }
    }

    fn key_store() -> Arc<IdentityContext> {
        let storage: Arc<dyn SecureStorage> = Arc::new(MemoryStorage::default());
        IdentityContext::new(storage)
    }

    fn verifying_key(identity: &FfiIdentity) -> VerifyingKey {
        VerifyingKey::from_bytes(
            &<[u8; 32]>::try_from(identity.key.signing_key.as_slice()).unwrap(),
        )
        .unwrap()
    }

    fn public_identity_key(identity: &FfiIdentity) -> CryptoPublicIdentityKey {
        CryptoPublicIdentityKey::from_bytes(
            &identity.key.agreement_key,
            &identity.key.signing_key,
            &identity.binding_signature,
        )
        .unwrap()
    }

    fn public_discovery_key(bundle: &FfiPublicDiscoveryKey) -> CryptoPublicDiscoveryKey {
        CryptoPublicDiscoveryKey::from_bytes(
            &bundle.public_key,
            &bundle.verifying_key,
            bundle.epoch,
            bundle.created_at_millis / 1_000,
            &bundle.signature,
        )
        .unwrap()
    }

    fn public_signed_prekey(bundle: &FfiPublicSignedPreKey) -> CryptoPublicSignedPreKey {
        CryptoPublicSignedPreKey {
            id: bundle.id,
            public_key: PublicKey::from(
                <[u8; 32]>::try_from(bundle.public_key.as_slice()).unwrap(),
            ),
            signature: Signature::from_bytes(
                &<[u8; 64]>::try_from(bundle.signature.as_slice()).unwrap(),
            ),
            epoch: bundle.epoch,
            created_at_secs: bundle.created_at_millis / 1_000,
        }
    }

    fn assert_discovery_key_verifies(
        identity: &FfiIdentity,
        discovery: &FfiPublicDiscoveryKey,
    ) -> CryptoPublicDiscoveryKey {
        let crypto_discovery = public_discovery_key(discovery);
        assert!(verify_public_discovery_key(&crypto_discovery, &verifying_key(identity)).is_ok());
        crypto_discovery
    }

    fn assert_signed_prekey_verifies(
        signed_prekey: &FfiPublicSignedPreKey,
        discovery: &CryptoPublicDiscoveryKey,
    ) {
        let crypto_prekey = public_signed_prekey(signed_prekey);
        assert!(verify_public_signed_prekey(&crypto_prekey, &discovery.verifying_key).is_ok());
    }

    fn assert_discovery_to_identity_verifies(
        identity: &FfiIdentity,
        publication: &FfiPublicationBundle,
        discovery: &CryptoPublicDiscoveryKey,
    ) {
        let signature = Signature::from_bytes(
            &<[u8; 64]>::try_from(publication.discovery_to_identity.as_slice()).unwrap(),
        );
        assert!(
            verify_discovery_to_identity_binding(
                &public_identity_key(identity),
                &discovery.verifying_key,
                &signature,
            )
            .is_ok()
        );
    }

    fn assert_publication_verifies(identity: &FfiIdentity, publication: &FfiPublicationBundle) {
        assert_eq!(publication.version, roost_crypto::PREKEY_BUNDLE_VERSION);
        let discovery = assert_discovery_key_verifies(identity, &publication.discovery_key);
        assert_signed_prekey_verifies(&publication.signed_prekey, &discovery);
        assert_discovery_to_identity_verifies(identity, publication, &discovery);
    }

    /// The host registers the verifier and shares the capability only with authorized contacts, so
    /// both must cross the FFI boundary and the verifier must commit to the capability actually in
    /// storage.
    #[test]
    fn publication_verifier_commits_to_the_capability_across_ffi() {
        let key_store = key_store();
        key_store.generate_identity().unwrap();
        key_store.rotate_signed_prekey_now().unwrap();

        let publication = key_store.current_publication().unwrap();
        let capability = key_store.current_delivery_capability().unwrap();

        assert_eq!(publication.recipient_delivery_verifier.len(), 32);
        assert_eq!(capability.len(), 32);
        // The capability is the secret; publishing it instead of the verifier would be the whole
        // bug this separation exists to prevent.
        assert_ne!(publication.recipient_delivery_verifier, capability);

        let expected =
            CryptoCapability::from_bytes(<[u8; 32]>::try_from(capability.as_slice()).unwrap());
        assert_eq!(
            publication.recipient_delivery_verifier,
            expected.verifier().as_bytes().to_vec()
        );
    }

    /// The DK→IK binding must survive the FFI boundary as 64 usable bytes, not merely exist on the
    /// Rust side. A host reads this field straight out of the generated record to populate
    /// `relay.cloud.v1.KeyBindingSignatures.discovery_to_identity`.
    #[test]
    fn publication_bundle_carries_discovery_to_identity_binding_across_ffi() {
        let key_store = key_store();
        let identity = key_store.generate_identity().unwrap();
        key_store.rotate_signed_prekey_now().unwrap();

        let publication = key_store.current_publication().unwrap();

        assert_eq!(publication.discovery_to_identity.len(), 64);
        assert_ne!(publication.discovery_to_identity, vec![0u8; 64]);
        assert_publication_verifies(&identity, &publication);
    }

    fn assert_one_time_prekey_record(bundle: &FfiPublicOneTimePreKey, epoch: u32) {
        assert_eq!(bundle.public_key.len(), 32);
        assert_eq!(bundle.epoch, epoch);
    }

    fn identity_key(identity: &FfiIdentity) -> IdentityKey {
        identity.key.clone()
    }

    fn current_discovery_key(store: &IdentityContext) -> FfiPublicDiscoveryKey {
        FfiPublicDiscoveryKey::from_core(store.inner.current_public_discovery_key().unwrap())
            .unwrap()
    }

    fn contact_identity(
        identity: &FfiIdentity,
        publication: &FfiPublicationBundle,
    ) -> ContactIdentity {
        ContactIdentity {
            identity_key: identity_key(identity),
            discovery_key: ContactDiscoveryKey {
                x25519_public_key: publication.discovery_key.public_key.clone(),
                ed25519_verifying_key: publication.discovery_key.verifying_key.clone(),
                epoch: publication.discovery_key.epoch,
                created_at_millis: publication.discovery_key.created_at_millis,
                identity_signature: publication.discovery_key.signature.clone(),
            },
        }
    }

    fn same_protocol_state_kind(left: ProtocolStateKind, right: ProtocolStateKind) -> bool {
        matches!(
            (left, right),
            (
                ProtocolStateKind::RatchetSession,
                ProtocolStateKind::RatchetSession
            ) | (
                ProtocolStateKind::DeduplicationSet,
                ProtocolStateKind::DeduplicationSet
            ) | (
                ProtocolStateKind::PendingAcknowledgments,
                ProtocolStateKind::PendingAcknowledgments
            ) | (
                ProtocolStateKind::ContactState,
                ProtocolStateKind::ContactState
            ) | (
                ProtocolStateKind::PeerInboxAuthorization,
                ProtocolStateKind::PeerInboxAuthorization
            ) | (
                ProtocolStateKind::LocalInboxAuthorization,
                ProtocolStateKind::LocalInboxAuthorization
            )
        )
    }

    fn assert_protocol_state_kind(actual: ProtocolStateKind, expected: ProtocolStateKind) {
        assert!(same_protocol_state_kind(actual, expected));
    }

    fn apply_updates(entries: &mut Vec<ProtocolStateEntry>, updates: Vec<ProtocolStateUpdate>) {
        for update in updates {
            entries.retain(|entry| {
                !same_protocol_state_kind(entry.kind, update.kind) || entry.key != update.key
            });
            if let Some(blob) = update.blob {
                entries.push(ProtocolStateEntry {
                    kind: update.kind,
                    key: update.key,
                    blob,
                });
            }
        }
    }

    #[test]
    fn wipe_returns_only_active_protocol_state_kinds() {
        let engine = IdentityContext::new(Arc::new(MemoryStorage::default())).messaging();

        let updates = engine.wipe(Vec::new(), vec![0x44; 16]).unwrap();

        assert_eq!(updates.len(), 6);
        assert_protocol_state_kind(updates[0].kind, ProtocolStateKind::RatchetSession);
        assert_protocol_state_kind(updates[1].kind, ProtocolStateKind::DeduplicationSet);
        assert_protocol_state_kind(updates[2].kind, ProtocolStateKind::PendingAcknowledgments);
        assert_protocol_state_kind(updates[3].kind, ProtocolStateKind::ContactState);
        // A wipe must reach the peer's delivery capability too, or session replacement leaves a
        // stale bearer secret behind with nothing left that uses it.
        assert_protocol_state_kind(updates[4].kind, ProtocolStateKind::PeerInboxAuthorization);
        assert_protocol_state_kind(updates[5].kind, ProtocolStateKind::LocalInboxAuthorization);
        assert!(updates.iter().all(|update| update.blob.is_none()));
    }

    fn copy_snapshot(entries: &[ProtocolStateEntry]) -> Vec<ProtocolStateEntry> {
        entries
            .iter()
            .map(|entry| ProtocolStateEntry {
                kind: entry.kind,
                key: entry.key.clone(),
                blob: entry.blob.clone(),
            })
            .collect()
    }

    #[test]
    fn generate_identity_returns_ffi_safe_public_keys() {
        let store = key_store();
        let identity = store.generate_identity().unwrap();
        assert_eq!(identity.key.agreement_key.len(), 32);
        assert_eq!(identity.key.signing_key.len(), 32);
        assert_eq!(identity.binding_signature.len(), 64);
        verifying_key(&identity);
        assert!(verify_public_identity_key(&public_identity_key(&identity)).is_ok());
    }

    #[test]
    fn rotate_signed_prekey_if_stale_returns_verifiable_record() {
        let store = key_store();
        let identity = store.generate_identity().unwrap();
        let signed_prekey = store
            .rotate_signed_prekey_if_stale()
            .unwrap()
            .expect("first rotate must produce a bundle");
        let discovery = current_discovery_key(&store);
        let crypto_discovery = assert_discovery_key_verifies(&identity, &discovery);
        assert_signed_prekey_verifies(&signed_prekey, &crypto_discovery);
    }

    #[test]
    fn current_publication_bundle_returns_verifiable_records() {
        let store = key_store();
        let identity = store.generate_identity().unwrap();
        store.rotate_signed_prekey_now().unwrap();
        let publication = store.current_publication().unwrap();
        assert_publication_verifies(&identity, &publication);
    }

    #[test]
    fn generate_one_time_prekeys_returns_public_records() {
        let store = key_store();
        store.generate_identity().unwrap();
        let discovery = current_discovery_key(&store);
        let bundles = store.generate_one_time_prekeys(3).unwrap();

        assert_eq!(bundles.len(), 3);
        assert_eq!(
            bundles.iter().map(|bundle| bundle.id).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        for bundle in &bundles {
            assert_one_time_prekey_record(bundle, discovery.epoch);
        }
    }

    #[test]
    fn rotate_inbox_now_advances_epoch_and_returns_verifiable_records() {
        let store = key_store();
        let identity = store.generate_identity().unwrap();
        let initial_discovery = current_discovery_key(&store);
        let rotation = store.rotate_inbox_now().unwrap();
        assert_eq!(
            rotation.publication.discovery_key.epoch,
            initial_discovery.epoch + 1
        );
        assert_publication_verifies(&identity, &rotation.publication);
        // The capability returned by the rotation is the one the new verifier commits to.
        assert_eq!(rotation.capability.len(), 32);
        assert_eq!(
            rotation.capability,
            store.current_delivery_capability().unwrap()
        );
    }

    #[test]
    fn replenish_one_time_prekeys_returns_public_records() {
        let store = key_store();
        store.generate_identity().unwrap();
        let discovery = current_discovery_key(&store);
        let bundles = store.replenish_one_time_prekeys().unwrap();

        assert_eq!(bundles.len(), 100);
        for bundle in &bundles {
            assert_one_time_prekey_record(bundle, discovery.epoch);
        }
        assert!(store.replenish_one_time_prekeys().unwrap().is_empty());
    }

    #[test]
    fn session_establishment_round_trips_first_message_through_ffi_records() {
        let alice = key_store();
        let bob = key_store();
        let alice_identity = alice.generate_identity().unwrap();
        let bob_identity = bob.generate_identity().unwrap();
        bob.rotate_signed_prekey_now().unwrap();
        let bob_publication = bob.current_publication().unwrap();
        let bob_one_time_prekey = bob.generate_one_time_prekeys(1).unwrap().remove(0);

        let session_key = vec![0x44; 16];
        let initiation = alice
            .messaging()
            .initiate_session(
                session_key.clone(),
                bob_identity,
                bob_publication,
                Some(bob_one_time_prekey),
                b"alice certificate".to_vec(),
                b"alice signature".to_vec(),
                b"hello bob".to_vec(),
                crate::TransportBinding {
                    bytes: b"test-route".to_vec(),
                },
            )
            .unwrap();

        assert!(initiation.message.prekey_reference.is_some());
        assert_eq!(initiation.state_updates.len(), 2);

        let acceptance = bob
            .accept_session(session_key, Some(alice_identity), initiation.message)
            .unwrap();

        assert_eq!(acceptance.plaintext, b"hello bob".to_vec());
        assert_eq!(
            acceptance.sender_identity.certificate,
            b"alice certificate".to_vec()
        );
        assert_eq!(acceptance.state_updates.len(), 2);
    }

    #[test]
    fn encrypt_message_returns_message_and_pending_state_update() {
        let alice = key_store();
        let bob = key_store();
        let alice_identity = alice.generate_identity().unwrap();
        let bob_identity = bob.generate_identity().unwrap();
        bob.rotate_signed_prekey_now().unwrap();
        let bob_publication = bob.current_publication().unwrap();
        let bob_one_time_prekey = bob.generate_one_time_prekeys(1).unwrap().remove(0);
        let session_key = vec![0x55; 16];
        let initiation = alice
            .messaging()
            .initiate_session(
                session_key.clone(),
                bob_identity.clone(),
                bob_publication.clone(),
                Some(bob_one_time_prekey),
                b"alice certificate".to_vec(),
                b"alice signature".to_vec(),
                b"hello bob".to_vec(),
                crate::TransportBinding {
                    bytes: b"test-route".to_vec(),
                },
            )
            .unwrap();
        let acceptance = bob
            .accept_session(
                session_key.clone(),
                Some(alice_identity),
                initiation.message.clone(),
            )
            .unwrap();

        let engine = IdentityContext::new(Arc::new(MemoryStorage::default())).messaging();
        let mut alice_snapshot = Vec::new();
        apply_updates(&mut alice_snapshot, initiation.state_updates);
        let change = alice
            .contacts()
            .record_contact(
                Vec::new(),
                contact_identity(&bob_identity, &bob_publication),
            )
            .unwrap();
        apply_updates(&mut alice_snapshot, change.state_updates);
        let accepted = alice
            .contacts()
            .accept_contact(copy_snapshot(&alice_snapshot), identity_key(&bob_identity))
            .unwrap();
        apply_updates(&mut alice_snapshot, accepted.state_updates);

        let outbound = alice
            .messaging()
            .encrypt_message(
                copy_snapshot(&alice_snapshot),
                session_key.clone(),
                vec![0x77; 16],
                identity_key(&bob_identity),
                bob_publication.discovery_key.public_key,
                42,
                b"alice certificate".to_vec(),
                b"alice signature".to_vec(),
                b"follow-up".to_vec(),
                crate::TransportBinding {
                    bytes: b"test-route".to_vec(),
                },
            )
            .unwrap();

        assert_eq!(outbound.message_id, vec![0x77; 16]);
        assert_eq!(outbound.state_updates.len(), 2);
        apply_updates(&mut alice_snapshot, outbound.state_updates);
        let pending = engine
            .pending_acknowledgments(alice_snapshot, session_key)
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(acceptance.plaintext, b"hello bob".to_vec());
    }

    #[test]
    fn decrypt_message_requires_certificate_validation_for_unique_message() {
        let alice = key_store();
        let bob = key_store();
        let alice_identity = alice.generate_identity().unwrap();
        let bob_identity = bob.generate_identity().unwrap();
        alice.rotate_signed_prekey_now().unwrap();
        bob.rotate_signed_prekey_now().unwrap();
        let alice_publication = alice.current_publication().unwrap();
        let bob_publication = bob.current_publication().unwrap();
        let bob_one_time_prekey = bob.generate_one_time_prekeys(1).unwrap().remove(0);
        let session_key = vec![0x66; 16];
        let initiation = alice
            .messaging()
            .initiate_session(
                session_key.clone(),
                bob_identity.clone(),
                bob_publication.clone(),
                Some(bob_one_time_prekey),
                b"alice certificate".to_vec(),
                b"alice signature".to_vec(),
                b"hello bob".to_vec(),
                crate::TransportBinding {
                    bytes: b"test-route".to_vec(),
                },
            )
            .unwrap();
        let acceptance = bob
            .accept_session(
                session_key.clone(),
                Some(alice_identity.clone()),
                initiation.message,
            )
            .unwrap();

        let engine = IdentityContext::new(Arc::new(MemoryStorage::default())).messaging();
        let mut alice_snapshot = Vec::new();
        apply_updates(&mut alice_snapshot, initiation.state_updates);
        let change = alice
            .contacts()
            .record_contact(
                Vec::new(),
                contact_identity(&bob_identity, &bob_publication),
            )
            .unwrap();
        apply_updates(&mut alice_snapshot, change.state_updates);
        let accepted = alice
            .contacts()
            .accept_contact(copy_snapshot(&alice_snapshot), identity_key(&bob_identity))
            .unwrap();
        apply_updates(&mut alice_snapshot, accepted.state_updates);
        let outbound = alice
            .messaging()
            .encrypt_message(
                alice_snapshot,
                session_key.clone(),
                vec![0x88; 16],
                identity_key(&bob_identity),
                bob_publication.discovery_key.public_key,
                43,
                b"alice certificate".to_vec(),
                b"alice signature".to_vec(),
                b"follow-up".to_vec(),
                crate::TransportBinding {
                    bytes: b"test-route".to_vec(),
                },
            )
            .unwrap();

        let mut bob_snapshot = Vec::new();
        apply_updates(&mut bob_snapshot, acceptance.state_updates);
        let deduplication_key = b"bob-dedup".to_vec();
        apply_updates(
            &mut bob_snapshot,
            vec![
                engine
                    .initialize_deduplication_set(deduplication_key.clone())
                    .unwrap(),
            ],
        );
        let result = bob.messaging().decrypt_message(
            bob_snapshot,
            session_key,
            deduplication_key,
            outbound.message,
            vec![0x99; 16],
            alice_publication.discovery_key.public_key,
            44,
            b"bob certificate".to_vec(),
            b"bob signature".to_vec(),
            None,
            crate::TransportBinding {
                bytes: b"test-route".to_vec(),
            },
            crate::TransportBinding {
                bytes: b"test-route".to_vec(),
            },
        );

        match result {
            Err(RoostError::InvalidData { .. }) => {}
            Err(error) => panic!("expected InvalidData, got {error}"),
            Ok(_) => panic!("expected InvalidData"),
        }
    }
}
