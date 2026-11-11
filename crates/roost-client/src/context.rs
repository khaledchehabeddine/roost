//! The identity context and the messaging and contacts groups that share it.

use crate::SecureStorage;
use crate::error::RoostError;
use crate::identity::Identity;
use crate::operation::{
    OperationId, OperationStatus, PreparedIdentity, PreparedInboxRotation, PreparedOneTimePreKeys,
    PreparedSignedPreKeyRotation, UnfinishedOperation,
};
use crate::publication::{PublicSignedPreKey, PublicationBundle};
use crate::storage::SecureStorageAdapter;
use rand::rngs::OsRng;
use roost_core::KeyStore as CoreKeyStore;
use std::sync::Arc;
use zeroize::Zeroizing;

/// ASCII prefix reserved for preimages Roost signs or verifies itself.
///
/// Every signature context and domain tag Roost defines starts with it, so refusing it keeps
/// [`IdentityContext::sign_authentication_transcript`] disjoint from all of them. Matched in any
/// letter case, so a label written in lowercase stays covered.
const RESERVED_DOMAIN_PREFIX: &str = "Roost";

/// One local identity namespace: its keys in SecureStorage and every operation that uses them.
///
/// Create one context for each namespace, before or after the identity exists. Its
/// [`Self::messaging`] and [`Self::contacts`] groups share its storage. The context caches no
/// protocol state and holds no settings, so several contexts, including ones in an app extension,
/// can serve the same identity, and the app passes [`ReceiveSettings`](crate::ReceiveSettings) with
/// each receive.
///
/// Roost owns the identity's keys, backups, prekeys, inbox rotations, and the inbox grants that
/// share its inbox with contacts, the contents of protocol state blobs, and the journal that lets
/// an interrupted key change finish. It reads no clock for certificate checks, does no networking,
/// and keeps no copy of protocol state between calls.
///
/// The app owns the [`SecureStorage`] adapter, the database that stores protocol state blobs and
/// operation IDs, and its transactions. It stores the blobs without decoding them or keeping a
/// copy of its own, and calls Roost outside its database transactions, off the main thread. It
/// holds the identity lock, one lock that covers every process sharing the identity, from the
/// first call of any operation, such as a send or a key change, until its commit is resolved, and
/// while it resolves unfinished operations.
///
/// The app also owns the times it passes, such as send times and the current time for delivery
/// checks and certificate checks. The app takes them all from one clock that every process shares,
/// such as the device clock plus an offset measured from the relay's responses. Certificate checks
/// compare that time with an expiry the relay set, so it must be right. Delivery checks compare it
/// with the send times the app passed, so a clock that jumps starts recoveries early or late.
/// Roost reads the device clock itself only to date and expire its own keys.
///
/// The app protects stored blobs like identity keys, and keeps blobs, keys, passphrases, and
/// plaintext out of logs. Roost's tests don't cover the app's adapter or transactions, so the app
/// tests them itself.
///
/// # Key Changes
///
/// A method whose name starts with `prepare` stages a change in SecureStorage and returns its
/// output and an [`OperationId`]. Nothing is authoritative until the app:
///
/// 1. Calls [`Self::reserve_operation`].
/// 2. Commits the output with the operation ID in one transaction.
/// 3. Calls [`Self::finalize_operation`], then publishes the output.
///
/// When the commit definitely failed, call [`Self::abort_operation`] instead. When the outcome is
/// unknown, such as after a lost reply or a cancellation, neither finalize nor abort until you
/// resolve it as at startup. Releasing a context never aborts its operations.
///
/// At startup, and after any unknown outcome, resolve each of [`Self::unfinished_operations`]
/// against the app's records: finalize a reserved or finalizing operation whose ID the app
/// committed, abort a prepared or reserved one whose ID it didn't, and stop on anything else. An
/// app that records finalization itself also checks each committed operation it hasn't marked,
/// since a crash between finalizing and marking leaves [`Self::operation_status`] reporting it
/// finalized. When SecureStorage has no identity but the app's records still hold one, stop
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
///     case .unknown: throw StartupError.outcomeUnknown
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
///         CommitResult.UNKNOWN -> throw OutcomeUnknown()
///     }
/// }
/// ```
#[derive(uniffi::Object)]
pub struct IdentityContext {
    pub(crate) inner: Arc<CoreKeyStore>,
}

/// Message, acknowledgment, delivery-check, and recovery operations for one [`IdentityContext`].
///
/// Each send and receive is a [`MessageEncryption`](crate::MessageEncryption) or
/// [`MessageDecryption`](crate::MessageDecryption) that asks the app for exact records and
/// transport bindings. The app commits each result's [`StateChanges`](crate::StateChanges)
/// together with its application effects. Roost starts sessions with [`Contacts::request_contact`],
/// picks the session for each message, and finds it again from the session ID each message carries,
/// so the app never chooses one.
///
/// Send each message until the relay accepts it, then stop, since the relay redelivers it until the
/// contact saves it. A [`DeliveryCheck`](crate::DeliveryCheck) says when to recover messages on a
/// newer session, which only the sender can tell is needed, since the contact can't tell who sent a
/// message it can't decrypt.
///
/// The session ID is sealed to the recipient's discovery key, so anyone who gets that discovery key
/// can read it from recorded messages and tell which of them belong to the same session. Until the
/// recipient replies, or for a contact request until the recipient accepts, every message on a new
/// session also shows the transport which of the recipient's prekeys started it, so the transport
/// can tell those messages belong together.
#[derive(uniffi::Object)]
pub struct Messaging {
    pub(crate) inner: Arc<CoreKeyStore>,
}

/// Contact requests and acceptance, trust, blocking, and the decoders for contact records, for one
/// [`IdentityContext`].
///
/// A contact record exists only once someone asks. The app's own [`Self::request_contact`] creates
/// one when it commits, and so does a received contact request. Roost shares this identity's inbox
/// grant with contacts inside messages, so the app never handles a delivery capability except in an
/// established message's destination. Changes become visible when the app commits them, so read
/// contacts through [`Self::contact_states`] after that.
#[derive(uniffi::Object)]
pub struct Contacts {
    pub(crate) inner: Arc<CoreKeyStore>,
}

#[uniffi::export]
impl IdentityContext {
    /// Creates a context over `secure_storage`.
    ///
    /// Creating a context reads and writes nothing.
    #[uniffi::constructor]
    pub fn new(secure_storage: Arc<dyn SecureStorage>) -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(CoreKeyStore::new(Box::new(SecureStorageAdapter::new(
                secure_storage,
            )))),
        })
    }

    /// Returns the messaging group, which shares this context's storage.
    pub fn messaging(&self) -> Arc<Messaging> {
        Arc::new(Messaging {
            inner: Arc::clone(&self.inner),
        })
    }

    /// Returns the contacts group, which shares this context's storage.
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
    /// - [`RoostError::Corrupt`] if the operation journal is corrupt.
    /// - [`RoostError::UnfinishedReservation`] if a reserved operation is unfinished.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn identity(&self) -> Result<Option<Identity>, RoostError> {
        self.inner
            .identity()?
            .map(|identity| Ok(Identity::from_core(identity)?))
            .transpose()
    }

    /// Prepares a new identity and its first discovery key.
    ///
    /// The app saves the identity with the operation ID, and publishes it only after
    /// finalization.
    ///
    /// # Errors
    /// - [`RoostError::AlreadyExists`] if an identity is already stored.
    /// - [`RoostError::Corrupt`] if the operation journal is corrupt.
    /// - [`RoostError::UnfinishedReservation`] if a reserved operation is unfinished.
    /// - [`RoostError::TooManyUnfinishedOperations`] if too many operations are unfinished.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn prepare_identity_creation(&self) -> Result<PreparedIdentity, RoostError> {
        let prepared = self.inner.prepare_identity_creation(&mut OsRng)?;
        Ok(PreparedIdentity {
            operation_id: OperationId::from_core(prepared.id),
            identity: Identity::from_core(prepared.output)?,
        })
    }

    /// Prepares deletion of the identity and all of its keys.
    ///
    /// The app deletes its protocol state for the identity in the transaction that saves the
    /// operation ID. Preparing deletion with no identity stored still returns an operation.
    ///
    /// # Errors
    /// - [`RoostError::Corrupt`] if the operation journal is corrupt.
    /// - [`RoostError::UnfinishedReservation`] if a reserved operation is unfinished.
    /// - [`RoostError::TooManyUnfinishedOperations`] if too many operations are unfinished.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn prepare_identity_deletion(&self) -> Result<OperationId, RoostError> {
        Ok(OperationId::from_core(
            self.inner.prepare_identity_deletion(&mut OsRng)?.id,
        ))
    }

    /// Signs an app-built authentication transcript with the identity key and returns the 64-byte
    /// signature.
    ///
    /// The transcript is signed exactly as given, so the app puts its own domain separation inside
    /// it, as a relay authentication transcript does with its `Relay-HTTP-Auth-v1` prefix. Roost
    /// refuses a transcript that starts with `Roost`, in any letter case, because every preimage
    /// Roost signs starts with it. Without the check, this method could sign an identity binding or
    /// a message transcript chosen by whoever supplied the bytes. Signing is deterministic, so the
    /// same transcript always gives the same signature.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if the transcript starts with the reserved prefix.
    /// - [`RoostError::NotFound`] if no identity is stored.
    /// - [`RoostError::Corrupt`] if the operation journal is corrupt.
    /// - [`RoostError::UnfinishedReservation`] if a reserved operation is unfinished.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn sign_authentication_transcript(
        &self,
        transcript: Vec<u8>,
    ) -> Result<Vec<u8>, RoostError> {
        check_signable_transcript(&transcript)?;
        Ok(self
            .inner
            .load_identity()?
            .sign(&transcript)
            .to_bytes()
            .to_vec())
    }

    /// Returns a passphrase-encrypted backup of the identity and its current discovery key.
    ///
    /// Each call runs Argon2id with 64 MiB of memory, so call it off the main thread. The backup is
    /// about 295 bytes and restores on any device with [`Self::prepare_backup_import`].
    ///
    /// # Errors
    /// - [`RoostError::BackupFailed`] if key derivation or encryption fails.
    /// - [`RoostError::NotFound`] if no identity or discovery key is stored.
    /// - [`RoostError::Corrupt`] if the operation journal is corrupt.
    /// - [`RoostError::UnfinishedReservation`] if a reserved operation is unfinished.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn export_encrypted_backup(&self, passphrase: String) -> Result<Vec<u8>, RoostError> {
        let passphrase = Zeroizing::new(passphrase);
        Ok(self
            .inner
            .export_encrypted_backup(&mut OsRng, &passphrase)?)
    }

    /// Prepares replacing this context's identity with the one in `backup`.
    ///
    /// A wrong passphrase or a damaged backup fails here and changes nothing. In the transaction
    /// that saves the operation ID, the app keeps the
    /// [`ProtocolStateKind::ContactState`](crate::ProtocolStateKind::ContactState) records it
    /// restored with its own database and deletes every other protocol-state record for the
    /// identity. Reusing a restored session would reuse its encryption keys, so this identity's
    /// next message to each accepted contact starts a new session, and the contact encrypts its
    /// unacknowledged messages again on it. In the same transaction, show each sent message that
    /// has content and no acknowledgment yet as not delivered, since Roost stops tracking a message
    /// once its session is deleted. After finalization, prekeys and publication stay blocked until
    /// [`Self::prepare_inbox_rotation`] moves to the next discovery key epoch, so the restored
    /// identity never reuses prekey IDs already published under the backed-up one. Then send each
    /// contact a grant update through [`Contacts::start_grant_update`], so every contact can reach
    /// this identity again without a new link. A grant update to a contact this identity asked,
    /// and that hasn't accepted, fails with [`RoostError::ContactNotAccepted`], since the restore
    /// dropped the session its acceptance would arrive on. Send that contact a new request through
    /// [`Contacts::request_contact`] instead. If it accepted meanwhile, its acknowledgment of the
    /// request accepts it on this side too. Each call runs Argon2id with 64 MiB of memory.
    ///
    /// # Errors
    /// - [`RoostError::DecryptionFailed`] if the passphrase is wrong or the backup was altered.
    /// - [`RoostError::InvalidData`] or [`RoostError::UnsupportedVersion`] if the backup is
    ///   malformed.
    /// - [`RoostError::Corrupt`] if the operation journal is corrupt.
    /// - [`RoostError::UnfinishedReservation`] if a reserved operation is unfinished.
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
                .prepare_backup_import(&mut OsRng, backup.as_slice(), passphrase.as_str())?
                .id,
        ))
    }

    /// Returns the current discovery key and signed prekey, which verify as one chain.
    ///
    /// Publish the two together, since reading them separately could pair keys from different
    /// rotations, which peers reject.
    ///
    /// # Errors
    /// - [`RoostError::Corrupt`] if the stored keys don't verify as a chain, or the operation
    ///   journal is corrupt.
    /// - [`RoostError::InboxRotationRequired`] after a backup restore, until an inbox rotation.
    /// - [`RoostError::NotFound`] if no identity, discovery key, or signed prekey is stored.
    /// - [`RoostError::UnfinishedReservation`] if a reserved operation is unfinished.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn current_publication(&self) -> Result<PublicationBundle, RoostError> {
        PublicationBundle::from_core(self.inner.current_publication()?)
    }

    /// Returns this identity's contact publication, the bytes a contact link carries.
    ///
    /// The publication holds the identity and its current discovery key with the signatures that
    /// bind them, and nothing secret. The app owns the rest of the link, including how it writes
    /// these bytes into it. Make a new link after each inbox rotation, since an older one leads to
    /// an inbox the relay no longer serves.
    ///
    /// # Errors
    /// - [`RoostError::Corrupt`] if the stored keys don't verify as a chain, or the operation
    ///   journal is corrupt.
    /// - [`RoostError::InboxRotationRequired`] after a backup restore, until an inbox rotation.
    /// - [`RoostError::InvalidData`] if the stored identity is malformed.
    /// - [`RoostError::NotFound`] if no identity, discovery key, or signed prekey is stored.
    /// - [`RoostError::UnfinishedReservation`] if a reserved operation is unfinished.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    /// - [`RoostError::UnsupportedVersion`] if the stored identity uses an unknown format version.
    pub fn encode_contact_publication(&self) -> Result<Vec<u8>, RoostError> {
        Ok(self.inner.contact_publication()?.encode()?)
    }

    /// Prepares an inbox rotation: a discovery key at the next epoch, a signed prekey, and a
    /// delivery capability.
    ///
    /// Rotation clears the previous inbox's one-time prekeys and invalidates every contact's
    /// delivery capability. Roost keeps the previous discovery key long enough to open messages
    /// the relay still holds for it, but not the previous prekeys, so contact requests still
    /// queued for the old inbox are lost.
    ///
    /// After finalizing, register the new inbox with the relay before sending anything, and on
    /// launch whenever [`Self::current_publication`] shows a newer epoch than the last one
    /// registered. Roost attaches the new inbox grant to each contact's messages and
    /// acknowledgments from finalization on, until that contact acknowledges one. Send a grant
    /// update through [`Contacts::start_grant_update`] to each contact that should stay able to
    /// reach this identity without waiting for a message.
    ///
    /// # Errors
    /// - [`RoostError::NotFound`] if no identity is stored.
    /// - [`RoostError::Corrupt`] if the operation journal is corrupt.
    /// - [`RoostError::UnfinishedReservation`] if a reserved operation is unfinished.
    /// - [`RoostError::TooManyUnfinishedOperations`] if too many operations are unfinished.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn prepare_inbox_rotation(&self) -> Result<PreparedInboxRotation, RoostError> {
        let prepared = self.inner.prepare_inbox_rotation(&mut OsRng)?;
        Ok(PreparedInboxRotation {
            operation_id: OperationId::from_core(prepared.id),
            publication: PublicationBundle::from_core(prepared.output)?,
        })
    }

    /// Prepares a new signed prekey if the current one is missing or stale, and deletes the
    /// previous discovery keys the relay can no longer hold messages for.
    ///
    /// Call this at launch. Finalize or abort the operation even when it returns no signed prekey.
    ///
    /// # Errors
    /// - [`RoostError::InboxRotationRequired`] after a backup restore, until an inbox rotation.
    /// - [`RoostError::InvalidData`] if five older signed prekeys remain, so a rotation would
    ///   discard one that hasn't expired.
    /// - [`RoostError::NotFound`] if no identity or discovery key is stored.
    /// - [`RoostError::Corrupt`] if the operation journal is corrupt.
    /// - [`RoostError::UnfinishedReservation`] if a reserved operation is unfinished.
    /// - [`RoostError::TooManyUnfinishedOperations`] if too many operations are unfinished.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn prepare_signed_prekey_rotation_and_discovery_key_cleanup(
        &self,
    ) -> Result<PreparedSignedPreKeyRotation, RoostError> {
        let prepared = self
            .inner
            .prepare_signed_prekey_rotation_and_discovery_key_cleanup(&mut OsRng)?;
        Ok(PreparedSignedPreKeyRotation {
            operation_id: OperationId::from_core(prepared.id),
            signed_prekey: prepared
                .output
                .map(PublicSignedPreKey::from_core)
                .transpose()?,
        })
    }

    /// Prepares exactly `count` one-time prekeys for the current discovery key.
    ///
    /// # Errors
    /// - [`RoostError::InboxRotationRequired`] after a backup restore, until an inbox rotation.
    /// - [`RoostError::InvalidData`] if the pool can't hold `count` more prekeys.
    /// - [`RoostError::NotFound`] if no identity or discovery key is stored.
    /// - [`RoostError::Corrupt`] if the operation journal is corrupt.
    /// - [`RoostError::UnfinishedReservation`] if a reserved operation is unfinished.
    /// - [`RoostError::TooManyUnfinishedOperations`] if too many operations are unfinished.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn prepare_one_time_prekeys(
        &self,
        count: u32,
    ) -> Result<PreparedOneTimePreKeys, RoostError> {
        // A `u32` fits in `usize` on every target Roost builds for.
        let prepared = self
            .inner
            .prepare_one_time_prekeys(&mut OsRng, count as usize)?;
        Ok(PreparedOneTimePreKeys::from_core(prepared))
    }

    /// Prepares one-time prekeys to refill the pool once it runs low.
    ///
    /// Returns no prekeys while the pool is above its threshold. Finalize or abort the operation
    /// either way.
    ///
    /// # Errors
    /// - [`RoostError::InboxRotationRequired`] after a backup restore, until an inbox rotation.
    /// - [`RoostError::NotFound`] if no identity or discovery key is stored.
    /// - [`RoostError::Corrupt`] if the operation journal is corrupt.
    /// - [`RoostError::UnfinishedReservation`] if a reserved operation is unfinished.
    /// - [`RoostError::TooManyUnfinishedOperations`] if too many operations are unfinished.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn prepare_one_time_prekey_replenishment(
        &self,
    ) -> Result<PreparedOneTimePreKeys, RoostError> {
        let prepared = self
            .inner
            .prepare_one_time_prekey_replenishment(&mut OsRng)?;
        Ok(PreparedOneTimePreKeys::from_core(prepared))
    }

    /// Checks that SecureStorage still matches what a prepared operation read, and reserves it for
    /// the app's commit.
    ///
    /// Reserving again does nothing. Until the reserved operation is finalized or aborted, other
    /// calls return [`RoostError::UnfinishedReservation`].
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if `id` isn't a valid operation ID.
    /// - [`RoostError::NotFound`] if no recent operation has this ID.
    /// - [`RoostError::OperationConflict`] if the operation was aborted.
    /// - [`RoostError::Corrupt`] if the operation journal is corrupt.
    /// - [`RoostError::UnfinishedReservation`] if another reserved operation is unfinished.
    /// - [`RoostError::SecureStoragePreconditionChanged`] if another operation changed the keys
    ///   this one read. Abort it and prepare again.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn reserve_operation(&self, id: OperationId) -> Result<(), RoostError> {
        self.inner.reserve_operation(id.to_core()?)?;
        Ok(())
    }

    /// Applies a reserved operation's staged changes after the app's commit.
    ///
    /// Finalizing again resumes an interrupted finalization, or does nothing once it's done.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if `id` isn't a valid operation ID.
    /// - [`RoostError::NotFound`] if no recent operation has this ID.
    /// - [`RoostError::OperationConflict`] if the operation isn't reserved or was aborted.
    /// - [`RoostError::Corrupt`] if the operation journal is corrupt.
    /// - [`RoostError::Storage`] if SecureStorage fails. Finalize again to resume.
    pub fn finalize_operation(&self, id: OperationId) -> Result<(), RoostError> {
        self.inner.finalize_operation(id.to_core()?)?;
        Ok(())
    }

    /// Discards a prepared or reserved operation's staged changes.
    ///
    /// Abort a reserved operation only when the app's commit definitely didn't happen. Aborting
    /// again does nothing.
    ///
    /// # Errors
    /// - [`RoostError::InvalidData`] if `id` isn't a valid operation ID.
    /// - [`RoostError::NotFound`] if no recent operation has this ID.
    /// - [`RoostError::OperationConflict`] if finalization already started.
    /// - [`RoostError::Corrupt`] if the operation journal is corrupt.
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
    /// - [`RoostError::Corrupt`] if the operation journal is corrupt.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn operation_status(&self, id: OperationId) -> Result<OperationStatus, RoostError> {
        Ok(OperationStatus::from_core(
            self.inner.operation_status(id.to_core()?)?,
        ))
    }

    /// Returns every operation that is neither finalized nor aborted.
    ///
    /// # Errors
    /// - [`RoostError::Corrupt`] if the operation journal is corrupt.
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

fn check_signable_transcript(transcript: &[u8]) -> Result<(), RoostError> {
    if transcript
        .get(..RESERVED_DOMAIN_PREFIX.len())
        .is_some_and(|start| start.eq_ignore_ascii_case(RESERVED_DOMAIN_PREFIX.as_bytes()))
    {
        return Err(RoostError::InvalidData {
            reason: format!(
                "authentication transcript starts with the reserved {RESERVED_DOMAIN_PREFIX} \
                 domain prefix"
            ),
        });
    }
    Ok(())
}
