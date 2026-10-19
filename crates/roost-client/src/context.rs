//! The identity context and the messaging and contacts groups that share it.

use crate::SecureStorage;
use crate::error::RoostError;
use crate::identity::Identity;
use crate::operation::{
    OperationId, OperationStatus, PreparedIdentity, PreparedInboxRotation, PreparedOneTimePreKeys,
    PreparedSignedPreKeyRotation, UnfinishedOperation,
};
use crate::publication::{PublicOneTimePreKey, PublicSignedPreKey, PublicationBundle};
use crate::storage::SecureStorageAdapter;
use roost_core::{
    KeyStore as CoreKeyStore, PreparedKeyStoreOperation as CorePreparedKeyStoreOperation,
};
use std::sync::Arc;
use zeroize::Zeroizing;

/// Largest authentication transcript the Identity Key will sign, in bytes.
///
/// A relay authentication transcript is 159 bytes for the HTTP form and 120 for the WebSocket
/// form, so this leaves room for long request targets while keeping the export from doubling as a
/// bulk document signer.
const MAX_AUTHENTICATION_TRANSCRIPT_LEN: usize = 4096;

/// ASCII prefix reserved for preimages Roost signs or verifies itself.
///
/// Every signature context and domain tag Roost defines starts with it, so refusing it keeps
/// [`IdentityContext::sign_authentication_transcript`] disjoint from all of them. Matched
/// case-insensitively to cover the lowercase hash-domain convention as well.
const RESERVED_DOMAIN_PREFIX: &str = "Roost";

/// One local identity namespace: its keys in SecureStorage and every operation that uses them.
///
/// Create one context for each namespace, before or after the identity exists. Its
/// [`Self::messaging`] and [`Self::contacts`] groups share its storage. The context caches no
/// protocol state and holds no settings, so several contexts, including ones in an app extension,
/// can serve the same identity, and the app passes [`ReceiveSettings`](crate::ReceiveSettings) with
/// each receive.
///
/// Roost owns the identity's keys, backups, prekeys, inbox rotations, and the Inbox Grants that
/// share its inbox with contacts, the contents of Protocol State Blobs, and the journal that makes
/// key changes recoverable. It reads no clock
/// for certificate checks, does no networking, and keeps no copy of protocol state between calls.
///
/// The host owns the [`SecureStorage`] adapter, the database that stores Protocol State Blobs and
/// operation IDs, and its transactions. It stores the blobs without decoding them or keeping a
/// copy of its own, and calls Roost outside its database transactions, off the main thread. It
/// holds one lock that covers every process sharing the identity from preparing an operation until
/// its host commit is resolved.
///
/// The host protects stored blobs like identity keys, and keeps blobs, keys, passphrases, and
/// plaintext out of logs. Roost's tests don't cover the host's adapter or transactions, so the
/// host tests them itself.
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
}

/// Message, acknowledgment, delivery-check, and recovery operations for one [`IdentityContext`].
///
/// Each send and receive is a [`MessageEncryption`](crate::MessageEncryption) or
/// [`MessageDecryption`](crate::MessageDecryption) that asks the host for exact records and
/// Transport Bindings. The host commits each result's [`StateChanges`](crate::StateChanges)
/// together with its application effects. Roost starts Sessions with [`Contacts::request_contact`],
/// picks the Session for each Message, and finds it again from the SessionID each Message carries,
/// so the host never chooses one.
///
/// Send each Message until the Relay accepts it, then stop: the Relay redelivers it until the
/// contact saves it. A [`DeliveryCheck`](crate::DeliveryCheck) says when to send Messages again or
/// recover them on a newer Session, which only the sender can tell is needed, since the contact
/// can't tell who sent a Message it can't decrypt.
///
/// The SessionID is sealed to the recipient's Discovery Key, so anyone who gets that Discovery Key
/// can read it from recorded Messages and tell which of them belong to the same Session. Until the
/// recipient replies, every Message on a new Session also shows the transport which of the
/// recipient's prekeys started it, so the transport can tell those Messages belong together.
#[derive(uniffi::Object)]
pub struct Messaging {
    pub(crate) inner: Arc<CoreKeyStore>,
}

/// Contact Requests and acceptance, trust, blocking, and the decoders for contact records, for one
/// [`IdentityContext`].
///
/// A contact record exists only once someone asks: the host's own
/// [`Self::request_contact`] creates one when it commits, and so does a received Contact Request.
/// Roost shares this identity's Inbox Grant with contacts inside Messages, so the host never
/// handles a Delivery Capability except in an established Message's destination. Changes become
/// visible when the host commits them; read contacts through [`Self::contact_states`] after that.
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
            self.inner.prepare_identity_deletion()?.id,
        ))
    }

    /// Signs a host-built authentication transcript with the Identity Key and returns the
    /// 64-byte signature.
    ///
    /// The transcript is signed exactly as given, so the host puts its own domain separation inside
    /// it, as a relay authentication transcript does with its `Relay-HTTP-Auth-v1` prefix. Roost
    /// refuses a transcript that starts with `Roost`, in any letter case, because every preimage
    /// Roost signs starts with it: without the check, this method could sign an
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

    /// Prepares an inbox rotation: a Discovery Key at the next epoch, a signed prekey, and a
    /// Delivery Capability.
    ///
    /// Rotation clears the previous inbox's one-time prekeys and invalidates every contact's
    /// Delivery Capability. Roost keeps the previous Discovery Key long enough to open Messages
    /// the Relay still holds for it, but not the previous prekeys, so Contact Requests still
    /// queued for the old inbox are lost.
    ///
    /// After finalizing, register the new inbox with the Relay before sending anything, and on
    /// launch whenever [`Self::current_publication`] shows a newer epoch than the last one
    /// registered. Roost attaches the new Inbox Grant to each contact's Messages and
    /// acknowledgments from finalization on, until that contact acknowledges one. Send a Grant
    /// Update through [`Contacts::start_grant_update`] to each contact that should stay able to
    /// reach this identity without waiting for a Message.
    ///
    /// # Errors
    /// - [`RoostError::NotFound`] if no identity is stored.
    /// - [`RoostError::OperationRecoveryRequired`] if a reserved operation needs recovery.
    /// - [`RoostError::TooManyUnfinishedOperations`] if too many operations are unfinished.
    /// - [`RoostError::Storage`] if SecureStorage fails.
    pub fn prepare_inbox_rotation(&self) -> Result<PreparedInboxRotation, RoostError> {
        let (operation_id, publication) = convert_prepared(
            &self.inner,
            self.inner.prepare_inbox_rotation()?,
            PublicationBundle::from_core,
        )?;
        Ok(PreparedInboxRotation {
            operation_id,
            publication,
        })
    }

    /// Prepares a new signed prekey if the current one is missing or stale, and deletes the
    /// previous Discovery Keys the Relay can no longer hold Messages for.
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

fn convert_prepared<T, U>(
    store: &CoreKeyStore,
    prepared: CorePreparedKeyStoreOperation<T>,
    convert: impl FnOnce(T) -> Result<U, RoostError>,
) -> Result<(OperationId, U), RoostError> {
    let id = prepared.id;
    match convert(prepared.output) {
        Ok(output) => Ok((OperationId::from_core(id), output)),
        Err(error) => Err(abort_unconverted(store, Some(id), error)),
    }
}

// Aborts the operation whose prepared output failed to convert, since the host never sees it, or
// returns its identifier so the host can reconcile an uncertain cleanup after restart.
pub(crate) fn abort_unconverted(
    store: &CoreKeyStore,
    operation: Option<roost_core::KeyStoreOperationId>,
    error: RoostError,
) -> RoostError {
    let Some(id) = operation else {
        return error;
    };
    match store.abort_operation(id) {
        Ok(_) => error,
        Err(abort_error) => RoostError::OperationRecoveryRequired {
            operation_id: OperationId::from_core(id),
            reason: format!(
                "prepared output conversion failed and cleanup also failed: {}",
                crate::error::reason_from_chain(&abort_error)
            ),
        },
    }
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

    pub(crate) fn replenish_one_time_prekeys(
        &self,
    ) -> Result<Vec<PublicOneTimePreKey>, RoostError> {
        let prepared = self.prepare_one_time_prekey_replenishment()?;
        self.complete_prepared(prepared.operation_id, prepared.one_time_prekeys)
    }

    pub(crate) fn rotate_signed_prekey_now(&self) -> Result<PublicSignedPreKey, RoostError> {
        let prepared = self.prepare_signed_prekey_rotation()?;
        let signed_prekey = prepared.signed_prekey.ok_or(RoostError::InternalError {
            reason: "forced signed-prekey rotation returned no bundle".into(),
        })?;
        self.complete_prepared(prepared.operation_id, signed_prekey)
    }
}

#[cfg(test)]
mod tests {
    use super::{IdentityContext, MAX_AUTHENTICATION_TRANSCRIPT_LEN};
    use crate::storage::MemoryStorage;
    use crate::{
        Identity as FfiIdentity, PublicDiscoveryKey as FfiPublicDiscoveryKey,
        PublicOneTimePreKey as FfiPublicOneTimePreKey, PublicSignedPreKey as FfiPublicSignedPreKey,
        PublicationBundle as FfiPublicationBundle, RoostError, SecureStorage,
    };
    use roost_crypto::{
        PublicDiscoveryKey as CryptoPublicDiscoveryKey,
        PublicIdentityKey as CryptoPublicIdentityKey, PublicKey,
        PublicSignedPreKey as CryptoPublicSignedPreKey, Signature, VerifyingKey,
        verify_discovery_to_identity_binding, verify_public_discovery_key,
        verify_public_identity_key, verify_public_signed_prekey,
    };
    use roost_protocol::SignatureError;
    use roost_protocol::verify_with_context;
    use std::sync::Arc;

    /// Every Ed25519 signature context and canonical-encoding domain tag Roost defines, plus the
    /// protocol-state commit and lowercase hash domains.
    const DOMAIN_REGISTRY: [&str; 10] = [
        "RoostIKBinding-v1:",
        "RoostDK-v1:",
        "RoostDKToIK-v1:",
        "RoostSPK-v1:",
        "RoostMessageTranscript-v1:",
        "RoostIK-v1:",
        "RoostSafetyNumber-v1:",
        "RoostSenderCertificate-v2:",
        "RoostProtocolStateCommit-v1:",
        "roost-recipient-delivery-capability-v1",
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
        verifying.verify_strict(&transcript, &signature).unwrap();
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
    /// under starts with `Roost`, so refusing that prefix makes the two preimage sets disjoint.
    /// Roost names its labels with a `Roost` prefix, which is refused in any letter case, and
    /// every preimage Roost signs itself is refused too.
    #[test]
    fn sign_authentication_transcript_refuses_reserved_preimages_and_prefixes() {
        let store = key_store();
        let identity = store.generate_identity().unwrap();
        let preimages = DOMAIN_REGISTRY.iter().map(|context| {
            [
                context.as_bytes(),
                &identity.key.agreement_key,
                &identity.key.signing_key,
            ]
            .concat()
        });
        let prefixed = ["Roost", "roost", "ROOST"]
            .iter()
            .map(|prefix| [prefix.as_bytes(), &[0x41; 32]].concat());

        for transcript in preimages.chain(prefixed) {
            let start = String::from_utf8_lossy(&transcript[..10]).into_owned();
            assert!(
                matches!(
                    store.sign_authentication_transcript(transcript),
                    Err(RoostError::InvalidData { .. })
                ),
                "expected InvalidData for a transcript starting {start}"
            );
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
        store
            .sign_authentication_transcript(vec![0x41; MAX_AUTHENTICATION_TRANSCRIPT_LEN])
            .unwrap();
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
        verify_public_discovery_key(&crypto_discovery, &verifying_key(identity)).unwrap();
        crypto_discovery
    }

    fn assert_signed_prekey_verifies(
        signed_prekey: &FfiPublicSignedPreKey,
        discovery: &CryptoPublicDiscoveryKey,
    ) {
        let crypto_prekey = public_signed_prekey(signed_prekey);
        verify_public_signed_prekey(&crypto_prekey, &discovery.verifying_key).unwrap();
    }

    fn assert_discovery_to_identity_verifies(
        identity: &FfiIdentity,
        publication: &FfiPublicationBundle,
        discovery: &CryptoPublicDiscoveryKey,
    ) {
        let signature = Signature::from_bytes(
            &<[u8; 64]>::try_from(publication.discovery_to_identity.as_slice()).unwrap(),
        );
        verify_discovery_to_identity_binding(
            &public_identity_key(identity),
            &discovery.verifying_key,
            &signature,
        )
        .unwrap();
    }

    fn assert_publication_verifies(identity: &FfiIdentity, publication: &FfiPublicationBundle) {
        assert_eq!(publication.version, roost_crypto::PREKEY_BUNDLE_VERSION);
        let discovery = assert_discovery_key_verifies(identity, &publication.discovery_key);
        assert_signed_prekey_verifies(&publication.signed_prekey, &discovery);
        assert_discovery_to_identity_verifies(identity, publication, &discovery);
    }

    fn assert_one_time_prekey_record(bundle: &FfiPublicOneTimePreKey, epoch: u32) {
        assert_eq!(bundle.public_key.len(), 32);
        assert_eq!(bundle.epoch, epoch);
    }

    #[test]
    fn generate_identity_returns_ffi_safe_public_keys() {
        let store = key_store();
        let identity = store.generate_identity().unwrap();
        assert_eq!(identity.key.agreement_key.len(), 32);
        assert_eq!(identity.key.signing_key.len(), 32);
        assert_eq!(identity.binding_signature.len(), 64);
        verifying_key(&identity);
        verify_public_identity_key(&public_identity_key(&identity)).unwrap();
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
    fn replenish_one_time_prekeys_returns_public_records() {
        let store = key_store();
        store.generate_identity().unwrap();
        store.rotate_signed_prekey_now().unwrap();
        let epoch = store.current_publication().unwrap().discovery_key.epoch;
        let bundles = store.replenish_one_time_prekeys().unwrap();

        assert_eq!(bundles.len(), 100);
        for bundle in &bundles {
            assert_one_time_prekey_record(bundle, epoch);
        }
        assert!(store.replenish_one_time_prekeys().unwrap().is_empty());
    }
}
