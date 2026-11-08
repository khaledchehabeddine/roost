mod messaging;
mod operation;

pub use messaging::MessageStartError;
pub use operation::{
    JournalCorruption, KeyStoreOperationError, KeyStoreOperationId, KeyStoreOperationStatus,
    PreparedKeyStoreOperation, UnfinishedKeyStoreOperation,
};

use crate::contact_publication::ContactPublication;
use crate::discovery_key::{DiscoveryKeyError, DiscoveryKeyManager};
use crate::identity::{Identity, IdentityError, IdentityManager, decrypt_backup};
use crate::one_time_prekey::{OneTimePreKeyError, OneTimePreKeyManager};
use crate::protocol_state::{ProtocolStateBlob, ProtocolStateEngine, StateChanges};
use crate::signed_prekey::{SignedPreKeyError, SignedPreKeyManager};
use crate::storage::SecureStorage;
use rand::{CryptoRng, RngCore};
use roost_crypto::{
    PREKEY_BUNDLE_VERSION, PublicDiscoveryKey, PublicOneTimePreKey, PublicSignedPreKey,
    RecipientDeliveryVerifier, Signature, verify_public_signed_prekey,
};
use roost_protocol::IdentityKey;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::SystemTime;

/// Errors returned by [`KeyStore`] operations.
#[derive(Debug, thiserror::Error)]
pub enum KeyStoreError {
    /// A discovery key operation failed.
    #[error(transparent)]
    Discovery(#[from] DiscoveryKeyError),
    /// An identity-layer operation failed.
    #[error(transparent)]
    Identity(#[from] IdentityError),
    /// A one-time prekey operation failed.
    #[error(transparent)]
    OneTimePreKey(#[from] OneTimePreKeyError),
    /// A prepared-operation lifecycle step failed.
    #[error(transparent)]
    Operation(#[from] KeyStoreOperationError),
    /// A protocol-state operation failed.
    #[error(transparent)]
    ProtocolState(#[from] crate::protocol_state::ProtocolStateError),
    /// A signed prekey operation failed.
    #[error(transparent)]
    SignedPreKey(#[from] SignedPreKeyError),
}

/// A key publication that verifies from the identity key to the discovery key to the signed
/// prekey.
///
/// Peers verify [`Self::discovery_key`] with the identity verifying key, then verify
/// [`Self::signed_prekey`] with the discovery key's verifying key.
#[derive(Clone, Debug)]
pub struct PublicationBundle {
    /// Version of the public prekey bundle format.
    pub version: u8,
    /// The discovery key for this publication.
    ///
    /// Its `identity_signature` field is the identity key's half of the mutual binding.
    pub discovery_key: PublicDiscoveryKey,
    /// The discovery key's half of the mutual binding: [`Self::discovery_key`] signing the identity
    /// it belongs to.
    ///
    /// A relay verifies both halves before accepting a registration, and a peer that starts from a
    /// discovery key verifies this one to learn that the discovery key authorized the identity.
    pub discovery_to_identity: Signature,
    /// Public commitment to the delivery capability of this inbox.
    ///
    /// Register this with the relay. The capability it commits to is a secret that Roost shares
    /// with contacts only inside inbox grants.
    pub recipient_delivery_verifier: RecipientDeliveryVerifier,
    /// The signed prekey for this publication.
    pub signed_prekey: PublicSignedPreKey,
}

/// Result of blocking a contact.
pub struct ContactBlock {
    /// The contact change to commit, carrying the inbox rotation's prepared KeyStore operation
    /// when the block rotated the inbox.
    pub changes: StateChanges,
    /// The rotated inbox's publication, or `None` when the contact was already blocked.
    ///
    /// Present means every remaining contact holds a stale delivery capability until a message,
    /// acknowledgment, or grant update carries them the new inbox grant. The blocked contact never
    /// gets one, which is what makes the block bite at the relay rather than only locally.
    pub publication: Option<PublicationBundle>,
}

struct KeyStoreInner {
    storage: Arc<Mutex<Box<dyn SecureStorage>>>,
    identity: Arc<IdentityManager>,
    discovery: Arc<DiscoveryKeyManager>,
    one_time_prekey: Arc<OneTimePreKeyManager>,
    signed_prekey: Arc<SignedPreKeyManager>,
    engine: ProtocolStateEngine,
    // Coordinates operations that update more than one stored key.
    lifecycle: Mutex<()>,
}

/// Facade over identity, discovery key, and prekey managers sharing one [`SecureStorage`].
///
/// Clones share the same underlying storage and synchronization. Separately constructed instances
/// do not. An app that uses multiple instances or processes for one identity namespace must hold
/// one identity lock across them, from the first call of any operation, including a message
/// operation, until its commit is resolved, and while it resolves unfinished operations.
///
/// Methods named `prepare_*` stage a secure-storage change and return it with an operation ID.
/// Reserve the operation, persist its output and ID in the app's transaction, then finalize:
///
/// ```
/// use rand::rngs::OsRng;
/// use roost_core::{KeyStore, KeyStoreError, SecureStorage};
///
/// fn create_identity(storage: Box<dyn SecureStorage>) -> Result<(), KeyStoreError> {
///     let store = KeyStore::new(storage);
///     let prepared = store.prepare_identity_creation(&mut OsRng)?;
///     store.reserve_operation(prepared.id)?;
///     // Persist or publish `prepared.output` with the operation ID.
///     store.finalize_operation(prepared.id)?;
///     Ok(())
/// }
/// ```
#[derive(Clone)]
pub struct KeyStore(Arc<KeyStoreInner>);

impl KeyStore {
    /// Creates a keystore backed by `storage`, reading time from the system clock.
    pub fn new(storage: Box<dyn SecureStorage>) -> Self {
        Self::from_shared_storage(Arc::new(Mutex::new(storage)), ProtocolStateEngine::new())
    }

    /// Returns the engine shared by identity, messaging, and contact operations.
    pub fn protocol_engine(&self) -> &ProtocolStateEngine {
        &self.0.engine
    }

    fn from_shared_storage(
        storage: Arc<Mutex<Box<dyn SecureStorage>>>,
        engine: ProtocolStateEngine,
    ) -> Self {
        let identity = Arc::new(IdentityManager::new(Arc::clone(&storage)));
        let discovery = Arc::new(DiscoveryKeyManager::new(
            Arc::clone(&storage),
            Arc::clone(&identity),
        ));
        let one_time_prekey = Arc::new(OneTimePreKeyManager::new(
            Arc::clone(&storage),
            Arc::clone(&discovery),
        ));
        let signed_prekey = Arc::new(SignedPreKeyManager::new(
            Arc::clone(&storage),
            Arc::clone(&discovery),
        ));
        KeyStore(Arc::new(KeyStoreInner {
            storage,
            identity,
            discovery,
            one_time_prekey,
            signed_prekey,
            engine,
            lifecycle: Mutex::new(()),
        }))
    }

    /// Prepares fresh identity and discovery key material without changing authoritative storage.
    pub fn prepare_identity_creation<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<PreparedKeyStoreOperation<Identity>, KeyStoreError> {
        self.prepare_operation(rng, |staged, rng| staged.create_identity(rng))
    }

    /// Returns the stored [`Identity`], or `None` when no identity is stored.
    ///
    /// A storage fault or a malformed identity secret blob is an error, not `None`.
    pub fn identity(&self) -> Result<Option<Identity>, KeyStoreError> {
        match self.load_identity() {
            Ok(identity) => Ok(Some(identity)),
            Err(KeyStoreError::Identity(IdentityError::NotFound)) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Loads the stored [`Identity`].
    pub fn load_identity(&self) -> Result<Identity, KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        self.ensure_no_unfinished_reservation()?;
        Ok(self.0.identity.load_identity()?)
    }

    /// Returns the current discovery key and signed prekey, which verify as one chain.
    ///
    /// Public one-time prekeys come from [`Self::prepare_one_time_prekeys`] and
    /// [`Self::prepare_one_time_prekey_replenishment`].
    pub fn current_publication(&self) -> Result<PublicationBundle, KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        self.ensure_no_unfinished_reservation()?;
        self.publication()
    }

    /// Returns the stored identity key and the current discovery key, which a contact link carries.
    ///
    /// It fails whenever [`Self::current_publication`] does, so a link never points peers at an
    /// inbox that has no publication.
    pub fn contact_publication(&self) -> Result<ContactPublication, KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        self.ensure_no_unfinished_reservation()?;
        let identity = self.0.identity.load_identity()?.public()?;
        let publication = self.publication()?;
        Ok(ContactPublication {
            identity,
            discovery_key: publication.discovery_key,
            discovery_to_identity: publication.discovery_to_identity,
        })
    }

    fn publication(&self) -> Result<PublicationBundle, KeyStoreError> {
        let discovery_key = self.0.discovery.current()?;
        let discovery_to_identity = self.0.discovery.identity_binding(&discovery_key)?;
        let recipient_delivery_verifier = self.0.discovery.current_capability()?.verifier();
        let discovery_key = discovery_key.public();
        let signed_prekey = self.0.signed_prekey.current_public(SystemTime::now())?;
        // A rolled-back or mismatched entry fails here, before Roost publishes the pair.
        verify_public_signed_prekey(&signed_prekey, &discovery_key.verifying_key)
            .map_err(SignedPreKeyError::Corrupt)?;
        Ok(PublicationBundle {
            version: PREKEY_BUNDLE_VERSION,
            discovery_key,
            discovery_to_identity,
            recipient_delivery_verifier,
            signed_prekey,
        })
    }

    /// Blocks a contact, given its record or the record's absence, and rotates the inbox so the
    /// block takes effect at the relay.
    ///
    /// Blocking alone only stops messages being surfaced locally. The relay would still accept and
    /// queue them, because the blocked contact still holds a working delivery capability or knows
    /// the inbox's prekeys. Rotating the inbox replaces both, even for a stranger who never got a
    /// grant, so a blocked person can't come back with a new identity at the same address. A
    /// stranger with no record gets one that holds only the block.
    ///
    /// A contact that is already blocked produces no change and no rotation, so repeating the call
    /// does not churn every contact's capability.
    ///
    /// Neither change is authoritative when this returns. Reserve the operation in
    /// [`ContactBlock::changes`], commit the changes with its ID, then finalize it. Abort only after
    /// proving the app's transaction did not commit.
    pub fn prepare_block_contact<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        identity_key: IdentityKey,
        record: Option<&ProtocolStateBlob>,
    ) -> Result<ContactBlock, KeyStoreError> {
        let (changes, blocks) = self.0.engine.block_contact(identity_key, record)?;
        if !blocks {
            return Ok(ContactBlock {
                changes,
                publication: None,
            });
        }
        let prepared = self.prepare_operation(rng, |staged, rng| staged.rotate_inbox(rng))?;
        Ok(ContactBlock {
            changes: changes.with_operation(prepared.id),
            publication: Some(prepared.output),
        })
    }

    /// Prepares exactly `batch_size` one-time prekeys for the current discovery key's epoch.
    ///
    /// The new secrets remain staged until finalization. No discovery key rotation is required.
    /// The call fails if the requested batch would exceed the pool cap.
    pub fn prepare_one_time_prekeys<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        batch_size: usize,
    ) -> Result<PreparedKeyStoreOperation<Vec<PublicOneTimePreKey>>, KeyStoreError> {
        self.prepare_operation(rng, |staged, rng| {
            Ok(staged.0.one_time_prekey.generate_batch(rng, batch_size)?)
        })
    }

    /// Prepares replenishment of the stored one-time prekey pool.
    ///
    /// Returns the public one-time prekeys created by this call. A missing pool is created for the
    /// current discovery key's epoch, and a pool above the replenish threshold is left unchanged
    /// and returns an empty list. The returned no-op operation must still be finalized or aborted.
    pub fn prepare_one_time_prekey_replenishment<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<PreparedKeyStoreOperation<Vec<PublicOneTimePreKey>>, KeyStoreError> {
        self.prepare_operation(rng, |staged, rng| {
            Ok(staged.0.one_time_prekey.replenish(rng)?)
        })
    }

    /// Prepares rotation of the whole inbox.
    ///
    /// Advances the epoch, replaces the discovery key and the delivery capability together, clears
    /// epoch-bound one-time prekeys, and returns the publishable material. A preparation failure
    /// discards the staged changes, leaving the previous authoritative inbox intact.
    ///
    /// This invalidates every contact's delivery capability until a message, acknowledgment, or
    /// grant update carries them the new inbox grant. That makes it the mechanism behind blocking,
    /// and why it is not merely a discovery key rotation. The replaced discovery key
    /// still opens messages the relay queued for it, for as long as the relay may hold them.
    pub fn prepare_inbox_rotation<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<PreparedKeyStoreOperation<PublicationBundle>, KeyStoreError> {
        self.prepare_operation(rng, |staged, rng| staged.rotate_inbox(rng))
    }

    /// Prepares a signed prekey rotation when the stored one is stale or missing, and deletes the
    /// previous discovery keys the relay can no longer hold messages for.
    ///
    /// Returns the new public signed prekey when the app needs to upload it, or `None` when no
    /// rotation was needed. The returned operation must be finalized or aborted either way.
    pub fn prepare_signed_prekey_rotation_and_discovery_key_cleanup<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<PreparedKeyStoreOperation<Option<PublicSignedPreKey>>, KeyStoreError> {
        self.prepare_operation(rng, |staged, rng| {
            staged.rotate_signed_prekey_and_clean_up_discovery_keys(rng)
        })
    }

    /// Prepares a signed prekey rotation even when the current one is fresh, and returns the
    /// provisional public key.
    pub fn prepare_signed_prekey_rotation<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<PreparedKeyStoreOperation<PublicSignedPreKey>, KeyStoreError> {
        self.prepare_operation(rng, |staged, rng| {
            Ok(staged
                .0
                .signed_prekey
                .rotate_now(rng, SystemTime::now())?
                .public())
        })
    }

    /// Exports the stored identity and current discovery key as a passphrase-encrypted backup.
    pub fn export_encrypted_backup<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        passphrase: &str,
    ) -> Result<Vec<u8>, KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        self.ensure_no_unfinished_reservation()?;
        self.0.discovery.current()?;
        let discovery_key_entry = self.0.discovery.export_entry()?;
        Ok(self
            .0
            .identity
            .export_encrypted_backup(rng, passphrase, &discovery_key_entry)?)
    }

    /// Prepares restoration of an identity and discovery key from an encrypted backup.
    ///
    /// A wrong passphrase, or a backup whose discovery key the restored identity didn't sign, fails
    /// the preparation and leaves existing material untouched. Reserve this operation, then in the
    /// transaction that commits its ID, keep the
    /// [`ProtocolStateKind::ContactState`](crate::ProtocolStateKind::ContactState) records restored
    /// with the app's database and delete every other protocol-state record, then finalize. A
    /// restored session would reuse message keys its copy already used, so each contact's next
    /// message starts a new session instead. Roost stops tracking a message once its session is
    /// deleted, so in the same transaction, also mark each sent message that has no acknowledgment
    /// yet not delivered. The restored identity keeps the discovery key's epoch lineage from the
    /// backup, but prekey generation and publication stay blocked until
    /// [`Self::prepare_inbox_rotation`] advances to the next epoch. This avoids reusing prekey
    /// identifiers already published under the backed-up epoch.
    pub fn prepare_backup_import<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        data: &[u8],
        passphrase: &str,
    ) -> Result<PreparedKeyStoreOperation<()>, KeyStoreError> {
        self.prepare_operation(rng, |staged, _| staged.import_backup(data, passphrase))
    }

    /// Prepares deletion of the stored prekeys, discovery key, and identity.
    ///
    /// Reserve this operation, atomically wipe the protocol state the app holds, then finalize.
    /// Interrupted finalization resumes from durable progress.
    pub fn prepare_identity_deletion<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<PreparedKeyStoreOperation<()>, KeyStoreError> {
        self.prepare_operation(rng, |staged, _| staged.delete_keys())
    }

    // Keeps updates of several keys from interleaving across cloned keystores. The storage mutex
    // only protects single storage calls, and this guard keeps the stored keys consistent.
    fn lifecycle_guard(&self) -> MutexGuard<'_, ()> {
        self.0
            .lifecycle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

// The changes each prepared operation stages. They run on the staging KeyStore that
// `prepare_operation` builds while it holds the lifecycle guard, and each reads the clock once.
impl KeyStore {
    // Creates the identity and its first discovery key.
    fn create_identity<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<Identity, KeyStoreError> {
        let identity = self.0.identity.generate_identity(rng)?;
        self.0.discovery.rotate_now(rng, SystemTime::now())?;
        Ok(identity)
    }

    fn rotate_inbox<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<PublicationBundle, KeyStoreError> {
        let now = SystemTime::now();
        self.0.one_time_prekey.reset()?;
        self.0.signed_prekey.reset()?;
        let discovery_key = self.0.discovery.rotate_now(rng, now)?;
        let discovery_to_identity = self.0.discovery.identity_binding(&discovery_key)?;
        let recipient_delivery_verifier = self.0.discovery.current_capability()?.verifier();
        let signed_prekey = self.0.signed_prekey.rotate_now(rng, now)?;
        Ok(PublicationBundle {
            version: PREKEY_BUNDLE_VERSION,
            discovery_key: discovery_key.public(),
            discovery_to_identity,
            recipient_delivery_verifier,
            signed_prekey: signed_prekey.public(),
        })
    }

    fn rotate_signed_prekey_and_clean_up_discovery_keys<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<Option<PublicSignedPreKey>, KeyStoreError> {
        let now = SystemTime::now();
        let signed_prekey = self
            .0
            .signed_prekey
            .rotate_if_stale(rng, now)?
            .map(|signed_prekey| signed_prekey.public());
        self.0.discovery.delete_expired_previous(now)?;
        Ok(signed_prekey)
    }

    fn import_backup(&self, data: &[u8], passphrase: &str) -> Result<(), KeyStoreError> {
        let (identity, discovery_key_entry) = decrypt_backup(data, passphrase)?;
        // Validate the restored keys before clearing any existing material.
        DiscoveryKeyManager::validate_entry_for_identity(
            &discovery_key_entry,
            identity.verifying_key(),
        )?;
        self.0.one_time_prekey.mark_inbox_rotation_required()?;
        self.0.signed_prekey.mark_inbox_rotation_required()?;
        self.0.discovery.reset()?;
        self.0.identity.replace_identity(&identity)?;
        self.0.discovery.restore_entry(&discovery_key_entry)?;
        Ok(())
    }

    fn delete_keys(&self) -> Result<(), KeyStoreError> {
        self.0.one_time_prekey.reset()?;
        self.0.signed_prekey.reset()?;
        self.0.discovery.reset()?;
        self.0.identity.reset()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::one_time_prekey::{
        ONE_TIME_PREKEY_POOL_TARGET, ONE_TIME_PREKEY_REPLENISH_THRESHOLD,
    };
    use crate::storage::{InMemorySecureStorage, StorageError};
    use crate::stored_data::StoredDataError;
    use rand::SeedableRng;
    use rand::rngs::OsRng;
    use rand_chacha::ChaCha20Rng;
    use roost_crypto::{
        PublicKeyError, verify_discovery_to_identity_binding, verify_public_discovery_key,
    };
    use roost_protocol::{SignatureError, from_unix_secs};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use zeroize::Zeroizing;

    // Storage keys are duplicated from the manager modules so tests can inspect and tamper.
    const DISCOVERY_KEY: &str = "discovery/current";
    const PREVIOUS_DISCOVERY_KEYS: &str = "discovery/previous";
    const IDENTITY_CURRENT_KEY: &str = "identity/current";
    const SIGNED_PREKEYS: &str = "prekey/signed";
    const ONE_TIME_PREKEYS: &str = "prekey/one-time-pool";

    type SharedStorage = Arc<Mutex<Box<dyn SecureStorage>>>;

    fn store() -> KeyStore {
        KeyStore::new(Box::new(InMemorySecureStorage::new()))
    }

    fn store_with_storage() -> (KeyStore, SharedStorage) {
        let storage: SharedStorage = Arc::new(Mutex::new(Box::new(InMemorySecureStorage::new())));
        let key_store =
            KeyStore::from_shared_storage(Arc::clone(&storage), ProtocolStateEngine::new());
        (key_store, storage)
    }

    fn load(storage: &SharedStorage, key: &str) -> Option<Zeroizing<Vec<u8>>> {
        storage.lock().unwrap().load(key).unwrap()
    }

    // Reserves and finalizes `prepared`, as an app does around its commit, and returns its output.
    fn commit<T>(store: &KeyStore, prepared: PreparedKeyStoreOperation<T>) -> T {
        store.reserve_operation(prepared.id).unwrap();
        store.finalize_operation(prepared.id).unwrap();
        prepared.output
    }

    fn commit_identity_creation(store: &KeyStore) -> Identity {
        commit(store, store.prepare_identity_creation(&mut OsRng).unwrap())
    }

    fn commit_inbox_rotation(store: &KeyStore) -> PublicationBundle {
        commit(store, store.prepare_inbox_rotation(&mut OsRng).unwrap())
    }

    fn commit_signed_prekey_rotation(store: &KeyStore) -> PublicSignedPreKey {
        commit(
            store,
            store.prepare_signed_prekey_rotation(&mut OsRng).unwrap(),
        )
    }

    fn commit_replenishment(store: &KeyStore) -> Vec<PublicOneTimePreKey> {
        commit(
            store,
            store
                .prepare_one_time_prekey_replenishment(&mut OsRng)
                .unwrap(),
        )
    }

    fn commit_import(store: &KeyStore, backup: &[u8], passphrase: &str) {
        commit(
            store,
            store
                .prepare_backup_import(&mut OsRng, backup, passphrase)
                .unwrap(),
        );
    }

    fn discovery_key(store: &KeyStore) -> Result<PublicDiscoveryKey, DiscoveryKeyError> {
        Ok(store.0.discovery.current()?.public())
    }

    fn signed_prekey(store: &KeyStore) -> Result<PublicSignedPreKey, SignedPreKeyError> {
        store.0.signed_prekey.current_public(SystemTime::now())
    }

    #[test]
    fn load_identity_succeeds_without_discovery_key() {
        let (key_store, storage) = store_with_storage();
        commit_identity_creation(&key_store);
        storage.lock().unwrap().delete(DISCOVERY_KEY).unwrap();
        key_store.load_identity().unwrap();
    }

    #[test]
    fn inbox_rotation_carries_both_binding_directions() {
        let key_store = store();
        let identity = commit_identity_creation(&key_store);

        let publication = commit_inbox_rotation(&key_store);

        verify_public_discovery_key(&publication.discovery_key, identity.verifying_key()).unwrap();
        verify_discovery_to_identity_binding(
            &identity.public().unwrap(),
            &publication.discovery_key.verifying_key,
            &publication.discovery_to_identity,
        )
        .unwrap();
    }

    #[test]
    fn discovery_to_identity_binding_is_stable_across_reads() {
        let key_store = store();
        commit_identity_creation(&key_store);
        commit_signed_prekey_rotation(&key_store);

        let first = key_store.current_publication().unwrap();
        let second = key_store.current_publication().unwrap();

        assert_eq!(
            first.discovery_to_identity.to_bytes(),
            second.discovery_to_identity.to_bytes()
        );
    }

    #[test]
    fn replenishment_returns_nothing_above_the_threshold() {
        let key_store = store();
        commit_identity_creation(&key_store);
        commit_replenishment(&key_store);
        assert!(commit_replenishment(&key_store).is_empty());
    }

    #[test]
    fn replenishment_tops_up_at_the_threshold() {
        let key_store = store();
        commit_identity_creation(&key_store);
        let epoch = discovery_key(&key_store).unwrap().epoch;
        let prekeys = commit_replenishment(&key_store);
        let keys_to_use = ONE_TIME_PREKEY_POOL_TARGET - ONE_TIME_PREKEY_REPLENISH_THRESHOLD;
        for prekey in prekeys.iter().take(keys_to_use) {
            let id = key_store
                .prepare_one_time_prekey_use(&mut OsRng, epoch, prekey.id)
                .unwrap();
            key_store.reserve_operation(id).unwrap();
            key_store.finalize_operation(id).unwrap();
        }
        let replenished = commit_replenishment(&key_store);
        assert_eq!(replenished.len(), keys_to_use);
        assert_eq!(
            replenished.first().map(|prekey| prekey.id),
            Some(ONE_TIME_PREKEY_POOL_TARGET as u64)
        );
    }

    #[test]
    fn a_one_time_prekey_use_commits_only_once() {
        let key_store = store();
        commit_identity_creation(&key_store);
        let epoch = discovery_key(&key_store).unwrap().epoch;
        let prekey = commit_replenishment(&key_store).remove(0);
        let first = key_store
            .prepare_one_time_prekey_use(&mut OsRng, epoch, prekey.id)
            .unwrap();
        let second = key_store
            .prepare_one_time_prekey_use(&mut OsRng, epoch, prekey.id)
            .unwrap();

        key_store.reserve_operation(first).unwrap();
        key_store.finalize_operation(first).unwrap();

        assert!(matches!(
            key_store.reserve_operation(second),
            Err(KeyStoreError::Operation(
                KeyStoreOperationError::PreconditionChanged { key }
            )) if key == ONE_TIME_PREKEYS
        ));
        assert_eq!(
            key_store.operation_status(second).unwrap(),
            KeyStoreOperationStatus::Prepared
        );
    }

    #[test]
    fn backup_import_blocks_one_time_prekeys_until_inbox_rotation() {
        let destination_store = store();
        commit_identity_creation(&destination_store);
        commit_replenishment(&destination_store);
        let source_store = store();
        commit_identity_creation(&source_store);
        let backup = source_store
            .export_encrypted_backup(&mut OsRng, "pass")
            .unwrap();
        commit_import(&destination_store, &backup, "pass");
        assert!(matches!(
            destination_store.prepare_one_time_prekey_use(&mut OsRng, 1, 0),
            Err(KeyStoreError::OneTimePreKey(
                OneTimePreKeyError::InboxRotationRequired
            ))
        ));
        assert!(matches!(
            destination_store.prepare_one_time_prekey_replenishment(&mut OsRng),
            Err(KeyStoreError::OneTimePreKey(
                OneTimePreKeyError::InboxRotationRequired
            ))
        ));

        let rotation = commit_inbox_rotation(&destination_store);
        let one_time_prekeys = commit_replenishment(&destination_store);
        assert_eq!(one_time_prekeys[0].epoch, rotation.discovery_key.epoch);
        assert_eq!(one_time_prekeys[0].id, 0);
    }

    #[test]
    fn current_publication_rejects_a_prekey_signed_by_a_superseded_discovery_key() {
        let (key_store, storage) = store_with_storage();
        commit_identity_creation(&key_store);
        commit_signed_prekey_rotation(&key_store);
        key_store.current_publication().unwrap();
        let stale_prekeys = load(&storage, SIGNED_PREKEYS).unwrap();
        commit_inbox_rotation(&key_store);
        storage
            .lock()
            .unwrap()
            .store(SIGNED_PREKEYS, &stale_prekeys)
            .unwrap();
        assert!(matches!(
            key_store.current_publication(),
            Err(KeyStoreError::SignedPreKey(SignedPreKeyError::Corrupt(
                PublicKeyError::Signature(SignatureError::SignatureInvalid)
            )))
        ));
    }

    #[test]
    fn inbox_rotation_advances_the_epoch_and_refreshes_the_prekey() {
        let key_store = store();
        commit_identity_creation(&key_store);
        let first = discovery_key(&key_store).unwrap();
        assert_eq!(first.epoch, 1);

        let rotation = commit_inbox_rotation(&key_store);
        assert_eq!(rotation.version, PREKEY_BUNDLE_VERSION);
        assert_eq!(rotation.discovery_key.epoch, 2);
        assert_ne!(
            rotation.discovery_key.public_key.as_bytes(),
            first.public_key.as_bytes()
        );
        verify_public_signed_prekey(
            &rotation.signed_prekey,
            &rotation.discovery_key.verifying_key,
        )
        .unwrap();
    }

    #[test]
    fn inbox_rotation_deletes_the_previous_epochs_signed_prekey() {
        let key_store = store();
        commit_identity_creation(&key_store);
        let first_epoch = discovery_key(&key_store).unwrap().epoch;
        let first_prekey = commit_signed_prekey_rotation(&key_store);

        commit_inbox_rotation(&key_store);

        assert!(matches!(
            key_store.0.signed_prekey.prekey_for_first_message(
                first_epoch,
                first_prekey.public_key.as_bytes(),
                SystemTime::now(),
            ),
            Err(SignedPreKeyError::NotFound)
        ));
    }

    #[test]
    fn cleanup_deletes_expired_previous_discovery_keys_without_rotating() {
        let mut rng = ChaCha20Rng::from_seed([0xe1; 32]);
        let (key_store, storage) = store_with_storage();
        commit_identity_creation(&key_store);
        // An inbox rotation long ago retired the first discovery key, so the relay can no longer
        // hold messages for it, and the next signed prekey is fresh.
        let long_ago = from_unix_secs(1_700_000_000).unwrap();
        key_store
            .0
            .discovery
            .rotate_now(&mut rng, long_ago)
            .unwrap();
        key_store
            .0
            .signed_prekey
            .rotate_now(&mut rng, SystemTime::now())
            .unwrap();
        assert!(load(&storage, PREVIOUS_DISCOVERY_KEYS).is_some());

        let rotated = commit(
            &key_store,
            key_store
                .prepare_signed_prekey_rotation_and_discovery_key_cleanup(&mut OsRng)
                .unwrap(),
        );

        assert!(rotated.is_none());
        assert!(load(&storage, PREVIOUS_DISCOVERY_KEYS).is_none());
    }

    #[test]
    fn publication_never_sees_a_half_finished_rotation() {
        let key_store = store();
        commit_identity_creation(&key_store);
        commit_signed_prekey_rotation(&key_store);

        let rotator = key_store.clone();
        let rotate_thread = std::thread::spawn(move || {
            for _ in 0..8 {
                commit_inbox_rotation(&rotator);
            }
        });
        for _ in 0..64 {
            match key_store.current_publication() {
                Ok(publication) => verify_public_signed_prekey(
                    &publication.signed_prekey,
                    &publication.discovery_key.verifying_key,
                )
                .unwrap(),
                // A reserved rotation blocks reads until it is finalized.
                Err(KeyStoreError::Operation(KeyStoreOperationError::UnfinishedReservation {
                    ..
                })) => {}
                Err(error) => panic!("unexpected publication failure: {error}"),
            }
        }
        rotate_thread.join().unwrap();
    }

    #[test]
    fn a_failed_import_leaves_the_existing_identity_and_prekeys() {
        type Matcher = fn(&KeyStoreError) -> bool;
        let mut rng = ChaCha20Rng::from_seed([0xe0; 32]);
        let source_store = store();
        commit_identity_creation(&source_store);
        let other_store = store();
        commit_identity_creation(&other_store);
        let mut backup = |discovery_key_entry: &[u8]| {
            source_store
                .0
                .identity
                .export_encrypted_backup(&mut rng, "pass", discovery_key_entry)
                .unwrap()
        };
        let cases: [(Vec<u8>, &str, Matcher); 3] = [
            (
                source_store
                    .export_encrypted_backup(&mut OsRng, "pass")
                    .unwrap(),
                "wrong",
                |error| {
                    matches!(
                        error,
                        KeyStoreError::Identity(IdentityError::DecryptionFailed)
                    )
                },
            ),
            (
                backup(&other_store.0.discovery.export_entry().unwrap()),
                "pass",
                |error| {
                    matches!(
                        error,
                        KeyStoreError::Discovery(DiscoveryKeyError::Corrupt(
                            PublicKeyError::Signature(SignatureError::SignatureInvalid)
                        ))
                    )
                },
            ),
            // An authentic backup whose discovery key entry is malformed.
            (backup(&[0xAAu8; 50]), "pass", |error| {
                matches!(
                    error,
                    KeyStoreError::Discovery(DiscoveryKeyError::StoredData(
                        StoredDataError::UnsupportedVersion { version: 0xAA }
                    ))
                )
            }),
        ];

        for (backup, passphrase, rejects) in cases {
            let destination_store = store();
            let original_identity = commit_identity_creation(&destination_store);
            let original_signed_prekey =
                commit_signed_prekey_rotation(&destination_store).public_key;

            let error = destination_store
                .prepare_backup_import(&mut OsRng, &backup, passphrase)
                .err()
                .unwrap();

            assert!(rejects(&error), "unexpected error: {error}");
            assert!(
                destination_store
                    .unfinished_operations()
                    .unwrap()
                    .is_empty()
            );
            let current_identity = destination_store.load_identity().unwrap();
            assert_eq!(
                original_identity.public_key(),
                current_identity.public_key()
            );
            assert_eq!(
                original_identity.verifying_key().as_bytes(),
                current_identity.verifying_key().as_bytes()
            );
            assert_eq!(
                signed_prekey(&destination_store)
                    .unwrap()
                    .public_key
                    .as_bytes(),
                original_signed_prekey.as_bytes()
            );
        }
    }

    #[test]
    fn backup_import_rejects_an_unknown_backup_version() {
        let source_store = store();
        commit_identity_creation(&source_store);
        let mut backup = source_store
            .export_encrypted_backup(&mut OsRng, "passphrase")
            .unwrap();
        backup[0] = 0xFF;
        let destination_store = store();

        let result = destination_store.prepare_backup_import(&mut OsRng, &backup, "passphrase");

        assert!(matches!(
            result,
            Err(KeyStoreError::Identity(IdentityError::BackupFormat(
                StoredDataError::UnsupportedVersion { version: 0xFF }
            )))
        ));
        assert!(matches!(
            destination_store.load_identity(),
            Err(KeyStoreError::Identity(IdentityError::NotFound))
        ));
    }

    #[test]
    fn backup_import_writes_the_identity_with_one_store() {
        struct CountingIdentityWriteStorage {
            inner: InMemorySecureStorage,
            counting: Arc<AtomicBool>,
            writes: Arc<AtomicUsize>,
        }

        impl SecureStorage for CountingIdentityWriteStorage {
            fn store(&mut self, key: &str, value: &[u8]) -> Result<(), StorageError> {
                if self.counting.load(Ordering::SeqCst) && key == IDENTITY_CURRENT_KEY {
                    self.writes.fetch_add(1, Ordering::SeqCst);
                }
                self.inner.store(key, value)
            }

            fn load(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
                self.inner.load(key)
            }

            fn delete(&mut self, key: &str) -> Result<(), StorageError> {
                self.inner.delete(key)
            }
        }

        let counting = Arc::new(AtomicBool::new(false));
        let writes = Arc::new(AtomicUsize::new(0));
        let destination_store = KeyStore::new(Box::new(CountingIdentityWriteStorage {
            inner: InMemorySecureStorage::new(),
            counting: Arc::clone(&counting),
            writes: Arc::clone(&writes),
        }));
        commit_identity_creation(&destination_store);

        let source_store = store();
        let source_identity = commit_identity_creation(&source_store);
        let backup = source_store
            .export_encrypted_backup(&mut OsRng, "pass")
            .unwrap();

        counting.store(true, Ordering::SeqCst);
        commit_import(&destination_store, &backup, "pass");

        let imported_identity = destination_store.load_identity().unwrap();
        assert_eq!(writes.load(Ordering::SeqCst), 1);
        assert_eq!(source_identity.public_key(), imported_identity.public_key());
        assert_eq!(
            source_identity.verifying_key().as_bytes(),
            imported_identity.verifying_key().as_bytes()
        );
    }

    #[test]
    fn backup_import_blocks_signed_prekeys_until_inbox_rotation() {
        let destination_store = store();
        commit_identity_creation(&destination_store);
        commit_signed_prekey_rotation(&destination_store);

        let source_store = store();
        commit_identity_creation(&source_store);
        let backup = source_store
            .export_encrypted_backup(&mut OsRng, "pass")
            .unwrap();

        commit_import(&destination_store, &backup, "pass");
        assert!(matches!(
            signed_prekey(&destination_store),
            Err(SignedPreKeyError::InboxRotationRequired)
        ));
        assert!(matches!(
            destination_store.prepare_signed_prekey_rotation_and_discovery_key_cleanup(&mut OsRng),
            Err(KeyStoreError::SignedPreKey(
                SignedPreKeyError::InboxRotationRequired
            ))
        ));
    }

    #[test]
    fn inbox_rotation_after_import_uses_a_fresh_epoch_and_signed_prekey_id() {
        let destination_store = store();
        commit_identity_creation(&destination_store);
        commit_signed_prekey_rotation(&destination_store);

        let source_store = store();
        commit_identity_creation(&source_store);
        let backup = source_store
            .export_encrypted_backup(&mut OsRng, "pass")
            .unwrap();
        let backed_up_epoch = discovery_key(&source_store).unwrap().epoch;
        commit_import(&destination_store, &backup, "pass");
        let rotation = commit_inbox_rotation(&destination_store);

        let rotated_prekey = signed_prekey(&destination_store).unwrap();
        let imported_identity = destination_store.load_identity().unwrap();
        let public_discovery_key = discovery_key(&destination_store).unwrap();
        assert_eq!(public_discovery_key.epoch, backed_up_epoch + 1);
        assert_eq!(rotation.signed_prekey.id, 0);
        assert_eq!(rotated_prekey.id, 0);
        verify_public_discovery_key(&public_discovery_key, imported_identity.verifying_key())
            .unwrap();
        verify_public_signed_prekey(&rotated_prekey, &public_discovery_key.verifying_key).unwrap();
    }

    #[test]
    fn import_restores_the_discovery_key_epoch_lineage() {
        let source_store = store();
        commit_identity_creation(&source_store);
        commit_inbox_rotation(&source_store);
        commit_inbox_rotation(&source_store);
        assert_eq!(discovery_key(&source_store).unwrap().epoch, 3);
        let backup = source_store
            .export_encrypted_backup(&mut OsRng, "pass")
            .unwrap();

        let destination_store = store();
        commit_identity_creation(&destination_store);
        commit_import(&destination_store, &backup, "pass");

        // The restored discovery key keeps the source epoch lineage instead of resetting to
        // the first epoch, and verifies against the restored identity.
        assert_eq!(discovery_key(&destination_store).unwrap().epoch, 3);
    }

    #[test]
    fn export_rejects_a_discovery_key_not_signed_by_the_identity() {
        let (key_store, storage) = store_with_storage();
        commit_identity_creation(&key_store);
        let other_store = store();
        commit_identity_creation(&other_store);
        let other_entry = other_store.0.discovery.export_entry().unwrap();
        storage
            .lock()
            .unwrap()
            .store(DISCOVERY_KEY, &other_entry)
            .unwrap();

        assert!(matches!(
            key_store.export_encrypted_backup(&mut OsRng, "pass"),
            Err(KeyStoreError::Discovery(DiscoveryKeyError::Corrupt(
                PublicKeyError::Signature(SignatureError::SignatureInvalid)
            )))
        ));
    }

    #[test]
    fn unicode_normalized_passphrases_restore_same_identity_and_discovery_key() {
        let source_store = store();
        let source_identity = commit_identity_creation(&source_store);
        let source_discovery = discovery_key(&source_store).unwrap();
        let backup = source_store
            .export_encrypted_backup(&mut OsRng, "caf\u{00e9}")
            .unwrap();

        let destination_store = store();
        commit_import(&destination_store, &backup, "cafe\u{0301}");

        let destination_identity = destination_store.load_identity().unwrap();
        let destination_discovery = discovery_key(&destination_store).unwrap();
        assert_eq!(
            source_identity.public_key(),
            destination_identity.public_key()
        );
        assert_eq!(
            source_identity.verifying_key().as_bytes(),
            destination_identity.verifying_key().as_bytes()
        );
        assert_eq!(
            source_discovery.public_key.as_bytes(),
            destination_discovery.public_key.as_bytes()
        );
        assert_eq!(
            source_discovery.verifying_key.as_bytes(),
            destination_discovery.verifying_key.as_bytes()
        );
    }

    #[test]
    fn export_without_discovery_key_returns_not_found() {
        let (key_store, storage) = store_with_storage();
        commit_identity_creation(&key_store);
        storage.lock().unwrap().delete(DISCOVERY_KEY).unwrap();
        assert!(matches!(
            key_store.export_encrypted_backup(&mut OsRng, "pass"),
            Err(KeyStoreError::Discovery(DiscoveryKeyError::NotFound))
        ));
    }

    #[test]
    fn identity_deletion_clears_the_identity_discovery_key_and_prekeys() {
        let key_store = store();
        commit_identity_creation(&key_store);
        commit_replenishment(&key_store);
        commit_signed_prekey_rotation(&key_store);
        commit(
            &key_store,
            key_store.prepare_identity_deletion(&mut OsRng).unwrap(),
        );
        assert!(matches!(
            key_store.load_identity(),
            Err(KeyStoreError::Identity(IdentityError::NotFound))
        ));
        assert!(matches!(
            discovery_key(&key_store),
            Err(DiscoveryKeyError::NotFound)
        ));
        assert!(matches!(
            key_store.0.one_time_prekey.consume_one_time_prekey(1, 0),
            Err(OneTimePreKeyError::NotFound)
        ));
        assert!(matches!(
            signed_prekey(&key_store),
            Err(SignedPreKeyError::NotFound)
        ));
    }

    #[test]
    fn identity_deletion_on_an_empty_store_succeeds() {
        let key_store = store();
        commit(
            &key_store,
            key_store.prepare_identity_deletion(&mut OsRng).unwrap(),
        );
        commit(
            &key_store,
            key_store.prepare_identity_deletion(&mut OsRng).unwrap(),
        );
    }

    #[test]
    fn reserving_an_operation_while_another_is_reserved_names_the_other() {
        let key_store = store();
        commit_identity_creation(&key_store);
        let first = key_store.prepare_one_time_prekeys(&mut OsRng, 1).unwrap();
        let second = key_store.prepare_one_time_prekeys(&mut OsRng, 1).unwrap();
        key_store.reserve_operation(first.id).unwrap();

        assert!(matches!(
            key_store.reserve_operation(second.id),
            Err(KeyStoreError::Operation(KeyStoreOperationError::UnfinishedReservation { id }))
                if id == first.id
        ));
        assert_eq!(
            key_store.operation_status(second.id).unwrap(),
            KeyStoreOperationStatus::Prepared
        );
    }

    #[test]
    fn a_finalized_operations_status_survives_the_next_preparation() {
        let key_store = store();
        let created = key_store.prepare_identity_creation(&mut OsRng).unwrap();
        key_store.reserve_operation(created.id).unwrap();
        key_store.finalize_operation(created.id).unwrap();
        key_store.prepare_one_time_prekeys(&mut OsRng, 1).unwrap();
        assert_eq!(
            key_store.operation_status(created.id).unwrap(),
            KeyStoreOperationStatus::Finalized
        );
    }
}
