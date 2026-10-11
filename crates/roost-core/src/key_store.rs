mod messaging;
mod operation;
mod session;

pub use messaging::{
    AcknowledgmentProcessing, MessageDecryption, MessageEncryption, MessageOperationError,
};
pub use operation::{
    JournalCorruption, KeyStoreOperation, KeyStoreOperationError, KeyStoreOperationId,
    KeyStoreOperationStatus, PreparedKeyStoreOperation, SecureStorageExpectedValue,
    SecureStoragePrecondition, UnfinishedKeyStoreOperation,
};
pub use session::{
    SessionAcceptance, SessionAcceptanceResult, SessionEstablishmentError, SessionInitiation,
    SessionInitiationResult,
};

use crate::contact::{ContactIdentityKey, ContactStateChange};
use crate::discovery_key::{DiscoveryKeyError, DiscoveryKeyManager, DiscoveryKeyStatus};
use crate::identity::{Identity, IdentityError, IdentityManager};
use crate::one_time_prekey::{OneTimePreKeyError, OneTimePreKeyManager};
use crate::protocol_state::{ProtocolStateEngine, ProtocolStateSnapshot};
use crate::signed_prekey::{SignedPreKeyError, SignedPreKeyManager};
use crate::storage::SecureStorage;
use rand::rngs::OsRng;
#[cfg(test)]
use roost_crypto::OneTimePreKey;
use roost_crypto::{
    PREKEY_BUNDLE_VERSION, PublicDiscoveryKey, PublicOneTimePreKey, PublicSignedPreKey,
    RecipientDeliveryCapability, RecipientDeliveryVerifier, Signature, verify_public_signed_prekey,
};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

/// Errors returned by [`KeyStore`] operations.
#[derive(Debug, thiserror::Error)]
pub enum KeyStoreError {
    /// A discovery-key operation failed.
    #[error(transparent)]
    Discovery(#[from] DiscoveryKeyError),
    /// An identity-layer operation failed.
    #[error(transparent)]
    Identity(#[from] IdentityError),
    /// A one-time-pre-key operation failed.
    #[error(transparent)]
    OneTimePreKey(#[from] OneTimePreKeyError),
    /// A prepared-operation lifecycle step failed.
    #[error(transparent)]
    Operation(#[from] KeyStoreOperationError),
    /// A protocol-state operation failed.
    #[error(transparent)]
    ProtocolState(#[from] crate::protocol_state::ProtocolStateError),
    /// A signed-pre-key operation failed.
    #[error(transparent)]
    SignedPreKey(#[from] SignedPreKeyError),
}

/// A key publication that verifies as identity -> discovery key -> signed pre-key.
///
/// Peers verify [`Self::discovery_key`] with the identity verifying key, then verify
/// [`Self::signed_prekey`] with the discovery key's verifying key.
#[derive(Clone, Debug)]
pub struct PublicationBundle {
    /// Version of the public pre-key bundle format.
    pub version: u8,
    /// The discovery key for this publication.
    ///
    /// Its `signature` field is the IK→DK half of the mutual binding.
    pub discovery_key: PublicDiscoveryKey,
    /// The DK→IK half of the mutual binding: [`Self::discovery_key`] signing the identity it
    /// belongs to.
    ///
    /// A relay verifies this alongside the IK→DK direction before accepting a registration, and a
    /// peer that starts from a discovery key verifies it to learn the identity really was
    /// authorized by that discovery key.
    pub discovery_to_identity: Signature,
    /// Public commitment to the recipient delivery capability of this inbox.
    ///
    /// Register this with the relay. The capability it commits to is a bearer secret and is
    /// reached only through [`KeyStore::current_delivery_capability`].
    pub recipient_delivery_verifier: RecipientDeliveryVerifier,
    /// The signed pre-key for this publication.
    pub signed_prekey: PublicSignedPreKey,
}

/// Everything one inbox rotation produces.
///
/// A rotation advances the epoch and replaces the discovery key, its mutual binding
/// signatures, the prekey bundle, and the recipient delivery capability together. Both halves are
/// returned from the one call so a caller cannot publish the new inbox while still
/// distributing the previous inbox's capability.
pub struct InboxRotation {
    /// Material to publish and register, including the new Discovery Key and verifier.
    pub publication: PublicationBundle,
    /// The new inbox's bearer secret, to persist and share with authorized contacts.
    ///
    /// Deliberately kept out of [`PublicationBundle`]: everything in that struct is meant to be
    /// published, and a secret sitting inside it is one careless `publish(bundle)` away from
    /// reaching the relay.
    pub capability: RecipientDeliveryCapability,
}

/// Result of blocking a contact.
pub struct ContactBlock {
    /// Contact state change to commit durably, then emit.
    pub contact: ContactStateChange,
    /// The inbox rotation the block performed, or `None` when the contact was already blocked.
    ///
    /// Present means every remaining contact now holds a stale delivery capability and must be
    /// given [`InboxRotation::capability`] before they can reach this inbox again. The blocked
    /// contact is deliberately not among them — that is what makes the block bite at the relay
    /// rather than only locally.
    pub rotation: Option<InboxRotation>,
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

/// Facade over identity, discovery-key, and signed-pre-key managers sharing one [`SecureStorage`].
///
/// Clones share the same underlying storage and synchronization. Separately constructed instances
/// do not. A host that uses multiple instances or processes for one identity namespace must hold
/// one shared per-identity actor or lock from before preparing an operation until it is finalized,
/// aborted, or reconciled after an ambiguous host commit.
///
/// Methods named `prepare_*` stage a secure-storage change and return it with an operation id.
/// Reserve the operation, persist its output and id in the host transaction, then finalize:
///
/// ```
/// use roost_core::{InMemorySecureStorage, KeyStore};
///
/// let store = KeyStore::new(Box::new(InMemorySecureStorage::new()));
/// let prepared = store.prepare_identity_creation()?;
/// store.reserve_operation(prepared.operation.id)?;
/// // Persist or publish `prepared.output` with the host operation id.
/// store.finalize_operation(prepared.operation.id)?;
/// # Ok::<(), roost_core::KeyStoreError>(())
/// ```
#[derive(Clone)]
pub struct KeyStore(Arc<KeyStoreInner>);

impl KeyStore {
    /// Creates a keystore backed by `storage`, reading time from the system clock.
    pub fn new(storage: Box<dyn SecureStorage>) -> Self {
        Self::with_protocol_engine(storage, ProtocolStateEngine::new())
    }

    /// Creates a keystore whose operations share the supplied protocol configuration.
    ///
    /// The engine is immutable for this identity context, including prepared operations.
    pub fn with_protocol_engine(
        storage: Box<dyn SecureStorage>,
        engine: ProtocolStateEngine,
    ) -> Self {
        Self::from_shared_storage(Arc::new(Mutex::new(storage)), engine)
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

    /// Prepares fresh identity and discovery-key material without changing authoritative storage.
    pub fn prepare_identity_creation(
        &self,
    ) -> Result<PreparedKeyStoreOperation<Identity>, KeyStoreError> {
        self.prepare_operation(|staged| staged.generate_identity_eager())
    }

    fn generate_identity_eager(&self) -> Result<Identity, KeyStoreError> {
        let identity = match self.0.identity.generate_identity(&mut OsRng) {
            Ok(identity) => identity,
            // A prior partial creation may have stored the identity but not the discovery key.
            Err(IdentityError::AlreadyExists) => match self.0.discovery.stored_status()? {
                DiscoveryKeyStatus::Absent => self.0.identity.load_identity()?,
                DiscoveryKeyStatus::Present { .. } => {
                    return Err(IdentityError::AlreadyExists.into());
                }
                DiscoveryKeyStatus::Malformed => return Err(DiscoveryKeyError::Malformed.into()),
            },
            Err(e) => return Err(e.into()),
        };
        self.0.discovery.rotate_now(&mut OsRng, SystemTime::now())?;
        Ok(identity)
    }

    /// Returns the stored [`Identity`], or `None` when no identity is stored.
    ///
    /// A storage fault or a malformed Identity Secret Blob is an error, not `None`.
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
        self.ensure_no_recovery_required()?;
        Ok(self.0.identity.load_identity()?)
    }

    /// Returns the current [`PublicDiscoveryKey`], verified against the identity key.
    pub fn current_public_discovery_key(&self) -> Result<PublicDiscoveryKey, KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        self.ensure_no_recovery_required()?;
        Ok(self.0.discovery.current_public()?)
    }

    /// Returns a publishable key pair.
    ///
    /// Returns a [`PublicationBundle`] whose caller-created keys verify together. Prefer this for
    /// identity publication over reading the two public keys separately. Public one-time pre-keys
    /// are managed by [`Self::prepare_one_time_prekeys`] and
    /// [`Self::prepare_one_time_prekey_replenishment`].
    pub fn current_publication(&self) -> Result<PublicationBundle, KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        self.ensure_no_recovery_required()?;
        let discovery_key = self.0.discovery.current()?;
        let discovery_to_identity = self.0.discovery.identity_binding(&discovery_key)?;
        let recipient_delivery_verifier = self.0.discovery.current_capability()?.verifier();
        let discovery_key = discovery_key.public();
        let signed_prekey = self.0.signed_prekey.current_public(SystemTime::now())?;
        // Reject storage rollback/desync before publishing a mismatched pair.
        verify_public_signed_prekey(&signed_prekey, &discovery_key.verifying_key)
            .map_err(|_| SignedPreKeyError::Corrupt)?;
        Ok(PublicationBundle {
            version: PREKEY_BUNDLE_VERSION,
            discovery_key,
            discovery_to_identity,
            recipient_delivery_verifier,
            signed_prekey,
        })
    }

    /// Blocks a contact and rotates the inbox so the block takes effect at the relay.
    ///
    /// Blocking alone only stops messages being surfaced locally; the relay would still accept and
    /// queue them, because the blocked contact still holds a working delivery capability. Rotating
    /// the inbox invalidates that capability. The cost is that every *other* contact's copy is
    /// invalidated too and must be re-supplied — see [`ContactBlock::rotation`].
    ///
    /// A contact that is already blocked produces no state change and no rotation, so repeating the
    /// call does not churn every contact's capability. Its no-op operation must still be finalized
    /// or aborted.
    ///
    /// Neither change is authoritative when this returns. Reserve the operation, atomically apply
    /// [`ContactBlock::contact`] in the host transaction, then finalize the staged inbox rotation.
    /// Abort only after proving the host transaction did not commit.
    pub fn prepare_block_contact(
        &self,
        snapshot: &ProtocolStateSnapshot,
        identity_key: ContactIdentityKey,
    ) -> Result<PreparedKeyStoreOperation<ContactBlock>, KeyStoreError> {
        let contact = self.0.engine.block_contact(snapshot, identity_key)?;
        self.prepare_operation(move |staged| {
            // Repeated blocking still owns an operation, but must not rotate other contacts'
            // capabilities.
            let rotation = if contact.state_updates.is_empty() {
                None
            } else {
                Some(staged.rotate_inbox_now_eager()?)
            };
            Ok(ContactBlock { contact, rotation })
        })
    }

    /// Returns the recipient delivery capability for the current inbox.
    ///
    /// Secret-bearing. Give it only to authorized contacts through an encrypted channel, and
    /// register [`PublicationBundle::recipient_delivery_verifier`] instead — Roost never
    /// registers, validates, or transmits a capability.
    pub fn current_delivery_capability(
        &self,
    ) -> Result<RecipientDeliveryCapability, KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        self.ensure_no_recovery_required()?;
        Ok(self.0.discovery.current_capability()?)
    }

    /// Prepares exactly `batch_size` one-time prekeys for the current discovery-key epoch.
    ///
    /// The new secrets remain staged until finalization. No discovery-key rotation is required.
    /// The call fails if the requested batch would exceed the pool cap.
    pub fn prepare_one_time_prekeys(
        &self,
        batch_size: usize,
    ) -> Result<PreparedKeyStoreOperation<Vec<PublicOneTimePreKey>>, KeyStoreError> {
        self.prepare_operation(move |staged| staged.generate_one_time_prekeys_eager(batch_size))
    }

    fn generate_one_time_prekeys_eager(
        &self,
        batch_size: usize,
    ) -> Result<Vec<PublicOneTimePreKey>, KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        Ok(self
            .0
            .one_time_prekey
            .generate_batch(&mut OsRng, batch_size, SystemTime::now())?)
    }

    /// Prepares replenishment of the stored one-time pre-key pool.
    ///
    /// Returns the public one-time pre-keys created by this call. A missing or stale pool is
    /// rebuilt for the current discovery-key epoch; a current pool above the replenish threshold is
    /// left unchanged and returns an empty list. The returned no-op operation must still be
    /// finalized or aborted.
    pub fn prepare_one_time_prekey_replenishment(
        &self,
    ) -> Result<PreparedKeyStoreOperation<Vec<PublicOneTimePreKey>>, KeyStoreError> {
        self.prepare_operation(|staged| staged.replenish_one_time_prekeys_eager())
    }

    fn replenish_one_time_prekeys_eager(&self) -> Result<Vec<PublicOneTimePreKey>, KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        Ok(self
            .0
            .one_time_prekey
            .replenish(&mut OsRng, SystemTime::now())?)
    }

    #[cfg(test)]
    pub(crate) fn consume_one_time_prekey(
        &self,
        epoch: u32,
        id: u64,
    ) -> Result<OneTimePreKey, KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        self.ensure_no_recovery_required()?;
        Ok(self.0.one_time_prekey.consume_one_time_prekey(epoch, id)?)
    }

    /// Prepares rotation of the whole inbox.
    ///
    /// Advances the epoch, replaces the discovery key and the recipient delivery
    /// capability together, clears epoch-bound one-time pre-keys, and returns both the
    /// publishable material and the new capability. A preparation failure discards the staged
    /// changes, leaving the previous authoritative inbox intact.
    ///
    /// This invalidates every contact's delivery authorization — that is what makes it the
    /// mechanism behind blocking, and why it is not merely a discovery-key rotation.
    pub fn prepare_inbox_rotation(
        &self,
    ) -> Result<PreparedKeyStoreOperation<InboxRotation>, KeyStoreError> {
        self.prepare_operation(|staged| staged.rotate_inbox_now_eager())
    }

    fn rotate_inbox_now_eager(&self) -> Result<InboxRotation, KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        let now = SystemTime::now();
        self.0.one_time_prekey.reset()?;
        self.0.signed_prekey.reset()?;
        let discovery_key = self.0.discovery.rotate_now(&mut OsRng, now)?;
        let discovery_to_identity = self.0.discovery.identity_binding(&discovery_key)?;
        let capability = self.0.discovery.current_capability()?;
        let recipient_delivery_verifier = capability.verifier();
        let signed_prekey = self.0.signed_prekey.rotate_now(&mut OsRng, now)?;
        let publication = PublicationBundle {
            version: PREKEY_BUNDLE_VERSION,
            discovery_key: discovery_key.public(),
            discovery_to_identity,
            recipient_delivery_verifier,
            signed_prekey: signed_prekey.public(),
        };
        Ok(InboxRotation {
            publication,
            capability,
        })
    }

    /// Prepares a signed-pre-key rotation when the stored one is stale or missing.
    ///
    /// Returns the new public signed pre-key when callers need to upload it, or `None` when no
    /// rotation was needed. The returned no-op operation must still be finalized or aborted.
    pub fn prepare_signed_prekey_rotation_if_stale(
        &self,
    ) -> Result<PreparedKeyStoreOperation<Option<PublicSignedPreKey>>, KeyStoreError> {
        self.prepare_operation(|staged| staged.rotate_signed_prekey_if_stale_eager())
    }

    fn rotate_signed_prekey_if_stale_eager(
        &self,
    ) -> Result<Option<PublicSignedPreKey>, KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        Ok(self
            .0
            .signed_prekey
            .rotate_if_stale(&mut OsRng, SystemTime::now())?
            .map(|signed_prekey| signed_prekey.public()))
    }

    /// Prepares an immediate signed-prekey rotation and returns the provisional public key.
    ///
    /// Use this for explicit key-reset operations that must publish a fresh signed pre-key even
    /// when the stored one is still fresh.
    pub fn prepare_signed_prekey_rotation(
        &self,
    ) -> Result<PreparedKeyStoreOperation<PublicSignedPreKey>, KeyStoreError> {
        self.prepare_operation(|staged| staged.rotate_signed_prekey_now_eager())
    }

    fn rotate_signed_prekey_now_eager(&self) -> Result<PublicSignedPreKey, KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        Ok(self
            .0
            .signed_prekey
            .rotate_now(&mut OsRng, SystemTime::now())?
            .public())
    }

    /// Exports the stored identity and current discovery key as a passphrase-encrypted backup blob.
    ///
    /// Requires a stored discovery key; a partially generated identity must be completed with
    /// [`Self::prepare_identity_creation`] (which repairs a missing discovery key) before
    /// exporting.
    pub fn export_encrypted_backup(&self, passphrase: &str) -> Result<Vec<u8>, KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        self.ensure_no_recovery_required()?;
        self.0.discovery.current()?;
        let discovery_key_blob = self.0.discovery.export_blob()?;
        Ok(self
            .0
            .identity
            .export_encrypted_backup(&mut OsRng, passphrase, &discovery_key_blob)?)
    }

    /// Prepares restoration of an identity and discovery key from an encrypted backup.
    ///
    /// Authenticates the backup and validates the restored discovery key against the restored
    /// identity before staging changes, so a wrong passphrase or malformed blob leaves existing
    /// material untouched. Reserve this operation, atomically wipe or replace host-owned Session,
    /// deduplication, and pending-acknowledgment state, then finalize. The restored identity keeps
    /// the discovery-key epoch lineage from the backup, but prekey generation and publication stay
    /// blocked until [`Self::prepare_inbox_rotation`] advances to the next epoch. This avoids
    /// reusing prekey identifiers already published under the backed-up epoch.
    pub fn prepare_backup_import(
        &self,
        data: &[u8],
        passphrase: &str,
    ) -> Result<PreparedKeyStoreOperation<()>, KeyStoreError> {
        self.prepare_operation(move |staged| staged.import_encrypted_backup_eager(data, passphrase))
    }

    fn import_encrypted_backup_eager(
        &self,
        data: &[u8],
        passphrase: &str,
    ) -> Result<(), KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        let (identity_key, discovery_key_blob) =
            self.0.identity.decrypt_backup(data, passphrase)?;
        // Validate the restored key graph before clearing any existing material.
        DiscoveryKeyManager::validate_blob_for_identity(&discovery_key_blob, &identity_key)?;
        self.0.one_time_prekey.mark_inbox_rotation_required()?;
        self.0.signed_prekey.mark_inbox_rotation_required()?;
        self.0.discovery.reset()?;
        self.0.identity.reset()?;
        self.0.identity.store_decrypted_identity(&identity_key)?;
        self.0.discovery.restore_from_blob(&discovery_key_blob)?;
        Ok(())
    }

    /// Prepares deletion of the stored pre-keys, discovery key, and identity.
    ///
    /// Reserve this operation, atomically wipe host-owned protocol state, then finalize.
    /// Interrupted finalization resumes from durable progress.
    pub fn prepare_identity_deletion(
        &self,
    ) -> Result<PreparedKeyStoreOperation<()>, KeyStoreError> {
        self.prepare_operation(|staged| staged.reset_eager())
    }

    fn reset_eager(&self) -> Result<(), KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        self.0.one_time_prekey.reset()?;
        self.0.signed_prekey.reset()?;
        self.0.discovery.reset()?;
        self.0.identity.reset()?;
        Ok(())
    }

    // Keeps multikey updates from interleaving across cloned keystores. The per-storage mutex only
    // protects individual storage calls. This guard protects the keychain invariant.
    fn lifecycle_guard(&self) -> std::sync::MutexGuard<'_, ()> {
        self.0
            .lifecycle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

// Existing unit tests exercise the eager manager composition directly. Public integration tests
// below exercise the prepared-operation boundary; keeping these shims test-only avoids conflating
// those two responsibility layers.
#[cfg(test)]
impl KeyStore {
    fn current_public_signed_prekey(&self) -> Result<PublicSignedPreKey, KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        self.ensure_no_recovery_required()?;
        Ok(self.0.signed_prekey.current_public(SystemTime::now())?)
    }

    fn generate_identity(&self) -> Result<Identity, KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        self.generate_identity_eager()
    }

    fn generate_one_time_prekeys(
        &self,
        batch_size: usize,
    ) -> Result<Vec<PublicOneTimePreKey>, KeyStoreError> {
        self.generate_one_time_prekeys_eager(batch_size)
    }

    fn replenish_one_time_prekeys(&self) -> Result<Vec<PublicOneTimePreKey>, KeyStoreError> {
        self.replenish_one_time_prekeys_eager()
    }

    fn rotate_inbox_now(&self) -> Result<InboxRotation, KeyStoreError> {
        self.rotate_inbox_now_eager()
    }

    fn rotate_signed_prekey_if_stale(&self) -> Result<Option<PublicSignedPreKey>, KeyStoreError> {
        self.rotate_signed_prekey_if_stale_eager()
    }

    fn rotate_signed_prekey_now(&self) -> Result<PublicSignedPreKey, KeyStoreError> {
        self.rotate_signed_prekey_now_eager()
    }

    fn import_encrypted_backup(&self, data: &[u8], passphrase: &str) -> Result<(), KeyStoreError> {
        self.import_encrypted_backup_eager(data, passphrase)
    }

    fn reset(&self) -> Result<(), KeyStoreError> {
        self.reset_eager()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::one_time_prekey::{
        ONE_TIME_PREKEY_POOL_TARGET, ONE_TIME_PREKEY_REPLENISH_THRESHOLD,
    };
    use crate::storage::{InMemorySecureStorage, StorageError};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use roost_crypto::{verify_discovery_to_identity_binding, verify_public_discovery_key};
    use std::collections::HashSet;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use zeroize::Zeroizing;

    // Storage keys are duplicated from the manager modules so tests can inspect and tamper.
    const DISCOVERY_KEY: &str = "discovery/current";
    const IDENTITY_CURRENT_KEY: &str = "identity/current";
    const SIGNED_PREKEY: &str = "prekey/signed";

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

    #[test]
    fn key_store_clone_shares_storage() {
        let original_store = store();
        let cloned_store = original_store.clone();
        original_store.generate_identity().unwrap();
        assert!(cloned_store.load_identity().is_ok());
    }

    /// One operation must return everything a rotation produces. Returning the
    /// publishable material without the capability invites a caller to publish a new inbox
    /// while still handing contacts the previous inbox's secret.
    #[test]
    fn inbox_rotation_returns_publication_and_capability_together() {
        let key_store = store();
        key_store.generate_identity().unwrap();

        let rotation = key_store.rotate_inbox_now().unwrap();

        assert_eq!(
            rotation.publication.recipient_delivery_verifier,
            rotation.capability.verifier()
        );
        assert_eq!(
            *rotation.capability.to_bytes(),
            *key_store.current_delivery_capability().unwrap().to_bytes()
        );
        assert_eq!(rotation.publication.discovery_key.epoch, 2);
    }

    /// The host registers the verifier and never the capability, so the published
    /// bundle must carry a verifier that actually commits to the capability currently in storage.
    #[test]
    fn publication_bundle_carries_the_verifier_for_the_current_capability() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        key_store.rotate_signed_prekey_now().unwrap();

        let publication = key_store.current_publication().unwrap();
        let capability = key_store.current_delivery_capability().unwrap();

        assert_eq!(
            publication.recipient_delivery_verifier,
            capability.verifier()
        );
    }

    #[test]
    fn rotation_changes_the_published_verifier() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        key_store.rotate_signed_prekey_now().unwrap();
        let before = key_store.current_publication().unwrap();

        let after = key_store.rotate_inbox_now().unwrap().publication;

        assert_ne!(
            before.recipient_delivery_verifier,
            after.recipient_delivery_verifier
        );
    }

    #[test]
    fn generate_identity_persists_discovery_key_at_epoch_one() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        let bundle = key_store.current_public_discovery_key().unwrap();
        assert_eq!(bundle.epoch, 1);
    }

    #[test]
    fn generate_identity_completes_partial_discovery_key() {
        let (key_store, storage) = store_with_storage();
        key_store.generate_identity().unwrap();
        storage.lock().unwrap().delete(DISCOVERY_KEY).unwrap();
        key_store.generate_identity().unwrap();
        assert!(key_store.current_public_discovery_key().is_ok());
    }

    #[test]
    fn generate_identity_rejects_malformed_discovery_key() {
        let (key_store, storage) = store_with_storage();
        key_store.generate_identity().unwrap();
        storage
            .lock()
            .unwrap()
            .store(DISCOVERY_KEY, &[0xAAu8; 50])
            .unwrap();
        assert!(matches!(
            key_store.generate_identity(),
            Err(KeyStoreError::Discovery(DiscoveryKeyError::Malformed))
        ));
    }

    #[test]
    fn load_identity_succeeds_without_discovery_key() {
        let (key_store, storage) = store_with_storage();
        key_store.generate_identity().unwrap();
        storage.lock().unwrap().delete(DISCOVERY_KEY).unwrap();
        assert!(key_store.load_identity().is_ok());
    }

    #[test]
    fn current_publication_bundle_carries_both_binding_directions() {
        let key_store = store();
        let identity = key_store.generate_identity().unwrap();
        key_store.rotate_signed_prekey_now().unwrap();

        let publication = key_store.current_publication().unwrap();

        // IK→DK: the identity authorized this discovery key.
        assert!(
            verify_public_discovery_key(&publication.discovery_key, identity.verifying_key())
                .is_ok()
        );
        // DK→IK: the discovery key authorized this identity.
        assert!(
            verify_discovery_to_identity_binding(
                &identity.public().unwrap(),
                &publication.discovery_key.verifying_key,
                &publication.discovery_to_identity,
            )
            .is_ok()
        );
    }

    #[test]
    fn rotate_inbox_now_carries_both_binding_directions() {
        let key_store = store();
        let identity = key_store.generate_identity().unwrap();

        let publication = key_store.rotate_inbox_now().unwrap().publication;

        assert!(
            verify_public_discovery_key(&publication.discovery_key, identity.verifying_key())
                .is_ok()
        );
        assert!(
            verify_discovery_to_identity_binding(
                &identity.public().unwrap(),
                &publication.discovery_key.verifying_key,
                &publication.discovery_to_identity,
            )
            .is_ok()
        );
    }

    /// The binding is recomputed per read rather than persisted, so it must be byte-stable.
    /// Ed25519 is deterministic and the payload carries no timestamp, so two reads of an
    /// unchanged discovery key must produce identical bytes.
    #[test]
    fn discovery_to_identity_binding_is_stable_across_reads() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        key_store.rotate_signed_prekey_now().unwrap();

        let first = key_store.current_publication().unwrap();
        let second = key_store.current_publication().unwrap();

        assert_eq!(
            first.discovery_to_identity.to_bytes(),
            second.discovery_to_identity.to_bytes()
        );
    }

    #[test]
    fn rotation_changes_the_discovery_to_identity_binding() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        key_store.rotate_signed_prekey_now().unwrap();
        let before = key_store.current_publication().unwrap();

        let after = key_store.rotate_inbox_now().unwrap().publication;

        assert_ne!(
            before.discovery_to_identity.to_bytes(),
            after.discovery_to_identity.to_bytes()
        );
    }

    #[test]
    fn current_publication_bundle_returns_verifiable_chain() {
        let key_store = store();
        let identity = key_store.generate_identity().unwrap();
        assert!(matches!(
            key_store.current_publication(),
            Err(KeyStoreError::SignedPreKey(SignedPreKeyError::NotFound))
        ));
        key_store.rotate_signed_prekey_now().unwrap();
        let publication = key_store.current_publication().unwrap();
        assert_eq!(publication.version, roost_crypto::PREKEY_BUNDLE_VERSION);
        assert!(
            verify_public_discovery_key(&publication.discovery_key, identity.verifying_key())
                .is_ok()
        );
        assert!(
            verify_public_signed_prekey(
                &publication.signed_prekey,
                &publication.discovery_key.verifying_key
            )
            .is_ok()
        );
    }

    #[test]
    fn replenish_one_time_prekeys_creates_initial_pool() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        let discovery = key_store.current_public_discovery_key().unwrap();
        let bundles = key_store.replenish_one_time_prekeys().unwrap();
        assert_eq!(bundles.len(), ONE_TIME_PREKEY_POOL_TARGET);
        assert!(bundles.iter().all(|bundle| bundle.epoch == discovery.epoch));
    }

    #[test]
    fn generate_one_time_prekeys_creates_exact_caller_size() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        let discovery = key_store.current_public_discovery_key().unwrap();
        let first = key_store.generate_one_time_prekeys(3).unwrap();
        let second = key_store.generate_one_time_prekeys(2).unwrap();

        assert_eq!(first.len(), 3);
        assert_eq!(second.len(), 2);
        assert!(
            first
                .iter()
                .chain(&second)
                .all(|bundle| bundle.epoch == discovery.epoch)
        );
        assert_eq!(
            first
                .iter()
                .chain(&second)
                .map(|bundle| bundle.id)
                .collect::<Vec<_>>(),
            vec![0, 1, 2, 3, 4]
        );
    }

    #[test]
    fn generate_one_time_prekeys_rejects_over_cap_batch() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        key_store
            .generate_one_time_prekeys(ONE_TIME_PREKEY_POOL_TARGET)
            .unwrap();

        assert!(matches!(
            key_store.generate_one_time_prekeys(1),
            Err(KeyStoreError::OneTimePreKey(
                OneTimePreKeyError::BatchExceedsCapacity {
                    requested: 1,
                    available: 0
                }
            ))
        ));
    }

    #[test]
    fn generated_one_time_prekeys_persist_until_consumed() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        let epoch = key_store.current_public_discovery_key().unwrap().epoch;
        let bundle = key_store.generate_one_time_prekeys(1).unwrap().remove(0);

        let prekey = key_store.consume_one_time_prekey(epoch, bundle.id).unwrap();
        assert_eq!(prekey.id(), bundle.id);
        assert!(matches!(
            key_store.consume_one_time_prekey(epoch, bundle.id),
            Err(KeyStoreError::OneTimePreKey(OneTimePreKeyError::NotFound))
        ));
    }

    #[test]
    fn consume_one_time_prekey_rejects_stale_epoch() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        let epoch = key_store.current_public_discovery_key().unwrap().epoch;
        let bundle = key_store.generate_one_time_prekeys(1).unwrap().remove(0);

        assert!(matches!(
            key_store.consume_one_time_prekey(epoch + 1, bundle.id),
            Err(KeyStoreError::OneTimePreKey(OneTimePreKeyError::StaleEpoch))
        ));
    }

    #[test]
    fn replenish_one_time_prekeys_returns_empty_above_threshold() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        key_store.replenish_one_time_prekeys().unwrap();
        let bundles = key_store.replenish_one_time_prekeys().unwrap();
        assert!(bundles.is_empty());
    }

    #[test]
    fn replenish_one_time_prekeys_tops_up_at_threshold() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        let epoch = key_store.current_public_discovery_key().unwrap().epoch;
        let bundles = key_store.replenish_one_time_prekeys().unwrap();
        let keys_to_use = ONE_TIME_PREKEY_POOL_TARGET - ONE_TIME_PREKEY_REPLENISH_THRESHOLD;
        for bundle in bundles.iter().take(keys_to_use) {
            key_store.consume_one_time_prekey(epoch, bundle.id).unwrap();
        }
        let replenished = key_store.replenish_one_time_prekeys().unwrap();
        assert_eq!(replenished.len(), keys_to_use);
        assert_eq!(
            replenished.first().map(|bundle| bundle.id),
            Some(ONE_TIME_PREKEY_POOL_TARGET as u64)
        );
    }

    #[test]
    fn consume_one_time_prekey_consumes_secret_once() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        let epoch = key_store.current_public_discovery_key().unwrap().epoch;
        let bundle = key_store.replenish_one_time_prekeys().unwrap().remove(0);
        let prekey = key_store.consume_one_time_prekey(epoch, bundle.id).unwrap();
        assert_eq!(prekey.id(), bundle.id);
        assert!(matches!(
            key_store.consume_one_time_prekey(epoch, bundle.id),
            Err(KeyStoreError::OneTimePreKey(OneTimePreKeyError::NotFound))
        ));
    }

    #[test]
    fn concurrent_consume_returns_one_time_prekey_once() {
        const THREADS: usize = 8;

        let key_store = store();
        key_store.generate_identity().unwrap();
        let epoch = key_store.current_public_discovery_key().unwrap().epoch;
        let bundle = key_store.replenish_one_time_prekeys().unwrap().remove(0);
        let barrier = Arc::new(Barrier::new(THREADS));
        let mut threads = Vec::new();
        for _ in 0..THREADS {
            let key_store = key_store.clone();
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                key_store
                    .consume_one_time_prekey(epoch, bundle.id)
                    .ok()
                    .map(|prekey| prekey.id())
            }));
        }
        let successes: Vec<u64> = threads
            .into_iter()
            .filter_map(|thread| thread.join().unwrap())
            .collect();
        assert_eq!(successes.len(), 1);
        assert_eq!(successes[0], bundle.id);
    }

    #[test]
    fn concurrent_replenish_does_not_return_duplicate_one_time_prekeys() {
        const THREADS: usize = 8;

        let key_store = store();
        key_store.generate_identity().unwrap();
        let barrier = Arc::new(Barrier::new(THREADS));
        let mut threads = Vec::new();
        for _ in 0..THREADS {
            let key_store = key_store.clone();
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                key_store.replenish_one_time_prekeys().unwrap()
            }));
        }
        let bundles: Vec<_> = threads
            .into_iter()
            .flat_map(|thread| thread.join().unwrap())
            .collect();
        let ids: HashSet<_> = bundles.iter().map(|bundle| bundle.id).collect();
        assert_eq!(
            (bundles.len(), ids.len()),
            (ONE_TIME_PREKEY_POOL_TARGET, ONE_TIME_PREKEY_POOL_TARGET)
        );
    }

    #[test]
    fn rotate_inbox_now_clears_one_time_prekey_pool() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        key_store.replenish_one_time_prekeys().unwrap();
        let rotation = key_store.rotate_inbox_now().unwrap().publication;
        let bundles = key_store.replenish_one_time_prekeys().unwrap();
        assert_eq!(bundles.len(), ONE_TIME_PREKEY_POOL_TARGET);
        assert!(
            bundles
                .iter()
                .all(|bundle| bundle.epoch == rotation.discovery_key.epoch)
        );
        assert_eq!(bundles.first().map(|bundle| bundle.id), Some(0));
    }

    #[test]
    fn import_encrypted_backup_blocks_one_time_prekeys_until_inbox_rotation() {
        let destination_store = store();
        destination_store.generate_identity().unwrap();
        destination_store.replenish_one_time_prekeys().unwrap();
        let source_store = store();
        source_store.generate_identity().unwrap();
        let backup = source_store.export_encrypted_backup("pass").unwrap();
        destination_store
            .import_encrypted_backup(&backup, "pass")
            .unwrap();
        assert!(matches!(
            destination_store
                .0
                .one_time_prekey
                .consume_one_time_prekey(0, 0),
            Err(OneTimePreKeyError::InboxRotationRequired)
        ));
        assert!(matches!(
            destination_store.replenish_one_time_prekeys(),
            Err(KeyStoreError::OneTimePreKey(
                OneTimePreKeyError::InboxRotationRequired
            ))
        ));

        let rotation = destination_store.rotate_inbox_now().unwrap().publication;
        let one_time_prekeys = destination_store.replenish_one_time_prekeys().unwrap();
        assert_eq!(one_time_prekeys[0].epoch, rotation.discovery_key.epoch);
        assert_eq!(one_time_prekeys[0].id, 0);
    }

    #[test]
    fn current_publication_bundle_rejects_prekey_signed_by_superseded_discovery_key() {
        let (key_store, storage) = store_with_storage();
        key_store.generate_identity().unwrap();
        key_store.rotate_signed_prekey_now().unwrap();
        key_store.current_publication().unwrap();
        let stale_prekey = storage
            .lock()
            .unwrap()
            .load(SIGNED_PREKEY)
            .unwrap()
            .unwrap()
            .to_vec();
        key_store.rotate_inbox_now().unwrap();
        storage
            .lock()
            .unwrap()
            .store(SIGNED_PREKEY, &stale_prekey)
            .unwrap();
        assert!(matches!(
            key_store.current_publication(),
            Err(KeyStoreError::SignedPreKey(SignedPreKeyError::Corrupt))
        ));
    }

    #[test]
    fn rotate_inbox_now_advances_epoch_and_refreshes_prekey() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        let first_dk = key_store.current_public_discovery_key().unwrap();
        assert_eq!(first_dk.epoch, 1);

        let rotation = key_store.rotate_inbox_now().unwrap().publication;
        assert_eq!(rotation.version, roost_crypto::PREKEY_BUNDLE_VERSION);
        assert_eq!(rotation.discovery_key.epoch, 2);
        assert_ne!(
            rotation.discovery_key.public_key.as_bytes(),
            first_dk.public_key.as_bytes()
        );
        assert!(
            verify_public_signed_prekey(
                &rotation.signed_prekey,
                &rotation.discovery_key.verifying_key
            )
            .is_ok()
        );
    }

    #[test]
    fn rotate_inbox_now_clears_prior_epoch_signed_prekey_secret() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        let first_epoch = key_store.current_public_discovery_key().unwrap().epoch;
        let first_prekey = key_store.rotate_signed_prekey_now().unwrap();

        key_store.rotate_inbox_now().unwrap();

        assert!(matches!(
            key_store.0.signed_prekey.prekey_for_reference(
                first_epoch,
                first_prekey.id,
                first_prekey.public_key.as_bytes(),
                SystemTime::now(),
            ),
            Err(SignedPreKeyError::NotFound)
        ));
    }

    #[test]
    fn rotate_inbox_now_failure_leaves_no_mismatched_prekey() {
        struct FailingSignedPreKeyStorage {
            inner: InMemorySecureStorage,
            should_fail: Arc<AtomicBool>,
        }

        impl SecureStorage for FailingSignedPreKeyStorage {
            fn store(&mut self, key: &str, value: &[u8]) -> Result<(), StorageError> {
                if self.should_fail.load(Ordering::SeqCst) && key == SIGNED_PREKEY {
                    return Err(StorageError::IO("injected store failure".into()));
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

        let should_fail = Arc::new(AtomicBool::new(false));
        let storage = FailingSignedPreKeyStorage {
            inner: InMemorySecureStorage::new(),
            should_fail: Arc::clone(&should_fail),
        };
        let key_store = KeyStore::new(Box::new(storage));
        key_store.generate_identity().unwrap();
        assert!(key_store.rotate_signed_prekey_if_stale().unwrap().is_some());

        should_fail.store(true, Ordering::SeqCst);
        assert!(matches!(
            key_store.rotate_inbox_now(),
            Err(KeyStoreError::SignedPreKey(SignedPreKeyError::Storage(
                StorageError::IO(_)
            )))
        ));
        should_fail.store(false, Ordering::SeqCst);

        assert_eq!(key_store.current_public_discovery_key().unwrap().epoch, 2);
        assert!(matches!(
            key_store.current_public_signed_prekey(),
            Err(KeyStoreError::SignedPreKey(SignedPreKeyError::NotFound))
        ));
    }

    #[test]
    fn concurrent_rotations_keep_discovery_key_and_signed_prekey_consistent() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        key_store.rotate_signed_prekey_if_stale().unwrap();

        let rotate_discovery = key_store.clone();
        let rotate_prekey = key_store.clone();
        let discovery_thread = std::thread::spawn(move || {
            for _ in 0..8 {
                rotate_discovery.rotate_inbox_now().unwrap();
            }
        });
        let prekey_thread = std::thread::spawn(move || {
            let mut rotations = 0;
            for _ in 0..8 {
                match rotate_prekey.rotate_signed_prekey_now() {
                    Ok(_) => rotations += 1,
                    Err(KeyStoreError::SignedPreKey(
                        SignedPreKeyError::RetainedCapacityReached { .. },
                    )) => {}
                    Err(error) => panic!("unexpected signed pre-key rotation failure: {error}"),
                }
            }
            rotations
        });
        discovery_thread.join().unwrap();
        assert!(prekey_thread.join().unwrap() > 0);

        let discovery = key_store.current_public_discovery_key().unwrap();
        let prekey = key_store.current_public_signed_prekey().unwrap();
        assert!(verify_public_signed_prekey(&prekey, &discovery.verifying_key).is_ok());
    }

    #[test]
    fn concurrent_publication_and_rotation_stays_consistent() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        key_store.rotate_signed_prekey_now().unwrap();

        let publisher = key_store.clone();
        let rotator = key_store.clone();
        let rotate_thread = std::thread::spawn(move || {
            for _ in 0..8 {
                rotator.rotate_inbox_now().unwrap();
            }
        });
        for _ in 0..8 {
            let publication = publisher.current_publication().unwrap();
            assert!(
                verify_public_signed_prekey(
                    &publication.signed_prekey,
                    &publication.discovery_key.verifying_key
                )
                .is_ok()
            );
        }
        rotate_thread.join().unwrap();
    }

    #[test]
    fn import_with_wrong_passphrase_does_not_disturb_existing_state() {
        let destination_store = store();
        destination_store.generate_identity().unwrap();
        destination_store.rotate_signed_prekey_if_stale().unwrap();
        let original_identity = destination_store.load_identity().unwrap();
        let original_signed_prekey = destination_store
            .current_public_signed_prekey()
            .unwrap()
            .public_key;

        let source_store = store();
        source_store.generate_identity().unwrap();
        let backup = source_store.export_encrypted_backup("right").unwrap();
        assert!(matches!(
            destination_store.import_encrypted_backup(&backup, "wrong"),
            Err(KeyStoreError::Identity(IdentityError::DecryptionFailed))
        ));

        let current_identity = destination_store.load_identity().unwrap();
        let current_signed_prekey = destination_store
            .current_public_signed_prekey()
            .unwrap()
            .public_key;
        assert_eq!(
            original_identity.public_key(),
            current_identity.public_key()
        );
        assert_eq!(
            original_signed_prekey.as_bytes(),
            current_signed_prekey.as_bytes()
        );
    }

    #[test]
    fn import_with_mismatched_discovery_key_leaves_state_untouched() {
        let mut rng = ChaCha20Rng::from_seed([0xe0; 32]);
        let source_store = store();
        source_store.generate_identity().unwrap();
        let other_store = store();
        other_store.generate_identity().unwrap();
        let other_discovery_blob = other_store.0.discovery.export_blob().unwrap();
        let mismatched_backup = source_store
            .0
            .identity
            .export_encrypted_backup(&mut rng, "pass", &other_discovery_blob)
            .unwrap();

        let destination_store = store();
        let original_identity = destination_store.generate_identity().unwrap();
        destination_store.rotate_signed_prekey_if_stale().unwrap();

        assert!(matches!(
            destination_store.import_encrypted_backup(&mismatched_backup, "pass"),
            Err(KeyStoreError::Discovery(DiscoveryKeyError::Corrupt))
        ));

        let current_identity = destination_store.load_identity().unwrap();
        assert_eq!(
            original_identity.public_key(),
            current_identity.public_key()
        );
        assert_eq!(
            original_identity.verifying_key().as_bytes(),
            current_identity.verifying_key().as_bytes()
        );
        assert!(destination_store.current_public_signed_prekey().is_ok());
    }

    #[test]
    fn prepare_backup_import_rejects_unknown_backup_version() {
        let source_store = store();
        source_store.generate_identity().unwrap();
        let mut backup = source_store.export_encrypted_backup("passphrase").unwrap();
        backup[0] = 0xFF;
        let destination_store = store();

        let result = destination_store.prepare_backup_import(&backup, "passphrase");

        assert!(matches!(
            result,
            Err(KeyStoreError::Identity(
                IdentityError::UnsupportedBackupVersion(0xFF)
            ))
        ));
        assert!(matches!(
            destination_store.load_identity(),
            Err(KeyStoreError::Identity(IdentityError::NotFound))
        ));
    }

    #[test]
    fn import_encrypted_backup_commits_identity_with_single_store() {
        struct CountingIdentityWriteStorage {
            inner: InMemorySecureStorage,
            fail_enabled: Arc<AtomicBool>,
            writes: Arc<AtomicUsize>,
        }

        impl SecureStorage for CountingIdentityWriteStorage {
            fn store(&mut self, key: &str, value: &[u8]) -> Result<(), StorageError> {
                if self.fail_enabled.load(Ordering::SeqCst) && key == IDENTITY_CURRENT_KEY {
                    let writes = self.writes.fetch_add(1, Ordering::SeqCst) + 1;
                    if writes == 2 {
                        return Err(StorageError::IO("injected identity store failure".into()));
                    }
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

        let fail_enabled = Arc::new(AtomicBool::new(false));
        let writes = Arc::new(AtomicUsize::new(0));
        let destination_store = KeyStore::new(Box::new(CountingIdentityWriteStorage {
            inner: InMemorySecureStorage::new(),
            fail_enabled: Arc::clone(&fail_enabled),
            writes: Arc::clone(&writes),
        }));
        destination_store.generate_identity().unwrap();

        let source_store = store();
        let source_identity = source_store.generate_identity().unwrap();
        let backup = source_store.export_encrypted_backup("pass").unwrap();

        fail_enabled.store(true, Ordering::SeqCst);
        destination_store
            .import_encrypted_backup(&backup, "pass")
            .unwrap();

        let imported_identity = destination_store.load_identity().unwrap();
        assert_eq!(writes.load(Ordering::SeqCst), 1);
        assert_eq!(source_identity.public_key(), imported_identity.public_key());
        assert_eq!(
            source_identity.verifying_key().as_bytes(),
            imported_identity.verifying_key().as_bytes()
        );
    }

    #[test]
    fn import_encrypted_backup_blob_store_failure_leaves_no_identity() {
        struct FailingBlobStorage {
            inner: InMemorySecureStorage,
            fail_blob_store: Arc<AtomicBool>,
        }

        impl SecureStorage for FailingBlobStorage {
            fn store(&mut self, key: &str, value: &[u8]) -> Result<(), StorageError> {
                if self.fail_blob_store.load(Ordering::SeqCst) && key == IDENTITY_CURRENT_KEY {
                    return Err(StorageError::IO("injected identity blob failure".into()));
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

        let fail_blob_store = Arc::new(AtomicBool::new(false));
        let destination_store = KeyStore::new(Box::new(FailingBlobStorage {
            inner: InMemorySecureStorage::new(),
            fail_blob_store: Arc::clone(&fail_blob_store),
        }));
        destination_store.generate_identity().unwrap();

        let source_store = store();
        source_store.generate_identity().unwrap();
        let backup = source_store.export_encrypted_backup("pass").unwrap();

        fail_blob_store.store(true, Ordering::SeqCst);
        assert!(matches!(
            destination_store.import_encrypted_backup(&backup, "pass"),
            Err(KeyStoreError::Identity(IdentityError::Storage(
                StorageError::IO(_)
            )))
        ));
        assert!(matches!(
            destination_store.load_identity(),
            Err(KeyStoreError::Identity(IdentityError::NotFound))
        ));
    }

    #[test]
    fn import_encrypted_backup_blocks_signed_prekeys_until_inbox_rotation() {
        let destination_store = store();
        destination_store.generate_identity().unwrap();
        destination_store.rotate_signed_prekey_if_stale().unwrap();

        let source_store = store();
        source_store.generate_identity().unwrap();
        let backup = source_store.export_encrypted_backup("pass").unwrap();

        destination_store
            .import_encrypted_backup(&backup, "pass")
            .unwrap();
        assert!(matches!(
            destination_store.current_public_signed_prekey(),
            Err(KeyStoreError::SignedPreKey(
                SignedPreKeyError::InboxRotationRequired
            ))
        ));
        assert!(matches!(
            destination_store.rotate_signed_prekey_if_stale(),
            Err(KeyStoreError::SignedPreKey(
                SignedPreKeyError::InboxRotationRequired
            ))
        ));
    }

    #[test]
    fn import_then_inbox_rotation_uses_fresh_epoch_and_signed_prekey_id() {
        let destination_store = store();
        destination_store.generate_identity().unwrap();
        destination_store.rotate_signed_prekey_if_stale().unwrap();

        let source_store = store();
        source_store.generate_identity().unwrap();
        let backup = source_store.export_encrypted_backup("pass").unwrap();
        let backed_up_epoch = source_store.current_public_discovery_key().unwrap().epoch;
        destination_store
            .import_encrypted_backup(&backup, "pass")
            .unwrap();
        let rotation = destination_store.rotate_inbox_now().unwrap().publication;

        let rotated_bundle = destination_store.current_public_signed_prekey().unwrap();
        let imported_identity = destination_store.load_identity().unwrap();
        let public_discovery_key = destination_store.current_public_discovery_key().unwrap();
        assert_eq!(public_discovery_key.epoch, backed_up_epoch + 1);
        assert_eq!(rotation.signed_prekey.id, 0);
        assert_eq!(rotated_bundle.id, 0);
        assert!(
            verify_public_discovery_key(&public_discovery_key, imported_identity.verifying_key())
                .is_ok()
        );
        assert!(
            verify_public_signed_prekey(&rotated_bundle, &public_discovery_key.verifying_key)
                .is_ok()
        );
    }

    #[test]
    fn import_restores_discovery_key_epoch_lineage() {
        let source_store = store();
        source_store.generate_identity().unwrap();
        source_store.rotate_inbox_now().unwrap();
        source_store.rotate_inbox_now().unwrap();
        assert_eq!(
            source_store.current_public_discovery_key().unwrap().epoch,
            3
        );
        let backup = source_store.export_encrypted_backup("pass").unwrap();

        let destination_store = store();
        destination_store.generate_identity().unwrap();
        destination_store
            .import_encrypted_backup(&backup, "pass")
            .unwrap();

        // The restored discovery key keeps the source epoch lineage instead of resetting to
        // the first epoch, and verifies against the restored identity.
        assert_eq!(
            destination_store
                .current_public_discovery_key()
                .unwrap()
                .epoch,
            3
        );
    }

    #[test]
    fn export_rejects_discovery_key_not_signed_by_identity() {
        let (key_store, storage) = store_with_storage();
        key_store.generate_identity().unwrap();
        let mut blob = storage
            .lock()
            .unwrap()
            .load(DISCOVERY_KEY)
            .unwrap()
            .unwrap()
            .to_vec();
        blob[69] ^= 0x01;
        storage.lock().unwrap().store(DISCOVERY_KEY, &blob).unwrap();

        assert!(matches!(
            key_store.export_encrypted_backup("pass"),
            Err(KeyStoreError::Discovery(DiscoveryKeyError::Corrupt))
        ));
    }

    #[test]
    fn unicode_normalized_passphrases_restore_same_identity_and_discovery_key() {
        let source_store = store();
        let source_identity = source_store.generate_identity().unwrap();
        let source_discovery = source_store.current_public_discovery_key().unwrap();
        let backup = source_store.export_encrypted_backup("caf\u{00e9}").unwrap();

        let destination_store = store();
        destination_store
            .import_encrypted_backup(&backup, "cafe\u{0301}")
            .unwrap();

        let destination_identity = destination_store.load_identity().unwrap();
        let destination_discovery = destination_store.current_public_discovery_key().unwrap();
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
        key_store.generate_identity().unwrap();
        storage.lock().unwrap().delete(DISCOVERY_KEY).unwrap();
        assert!(matches!(
            key_store.export_encrypted_backup("pass"),
            Err(KeyStoreError::Discovery(DiscoveryKeyError::NotFound))
        ));
    }

    #[test]
    fn import_with_malformed_discovery_blob_leaves_state_untouched() {
        let mut rng = ChaCha20Rng::from_seed([0xe1; 32]);
        // Build an authentic backup whose discovery-key region is structurally invalid.
        let source_storage: SharedStorage =
            Arc::new(Mutex::new(Box::new(InMemorySecureStorage::new())));
        let source_identity = IdentityManager::new(source_storage);
        source_identity.generate_identity(&mut rng).unwrap();
        let malformed_backup = source_identity
            .export_encrypted_backup(&mut rng, "pass", &[0xAAu8; 50])
            .unwrap();

        let destination_store = store();
        let original_identity = destination_store.generate_identity().unwrap();
        destination_store.rotate_signed_prekey_if_stale().unwrap();

        assert!(matches!(
            destination_store.import_encrypted_backup(&malformed_backup, "pass"),
            Err(KeyStoreError::Discovery(
                DiscoveryKeyError::InvalidBlobLength { actual: 50, .. }
            ))
        ));

        let current_identity = destination_store.load_identity().unwrap();
        assert_eq!(
            original_identity.public_key(),
            current_identity.public_key()
        );
        assert!(destination_store.current_public_signed_prekey().is_ok());
    }

    #[test]
    fn reset_clears_identity_discovery_key_and_prekeys() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        key_store.replenish_one_time_prekeys().unwrap();
        key_store.rotate_signed_prekey_if_stale().unwrap();
        key_store.reset().unwrap();
        assert!(matches!(
            key_store.load_identity(),
            Err(KeyStoreError::Identity(IdentityError::NotFound))
        ));
        assert!(matches!(
            key_store.current_public_discovery_key(),
            Err(KeyStoreError::Discovery(DiscoveryKeyError::NotFound))
        ));
        assert!(matches!(
            key_store.0.one_time_prekey.consume_one_time_prekey(0, 0),
            Err(OneTimePreKeyError::NotFound)
        ));
        assert!(matches!(
            key_store.current_public_signed_prekey(),
            Err(KeyStoreError::SignedPreKey(SignedPreKeyError::NotFound))
        ));
    }

    #[test]
    fn reset_on_empty_store_succeeds() {
        let key_store = store();
        key_store.reset().unwrap();
        key_store.reset().unwrap();
    }
}
