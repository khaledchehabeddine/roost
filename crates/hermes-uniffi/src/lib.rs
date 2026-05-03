//! UniFFI bindings for the Hermes cryptographic core.
//!
//! Exposes a small, stable Rust surface that UniFFI projects into Swift and Kotlin via the
//! generated bindings. Consumers construct a single [`KeyStore`], plug in a platform
//! [`SecureStorage`] (iOS Keychain or Android Keystore), and use the keystore to manage the local
//! identity and its signed pre-key.
//!
//! # Quick start
//!
//! ```no_run
//! use hermes::{HermesError, InMemorySecureStorage, KeyStore, SecureStorage};
//! use std::sync::Arc;
//!
//! # fn main() -> Result<(), HermesError> {
//! let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
//! let store = KeyStore::new(storage);
//!
//! if !store.has_identity()? {
//!     store.generate_identity()?;
//! }
//!
//! if let Some(new_bundle) = store.rotate_signed_prekey_if_stale()? {
//!     // upload `new_bundle` to peers
//!     let _ = new_bundle;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Mental model
//!
//! - One [`KeyStore`] per app, constructed once at launch and held by the app shell.
//! - The [`SecureStorage`] trait is the platform integration point. The bundled
//!   [`InMemorySecureStorage`] is for prototypes and tests only — production builds wire iOS
//!   Keychain or Android Keystore via [`#[uniffi::export(with_foreign)]`] (`SecureStorage`).
//! - All errors funnel into [`HermesError`]. Variants describe what the consumer can act on;
//!   unrecoverable internals collapse into [`HermesError::InternalError`] with a `reason` string
//!   for telemetry.

uniffi::setup_scaffolding!("hermes");

use hermes_core::{
    Identity as CoreIdentity, IdentityError, KeyStore as CoreKeyStore, KeyStoreError,
    SecureStorage as CoreSecureStorage, SignedPreKeyError, StorageError,
};
use hermes_crypto::SignedPreKeyBundle as CoreSignedPreKeyBundle;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

/// Errors surfaced across the FFI boundary.
///
/// Each variant maps to a recovery action the consumer can take. Internal failures the consumer
/// cannot meaningfully act on (lock poisoning, KDF arithmetic overflow, system clock anomalies)
/// collapse into [`HermesError::InternalError`] — the `reason` string is for logging and
/// telemetry only and may change without semver impact.
#[derive(Debug, uniffi::Error)]
pub enum HermesError {
    /// An identity is already stored. Recovery: load the existing identity instead of generating.
    AlreadyExists,
    /// Encrypted backup creation failed. Recovery: surface to the user; check the
    /// `reason` for diagnostic context.
    BackupFailed {
        /// Human-readable failure context (RNG failure, encryption error). For logs only.
        reason: String,
    },
    /// Identity storage contains only one of the two key components — partial-write damage.
    /// Recovery: prompt the user to restore from backup or reset.
    Corrupt,
    /// Backup decryption failed: wrong passphrase, tampered ciphertext, or wrong cipher
    /// parameters. Recovery: ask the user to re-enter the passphrase.
    DecryptionFailed,
    /// Unrecoverable internal failure (lock poisoning, system clock before Unix epoch, etc.).
    /// Recovery: surface a generic error to the user; consider restarting the app.
    InternalError {
        /// Diagnostic context for logging and telemetry only. May change without semver impact.
        reason: String,
    },
    /// Input bytes are malformed or the wrong length. Recovery: validate the source of the bytes
    /// (corrupt backup blob, wrong-version stored data) and present a user-actionable message.
    InvalidData {
        /// Human-readable description of what was invalid. For logs only.
        reason: String,
    },
    /// No identity is stored. Recovery: call [`KeyStore::generate_identity`] or import a backup.
    NotFound,
    /// Underlying [`SecureStorage`] returned an error from the platform Keychain or Keystore.
    /// Recovery: surface the error to the user; persistent failures may indicate revoked
    /// permissions or platform misconfiguration.
    Storage {
        /// Platform-specific error message from the underlying [`SecureStorage`] implementation.
        reason: String,
    },
}

impl std::fmt::Display for HermesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HermesError::AlreadyExists => write!(f, "identity already exists"),
            HermesError::BackupFailed { reason } => write!(f, "backup failed: {reason}"),
            HermesError::Corrupt => write!(f, "identity data is corrupt"),
            HermesError::DecryptionFailed => write!(f, "decryption failed"),
            HermesError::InternalError { reason } => write!(f, "internal error: {reason}"),
            HermesError::InvalidData { reason } => write!(f, "invalid data: {reason}"),
            HermesError::NotFound => write!(f, "no identity found"),
            HermesError::Storage { reason } => write!(f, "storage error: {reason}"),
        }
    }
}

impl std::error::Error for HermesError {}

impl From<IdentityError> for HermesError {
    fn from(e: IdentityError) -> Self {
        match e {
            IdentityError::AlreadyExists => HermesError::AlreadyExists,
            IdentityError::BackupFailed(reason) => HermesError::BackupFailed { reason },
            IdentityError::Corrupt => HermesError::Corrupt,
            IdentityError::DecryptionFailed => HermesError::DecryptionFailed,
            IdentityError::InvalidData(reason) => HermesError::InvalidData { reason },
            IdentityError::LockPoisoned => HermesError::InternalError {
                reason: "internal lock poisoned".into(),
            },
            IdentityError::NotFound => HermesError::NotFound,
            IdentityError::Storage(e) => HermesError::Storage {
                reason: e.to_string(),
            },
        }
    }
}

impl From<SignedPreKeyError> for HermesError {
    fn from(e: SignedPreKeyError) -> Self {
        match e {
            SignedPreKeyError::Clock => HermesError::InternalError {
                reason: "system clock is before Unix epoch".into(),
            },
            SignedPreKeyError::Identity(e) => e.into(),
            SignedPreKeyError::InvalidData(reason) => HermesError::InvalidData { reason },
            SignedPreKeyError::LockPoisoned => HermesError::InternalError {
                reason: "internal lock poisoned".into(),
            },
            SignedPreKeyError::Storage(e) => e.into(),
        }
    }
}

impl From<StorageError> for HermesError {
    fn from(e: StorageError) -> Self {
        HermesError::Storage {
            reason: e.to_string(),
        }
    }
}

impl From<KeyStoreError> for HermesError {
    fn from(e: KeyStoreError) -> Self {
        match e {
            KeyStoreError::Identity(e) => e.into(),
            KeyStoreError::SignedPreKey(e) => e.into(),
        }
    }
}

/// FFI-visible identity snapshot.
#[derive(uniffi::Record)]
pub struct Identity {
    /// X25519 public key bytes (32 bytes).
    pub public_key: Vec<u8>,
    /// Ed25519 verifying key bytes (32 bytes).
    pub verifying_key: Vec<u8>,
}

impl From<CoreIdentity> for Identity {
    fn from(id: CoreIdentity) -> Self {
        Identity {
            public_key: id.public_key().as_bytes().to_vec(),
            verifying_key: id.verifying_key().as_bytes().to_vec(),
        }
    }
}

/// Public material a peer needs to start a session with this identity. Signed by the identity's
/// Ed25519 key over [`SignedPreKeyBundle::public_key`].
///
/// The owning identity's verifying key is not embedded — verifiers retrieve it through a
/// separate channel and pass it alongside.
#[derive(uniffi::Record)]
pub struct SignedPreKeyBundle {
    /// X25519 public key (32 bytes).
    pub public_key: Vec<u8>,
    /// Ed25519 signature over `public_key` (64 bytes).
    pub signature: Vec<u8>,
    /// Unix timestamp (seconds) when this signed pre-key was generated.
    pub created_at: u64,
}

impl From<CoreSignedPreKeyBundle> for SignedPreKeyBundle {
    fn from(b: CoreSignedPreKeyBundle) -> Self {
        SignedPreKeyBundle {
            public_key: b.public_key.as_bytes().to_vec(),
            signature: b.signature.to_bytes().to_vec(),
            created_at: b.created_at,
        }
    }
}

/// Platform storage abstraction exposed to Swift and Kotlin.
///
/// Implementations must back this with platform secure storage (iOS Keychain, Android Keystore)
/// — never plain files or bare heap allocations. The keystore relies on the platform's
/// memory-protection guarantees to prevent secret material from leaking.
///
/// `value` and `load` cross the FFI as bare `Vec<u8>` because UniFFI does not support
/// `Zeroizing`. Hermes wraps loaded values in `Zeroizing` on the Rust side immediately;
/// implementors must take the same care on the platform side.
///
/// # Implementing
///
/// On Swift, conform to the generated protocol; on Kotlin, implement the generated interface.
/// All methods are called synchronously from Rust. Implementations must not panic — surface any
/// platform error as [`HermesError::Storage`] with a descriptive `reason`.
///
/// See [`InMemorySecureStorage`] for a reference implementation suitable for tests.
#[uniffi::export(with_foreign)]
pub trait SecureStorage: Send + Sync {
    /// Stores `value` under `key`, overwriting any existing entry.
    ///
    /// # Errors
    /// - [`HermesError::Storage`] when the platform Keychain or Keystore returns an error.
    ///
    /// # Panics
    /// Implementations must not panic. Surface platform errors as [`HermesError::Storage`].
    ///
    /// # Performance
    /// Implementations should be O(1) amortized in `value.len()`. Hermes calls this on the
    /// foreground thread of the consumer.
    fn store(&self, key: String, value: Vec<u8>) -> Result<(), HermesError>;

    /// Returns the value stored under `key`, or `None` if not present.
    ///
    /// # Errors
    /// - [`HermesError::Storage`] when the platform Keychain or Keystore returns an error.
    ///
    /// # Panics
    /// Implementations must not panic. Surface platform errors as [`HermesError::Storage`].
    ///
    /// # Performance
    /// Implementations should be O(1) amortized. Hermes calls this on the foreground thread.
    fn load(&self, key: String) -> Result<Option<Vec<u8>>, HermesError>;

    /// Removes the value stored under `key`. Idempotent — does nothing if the key is not
    /// present.
    ///
    /// # Errors
    /// - [`HermesError::Storage`] when the platform Keychain or Keystore returns an error.
    ///
    /// # Panics
    /// Implementations must not panic. Surface platform errors as [`HermesError::Storage`].
    ///
    /// # Performance
    /// Implementations should be O(1) amortized. Hermes calls this on the foreground thread.
    fn delete(&self, key: String) -> Result<(), HermesError>;
}

/// In-memory secure storage for use in proofs-of-concept and tests.
///
/// Not suitable for production — data is not persisted and has no platform security guarantees.
#[derive(uniffi::Object)]
pub struct InMemorySecureStorage {
    inner: Mutex<hermes_core::InMemorySecureStorage>,
}

impl Default for InMemorySecureStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[uniffi::export]
impl InMemorySecureStorage {
    /// Creates an empty in-memory storage instance for use in tests and prototypes.
    ///
    /// # Examples
    /// ```
    /// use hermes::InMemorySecureStorage;
    ///
    /// let _storage = InMemorySecureStorage::new();
    /// ```
    ///
    /// # Panics
    /// Never panics.
    ///
    /// # Performance
    /// O(1). Allocates a single empty `HashMap`.
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(hermes_core::InMemorySecureStorage::new()),
        }
    }
}

impl InMemorySecureStorage {
    fn lock_inner(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, hermes_core::InMemorySecureStorage>, HermesError> {
        self.inner.lock().map_err(|_| HermesError::InternalError {
            reason: "storage lock poisoned".into(),
        })
    }
}

#[uniffi::export]
impl SecureStorage for InMemorySecureStorage {
    fn store(&self, key: String, value: Vec<u8>) -> Result<(), HermesError> {
        Ok(self.lock_inner()?.store(&key, &value)?)
    }

    fn load(&self, key: String) -> Result<Option<Vec<u8>>, HermesError> {
        Ok(self.lock_inner()?.load(&key)?.map(|z| z.to_vec()))
    }

    fn delete(&self, key: String) -> Result<(), HermesError> {
        Ok(self.lock_inner()?.delete(&key)?)
    }
}

/// Bridges an FFI [`SecureStorage`] into the core's [`SecureStorage`](CoreSecureStorage) trait.
struct SecureStorageAdapter {
    storage: Arc<dyn SecureStorage>,
}

impl CoreSecureStorage for SecureStorageAdapter {
    fn store(&mut self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        self.storage
            .store(key.to_string(), value.to_vec())
            .map_err(|e| StorageError::IO(e.to_string()))
    }

    fn load(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
        self.storage
            .load(key.to_string())
            .map(|opt| opt.map(Zeroizing::new))
            .map_err(|e| StorageError::IO(e.to_string()))
    }

    fn delete(&mut self, key: &str) -> Result<(), StorageError> {
        self.storage
            .delete(key.to_string())
            .map_err(|e| StorageError::IO(e.to_string()))
    }
}

/// The single entry point for managing the local Hermes identity and its signed pre-key.
///
/// Construct once at app launch via [`KeyStore::new`] and hold the returned `Arc<KeyStore>` for
/// the app's lifetime. All methods are safe to call concurrently — the keystore serializes access
/// to the underlying [`SecureStorage`].
///
/// # Lifecycle
///
/// 1. App launches → construct the keystore.
/// 2. Check [`Self::has_identity`] → if `false`, call [`Self::generate_identity`] (first launch)
///    or [`Self::import_encrypted_backup`] (restore).
/// 3. Call [`Self::rotate_signed_prekey_if_stale`] once at launch and upload any returned bundle.
/// 4. Use [`Self::current_signed_prekey_bundle`] when peers ask for the bundle.
/// 5. Call [`Self::reset`] to clear all keys (e.g., user logged out).
#[derive(uniffi::Object)]
pub struct KeyStore {
    inner: CoreKeyStore,
}

#[uniffi::export]
impl KeyStore {
    /// Constructs a keystore backed by the given platform [`SecureStorage`].
    ///
    /// Cheap — no I/O, no key generation. Use [`Self::has_identity`] afterward to decide
    /// whether to generate or import.
    ///
    /// # Examples
    /// ```no_run
    /// use hermes::{InMemorySecureStorage, KeyStore, SecureStorage};
    /// use std::sync::Arc;
    ///
    /// let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// let _store = KeyStore::new(storage);
    /// ```
    ///
    /// # Panics
    /// Never panics.
    ///
    /// # Performance
    /// O(1). One small heap allocation for the inner adapter.
    #[uniffi::constructor]
    pub fn new(storage: Arc<dyn SecureStorage>) -> Arc<Self> {
        Arc::new(KeyStore {
            inner: CoreKeyStore::new(Box::new(SecureStorageAdapter { storage })),
        })
    }

    /// Generates a fresh identity (X25519 + Ed25519 key pairs) and persists it via
    /// [`SecureStorage`].
    ///
    /// # Examples
    /// ```no_run
    /// # use hermes::{HermesError, InMemorySecureStorage, KeyStore, SecureStorage};
    /// # use std::sync::Arc;
    /// # fn main() -> Result<(), HermesError> {
    /// # let store = KeyStore::new(Arc::new(InMemorySecureStorage::new()) as Arc<dyn SecureStorage>);
    /// let identity = store.generate_identity()?;
    /// assert_eq!(identity.public_key.len(), 32);
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    /// - [`HermesError::AlreadyExists`] if an identity is already stored — load it instead.
    /// - [`HermesError::Storage`] if the platform Keychain or Keystore returns an error.
    /// - [`HermesError::InternalError`] on storage lock poisoning.
    ///
    /// # Panics
    /// Never panics. Lock poisoning surfaces as [`HermesError::InternalError`].
    ///
    /// # Performance
    /// Two CSPRNG draws (32 bytes each), two `SecureStorage::store` calls.
    pub fn generate_identity(&self) -> Result<Identity, HermesError> {
        Ok(self.inner.generate_identity()?.into())
    }

    /// Loads the stored identity's public material.
    ///
    /// # Examples
    /// ```no_run
    /// # use hermes::{HermesError, InMemorySecureStorage, KeyStore, SecureStorage};
    /// # use std::sync::Arc;
    /// # fn main() -> Result<(), HermesError> {
    /// # let store = KeyStore::new(Arc::new(InMemorySecureStorage::new()) as Arc<dyn SecureStorage>);
    /// # store.generate_identity()?;
    /// let identity = store.load_identity()?;
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    /// - [`HermesError::NotFound`] if no identity is stored — call [`Self::generate_identity`]
    ///   or [`Self::import_encrypted_backup`].
    /// - [`HermesError::Corrupt`] if only one of the two key components is present.
    /// - [`HermesError::InvalidData`] if a stored key has the wrong byte length.
    /// - [`HermesError::Storage`] on platform storage failure.
    /// - [`HermesError::InternalError`] on storage lock poisoning.
    ///
    /// # Panics
    /// Never panics. Lock poisoning surfaces as [`HermesError::InternalError`].
    ///
    /// # Performance
    /// Two `SecureStorage::load` calls.
    pub fn load_identity(&self) -> Result<Identity, HermesError> {
        Ok(self.inner.load_identity()?.into())
    }

    /// Exports the current identity as a passphrase-encrypted blob.
    ///
    /// The blob is portable across devices: pass it to another keystore's
    /// [`Self::import_encrypted_backup`] with the same `passphrase` to restore.
    ///
    /// Format: `[Argon2id salt (16B)] | [XChaCha20-Poly1305 nonce (24B)] | [ciphertext (80B)]`.
    /// Argon2id parameters: m=64MiB, t=3, p=1.
    ///
    /// # Examples
    /// ```no_run
    /// # use hermes::{HermesError, InMemorySecureStorage, KeyStore, SecureStorage};
    /// # use std::sync::Arc;
    /// # fn main() -> Result<(), HermesError> {
    /// # let store = KeyStore::new(Arc::new(InMemorySecureStorage::new()) as Arc<dyn SecureStorage>);
    /// # store.generate_identity()?;
    /// let blob = store.export_encrypted_backup("strong passphrase".into())?;
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    /// - [`HermesError::NotFound`] if no identity is stored.
    /// - [`HermesError::Corrupt`] if only one of the two identity keys is present.
    /// - [`HermesError::InvalidData`] if a stored identity key has the wrong byte length.
    /// - [`HermesError::BackupFailed`] on RNG failure or encryption error.
    /// - [`HermesError::Storage`] on platform storage failure during identity load.
    /// - [`HermesError::InternalError`] on storage lock poisoning.
    ///
    /// # Panics
    /// Never panics. Lock poisoning surfaces as [`HermesError::InternalError`].
    ///
    /// # Performance
    /// One Argon2id derivation (deliberately expensive: ~64 MiB RAM, ~100ms on modern hardware).
    pub fn export_encrypted_backup(&self, passphrase: String) -> Result<Vec<u8>, HermesError> {
        Ok(self.inner.export_encrypted_backup(&passphrase)?)
    }

    /// Restores an identity from an encrypted backup, replacing any current identity.
    ///
    /// Decrypt-then-commit semantics: a wrong passphrase fails before any storage mutation, so
    /// the existing identity is preserved on error. After a successful import the previously
    /// stored signed pre-key is cleared (it was signed by the now-replaced identity); call
    /// [`Self::rotate_signed_prekey_if_stale`] to seed a new one.
    ///
    /// Pre-mutation failures ([`HermesError::DecryptionFailed`], [`HermesError::InvalidData`],
    /// [`HermesError::BackupFailed`]) leave any existing identity untouched. Failures returned
    /// after commit begins ([`HermesError::Storage`], [`HermesError::InternalError`]) may have
    /// partially written the new identity; in that case treat the keystore as compromised and
    /// call [`Self::reset`] before reuse — partial overwrite of an existing identity can leave
    /// storage with an inconsistent X25519/Ed25519 pair that [`Self::load_identity`] cannot
    /// detect.
    ///
    /// # Examples
    /// ```no_run
    /// # use hermes::{HermesError, InMemorySecureStorage, KeyStore, SecureStorage};
    /// # use std::sync::Arc;
    /// # fn main() -> Result<(), HermesError> {
    /// # let store = KeyStore::new(Arc::new(InMemorySecureStorage::new()) as Arc<dyn SecureStorage>);
    /// # let blob = vec![];
    /// store.import_encrypted_backup(blob, "strong passphrase".into())?;
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    /// - [`HermesError::DecryptionFailed`] on wrong passphrase or tampered ciphertext.
    /// - [`HermesError::InvalidData`] if the blob length is wrong.
    /// - [`HermesError::BackupFailed`] on Argon2id parameter error.
    /// - [`HermesError::Storage`] on platform storage failure during commit.
    /// - [`HermesError::InternalError`] on storage lock poisoning.
    ///
    /// # Panics
    /// Never panics. Lock poisoning surfaces as [`HermesError::InternalError`].
    ///
    /// # Performance
    /// One Argon2id derivation (~64 MiB RAM, ~100ms).
    pub fn import_encrypted_backup(
        &self,
        data: Vec<u8>,
        passphrase: String,
    ) -> Result<(), HermesError> {
        self.inner
            .import_encrypted_backup(&data, &passphrase)
            .map_err(Into::into)
    }

    /// Returns `true` if an X25519 identity key is present.
    ///
    /// Non-mutating storage probe; lets callers gate setup flows without exception-driven
    /// `loadIdentity` + `notFound` catches. The Ed25519 component is not checked, so callers
    /// must still handle [`HermesError::Corrupt`] from [`Self::load_identity`] in case of
    /// partial-write damage.
    ///
    /// # Examples
    /// ```no_run
    /// # use hermes::{HermesError, InMemorySecureStorage, KeyStore, SecureStorage};
    /// # use std::sync::Arc;
    /// # fn main() -> Result<(), HermesError> {
    /// # let store = KeyStore::new(Arc::new(InMemorySecureStorage::new()) as Arc<dyn SecureStorage>);
    /// if !store.has_identity()? {
    ///     store.generate_identity()?;
    /// }
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    /// - [`HermesError::Storage`] on platform storage failure.
    /// - [`HermesError::InternalError`] on storage lock poisoning.
    ///
    /// # Panics
    /// Never panics. Lock poisoning surfaces as [`HermesError::InternalError`].
    ///
    /// # Performance
    /// One `SecureStorage::load` call.
    pub fn has_identity(&self) -> Result<bool, HermesError> {
        Ok(self.inner.has_identity()?)
    }

    /// Rotates the signed pre-key if the stored one is missing or older than the rotation
    /// window. Returns the new bundle when rotation occurred, `None` when the stored SPK is
    /// still fresh.
    ///
    /// Call once at app launch. The `Some(bundle)` return is the cheap signal to upload the new
    /// bundle to peers — `None` means there is nothing new to push, so the consumer can skip
    /// the upload step entirely.
    ///
    /// # Examples
    /// ```no_run
    /// # use hermes::{HermesError, InMemorySecureStorage, KeyStore, SecureStorage};
    /// # use std::sync::Arc;
    /// # fn main() -> Result<(), HermesError> {
    /// # let store = KeyStore::new(Arc::new(InMemorySecureStorage::new()) as Arc<dyn SecureStorage>);
    /// # store.generate_identity()?;
    /// if let Some(new_bundle) = store.rotate_signed_prekey_if_stale()? {
    ///     // upload `new_bundle` to peers
    ///     let _ = new_bundle;
    /// }
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    /// - [`HermesError::NotFound`] if no identity is stored — generate one first.
    /// - [`HermesError::Corrupt`] if only one of the two identity keys is present.
    /// - [`HermesError::InvalidData`] if the stored SPK has wrong length or version.
    /// - [`HermesError::Storage`] on platform storage failure.
    /// - [`HermesError::InternalError`] on storage lock poisoning or system clock anomaly.
    ///
    /// # Panics
    /// Never panics. Lock poisoning and clock anomalies surface as [`HermesError::InternalError`].
    ///
    /// # Performance
    /// One [`SecureStorage::load`] always; one CSPRNG draw + Ed25519 sign + [`SecureStorage::store`]
    /// when rotation occurs.
    pub fn rotate_signed_prekey_if_stale(&self) -> Result<Option<SignedPreKeyBundle>, HermesError> {
        Ok(self.inner.rotate_signed_prekey_if_stale()?.map(Into::into))
    }

    /// Rotates the signed pre-key immediately, regardless of staleness, and returns the new
    /// bundle.
    ///
    /// Use for explicit user actions ("Reset Keys") or test scenarios where the consumer wants
    /// fresh material independent of the rotation window.
    ///
    /// # Examples
    /// ```no_run
    /// # use hermes::{HermesError, InMemorySecureStorage, KeyStore, SecureStorage};
    /// # use std::sync::Arc;
    /// # fn main() -> Result<(), HermesError> {
    /// # let store = KeyStore::new(Arc::new(InMemorySecureStorage::new()) as Arc<dyn SecureStorage>);
    /// # store.generate_identity()?;
    /// let new_bundle = store.rotate_signed_prekey_now()?;
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    /// - [`HermesError::NotFound`] if no identity is stored.
    /// - [`HermesError::Corrupt`] if only one of the two identity keys is present.
    /// - [`HermesError::InvalidData`] if a stored identity key has the wrong byte length.
    /// - [`HermesError::Storage`] on platform storage failure.
    /// - [`HermesError::InternalError`] on storage lock poisoning or system clock anomaly.
    ///
    /// # Panics
    /// Never panics. Lock poisoning and clock anomalies surface as [`HermesError::InternalError`].
    ///
    /// # Performance
    /// One CSPRNG draw + Ed25519 sign + one [`SecureStorage::store`] call.
    pub fn rotate_signed_prekey_now(&self) -> Result<SignedPreKeyBundle, HermesError> {
        Ok(self.inner.rotate_signed_prekey_now()?.into())
    }

    /// Returns the currently-stored signed pre-key bundle.
    ///
    /// Hand this to peers asking for the bundle they need to start a session.
    ///
    /// # Examples
    /// ```no_run
    /// # use hermes::{HermesError, InMemorySecureStorage, KeyStore, SecureStorage};
    /// # use std::sync::Arc;
    /// # fn main() -> Result<(), HermesError> {
    /// # let store = KeyStore::new(Arc::new(InMemorySecureStorage::new()) as Arc<dyn SecureStorage>);
    /// # store.generate_identity()?;
    /// # store.rotate_signed_prekey_if_stale()?;
    /// let bundle = store.current_signed_prekey_bundle()?;
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    /// - [`HermesError::InvalidData`] if no signed pre-key is stored, the stored blob has the
    ///   wrong length, or its version byte is unsupported. Call
    ///   [`Self::rotate_signed_prekey_if_stale`] first to seed one.
    /// - [`HermesError::Storage`] on platform storage failure.
    /// - [`HermesError::InternalError`] on storage lock poisoning.
    ///
    /// # Panics
    /// Never panics. Lock poisoning surfaces as [`HermesError::InternalError`].
    ///
    /// # Performance
    /// One [`SecureStorage::load`] call.
    pub fn current_signed_prekey_bundle(&self) -> Result<SignedPreKeyBundle, HermesError> {
        Ok(self.inner.current_signed_prekey_bundle()?.into())
    }

    /// Clears the stored identity and signed pre-key. Idempotent.
    ///
    /// Two-step: SPK is cleared first (so a partial failure leaves no SPK signed by an
    /// already-deleted identity), then the identity. Re-running after a partial failure
    /// completes the reset.
    ///
    /// # Examples
    /// ```no_run
    /// # use hermes::{HermesError, InMemorySecureStorage, KeyStore, SecureStorage};
    /// # use std::sync::Arc;
    /// # fn main() -> Result<(), HermesError> {
    /// # let store = KeyStore::new(Arc::new(InMemorySecureStorage::new()) as Arc<dyn SecureStorage>);
    /// store.reset()?;
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    /// - [`HermesError::Storage`] on platform storage failure.
    /// - [`HermesError::InternalError`] on storage lock poisoning.
    ///
    /// # Panics
    /// Never panics. Lock poisoning surfaces as [`HermesError::InternalError`].
    ///
    /// # Performance
    /// Up to three [`SecureStorage::delete`] calls.
    pub fn reset(&self) -> Result<(), HermesError> {
        self.inner.reset().map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hermes_crypto::{PublicKey, Signature, VerifyingKey, verify_bundle};

    fn key_store() -> Arc<KeyStore> {
        let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
        KeyStore::new(storage)
    }

    #[test]
    fn generate_identity_returns_32_byte_keys() {
        let ks = key_store();
        let generated = ks.generate_identity().unwrap();
        assert_eq!(generated.public_key.len(), 32);
        assert_eq!(generated.verifying_key.len(), 32);
    }

    #[test]
    fn key_store_full_round_trip() {
        let ks = key_store();
        let identity = ks.generate_identity().unwrap();
        let rotated = ks.rotate_signed_prekey_if_stale().unwrap();
        assert!(rotated.is_some(), "first rotate must produce a bundle");
        let bundle = ks.current_signed_prekey_bundle().unwrap();
        assert_eq!(bundle.public_key.len(), 32);
        assert_eq!(bundle.signature.len(), 64);
        assert!(bundle.created_at > 0);

        let verifying_bytes: [u8; 32] = identity.verifying_key.as_slice().try_into().unwrap();
        let verifying = VerifyingKey::from_bytes(&verifying_bytes).unwrap();
        let pk_bytes: [u8; 32] = bundle.public_key.as_slice().try_into().unwrap();
        let sig_bytes: [u8; 64] = bundle.signature.as_slice().try_into().unwrap();
        let core_bundle = hermes_crypto::SignedPreKeyBundle {
            public_key: PublicKey::from(pk_bytes),
            signature: Signature::from_bytes(&sig_bytes),
            created_at: bundle.created_at,
        };
        assert!(verify_bundle(&core_bundle, &verifying).is_ok());
    }
}
