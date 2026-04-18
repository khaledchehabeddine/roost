uniffi::setup_scaffolding!("hermes");

use hermes_core::{
    IdentityError, KeyStore as CoreKeyStore, KeyStoreError, SecureStorage as CoreSecureStorage,
    SignedPreKeyError, StorageError,
};
use hermes_crypto::PreKeyBundle as CorePreKeyBundle;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

/// FFI-visible identity snapshot returned by [`IdentityManager`].
#[derive(uniffi::Record)]
pub struct Identity {
    /// X25519 public key bytes (32 bytes).
    pub public_key: Vec<u8>,
    /// Ed25519 verifying key bytes (32 bytes).
    pub verifying_key: Vec<u8>,
}

/// `public_key` is 32 bytes, `signature` is 64 bytes. Identity verifying key is not
/// embedded — verifiers obtain it through other channels.
#[derive(uniffi::Record)]
pub struct PreKeyBundle {
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub created_at: u64,
}

impl From<CorePreKeyBundle> for PreKeyBundle {
    fn from(b: CorePreKeyBundle) -> Self {
        PreKeyBundle {
            public_key: b.public_key.as_bytes().to_vec(),
            signature: b.signature.to_bytes().to_vec(),
            created_at: b.created_at,
        }
    }
}

/// Errors surfaced across the FFI boundary.
#[derive(Debug, uniffi::Error)]
pub enum HermesError {
    AlreadyExists,
    BackupFailed { reason: String },
    Corrupt,
    DecryptionFailed,
    InternalError { reason: String },
    InvalidData { reason: String },
    NotFound,
    Storage { reason: String },
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

impl From<StorageError> for HermesError {
    fn from(e: StorageError) -> Self {
        HermesError::Storage {
            reason: e.to_string(),
        }
    }
}

impl From<SignedPreKeyError> for HermesError {
    fn from(e: SignedPreKeyError) -> Self {
        match e {
            SignedPreKeyError::Storage(e) => HermesError::Storage {
                reason: e.to_string(),
            },
            SignedPreKeyError::Identity(e) => e.into(),
            SignedPreKeyError::InvalidData(reason) => HermesError::InvalidData { reason },
            SignedPreKeyError::Clock => HermesError::InternalError {
                reason: "system clock is before Unix epoch".into(),
            },
            SignedPreKeyError::LockPoisoned => HermesError::InternalError {
                reason: "internal lock poisoned".into(),
            },
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

/// Platform storage abstraction exposed to Swift and Kotlin.
///
/// Implement this trait to provide [`KeyStore`] with platform-specific secure storage
/// (e.g., iOS Keychain, Android Keystore).
///
/// `value` and `load` return bare `Vec<u8>` because UniFFI does not support `Zeroizing`.
/// The `SecureStorageAdapter` wraps loaded values in `Zeroizing` on the Rust side.
#[uniffi::export(with_foreign)]
pub trait SecureStorage: Send + Sync {
    fn store(&self, key: String, value: Vec<u8>) -> Result<(), HermesError>;
    fn load(&self, key: String) -> Result<Option<Vec<u8>>, HermesError>;
    fn delete(&self, key: String) -> Result<(), HermesError>;
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
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(hermes_core::InMemorySecureStorage::new()),
        }
    }
}

#[uniffi::export]
impl SecureStorage for InMemorySecureStorage {
    fn store(&self, key: String, value: Vec<u8>) -> Result<(), HermesError> {
        self.inner
            .lock()
            .map_err(|_| HermesError::InternalError {
                reason: "storage lock poisoned".into(),
            })?
            .store(&key, &value)?;
        Ok(())
    }

    fn load(&self, key: String) -> Result<Option<Vec<u8>>, HermesError> {
        let result = self
            .inner
            .lock()
            .map_err(|_| HermesError::InternalError {
                reason: "storage lock poisoned".into(),
            })?
            .load(&key)?;
        Ok(result.map(|z| z.to_vec()))
    }

    fn delete(&self, key: String) -> Result<(), HermesError> {
        self.inner
            .lock()
            .map_err(|_| HermesError::InternalError {
                reason: "storage lock poisoned".into(),
            })?
            .delete(&key)?;
        Ok(())
    }
}

/// Obtained via [`KeyStore::identity`] — no standalone FFI constructor.
#[derive(uniffi::Object)]
pub struct IdentityManager {
    inner: Arc<hermes_core::IdentityManager>,
}

impl IdentityManager {
    fn from_inner(inner: Arc<hermes_core::IdentityManager>) -> Arc<Self> {
        Arc::new(IdentityManager { inner })
    }
}

#[uniffi::export]
impl IdentityManager {
    pub fn generate_identity(&self) -> Result<Identity, HermesError> {
        let id = self.inner.generate_identity()?;
        Ok(Identity {
            public_key: id.public_key().as_bytes().to_vec(),
            verifying_key: id.verifying_key().as_bytes().to_vec(),
        })
    }

    pub fn load_identity(&self) -> Result<Identity, HermesError> {
        let id = self.inner.load_identity()?;
        Ok(Identity {
            public_key: id.public_key().as_bytes().to_vec(),
            verifying_key: id.verifying_key().as_bytes().to_vec(),
        })
    }

    pub fn export_encrypted_backup(&self, passphrase: String) -> Result<Vec<u8>, HermesError> {
        Ok(self.inner.export_encrypted_backup(&passphrase)?)
    }
}

/// Construct once at app launch and hold a reference.
#[derive(uniffi::Object)]
pub struct KeyStore {
    inner: CoreKeyStore,
}

#[uniffi::export]
impl KeyStore {
    #[uniffi::constructor]
    pub fn new(storage: Arc<dyn SecureStorage>) -> Arc<Self> {
        Arc::new(KeyStore {
            inner: CoreKeyStore::new(Box::new(SecureStorageAdapter { storage })),
        })
    }

    pub fn identity(&self) -> Arc<IdentityManager> {
        IdentityManager::from_inner(self.inner.identity())
    }

    /// Call once at app launch.
    pub fn rotate_spk_if_stale(&self) -> Result<(), HermesError> {
        self.inner.rotate_spk_if_stale()?;
        Ok(())
    }

    pub fn current_pre_key_bundle(&self) -> Result<PreKeyBundle, HermesError> {
        Ok(self.inner.signed_prekey().current_bundle()?.into())
    }

    /// Use this rather than calling import on `IdentityManager` directly — that path
    /// would orphan the SPK signed by the previous identity.
    pub fn import_encrypted_backup(
        &self,
        data: Vec<u8>,
        passphrase: String,
    ) -> Result<(), HermesError> {
        self.inner
            .import_encrypted_backup(&data, &passphrase)
            .map_err(Into::into)
    }

    pub fn wipe_all(&self) -> Result<(), HermesError> {
        self.inner.wipe_all().map_err(Into::into)
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
    fn key_store_vends_identity_manager() {
        let ks = key_store();
        let id = ks.identity();
        let generated = id.generate_identity().unwrap();
        assert_eq!(generated.public_key.len(), 32);
        assert_eq!(generated.verifying_key.len(), 32);
    }

    #[test]
    fn key_store_full_roundtrip() {
        let ks = key_store();
        let id = ks.identity();
        let identity = id.generate_identity().unwrap();
        ks.rotate_spk_if_stale().unwrap();
        let bundle = ks.current_pre_key_bundle().unwrap();
        assert_eq!(bundle.public_key.len(), 32);
        assert_eq!(bundle.signature.len(), 64);
        assert!(bundle.created_at > 0);

        // Verify the bundle round-trips through hermes_crypto::verify_bundle.
        let verifying_bytes: [u8; 32] = identity.verifying_key.as_slice().try_into().unwrap();
        let verifying = VerifyingKey::from_bytes(&verifying_bytes).unwrap();
        let pk_bytes: [u8; 32] = bundle.public_key.as_slice().try_into().unwrap();
        let sig_bytes: [u8; 64] = bundle.signature.as_slice().try_into().unwrap();
        let core_bundle = hermes_crypto::PreKeyBundle {
            public_key: PublicKey::from(pk_bytes),
            signature: Signature::from_bytes(&sig_bytes),
            created_at: bundle.created_at,
        };
        assert!(verify_bundle(&core_bundle, &verifying).is_ok());
    }

    #[test]
    fn rotate_spk_without_identity_returns_error() {
        let ks = key_store();
        // No identity generated — rotation should fail with a NotFound-mapped error.
        let result = ks.rotate_spk_if_stale();
        assert!(matches!(result, Err(HermesError::NotFound)));
    }

    #[test]
    fn current_pre_key_bundle_without_rotation_returns_invalid_data() {
        let ks = key_store();
        ks.identity().generate_identity().unwrap();
        // Identity exists but no SPK has been rotated yet.
        let result = ks.current_pre_key_bundle();
        assert!(matches!(result, Err(HermesError::InvalidData { .. })));
    }

    #[test]
    fn import_encrypted_backup_via_keystore_clears_stale_spk() {
        let ks_b = key_store();
        ks_b.identity().generate_identity().unwrap();
        ks_b.rotate_spk_if_stale().unwrap();
        assert!(ks_b.current_pre_key_bundle().is_ok());

        let ks_a = key_store();
        ks_a.identity().generate_identity().unwrap();
        let backup = ks_a
            .identity()
            .export_encrypted_backup("pass".into())
            .unwrap();

        ks_b.import_encrypted_backup(backup, "pass".into()).unwrap();
        assert!(matches!(
            ks_b.current_pre_key_bundle(),
            Err(HermesError::InvalidData { .. })
        ));
    }

    #[test]
    fn wipe_all_via_keystore_clears_state() {
        let ks = key_store();
        ks.identity().generate_identity().unwrap();
        ks.rotate_spk_if_stale().unwrap();

        ks.wipe_all().unwrap();

        assert!(matches!(
            ks.identity().load_identity(),
            Err(HermesError::NotFound)
        ));
        assert!(matches!(
            ks.current_pre_key_bundle(),
            Err(HermesError::InvalidData { .. })
        ));
    }
}
