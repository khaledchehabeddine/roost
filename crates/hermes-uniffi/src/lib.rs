uniffi::setup_scaffolding!("hermes");

use hermes_core::{
    IdentityError, KeyStore as CoreKeyStore, KeyStoreError, SecureStorage as CoreSecureStorage,
    SignedPreKeyError, StorageError,
};
use hermes_crypto::PreKeyBundle as CorePreKeyBundle;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

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

/// `public_key` is 32 bytes, `signature` is 64 bytes. Identity verifying key is not embedded —
/// verifiers get it through other channels.
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
        Ok(self
            .inner
            .lock()
            .map_err(|_| HermesError::InternalError {
                reason: "storage lock poisoned".into(),
            })?
            .store(&key, &value)?)
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
        Ok(self
            .inner
            .lock()
            .map_err(|_| HermesError::InternalError {
                reason: "storage lock poisoned".into(),
            })?
            .delete(&key)?)
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

    pub fn generate_identity(&self) -> Result<Identity, HermesError> {
        let id = self.inner.identity().generate_identity()?;
        Ok(Identity {
            public_key: id.public_key().as_bytes().to_vec(),
            verifying_key: id.verifying_key().as_bytes().to_vec(),
        })
    }

    pub fn load_identity(&self) -> Result<Identity, HermesError> {
        let id = self.inner.identity().load_identity()?;
        Ok(Identity {
            public_key: id.public_key().as_bytes().to_vec(),
            verifying_key: id.verifying_key().as_bytes().to_vec(),
        })
    }

    pub fn export_encrypted_backup(&self, passphrase: String) -> Result<Vec<u8>, HermesError> {
        Ok(self.inner.identity().export_encrypted_backup(&passphrase)?)
    }

    pub fn import_encrypted_backup(
        &self,
        data: Vec<u8>,
        passphrase: String,
    ) -> Result<(), HermesError> {
        self.inner
            .import_encrypted_backup(&data, &passphrase)
            .map_err(Into::into)
    }

    /// Call once at app launch.
    pub fn rotate_spk_if_stale(&self) -> Result<(), HermesError> {
        Ok(self.inner.rotate_spk_if_stale()?)
    }

    pub fn current_pre_key_bundle(&self) -> Result<PreKeyBundle, HermesError> {
        Ok(self.inner.signed_prekey().current_bundle()?.into())
    }

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
        ks.rotate_spk_if_stale().unwrap();
        let bundle = ks.current_pre_key_bundle().unwrap();
        assert_eq!(bundle.public_key.len(), 32);
        assert_eq!(bundle.signature.len(), 64);
        assert!(bundle.created_at > 0);

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
}
