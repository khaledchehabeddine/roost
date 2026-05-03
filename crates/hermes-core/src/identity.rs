mod backup;

use crate::storage::{SecureStorage, StorageError};
use hermes_crypto::{
    KeyPair, PublicKey, SharedSecret, Signature, SigningKeyPair, VerifyingKey, generate_key_pair,
    generate_signing_key_pair,
};
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use zeroize::Zeroizing;

type KeyBytes = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>);

const IDENTITY_X25519_KEY: &str = "identity/x25519";
const IDENTITY_ED25519_KEY: &str = "identity/ed25519";

/// Errors returned by [`IdentityManager`] operations.
#[derive(Debug)]
pub enum IdentityError {
    /// An identity is already stored. The caller should load the existing identity rather than
    /// generate a new one.
    AlreadyExists,
    /// Encrypted-backup creation failed. Inner string carries diagnostic context for logs.
    BackupFailed(String),
    /// Only one of the two identity keys is present in storage, indicating a partial write.
    Corrupt,
    /// Backup decryption failed: wrong passphrase, tampered ciphertext, or wrong cipher
    /// parameters.
    DecryptionFailed,
    /// Stored bytes are malformed or the wrong length. Inner string describes what was invalid.
    InvalidData(String),
    /// The internal storage lock was poisoned by a panicked thread.
    LockPoisoned,
    /// No identity is stored.
    NotFound,
    /// The underlying [`SecureStorage`] returned an error.
    Storage(StorageError),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityError::AlreadyExists => write!(f, "identity already exists"),
            IdentityError::BackupFailed(reason) => write!(f, "backup failed: {reason}"),
            IdentityError::Corrupt => write!(f, "identity data is corrupt"),
            IdentityError::DecryptionFailed => {
                write!(f, "decryption failed: wrong passphrase or corrupt backup")
            }
            IdentityError::InvalidData(reason) => write!(f, "invalid identity data: {reason}"),
            IdentityError::LockPoisoned => write!(f, "internal lock poisoned"),
            IdentityError::NotFound => write!(f, "no identity found"),
            IdentityError::Storage(err) => write!(f, "storage error: {err}"),
        }
    }
}

impl Error for IdentityError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            IdentityError::Storage(e) => Some(e),
            _ => None,
        }
    }
}

/// A Hermes identity consisting of an X25519 key pair and an Ed25519 signing key pair.
pub struct Identity {
    key_pair: KeyPair,
    signing_key_pair: SigningKeyPair,
}

impl Identity {
    /// Returns the X25519 public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.key_pair.public
    }

    /// Returns the Ed25519 verifying key.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.signing_key_pair.verifying
    }

    /// Performs an X25519 Diffie–Hellman exchange with the given public key.
    pub fn diffie_hellman(&self, their_public: &PublicKey) -> SharedSecret {
        self.key_pair.diffie_hellman(their_public)
    }

    /// Signs `message` with the Ed25519 signing key and returns the signature.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key_pair.sign(message)
    }

    /// Application code signs via [`Self::sign`]; this exposes the keypair to crate-internal
    /// callers (SPK signing) only.
    pub(crate) fn signing_key_pair(&self) -> &SigningKeyPair {
        &self.signing_key_pair
    }
}

/// Manages creation and retrieval of the local Hermes identity.
///
/// Identities are persisted via a [`SecureStorage`] backend. On real devices this
/// will be the iOS Keychain or Android Keystore; in tests use
/// [`crate::InMemorySecureStorage`].
pub struct IdentityManager {
    storage: Arc<Mutex<Box<dyn SecureStorage>>>,
}

impl IdentityManager {
    /// Constructs a manager backed by the given shared storage handle. Cheap — no I/O.
    pub fn new(storage: Arc<Mutex<Box<dyn SecureStorage>>>) -> Self {
        IdentityManager { storage }
    }

    /// Acquires the storage lock, mapping a poisoned mutex to [`IdentityError::LockPoisoned`].
    fn lock_storage(&self) -> Result<MutexGuard<'_, Box<dyn SecureStorage>>, IdentityError> {
        self.storage.lock().map_err(|_| IdentityError::LockPoisoned)
    }

    /// Generates a new identity and persists it to storage.
    ///
    /// # Errors
    /// - [`IdentityError::AlreadyExists`] if an X25519 identity key is already stored.
    /// - [`IdentityError::Storage`] on platform storage failure.
    /// - [`IdentityError::LockPoisoned`] on storage lock poisoning.
    ///
    /// If the X25519 store succeeds but the Ed25519 store fails, the partial-write leaves
    /// storage in a `Corrupt` state. Call [`crate::KeyStore::reset`] before retrying.
    pub fn generate_identity(&self) -> Result<Identity, IdentityError> {
        let mut storage = self.lock_storage()?;

        let identity_exists = storage
            .load(IDENTITY_X25519_KEY)
            .map_err(log_storage_err)?
            .is_some();
        if identity_exists {
            return Err(IdentityError::AlreadyExists);
        }

        let key_pair = generate_key_pair();
        let signing_key_pair = generate_signing_key_pair();

        storage
            .store(IDENTITY_X25519_KEY, &*key_pair.to_secret_bytes())
            .map_err(log_storage_err)?;
        storage
            .store(IDENTITY_ED25519_KEY, &*signing_key_pair.to_signing_bytes())
            .map_err(log_storage_err)?;

        Ok(Identity {
            key_pair,
            signing_key_pair,
        })
    }

    /// Loads the existing identity from storage.
    ///
    /// # Errors
    /// - [`IdentityError::NotFound`] if neither key is present.
    /// - [`IdentityError::Corrupt`] if only one of the two keys is present.
    /// - [`IdentityError::InvalidData`] if a stored key has the wrong byte length.
    /// - [`IdentityError::Storage`] on platform storage failure.
    /// - [`IdentityError::LockPoisoned`] on storage lock poisoning.
    pub fn load_identity(&self) -> Result<Identity, IdentityError> {
        let (x25519, ed25519) = self.load_key_bytes()?;

        Ok(Identity {
            key_pair: KeyPair::from_secret_bytes(*x25519),
            signing_key_pair: SigningKeyPair::from_signing_bytes(*ed25519),
        })
    }

    /// Returns `true` if an X25519 identity key is present.
    ///
    /// Non-mutating storage probe. Lets callers gate setup flows without resorting to
    /// catching [`IdentityError::NotFound`] from [`Self::load_identity`]. The Ed25519
    /// component is not checked, so callers must still handle [`IdentityError::Corrupt`]
    /// from [`Self::load_identity`] in case of partial-write damage.
    ///
    /// # Errors
    /// - [`IdentityError::Storage`] on platform storage failure.
    /// - [`IdentityError::LockPoisoned`] on storage lock poisoning.
    pub fn has_identity(&self) -> Result<bool, IdentityError> {
        let storage = self.lock_storage()?;
        Ok(storage
            .load(IDENTITY_X25519_KEY)
            .map_err(log_storage_err)?
            .is_some())
    }

    /// Applications must use [`crate::KeyStore::reset`] — direct identity-only deletion would
    /// orphan the SPK signed by this identity.
    pub(crate) fn reset(&self) -> Result<(), IdentityError> {
        let mut storage = self.lock_storage()?;
        storage
            .delete(IDENTITY_X25519_KEY)
            .map_err(log_storage_err)?;
        storage
            .delete(IDENTITY_ED25519_KEY)
            .map_err(log_storage_err)?;
        Ok(())
    }

    /// Reads both identity keys from storage, validates their length, and returns fixed-size arrays.
    fn load_key_bytes(&self) -> Result<KeyBytes, IdentityError> {
        let storage = self.lock_storage()?;
        let (x_vec, e_vec) = match (
            storage.load(IDENTITY_X25519_KEY).map_err(log_storage_err)?,
            storage
                .load(IDENTITY_ED25519_KEY)
                .map_err(log_storage_err)?,
        ) {
            (None, None) => return Err(IdentityError::NotFound),
            (Some(_), None) | (None, Some(_)) => return Err(IdentityError::Corrupt),
            (Some(x), Some(e)) => (x, e),
        };

        let x_bytes: [u8; 32] = x_vec
            .as_slice()
            .try_into()
            .map_err(|_| IdentityError::InvalidData("invalid X25519 key length".into()))?;
        let e_bytes: [u8; 32] = e_vec
            .as_slice()
            .try_into()
            .map_err(|_| IdentityError::InvalidData("invalid Ed25519 key length".into()))?;

        Ok((Zeroizing::new(x_bytes), Zeroizing::new(e_bytes)))
    }
}

/// Logs system-level storage errors internally and maps them to [`IdentityError::Storage`].
fn log_storage_err(e: StorageError) -> IdentityError {
    eprintln!("[hermes-core] storage error: {e}");
    IdentityError::Storage(e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::InMemorySecureStorage;

    fn manager() -> IdentityManager {
        IdentityManager::new(Arc::new(Mutex::new(Box::new(InMemorySecureStorage::new()))))
    }

    #[test]
    fn generate_identity_succeeds() {
        let m = manager();
        assert!(m.generate_identity().is_ok());
    }

    #[test]
    fn generate_identity_twice_returns_already_exists() {
        let m = manager();
        m.generate_identity().unwrap();
        assert!(matches!(
            m.generate_identity(),
            Err(IdentityError::AlreadyExists)
        ));
    }

    #[test]
    fn load_identity_without_generate_returns_not_found() {
        let m = manager();
        assert!(matches!(m.load_identity(), Err(IdentityError::NotFound)));
    }

    #[test]
    fn load_identity_returns_same_public_keys() {
        let m = manager();
        let generated = m.generate_identity().unwrap();
        let loaded = m.load_identity().unwrap();
        assert_eq!(generated.public_key(), loaded.public_key());
        assert_eq!(
            generated.verifying_key().as_bytes(),
            loaded.verifying_key().as_bytes()
        );
    }

    #[test]
    fn sign_round_trip_after_load_identity() {
        let m = manager();
        let generated = m.generate_identity().unwrap();
        let loaded = m.load_identity().unwrap();
        let message = b"hermes test message";
        // Ed25519 is deterministic — identical keys produce identical signatures
        assert_eq!(
            generated.sign(message).to_bytes(),
            loaded.sign(message).to_bytes()
        );
    }

    #[test]
    fn diffie_hellman_round_trip_after_load_identity() {
        let m = manager();
        let loaded = m.generate_identity().unwrap();
        let peer = generate_key_pair();
        let shared_a = loaded.diffie_hellman(&peer.public);
        let shared_b = peer.diffie_hellman(loaded.public_key());
        assert_eq!(shared_a.as_bytes(), shared_b.as_bytes());
    }

    #[test]
    fn load_identity_returns_corrupt_when_only_one_key_present() {
        let m = manager();
        m.generate_identity().unwrap();
        m.storage
            .lock()
            .unwrap()
            .delete(IDENTITY_ED25519_KEY)
            .unwrap();
        assert!(matches!(m.load_identity(), Err(IdentityError::Corrupt)));
    }
}
