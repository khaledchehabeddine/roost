use hermes_crypto::{
    KeyPair, PublicKey, SharedSecret, Signature, SigningKeyPair, VerifyingKey, generate_key_pair,
    generate_signing_key_pair,
};
use hermes_storage::{SecureStorage, StorageError};
use std::error::Error;
use std::fmt;

const IDENTITY_ED25519_KEY: &str = "identity/ed25519";
const IDENTITY_X25519_KEY: &str = "identity/x25519";

/// Errors returned by [`IdentityManager`] operations.
#[non_exhaustive]
#[derive(Debug)]
pub enum IdentityError {
    AlreadyExists,
    /// Only one of the two identity keys is present in storage, indicating a partial writing.
    Corrupt,
    InvalidData(String),
    NotFound,
    Storage(StorageError),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityError::AlreadyExists => {
                write!(f, "Identity already exists")
            }
            IdentityError::NotFound => {
                write!(f, "No identity found")
            }
            IdentityError::Corrupt | IdentityError::InvalidData(_) | IdentityError::Storage(_) => {
                write!(f, "Something went wrong")
            }
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
}

/// Manages creation and retrieval of the local Hermes identity.
///
/// Identities are persisted via a [`SecureStorage`] backend. On real devices this
/// will be the iOS Keychain or Android Keystore; in tests use
/// [`hermes_storage::InMemorySecureStorage`].
///
/// Only one `IdentityManager` instance should operate against a given storage backend at a time.
/// Concurrent access is not protected and may leave the identity state partially written.
pub struct IdentityManager<S: SecureStorage> {
    storage: S,
}

impl<S: SecureStorage> IdentityManager<S> {
    pub fn new(storage: S) -> Self {
        IdentityManager { storage }
    }

    /// Generates a new identity and persists it to storage.
    ///
    /// Returns [`IdentityError::AlreadyExists`] if an X25519 identity key is already stored.
    ///
    /// If the X25519 key is stored successfully but writing the Ed25519 key fails, the X25519 key
    /// is deleted to leave storage in a clean state. If that cleanup also fails, the error is
    /// logged, and the original writing error is returned — the identity can be re-created by
    /// calling this method again.
    pub fn generate_identity(&mut self) -> Result<Identity, IdentityError> {
        let identity_exists = self
            .storage
            .load(IDENTITY_X25519_KEY)
            .map_err(log_storage_err)?
            .is_some();
        if identity_exists {
            return Err(IdentityError::AlreadyExists);
        }

        let key_pair = generate_key_pair();
        let signing_key_pair = generate_signing_key_pair();

        self.storage
            .store(IDENTITY_X25519_KEY, &*key_pair.to_secret_bytes())
            .map_err(log_storage_err)?;

        let ed25519_result = self
            .storage
            .store(IDENTITY_ED25519_KEY, &*signing_key_pair.to_signing_bytes())
            .map_err(log_storage_err);

        if let Err(e) = ed25519_result {
            if let Err(cleanup_err) = self.storage.delete(IDENTITY_X25519_KEY) {
                eprintln!(
                    "[hermes-core] failed to roll back X25519 key after partial write: \
                    {cleanup_err}"
                );
            }
            return Err(e);
        }

        Ok(Identity {
            key_pair,
            signing_key_pair,
        })
    }

    /// Loads the existing identity from storage.
    ///
    /// Returns [`IdentityError::NotFound`] if neither key is present.
    /// Returns [`IdentityError::Corrupt`] if only one of the two keys is present.
    pub fn load_identity(&self) -> Result<Identity, IdentityError> {
        let x25519_bytes = self
            .storage
            .load(IDENTITY_X25519_KEY)
            .map_err(log_storage_err)?;

        let ed25519_bytes = self
            .storage
            .load(IDENTITY_ED25519_KEY)
            .map_err(log_storage_err)?;

        let (x25519_bytes, ed25519_bytes) = match (x25519_bytes, ed25519_bytes) {
            (None, None) => return Err(IdentityError::NotFound),
            (Some(_), None) | (None, Some(_)) => return Err(IdentityError::Corrupt),
            (Some(x), Some(e)) => (x, e),
        };

        let x25519_array: [u8; 32] = x25519_bytes
            .as_slice()
            .try_into()
            .map_err(|_| IdentityError::InvalidData("invalid X25519 key length".into()))?;

        let ed25519_array: [u8; 32] = ed25519_bytes
            .as_slice()
            .try_into()
            .map_err(|_| IdentityError::InvalidData("invalid Ed25519 key length".into()))?;

        Ok(Identity {
            key_pair: KeyPair::from_secret_bytes(x25519_array),
            signing_key_pair: SigningKeyPair::from_signing_bytes(ed25519_array),
        })
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
    use hermes_storage::InMemorySecureStorage;

    fn manager() -> IdentityManager<InMemorySecureStorage> {
        IdentityManager::new(InMemorySecureStorage::new())
    }

    #[test]
    fn generate_identity_succeeds() {
        let mut m = manager();
        assert!(m.generate_identity().is_ok());
    }

    #[test]
    fn generate_identity_twice_returns_already_exists() {
        let mut m = manager();
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
        let mut m = manager();
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
        let mut m = manager();
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
        let mut m = manager();
        let loaded = m.generate_identity().unwrap();
        let peer = generate_key_pair();
        let shared_a = loaded.diffie_hellman(&peer.public);
        let shared_b = peer.diffie_hellman(loaded.public_key());
        assert_eq!(shared_a.as_bytes(), shared_b.as_bytes());
    }

    #[test]
    fn load_identity_returns_corrupt_when_only_one_key_present() {
        let mut m = manager();
        m.generate_identity().unwrap();
        m.storage.delete(IDENTITY_ED25519_KEY).unwrap();
        assert!(matches!(m.load_identity(), Err(IdentityError::Corrupt)));
    }
}
