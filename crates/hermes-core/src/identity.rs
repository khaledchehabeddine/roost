use crate::storage::{SecureStorage, StorageError};
use argon2::{Argon2, Params};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use hermes_crypto::{
    KeyPair, PublicKey, SharedSecret, Signature, SigningKeyPair, VerifyingKey, generate_key_pair,
    generate_signing_key_pair,
};
use std::error::Error;
use std::fmt;
use std::sync::{Mutex, MutexGuard};
use zeroize::Zeroizing;

type KeyBytes = (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>);

const IDENTITY_X25519_KEY: &str = "identity/x25519";
const IDENTITY_ED25519_KEY: &str = "identity/ed25519";

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;

/// Argon2id memory cost in KiB. Primary defense: forces attackers to provision large amounts
/// of RAM per guess, defeating GPU and ASIC brute-force. OWASP baseline: 65,536 KiB (64 MiB).
const ARGON2_M_COST: u32 = 65536;
/// Argon2id time cost (iterations). Secondary defense: increases CPU work per guess without
/// raising memory requirements. OWASP baseline: 3.
const ARGON2_T_COST: u32 = 3;
/// Argon2id parallelism. OWASP baseline: 1. Security comes from [`ARGON2_M_COST`] and
/// [`ARGON2_T_COST`], not parallelism.
const ARGON2_P_COST: u32 = 1;
/// Argon2id output length in bytes. 32 bytes is the length of a XChaCha20-Poly1305 key.
const ARGON2_OUTPUT_LEN: usize = 32;

/// Errors returned by [`IdentityManager`] operations.
#[derive(Debug)]
pub enum IdentityError {
    AlreadyExists,
    BackupFailed(String),
    /// Only one of the two identity keys is present in storage, indicating a partial writing.
    Corrupt,
    DecryptionFailed,
    InvalidData(String),
    /// The internal storage lock was poisoned by a panicked thread.
    LockPoisoned,
    NotFound,
    Storage(StorageError),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityError::AlreadyExists => write!(f, "Identity already exists"),
            IdentityError::BackupFailed(reason) => write!(f, "Backup failed: {reason}"),
            IdentityError::Corrupt => write!(f, "Identity data is corrupt"),
            IdentityError::DecryptionFailed => {
                write!(f, "Decryption failed: wrong passphrase or corrupt backup")
            }
            IdentityError::InvalidData(reason) => write!(f, "Invalid identity data: {reason}"),
            IdentityError::LockPoisoned => write!(f, "Internal lock poisoned"),
            IdentityError::NotFound => write!(f, "No identity found"),
            IdentityError::Storage(err) => write!(f, "Storage error: {err}"),
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
/// [`crate::InMemorySecureStorage`].
///
/// Thread-safe: all methods take `&self` and synchronize internally. The storage backend is
/// exclusively owned — it cannot be shared across instances.
pub struct IdentityManager {
    storage: Mutex<Box<dyn SecureStorage>>,
}

impl IdentityManager {
    pub fn new(storage: Box<dyn SecureStorage>) -> Self {
        IdentityManager {
            storage: Mutex::new(storage),
        }
    }

    /// Acquires the storage lock, mapping a poisoned mutex to [`IdentityError::LockPoisoned`].
    fn lock_storage(&self) -> Result<MutexGuard<'_, Box<dyn SecureStorage>>, IdentityError> {
        self.storage.lock().map_err(|_| IdentityError::LockPoisoned)
    }

    /// Generates a new identity and persists it to storage.
    ///
    /// Returns [`IdentityError::AlreadyExists`] if an X25519 identity key is already stored.
    ///
    /// If the X25519 key is stored successfully but writing the Ed25519 key fails, the X25519 key
    /// is deleted to leave storage in a clean state. If that cleanup also fails, the error is
    /// logged, and the original writing error is returned — the identity can be re-created by
    /// calling this method again.
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

        let ed25519_result = storage
            .store(IDENTITY_ED25519_KEY, &*signing_key_pair.to_signing_bytes())
            .map_err(log_storage_err);

        if let Err(e) = ed25519_result {
            if let Err(cleanup_err) = storage.delete(IDENTITY_X25519_KEY) {
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
        let storage = self.lock_storage()?;

        let x25519_bytes = storage.load(IDENTITY_X25519_KEY).map_err(log_storage_err)?;

        let ed25519_bytes = storage
            .load(IDENTITY_ED25519_KEY)
            .map_err(log_storage_err)?;

        let (x25519_bytes, ed25519_bytes) = match (x25519_bytes, ed25519_bytes) {
            (None, None) => return Err(IdentityError::NotFound),
            (Some(_), None) | (None, Some(_)) => return Err(IdentityError::Corrupt),
            (Some(x), Some(e)) => (x, e),
        };

        let x25519_array = Zeroizing::new(<[u8; 32]>::try_from(x25519_bytes.as_slice())
            .map_err(|_| IdentityError::InvalidData("invalid X25519 key length".into()))?);

        let ed25519_array = Zeroizing::new(<[u8; 32]>::try_from(ed25519_bytes.as_slice())
            .map_err(|_| IdentityError::InvalidData("invalid Ed25519 key length".into()))?);

        Ok(Identity {
            key_pair: KeyPair::from_secret_bytes(x25519_array),
            signing_key_pair: SigningKeyPair::from_signing_bytes(ed25519_array),
        })
    }

    /// Exports the current identity as an encrypted backup blob.
    ///
    /// The backup format is:
    /// `[Argon2id salt (16B)] + [XChaCha20-Poly1305 nonce (24B)] + [ciphertext (nB)]`
    ///
    /// The plaintext is the concatenation of the X25519 secret key (32 bytes) and
    /// the Ed25519 signing key (32 bytes).
    ///
    /// Returns [`IdentityError::NotFound`] if no identity is stored, or
    /// [`IdentityError::BackupFailed`] on encryption or RNG failure.
    pub fn export_encrypted_backup(&self, passphrase: &str) -> Result<Vec<u8>, IdentityError> {
        let (x25519_bytes, ed25519_bytes) = self.load_key_bytes()?;

        let mut salt = [0u8; SALT_LEN];
        getrandom::getrandom(&mut salt).map_err(|e| IdentityError::BackupFailed(e.to_string()))?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| IdentityError::BackupFailed(e.to_string()))?;

        let key_bytes = derive_key(passphrase, &salt)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&*key_bytes));
        let nonce = XNonce::from_slice(&nonce_bytes);

        let x25519_array = Zeroizing::new(<[u8; 32]>::try_from(x25519_bytes.as_slice())
            .map_err(|_| IdentityError::InvalidData("invalid X25519 key length".into()))?);
        let ed25519_array = Zeroizing::new(<[u8; 32]>::try_from(ed25519_bytes.as_slice())
            .map_err(|_| IdentityError::InvalidData("invalid Ed25519 key length".into()))?);
        let mut plaintext = Zeroizing::new([0u8; 64]);
        plaintext[..32].copy_from_slice(&*x25519_array);
        plaintext[32..].copy_from_slice(&*ed25519_array);

        let ciphertext = cipher
            .encrypt(nonce, &plaintext[..])
            .map_err(|e| IdentityError::BackupFailed(e.to_string()))?;

        let mut backup = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
        backup.extend_from_slice(&salt);
        backup.extend_from_slice(&nonce_bytes);
        backup.extend_from_slice(&ciphertext);
        Ok(backup)
    }

    /// Imports an identity from an encrypted backup blob, overwriting any existing identity.
    ///
    /// Returns [`IdentityError::DecryptionFailed`] if the passphrase is wrong or the backup is
    /// corrupt. Returns [`IdentityError::BackupFailed`] if the data is malformed.
    pub fn import_encrypted_backup(
        &self,
        data: &[u8],
        passphrase: &str,
    ) -> Result<(), IdentityError> {
        // salt (16) + nonce (24) + ciphertext (64) + Poly1305 tag (16) = 120 bytes
        if data.len() != SALT_LEN + NONCE_LEN + 64 + 16 {
            return Err(IdentityError::BackupFailed("invalid backup length".into()));
        }

        let (salt, remainder) = data.split_at(SALT_LEN);
        let (nonce_bytes, ciphertext) = remainder.split_at(NONCE_LEN);

        let key_bytes = derive_key(passphrase, salt)?;
        let nonce = XNonce::from_slice(nonce_bytes);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&*key_bytes));

        let plaintext = Zeroizing::new(
            cipher
                .decrypt(nonce, ciphertext)
                .map_err(|_| IdentityError::DecryptionFailed)?,
        );

        if plaintext.len() != 64 {
            return Err(IdentityError::BackupFailed(
                "unexpected plaintext length".into(),
            ));
        }

        let mut storage = self.lock_storage()?;
        storage
            .store(IDENTITY_X25519_KEY, &plaintext[..32])
            .map_err(log_storage_err)?;
        storage
            .store(IDENTITY_ED25519_KEY, &plaintext[32..])
            .map_err(log_storage_err)?;

        Ok(())
    }

    /// Reads both raw key byte vectors from storage, propagating `NotFound` / `Corrupt`.
    fn load_key_bytes(&self) -> Result<KeyBytes, IdentityError> {
        let storage = self.lock_storage()?;
        match (
            storage.load(IDENTITY_X25519_KEY).map_err(log_storage_err)?,
            storage
                .load(IDENTITY_ED25519_KEY)
                .map_err(log_storage_err)?,
        ) {
            (None, None) => Err(IdentityError::NotFound),
            (Some(_), None) | (None, Some(_)) => Err(IdentityError::Corrupt),
            (Some(x), Some(e)) => Ok((x, e)),
        }
    }
}

/// Derives a 32-byte encryption key from `passphrase` and `salt` using Argon2id.
fn derive_key(
    passphrase: &str,
    salt: &[u8],
) -> Result<Zeroizing<[u8; ARGON2_OUTPUT_LEN]>, IdentityError> {
    let params = Params::new(
        ARGON2_M_COST,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(ARGON2_OUTPUT_LEN),
    )
    .map_err(|e| IdentityError::BackupFailed(e.to_string()))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; ARGON2_OUTPUT_LEN]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut *key)
        .map_err(|e| IdentityError::BackupFailed(e.to_string()))?;
    Ok(key)
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
        IdentityManager::new(Box::new(InMemorySecureStorage::new()))
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

    #[test]
    fn export_backup_without_identity_returns_not_found() {
        let m = manager();
        assert!(matches!(
            m.export_encrypted_backup("passphrase"),
            Err(IdentityError::NotFound)
        ));
    }

    #[test]
    fn export_import_round_trip_restores_identity() {
        let m = manager();
        let original = m.generate_identity().unwrap();

        let backup = m.export_encrypted_backup("correct-passphrase").unwrap();

        let m2 = manager();
        m2.import_encrypted_backup(&backup, "correct-passphrase")
            .unwrap();
        let restored = m2.load_identity().unwrap();

        assert_eq!(original.public_key(), restored.public_key());
        assert_eq!(
            original.verifying_key().as_bytes(),
            restored.verifying_key().as_bytes()
        );
    }

    #[test]
    fn import_with_wrong_passphrase_returns_decryption_failed() {
        let m = manager();
        m.generate_identity().unwrap();
        let backup = m.export_encrypted_backup("correct-passphrase").unwrap();

        let m2 = manager();
        assert!(matches!(
            m2.import_encrypted_backup(&backup, "wrong-passphrase"),
            Err(IdentityError::DecryptionFailed)
        ));
    }

    #[test]
    fn import_wrong_length_returns_backup_failed() {
        let m = manager();
        assert!(matches!(
            m.import_encrypted_backup(&[0u8; 10], "passphrase"),
            Err(IdentityError::BackupFailed(_))
        ));
        assert!(matches!(
            m.import_encrypted_backup(&[0u8; 121], "passphrase"),
            Err(IdentityError::BackupFailed(_))
        ));
    }

    #[test]
    fn two_exports_produce_different_ciphertexts() {
        let m = manager();
        m.generate_identity().unwrap();
        let b1 = m.export_encrypted_backup("passphrase").unwrap();
        let b2 = m.export_encrypted_backup("passphrase").unwrap();
        // Salt and nonce are random, so the blobs must differ
        assert_ne!(b1, b2);
    }

    #[test]
    fn argon2id_derive_key_is_deterministic() {
        let passphrase = "passphrase";
        let salt = [0x00u8; 16];
        let key1 = derive_key(passphrase, &salt).unwrap();
        let key2 = derive_key(passphrase, &salt).unwrap();
        assert_eq!(*key1, *key2);
    }

    #[test]
    fn argon2id_different_passphrases_produce_different_keys() {
        let salt = [0x01u8; 16];
        let key1 = derive_key("passphrase-one", &salt).unwrap();
        let key2 = derive_key("passphrase-two", &salt).unwrap();
        assert_ne!(*key1, *key2);
    }

    #[test]
    fn argon2id_different_salts_produce_different_keys() {
        let passphrase = "passphrase";
        let key1 = derive_key(passphrase, &[0x00u8; 16]).unwrap();
        let key2 = derive_key(passphrase, &[0x01u8; 16]).unwrap();
        assert_ne!(*key1, *key2);
    }
}
