mod backup;

use crate::storage::{SecureStorage, StorageError};
use rand::{CryptoRng, RngCore};
use roost_crypto::{
    KeyPair, PublicIdentityKey, PublicKey, SharedSecret, Signature, SigningKeyPair, VerifyingKey,
    generate_key_pair, generate_signing_key_pair, sign_identity_key_binding,
};
use roost_protocol::SignatureError;
use std::sync::{Arc, Mutex, MutexGuard};
use zeroize::{ZeroizeOnDrop, Zeroizing};

type IdentityKeyBytes = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>);

const IDENTITY_CURRENT_KEY: &str = "identity/current";
const IDENTITY_KEY_BLOB_VERSION: u8 = 1;
const IDENTITY_KEY_BLOB_LEN: usize = 1 + 32 + 32;
const IDENTITY_X25519_KEY: &str = "identity/x25519";
const IDENTITY_ED25519_KEY: &str = "identity/ed25519";

/// Errors returned by identity operations.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// Stored data uses an unsupported format version.
    #[error("unsupported stored format version: {0}")]
    UnsupportedVersion(u8),
    /// An encrypted backup uses a format version this build does not understand.
    #[error("unsupported backup format version: {0}")]
    UnsupportedBackupVersion(u8),
    /// An identity is already stored.
    #[error("identity already exists")]
    AlreadyExists,
    /// Encrypting the backup failed.
    #[error("backup encryption failed")]
    BackupEncryption,
    /// Argon2id failed to derive the backup key.
    #[error("backup key derivation failed")]
    BackupKeyDerivation(#[source] argon2::Error),
    /// A backup's Argon2id parameters are outside the range this build accepts.
    #[error(
        "backup Argon2id parameters are out of range: {memory_kib} KiB, {iterations} iterations, \
         parallelism {parallelism}"
    )]
    BackupParametersOutOfRange {
        /// Memory cost in KiB.
        memory_kib: u32,
        /// Number of iterations.
        iterations: u32,
        /// Degree of parallelism.
        parallelism: u32,
    },
    /// A decrypted backup is too short to hold an Identity Key.
    #[error("decrypted backup is {len} bytes, shorter than {min_len}")]
    BackupPlaintextTooShort {
        /// Decrypted length in bytes.
        len: usize,
        /// Shortest accepted length in bytes.
        min_len: usize,
    },
    /// The random number generator failed while creating a backup.
    #[error("backup randomness failed")]
    BackupRandomness(#[source] rand::Error),
    /// A backup is too short to hold its header.
    #[error("backup is {len} bytes, shorter than its {min_len}-byte header")]
    BackupTooShort {
        /// Backup length in bytes.
        len: usize,
        /// Header length in bytes.
        min_len: usize,
    },
    /// Signing the binding between the Identity Key's halves failed.
    #[error("signing the identity key binding failed")]
    BindingSignature(#[source] SignatureError),
    /// Only one of the two identity keys is present in storage.
    #[error("identity data is corrupt")]
    Corrupt,
    /// Backup decryption failed because the passphrase or ciphertext was invalid.
    #[error("decryption failed: wrong passphrase or corrupt backup")]
    DecryptionFailed,
    /// The stored Identity Secret Blob has the wrong length.
    #[error("identity secret blob is {actual} bytes, expected {expected}")]
    InvalidBlobLength {
        /// Expected length in bytes.
        expected: usize,
        /// Stored length in bytes.
        actual: usize,
    },
    /// A stored identity key half has the wrong length.
    #[error("identity key is {actual} bytes, expected {expected}")]
    InvalidKeyLength {
        /// Expected length in bytes.
        expected: usize,
        /// Stored length in bytes.
        actual: usize,
    },
    /// The internal storage lock was poisoned by a panicked thread.
    #[error("internal lock poisoned")]
    LockPoisoned,
    /// No identity is stored.
    #[error("no identity found")]
    NotFound,
    /// The underlying [`SecureStorage`] returned an error.
    #[error("identity storage failed")]
    Storage(#[from] StorageError),
}

/// A local identity containing X25519 and Ed25519 key pairs.
#[derive(ZeroizeOnDrop)]
pub struct Identity {
    key_pair: KeyPair,
    signing_key_pair: SigningKeyPair,
}

impl Identity {
    /// Returns the X25519 [`PublicKey`].
    pub fn public_key(&self) -> &PublicKey {
        &self.key_pair.public
    }

    /// Returns the Ed25519 [`VerifyingKey`].
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.signing_key_pair.verifying
    }

    /// Returns the public Identity Key proving that the X25519 and Ed25519 halves belong
    /// together.
    pub fn public(&self) -> Result<PublicIdentityKey, IdentityError> {
        let binding_signature =
            sign_identity_key_binding(&self.signing_key_pair, &self.key_pair.public)
                .map_err(IdentityError::BindingSignature)?;
        Ok(PublicIdentityKey {
            public_key: PublicKey::from(*self.key_pair.public.as_bytes()),
            verifying_key: self.signing_key_pair.verifying,
            binding_signature,
        })
    }

    /// Performs an X25519 Diffie–Hellman exchange with the given [`PublicKey`] and returns the
    /// [`SharedSecret`].
    pub fn diffie_hellman(&self, their_public: &PublicKey) -> SharedSecret {
        self.key_pair.diffie_hellman(their_public)
    }

    /// Signs `message` with the Ed25519 signing key and returns the [`Signature`].
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key_pair.sign(message)
    }

    pub(crate) fn signing_key_pair(&self) -> &SigningKeyPair {
        // Signed-pre-key rotation needs direct signing-key access inside the crate.
        &self.signing_key_pair
    }
}

pub(crate) struct IdentityManager {
    storage: Arc<Mutex<Box<dyn SecureStorage>>>,
}

impl IdentityManager {
    pub(crate) fn new(storage: Arc<Mutex<Box<dyn SecureStorage>>>) -> Self {
        IdentityManager { storage }
    }

    fn lock_storage(&self) -> Result<MutexGuard<'_, Box<dyn SecureStorage>>, IdentityError> {
        self.storage.lock().map_err(|_| IdentityError::LockPoisoned)
    }

    pub(crate) fn generate_identity<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<Identity, IdentityError> {
        let mut storage = self.lock_storage()?;
        let identity_exists = has_identity_entry(&**storage)?;
        if identity_exists {
            return Err(IdentityError::AlreadyExists);
        }

        let key_pair = generate_key_pair(rng);
        let signing_key_pair = generate_signing_key_pair(rng);
        let blob = encode_identity_key_blob(
            &key_pair.to_secret_bytes(),
            &signing_key_pair.to_signing_bytes(),
        );
        storage.store(IDENTITY_CURRENT_KEY, &*blob)?;
        Ok(Identity {
            key_pair,
            signing_key_pair,
        })
    }

    pub(crate) fn load_identity(&self) -> Result<Identity, IdentityError> {
        let (x25519, ed25519) = self.load_identity_key_bytes()?;
        Ok(Identity {
            key_pair: KeyPair::from_secret_bytes(*x25519),
            signing_key_pair: SigningKeyPair::from_signing_bytes(*ed25519),
        })
    }

    // Use `KeyStore::prepare_identity_deletion` to clear dependent key material before identity.
    pub(crate) fn reset(&self) -> Result<(), IdentityError> {
        let mut storage = self.lock_storage()?;
        storage.delete(IDENTITY_X25519_KEY)?;
        storage.delete(IDENTITY_ED25519_KEY)?;
        storage.delete(IDENTITY_CURRENT_KEY)?;
        Ok(())
    }

    fn load_identity_key_bytes(&self) -> Result<IdentityKeyBytes, IdentityError> {
        let storage = self.lock_storage()?;
        if let Some(blob) = storage.load(IDENTITY_CURRENT_KEY)? {
            return decode_identity_key_blob(&blob);
        }

        let (x25519_vec, ed25519_vec) = match (
            storage.load(IDENTITY_X25519_KEY)?,
            storage.load(IDENTITY_ED25519_KEY)?,
        ) {
            (None, None) => return Err(IdentityError::NotFound),
            (Some(_), None) | (None, Some(_)) => return Err(IdentityError::Corrupt),
            (Some(x25519), Some(ed25519)) => (x25519, ed25519),
        };
        let x25519_bytes: [u8; 32] =
            x25519_vec
                .as_slice()
                .try_into()
                .map_err(|_| IdentityError::InvalidKeyLength {
                    expected: 32,
                    actual: x25519_vec.len(),
                })?;
        let ed25519_bytes: [u8; 32] =
            ed25519_vec
                .as_slice()
                .try_into()
                .map_err(|_| IdentityError::InvalidKeyLength {
                    expected: 32,
                    actual: ed25519_vec.len(),
                })?;
        Ok((Zeroizing::new(x25519_bytes), Zeroizing::new(ed25519_bytes)))
    }
}

fn has_identity_entry(storage: &dyn SecureStorage) -> Result<bool, IdentityError> {
    if storage.load(IDENTITY_CURRENT_KEY)?.is_some() {
        return Ok(true);
    }
    Ok(storage.load(IDENTITY_X25519_KEY)?.is_some()
        || storage.load(IDENTITY_ED25519_KEY)?.is_some())
}

fn encode_identity_key_blob(
    x25519: &[u8; 32],
    ed25519: &[u8; 32],
) -> Zeroizing<[u8; IDENTITY_KEY_BLOB_LEN]> {
    let mut blob = Zeroizing::new([0u8; IDENTITY_KEY_BLOB_LEN]);
    blob[0] = IDENTITY_KEY_BLOB_VERSION;
    blob[1..33].copy_from_slice(x25519);
    blob[33..IDENTITY_KEY_BLOB_LEN].copy_from_slice(ed25519);
    blob
}

fn decode_identity_key_blob(raw: &[u8]) -> Result<IdentityKeyBytes, IdentityError> {
    let blob: &[u8; IDENTITY_KEY_BLOB_LEN] =
        raw.try_into()
            .map_err(|_| IdentityError::InvalidBlobLength {
                expected: IDENTITY_KEY_BLOB_LEN,
                actual: raw.len(),
            })?;
    if blob[0] != IDENTITY_KEY_BLOB_VERSION {
        return Err(IdentityError::UnsupportedVersion(blob[0]));
    }

    let mut x25519 = [0u8; 32];
    x25519.copy_from_slice(&blob[1..33]);
    let mut ed25519 = [0u8; 32];
    ed25519.copy_from_slice(&blob[33..IDENTITY_KEY_BLOB_LEN]);
    Ok((Zeroizing::new(x25519), Zeroizing::new(ed25519)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::InMemorySecureStorage;
    use rand::SeedableRng;
    use rand::rngs::OsRng;
    use rand_chacha::ChaCha20Rng;

    fn manager() -> IdentityManager {
        IdentityManager::new(Arc::new(Mutex::new(Box::new(InMemorySecureStorage::new()))))
    }

    /// Known-answer test for deterministic identity-key generation and storage encoding.
    ///
    /// Source: `rand_chacha` 0.3 `ChaCha20Rng` with Aether key constructors
    ///
    /// Inputs:
    /// - `rng_seed = [0x49; 32]`
    ///
    /// Output: `identity/x25519 secret || identity/ed25519 secret`.
    #[test]
    fn generate_identity_known_answer_and_canonical_blob_encoding() {
        const EXPECTED_CANONICAL_IDENTITY_SECRET: [u8; 64] = [
            38, 66, 93, 82, 83, 101, 158, 207, 181, 252, 75, 95, 72, 220, 75, 134, 99, 244, 117,
            171, 95, 230, 17, 124, 185, 206, 38, 77, 69, 114, 38, 71, 70, 17, 62, 74, 208, 54, 58,
            109, 199, 137, 67, 242, 51, 3, 21, 21, 45, 241, 16, 205, 23, 211, 147, 33, 6, 0, 90,
            170, 13, 30, 167, 208,
        ];

        let manager = manager();
        let mut rng = ChaCha20Rng::from_seed([0x49u8; 32]);

        manager.generate_identity(&mut rng).unwrap();

        let storage = manager.storage.lock().unwrap();
        let blob = storage.load(IDENTITY_CURRENT_KEY).unwrap().unwrap();

        assert_eq!(blob[0], 1);
        assert_eq!(&blob[1..], EXPECTED_CANONICAL_IDENTITY_SECRET);
        assert_ne!(&blob[1..33], &blob[33..IDENTITY_KEY_BLOB_LEN]);
        assert!(storage.load(IDENTITY_X25519_KEY).unwrap().is_none());
        assert!(storage.load(IDENTITY_ED25519_KEY).unwrap().is_none());
    }

    #[test]
    fn identity_zeroizes_on_drop() {
        fn assert_zeroizes_on_drop<T: zeroize::ZeroizeOnDrop>() {}

        assert_zeroizes_on_drop::<Identity>();
    }

    #[test]
    fn generate_identity_twice_returns_already_exists() {
        let manager = manager();
        manager.generate_identity(&mut OsRng).unwrap();
        assert!(matches!(
            manager.generate_identity(&mut OsRng),
            Err(IdentityError::AlreadyExists)
        ));
    }

    #[test]
    fn load_identity_without_generate_returns_not_found() {
        let manager = manager();
        assert!(matches!(
            manager.load_identity(),
            Err(IdentityError::NotFound)
        ));
    }

    #[test]
    fn load_identity_returns_same_public_keys() {
        let manager = manager();
        let generated_identity = manager.generate_identity(&mut OsRng).unwrap();
        let loaded_identity = manager.load_identity().unwrap();
        assert_eq!(
            generated_identity.public_key(),
            loaded_identity.public_key()
        );
        assert_eq!(
            generated_identity.verifying_key().as_bytes(),
            loaded_identity.verifying_key().as_bytes()
        );
    }

    #[test]
    fn load_identity_reads_legacy_two_entry_identity() {
        let manager = manager();
        let mut rng = ChaCha20Rng::from_seed([0x49u8; 32]);
        let key_pair = generate_key_pair(&mut rng);
        let signing_key_pair = generate_signing_key_pair(&mut rng);
        {
            let mut storage = manager.storage.lock().unwrap();
            storage
                .store(IDENTITY_X25519_KEY, &*key_pair.to_secret_bytes())
                .unwrap();
            storage
                .store(IDENTITY_ED25519_KEY, &*signing_key_pair.to_signing_bytes())
                .unwrap();
        }

        let loaded_identity = manager.load_identity().unwrap();

        assert_eq!(key_pair.public, *loaded_identity.public_key());
        assert_eq!(
            signing_key_pair.verifying.as_bytes(),
            loaded_identity.verifying_key().as_bytes()
        );
    }

    #[test]
    fn load_identity_returns_corrupt_when_only_one_key_present() {
        let manager = manager();
        manager
            .storage
            .lock()
            .unwrap()
            .store(IDENTITY_X25519_KEY, &[0u8; 32])
            .unwrap();
        assert!(matches!(
            manager.load_identity(),
            Err(IdentityError::Corrupt)
        ));
    }

    #[test]
    fn sign_round_trip_after_load_identity() {
        let manager = manager();
        let generated_identity = manager.generate_identity(&mut OsRng).unwrap();
        let loaded_identity = manager.load_identity().unwrap();
        let message = b"aether test message";
        // Ed25519 signing is deterministic, so identical keys produce identical signatures.
        assert_eq!(
            generated_identity.sign(message).to_bytes(),
            loaded_identity.sign(message).to_bytes()
        );
    }

    #[test]
    fn diffie_hellman_round_trip_after_load_identity() {
        let manager = manager();
        manager.generate_identity(&mut OsRng).unwrap();
        let loaded_identity = manager.load_identity().unwrap();
        let peer_key_pair = generate_key_pair(&mut OsRng);
        let identity_shared_secret = loaded_identity.diffie_hellman(&peer_key_pair.public);
        let peer_shared_secret = peer_key_pair.diffie_hellman(loaded_identity.public_key());
        assert_eq!(
            identity_shared_secret.as_bytes(),
            peer_shared_secret.as_bytes()
        );
    }
}
