mod backup;

use crate::storage::{SecureStorage, StorageError};
use crate::stored_data::{StoredDataError, decode_versioned, encode_versioned};
pub(crate) use backup::decrypt_backup;
use rand::{CryptoRng, RngCore};
use roost_crypto::{
    KeyPair, PublicIdentityKey, PublicKey, Signature, SigningKeyPair, VerifyingKey,
    generate_key_pair, generate_signing_key_pair, sign_identity_key_binding,
};
use roost_protocol::SignatureError;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex, MutexGuard};
use zeroize::{Zeroize, ZeroizeOnDrop};

const IDENTITY_CURRENT_KEY: &str = "identity/current";
const IDENTITY_SECRET_BLOB_VERSION: u8 = 1;

/// Errors returned by identity operations.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// An identity is already stored.
    #[error("identity already exists")]
    AlreadyExists,
    /// Encrypting the backup failed.
    #[error("backup encryption failed")]
    BackupEncryption,
    /// A backup failed to encode, or its bytes are malformed or use an unknown version.
    #[error("backup failed to encode or decode")]
    BackupFormat(#[source] StoredDataError),
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
    /// The random number generator failed while creating a backup.
    #[error("backup randomness failed")]
    BackupRandomness(#[source] rand::Error),
    /// Signing the binding between the Identity Key's halves failed.
    #[error("signing the identity key binding failed")]
    BindingSignature(#[source] SignatureError),
    /// Backup decryption failed because the passphrase or ciphertext was invalid.
    #[error("decryption failed: wrong passphrase or corrupt backup")]
    DecryptionFailed,
    /// The internal storage lock was poisoned by a panicked thread.
    #[error("internal lock poisoned")]
    LockPoisoned,
    /// No identity is stored.
    #[error("no identity found")]
    NotFound,
    /// The Identity Secret Blob failed to encode, or the stored one is malformed or uses an
    /// unknown version.
    #[error("identity secret blob failed to encode or decode")]
    SecretBlob(#[source] StoredDataError),
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

    /// Signs `message` with the Ed25519 signing key and returns the [`Signature`].
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key_pair.sign(message)
    }

    pub(crate) fn signing_key_pair(&self) -> &SigningKeyPair {
        &self.signing_key_pair
    }

    fn to_wire(&self) -> IdentitySecretsWire {
        IdentitySecretsWire {
            agreement_secret: *self.key_pair.to_secret_bytes(),
            signing_secret: *self.signing_key_pair.to_signing_bytes(),
        }
    }

    fn from_wire(wire: &IdentitySecretsWire) -> Self {
        let (key_pair, signing_key_pair) = wire.key_pairs();
        Self {
            key_pair,
            signing_key_pair,
        }
    }
}

// Both secret halves of the Identity Key, which the Identity Secret Blob and an Identity Backup
// each hold together.
#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
struct IdentitySecretsWire {
    agreement_secret: [u8; 32],
    signing_secret: [u8; 32],
}

impl IdentitySecretsWire {
    fn key_pairs(&self) -> (KeyPair, SigningKeyPair) {
        (
            KeyPair::from_secret_bytes(self.agreement_secret),
            SigningKeyPair::from_signing_bytes(self.signing_secret),
        )
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
        if storage.load(IDENTITY_CURRENT_KEY)?.is_some() {
            return Err(IdentityError::AlreadyExists);
        }
        let identity = Identity {
            key_pair: generate_key_pair(rng),
            signing_key_pair: generate_signing_key_pair(rng),
        };
        store_identity(&mut **storage, &identity)?;
        Ok(identity)
    }

    pub(crate) fn load_identity(&self) -> Result<Identity, IdentityError> {
        Ok(Identity::from_wire(&self.load_secrets()?))
    }

    // Returns the stored agreement and signing key pairs, for an operation that owns them.
    pub(crate) fn load_key_pairs(&self) -> Result<(KeyPair, SigningKeyPair), IdentityError> {
        Ok(self.load_secrets()?.key_pairs())
    }

    fn load_secrets(&self) -> Result<IdentitySecretsWire, IdentityError> {
        let blob = self
            .lock_storage()?
            .load(IDENTITY_CURRENT_KEY)?
            .ok_or(IdentityError::NotFound)?;
        decode_versioned(IDENTITY_SECRET_BLOB_VERSION, &blob).map_err(IdentityError::SecretBlob)
    }

    // Replaces the stored identity with `identity` in one write.
    pub(crate) fn replace_identity(&self, identity: &Identity) -> Result<(), IdentityError> {
        store_identity(&mut **self.lock_storage()?, identity)
    }

    pub(crate) fn reset(&self) -> Result<(), IdentityError> {
        self.lock_storage()?.delete(IDENTITY_CURRENT_KEY)?;
        Ok(())
    }
}

fn store_identity(
    storage: &mut dyn SecureStorage,
    identity: &Identity,
) -> Result<(), IdentityError> {
    let blob = encode_versioned(IDENTITY_SECRET_BLOB_VERSION, &identity.to_wire())
        .map_err(IdentityError::SecretBlob)?;
    storage.store(IDENTITY_CURRENT_KEY, &blob)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::InMemorySecureStorage;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn manager() -> IdentityManager {
        IdentityManager::new(Arc::new(Mutex::new(Box::new(InMemorySecureStorage::new()))))
    }

    #[test]
    fn generate_identity_stores_both_halves_in_one_versioned_blob() {
        let manager = manager();
        let identity = manager
            .generate_identity(&mut ChaCha20Rng::from_seed([0x49; 32]))
            .unwrap();

        let storage = manager.storage.lock().unwrap();
        let blob = storage.load(IDENTITY_CURRENT_KEY).unwrap().unwrap();
        let wire: IdentitySecretsWire =
            decode_versioned(IDENTITY_SECRET_BLOB_VERSION, &blob).unwrap();

        assert_eq!(wire.agreement_secret, *identity.key_pair.to_secret_bytes());
        assert_eq!(
            wire.signing_secret,
            *identity.signing_key_pair.to_signing_bytes()
        );
    }

    #[test]
    fn load_identity_rejects_an_unknown_blob_version() {
        let manager = manager();
        manager
            .generate_identity(&mut ChaCha20Rng::from_seed([0x4a; 32]))
            .unwrap();
        let mut blob = manager
            .storage
            .lock()
            .unwrap()
            .load(IDENTITY_CURRENT_KEY)
            .unwrap()
            .unwrap();
        blob[0] = IDENTITY_SECRET_BLOB_VERSION + 1;
        manager
            .storage
            .lock()
            .unwrap()
            .store(IDENTITY_CURRENT_KEY, &blob)
            .unwrap();

        assert!(matches!(
            manager.load_identity(),
            Err(IdentityError::SecretBlob(StoredDataError::UnsupportedVersion(version)))
                if version == IDENTITY_SECRET_BLOB_VERSION + 1
        ));
    }

    #[test]
    fn identity_zeroizes_on_drop() {
        fn assert_zeroizes_on_drop<T: zeroize::ZeroizeOnDrop>() {}

        assert_zeroizes_on_drop::<Identity>();
    }

    #[test]
    fn generate_identity_twice_returns_already_exists() {
        let mut rng = ChaCha20Rng::from_seed([0x60; 32]);
        let manager = manager();
        manager.generate_identity(&mut rng).unwrap();
        assert!(matches!(
            manager.generate_identity(&mut rng),
            Err(IdentityError::AlreadyExists)
        ));
    }
}
