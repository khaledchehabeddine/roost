//! Passphrase-encrypted identity backup using Argon2id and XChaCha20-Poly1305.

use super::{IDENTITY_ED25519_KEY, IDENTITY_X25519_KEY, IdentityError, IdentityManager};
use argon2::{Argon2, Params};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;

// Argon2id memory cost is in KiB. Memory is the primary brute-force defense. Time adds CPU work
// without raising memory use.
const ARGON2_M_COST: u32 = 65536;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;
const ARGON2_OUTPUT_LEN: usize = 32;

impl IdentityManager {
    // Exports the current identity as an encrypted backup blob.
    pub(crate) fn export_encrypted_backup<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        passphrase: &str,
    ) -> Result<Vec<u8>, IdentityError> {
        let (x25519_bytes, ed25519_bytes) = self.load_identity_key_bytes()?;

        let salt: [u8; SALT_LEN] = random_bytes(rng)?;
        let nonce_bytes: [u8; NONCE_LEN] = random_bytes(rng)?;

        let key_bytes = derive_key(passphrase, &salt)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&*key_bytes));
        let nonce = XNonce::from_slice(&nonce_bytes);

        // Plaintext layout: X25519 secret (32 bytes) | Ed25519 secret (32 bytes).
        let mut plaintext = Zeroizing::new([0u8; 64]);
        plaintext[..32].copy_from_slice(&*x25519_bytes);
        plaintext[32..].copy_from_slice(&*ed25519_bytes);

        let ciphertext = cipher
            .encrypt(nonce, &plaintext[..])
            .map_err(|e| IdentityError::BackupFailed(e.to_string()))?;

        // Backup layout: salt (16 bytes) | nonce (24 bytes) | ciphertext and tag (80 bytes).
        let mut backup = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
        backup.extend_from_slice(&salt);
        backup.extend_from_slice(&nonce_bytes);
        backup.extend_from_slice(&ciphertext);
        Ok(backup)
    }

    // Decrypts a backup blob into identity plaintext.
    pub(crate) fn decrypt_backup(
        &self,
        data: &[u8],
        passphrase: &str,
    ) -> Result<Zeroizing<[u8; 64]>, IdentityError> {
        // Only accept the fixed identity plaintext layout.
        if data.len() != SALT_LEN + NONCE_LEN + 64 + 16 {
            return Err(IdentityError::InvalidData("invalid backup length".into()));
        }

        let (salt, remainder) = data.split_at(SALT_LEN);
        let (nonce_bytes, ciphertext) = remainder.split_at(NONCE_LEN);

        let key_bytes = derive_key(passphrase, salt)?;
        let nonce = XNonce::from_slice(nonce_bytes);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&*key_bytes));

        let plaintext_vec = Zeroizing::new(
            cipher
                .decrypt(nonce, ciphertext)
                .map_err(|_| IdentityError::DecryptionFailed)?,
        );
        let plaintext = Zeroizing::new(
            <[u8; 64]>::try_from(plaintext_vec.as_slice())
                .map_err(|_| IdentityError::InvalidData("unexpected plaintext length".into()))?,
        );
        Ok(plaintext)
    }

    // Stores decrypted identity plaintext.
    pub(crate) fn store_decrypted_identity(
        &self,
        plaintext: &[u8; 64],
    ) -> Result<(), IdentityError> {
        let mut storage = self.lock_storage()?;
        storage
            .store(IDENTITY_X25519_KEY, &plaintext[..32])
            .map_err(super::map_storage_err)?;
        storage
            .store(IDENTITY_ED25519_KEY, &plaintext[32..])
            .map_err(super::map_storage_err)?;
        Ok(())
    }
}

// Salt and nonce come from the injected CSPRNG via the fallible `try_fill_bytes` (panics on
// entropy failure) so an RNG failure surfaces as `BackupFailed`.
fn random_bytes<const N: usize, R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Result<[u8; N], IdentityError> {
    let mut buf = [0u8; N];
    rng.try_fill_bytes(&mut buf)
        .map_err(|e| IdentityError::BackupFailed(e.to_string()))?;
    Ok(buf)
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::InMemorySecureStorage;
    use rand::rngs::OsRng;
    use std::sync::{Arc, Mutex};

    fn manager() -> IdentityManager {
        IdentityManager::new(Arc::new(Mutex::new(Box::new(InMemorySecureStorage::new()))))
    }

    #[test]
    fn export_backup_without_identity_returns_not_found() {
        let manager = manager();
        assert!(matches!(
            manager.export_encrypted_backup(&mut OsRng, "passphrase"),
            Err(IdentityError::NotFound)
        ));
    }

    #[test]
    fn each_export_uses_fresh_salt_and_nonce() {
        let manager = manager();
        manager.generate_identity(&mut OsRng).unwrap();
        let first_backup = manager
            .export_encrypted_backup(&mut OsRng, "passphrase")
            .unwrap();
        let second_backup = manager
            .export_encrypted_backup(&mut OsRng, "passphrase")
            .unwrap();
        // Nonce reuse would break XChaCha20-Poly1305 confidentiality.
        assert_ne!(first_backup, second_backup);
    }

    #[test]
    fn decrypt_backup_rejects_invalid_length() {
        let manager = manager();
        assert!(matches!(
            manager.decrypt_backup(&[0u8; 10], "passphrase"),
            Err(IdentityError::InvalidData(_))
        ));
        assert!(matches!(
            manager.decrypt_backup(&[0u8; 121], "passphrase"),
            Err(IdentityError::InvalidData(_))
        ));
    }

    #[test]
    fn decrypt_backup_with_wrong_passphrase_returns_decryption_failed() {
        let source_manager = manager();
        source_manager.generate_identity(&mut OsRng).unwrap();
        let backup = source_manager
            .export_encrypted_backup(&mut OsRng, "correct-passphrase")
            .unwrap();

        let destination_manager = manager();
        assert!(matches!(
            destination_manager.decrypt_backup(&backup, "wrong-passphrase"),
            Err(IdentityError::DecryptionFailed)
        ));
    }

    #[test]
    fn export_import_round_trip_restores_identity() {
        let source_manager = manager();
        let original_identity = source_manager.generate_identity(&mut OsRng).unwrap();
        let backup = source_manager
            .export_encrypted_backup(&mut OsRng, "correct-passphrase")
            .unwrap();

        let destination_manager = manager();
        let plaintext = destination_manager
            .decrypt_backup(&backup, "correct-passphrase")
            .unwrap();
        destination_manager
            .store_decrypted_identity(&plaintext)
            .unwrap();
        let restored_identity = destination_manager.load_identity().unwrap();

        assert_eq!(
            original_identity.public_key(),
            restored_identity.public_key()
        );
        assert_eq!(
            original_identity.verifying_key().as_bytes(),
            restored_identity.verifying_key().as_bytes()
        );
    }

    #[test]
    fn argon2id_derive_key_is_deterministic() {
        let passphrase = "passphrase";
        let salt = [0x00u8; 16];
        let first_key = derive_key(passphrase, &salt).unwrap();
        let second_key = derive_key(passphrase, &salt).unwrap();
        assert_eq!(*first_key, *second_key);
    }

    #[test]
    fn argon2id_different_passphrases_produce_different_keys() {
        let salt = [0x01u8; 16];
        let first_key = derive_key("passphrase-one", &salt).unwrap();
        let second_key = derive_key("passphrase-two", &salt).unwrap();
        assert_ne!(*first_key, *second_key);
    }

    #[test]
    fn argon2id_different_salts_produce_different_keys() {
        let passphrase = "passphrase";
        let first_key = derive_key(passphrase, &[0x00u8; 16]).unwrap();
        let second_key = derive_key(passphrase, &[0x01u8; 16]).unwrap();
        assert_ne!(*first_key, *second_key);
    }

    #[test]
    fn export_is_deterministic_under_seed() {
        // Identity keys, salt, and nonce all come from the seeded RNG, so the same seed must yield
        // a byte-identical backup blob and a different seed must not.
        fn export(seed: [u8; 32]) -> Vec<u8> {
            use crate::test_support::Sandbox;

            let mut sandbox = Sandbox::new(seed, 1_700_000_000);
            let (identity, _, _) = sandbox.managers();
            identity.generate_identity(&mut sandbox.rng).unwrap();
            identity
                .export_encrypted_backup(&mut sandbox.rng, "passphrase")
                .unwrap()
        }

        assert_eq!(export([9u8; 32]), export([9u8; 32]));
        assert_ne!(export([9u8; 32]), export([10u8; 32]));
    }
}
