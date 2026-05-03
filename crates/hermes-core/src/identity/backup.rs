//! Passphrase-encrypted identity backup: Argon2id key derivation + XChaCha20-Poly1305 envelope
//! for portable identity export and restore.

use super::{IDENTITY_ED25519_KEY, IDENTITY_X25519_KEY, IdentityError, IdentityManager};
use argon2::{Argon2, Params};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use zeroize::Zeroizing;

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

impl IdentityManager {
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

        let mut plaintext = Zeroizing::new([0u8; 64]);
        plaintext[..32].copy_from_slice(&*x25519_bytes);
        plaintext[32..].copy_from_slice(&*ed25519_bytes);

        let ciphertext = cipher
            .encrypt(nonce, &plaintext[..])
            .map_err(|e| IdentityError::BackupFailed(e.to_string()))?;

        let mut backup = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
        backup.extend_from_slice(&salt);
        backup.extend_from_slice(&nonce_bytes);
        backup.extend_from_slice(&ciphertext);
        Ok(backup)
    }

    /// Decrypts a blob produced by [`Self::export_encrypted_backup`] into the raw
    /// `[X25519 secret (32) | Ed25519 secret (32)]` plaintext.
    pub(crate) fn decrypt_backup(
        &self,
        data: &[u8],
        passphrase: &str,
    ) -> Result<Zeroizing<[u8; 64]>, IdentityError> {
        // salt (16) + nonce (24) + ciphertext (64) + Poly1305 tag (16) = 120 bytes
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

    /// Plaintext layout: `[X25519 secret (32) | Ed25519 secret (32)]`.
    pub(crate) fn store_decrypted_identity(
        &self,
        plaintext: &[u8; 64],
    ) -> Result<(), IdentityError> {
        let mut storage = self.lock_storage()?;
        storage
            .store(IDENTITY_X25519_KEY, &plaintext[..32])
            .map_err(super::log_storage_err)?;
        storage
            .store(IDENTITY_ED25519_KEY, &plaintext[32..])
            .map_err(super::log_storage_err)?;
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::InMemorySecureStorage;
    use std::sync::{Arc, Mutex};

    fn manager() -> IdentityManager {
        IdentityManager::new(Arc::new(Mutex::new(Box::new(InMemorySecureStorage::new()))))
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
        let plaintext = m2.decrypt_backup(&backup, "correct-passphrase").unwrap();
        m2.store_decrypted_identity(&plaintext).unwrap();
        let restored = m2.load_identity().unwrap();

        assert_eq!(original.public_key(), restored.public_key());
        assert_eq!(
            original.verifying_key().as_bytes(),
            restored.verifying_key().as_bytes()
        );
    }

    #[test]
    fn decrypt_backup_with_wrong_passphrase_returns_decryption_failed() {
        let m = manager();
        m.generate_identity().unwrap();
        let backup = m.export_encrypted_backup("correct-passphrase").unwrap();

        let m2 = manager();
        assert!(matches!(
            m2.decrypt_backup(&backup, "wrong-passphrase"),
            Err(IdentityError::DecryptionFailed)
        ));
    }

    #[test]
    fn decrypt_backup_rejects_invalid_length() {
        let m = manager();
        assert!(matches!(
            m.decrypt_backup(&[0u8; 10], "passphrase"),
            Err(IdentityError::InvalidData(_))
        ));
        assert!(matches!(
            m.decrypt_backup(&[0u8; 121], "passphrase"),
            Err(IdentityError::InvalidData(_))
        ));
    }

    #[test]
    fn each_export_uses_fresh_salt_and_nonce() {
        let m = manager();
        m.generate_identity().unwrap();
        let b1 = m.export_encrypted_backup("passphrase").unwrap();
        let b2 = m.export_encrypted_backup("passphrase").unwrap();
        // Each export must draw fresh salt + nonce — nonce reuse breaks
        // XChaCha20-Poly1305 confidentiality.
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
