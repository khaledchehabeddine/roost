//! Passphrase-encrypted identity backup using Argon2id and XChaCha20-Poly1305.
//!
//! The backup is a self-describing envelope. A cleartext header carries the format version and
//! the Argon2id parameters and is authenticated as the AEAD associated data. An unknown version is
//! rejected before key derivation, and a work-factor parameter can't be altered without failing
//! decryption. The encrypted
//! body holds the identity-key halves followed by the verbatim discovery-key blob, which this
//! module treats as opaque so discovery-key versioning stays owned by `discovery_key.rs`.
//!
//! Envelope: `version(1) | m_cost(4) | t_cost(4) | p_cost(4) | salt(16) | nonce(24)`, then
//! `XChaCha20-Poly1305(aad = header, plaintext = ik_x25519(32) | ik_ed25519(32) | discovery_key_blob)`.

use super::{IDENTITY_CURRENT_KEY, IdentityError, IdentityManager, encode_identity_key_blob};
use argon2::{Argon2, Params};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::{CryptoRng, RngCore};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

const BACKUP_FORMAT_VERSION: u8 = 2;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = 1 + 4 + 4 + 4 + SALT_LEN + NONCE_LEN;
const IDENTITY_KEY_LEN: usize = 64;

// Argon2id memory cost is in KiB. Memory is the primary brute-force defense; time adds CPU work
// without raising memory use. Parameters travel in the header so future backups can raise the work
// factor, while the floors below refuse any read weaker than today's defaults.
const ARGON2_M_COST: u32 = 65536;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;
const ARGON2_OUTPUT_LEN: usize = 32;
// Normative read bounds. The floors are pinned to the OWASP Argon2id baseline (today's export
// defaults) and stay independent of ARGON2_M_COST/ARGON2_T_COST, so raising an export default never
// strands backups written by older builds. The ceilings bound a hostile or corrupt header: the
// header parametrizes the KDF and must be acted on before the AEAD tag can authenticate it, so an
// explicit range check is the only thing stopping an unbounded allocation on import.
const MIN_M_COST: u32 = 65536;
const MIN_T_COST: u32 = 3;
const MAX_M_COST: u32 = 1 << 20; // 1 GiB; generous headroom above the default for future increases.
const MAX_T_COST: u32 = 16;
// Export writes the defaults, so a default outside the import range would produce unreadable backups.
const _: () = assert!(
    ARGON2_M_COST >= MIN_M_COST
        && ARGON2_M_COST <= MAX_M_COST
        && ARGON2_T_COST >= MIN_T_COST
        && ARGON2_T_COST <= MAX_T_COST
);

// Decrypted backup contents: the identity-key halves and the opaque discovery-key blob.
type DecryptedBackup = (Zeroizing<[u8; IDENTITY_KEY_LEN]>, Zeroizing<Vec<u8>>);

impl IdentityManager {
    // Exports the current identity and the given discovery-key blob as an encrypted backup.
    pub(crate) fn export_encrypted_backup<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        passphrase: &str,
        discovery_key_blob: &[u8],
    ) -> Result<Vec<u8>, IdentityError> {
        let (x25519_bytes, ed25519_bytes) = self.load_identity_key_bytes()?;

        let mut plaintext = Zeroizing::new(Vec::with_capacity(
            IDENTITY_KEY_LEN + discovery_key_blob.len(),
        ));
        plaintext.extend_from_slice(&*x25519_bytes);
        plaintext.extend_from_slice(&*ed25519_bytes);
        plaintext.extend_from_slice(discovery_key_blob);

        let salt: [u8; SALT_LEN] = random_bytes(rng)?;
        let nonce_bytes: [u8; NONCE_LEN] = random_bytes(rng)?;
        let header = encode_header(
            ARGON2_M_COST,
            ARGON2_T_COST,
            ARGON2_P_COST,
            &salt,
            &nonce_bytes,
        );

        let key_bytes = derive_key(
            passphrase,
            &salt,
            ARGON2_M_COST,
            ARGON2_T_COST,
            ARGON2_P_COST,
        )?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&*key_bytes));
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext.as_slice(),
                    aad: &header,
                },
            )
            .map_err(|_| IdentityError::BackupEncryption)?;

        let mut backup = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        backup.extend_from_slice(&header);
        backup.extend_from_slice(&ciphertext);
        Ok(backup)
    }

    // Decrypts a backup blob into the identity-key halves and the opaque discovery-key blob.
    pub(crate) fn decrypt_backup(
        &self,
        data: &[u8],
        passphrase: &str,
    ) -> Result<DecryptedBackup, IdentityError> {
        if let Some(&version) = data.first()
            && version != BACKUP_FORMAT_VERSION
        {
            return Err(IdentityError::UnsupportedBackupVersion(version));
        }
        if data.len() < HEADER_LEN {
            return Err(IdentityError::BackupTooShort {
                len: data.len(),
                min_len: HEADER_LEN,
            });
        }
        let (header, ciphertext) = data.split_at(HEADER_LEN);
        let m_cost = read_u32(&header[1..5]);
        let t_cost = read_u32(&header[5..9]);
        let p_cost = read_u32(&header[9..13]);
        // Bound the work factor before spending Argon2id memory: the floor blocks downgrade, the
        // ceiling blocks an unauthenticated memory-exhaustion DoS from a hostile header.
        validate_import_argon2_params(m_cost, t_cost, p_cost)?;
        let salt = &header[13..13 + SALT_LEN];
        let nonce_bytes = &header[13 + SALT_LEN..HEADER_LEN];

        let key_bytes = derive_key(passphrase, salt, m_cost, t_cost, p_cost)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&*key_bytes));
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(nonce_bytes),
                    Payload {
                        msg: ciphertext,
                        aad: header,
                    },
                )
                .map_err(|_| IdentityError::DecryptionFailed)?,
        );

        let identity_key: [u8; IDENTITY_KEY_LEN] = plaintext
            .get(..IDENTITY_KEY_LEN)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(IdentityError::BackupPlaintextTooShort {
                len: plaintext.len(),
                min_len: IDENTITY_KEY_LEN,
            })?;
        let discovery_key_blob = Zeroizing::new(plaintext[IDENTITY_KEY_LEN..].to_vec());
        Ok((Zeroizing::new(identity_key), discovery_key_blob))
    }

    // Stores decrypted identity-key halves as one versioned blob.
    pub(crate) fn store_decrypted_identity(
        &self,
        identity_key: &[u8; IDENTITY_KEY_LEN],
    ) -> Result<(), IdentityError> {
        let (x25519, ed25519) = identity_key.split_at(32);
        let invalid_key_length = |half: &[u8]| IdentityError::InvalidKeyLength {
            expected: 32,
            actual: half.len(),
        };
        let x25519 = x25519.try_into().map_err(|_| invalid_key_length(x25519))?;
        let ed25519 = ed25519
            .try_into()
            .map_err(|_| invalid_key_length(ed25519))?;
        let blob = encode_identity_key_blob(x25519, ed25519);
        let mut storage = self.lock_storage()?;
        storage.store(IDENTITY_CURRENT_KEY, &*blob)?;
        Ok(())
    }
}

fn encode_header(
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    header[0] = BACKUP_FORMAT_VERSION;
    header[1..5].copy_from_slice(&m_cost.to_be_bytes());
    header[5..9].copy_from_slice(&t_cost.to_be_bytes());
    header[9..13].copy_from_slice(&p_cost.to_be_bytes());
    header[13..13 + SALT_LEN].copy_from_slice(salt);
    header[13 + SALT_LEN..].copy_from_slice(nonce);
    header
}

fn read_u32(bytes: &[u8]) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(bytes);
    u32::from_be_bytes(buf)
}

fn validate_import_argon2_params(
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<(), IdentityError> {
    if !(MIN_M_COST..=MAX_M_COST).contains(&m_cost)
        || !(MIN_T_COST..=MAX_T_COST).contains(&t_cost)
        || p_cost != ARGON2_P_COST
    {
        return Err(IdentityError::BackupParametersOutOfRange {
            memory_kib: m_cost,
            iterations: t_cost,
            parallelism: p_cost,
        });
    }
    Ok(())
}

// Salt and nonce come from the injected CSPRNG via the fallible `try_fill_bytes`, so an entropy
// failure surfaces as `BackupRandomness` rather than a panic.
fn random_bytes<const N: usize, R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Result<[u8; N], IdentityError> {
    let mut buf = [0u8; N];
    rng.try_fill_bytes(&mut buf)
        .map_err(IdentityError::BackupRandomness)?;
    Ok(buf)
}

fn derive_key(
    passphrase: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; ARGON2_OUTPUT_LEN]>, IdentityError> {
    // Normalize to canonical Unicode (NFC) so the same characters typed on any platform derive the
    // same key. The normalized copy is a heap secret, so wipe it on drop.
    let normalized: Zeroizing<String> = Zeroizing::new(passphrase.nfc().collect());
    let params = Params::new(m_cost, t_cost, p_cost, Some(ARGON2_OUTPUT_LEN))
        .map_err(IdentityError::BackupKeyDerivation)?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; ARGON2_OUTPUT_LEN]);
    argon2
        .hash_password_into(normalized.as_bytes(), salt, &mut *key)
        .map_err(IdentityError::BackupKeyDerivation)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::InMemorySecureStorage;
    use rand::rngs::OsRng;
    use std::sync::{Arc, Mutex};

    // An arbitrary opaque "discovery-key blob" — this module never inspects its bytes.
    const DK_BLOB: [u8; 8] = [0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8];

    fn manager() -> IdentityManager {
        IdentityManager::new(Arc::new(Mutex::new(Box::new(InMemorySecureStorage::new()))))
    }

    fn manager_with_identity() -> IdentityManager {
        let manager = manager();
        manager.generate_identity(&mut OsRng).unwrap();
        manager
    }

    #[test]
    fn export_backup_without_identity_returns_not_found() {
        let manager = manager();
        assert!(matches!(
            manager.export_encrypted_backup(&mut OsRng, "passphrase", &DK_BLOB),
            Err(IdentityError::NotFound)
        ));
    }

    #[test]
    fn each_export_uses_fresh_salt_and_nonce() {
        let manager = manager_with_identity();
        let first = manager
            .export_encrypted_backup(&mut OsRng, "passphrase", &DK_BLOB)
            .unwrap();
        let second = manager
            .export_encrypted_backup(&mut OsRng, "passphrase", &DK_BLOB)
            .unwrap();
        // Nonce reuse would break XChaCha20-Poly1305 confidentiality.
        assert_ne!(first, second);
    }

    #[test]
    fn export_decrypt_round_trip_recovers_identity_and_discovery_blob() {
        let manager = manager_with_identity();
        let (expected_x25519, expected_ed25519) = manager.load_identity_key_bytes().unwrap();
        let backup = manager
            .export_encrypted_backup(&mut OsRng, "passphrase", &DK_BLOB)
            .unwrap();

        let (identity_key, discovery_key_blob) =
            manager.decrypt_backup(&backup, "passphrase").unwrap();
        assert_eq!(&identity_key[..32], &*expected_x25519);
        assert_eq!(&identity_key[32..], &*expected_ed25519);
        assert_eq!(discovery_key_blob.as_slice(), &DK_BLOB);
    }

    #[test]
    fn decrypt_backup_rejects_data_shorter_than_header() {
        let manager = manager();
        let mut short = [0u8; 10];
        short[0] = BACKUP_FORMAT_VERSION;
        assert!(matches!(
            manager.decrypt_backup(&short, "passphrase"),
            Err(IdentityError::BackupTooShort {
                len: 10,
                min_len: HEADER_LEN
            })
        ));
    }

    #[test]
    fn decrypt_backup_rejects_parameters_below_floor() {
        let manager = manager_with_identity();
        let backup = manager
            .export_encrypted_backup(&mut OsRng, "passphrase", &DK_BLOB)
            .unwrap();
        // m_cost and t_cost fail below their floor; p_cost must equal 1, so any other value fails.
        for (header_offset, weakened_value) in [(1usize, 1u32), (5, 1), (9, 2)] {
            let mut weakened = backup.clone();
            weakened[header_offset..header_offset + 4]
                .copy_from_slice(&weakened_value.to_be_bytes());
            assert!(
                matches!(
                    manager.decrypt_backup(&weakened, "passphrase"),
                    Err(IdentityError::BackupParametersOutOfRange { .. })
                ),
                "header offset {header_offset} should fail the work-factor floor"
            );
        }
    }

    #[test]
    fn decrypt_backup_rejects_parameters_above_ceiling() {
        let manager = manager_with_identity();
        let backup = manager
            .export_encrypted_backup(&mut OsRng, "passphrase", &DK_BLOB)
            .unwrap();
        // An oversized m_cost or t_cost must be rejected before Argon2id allocates, so a hostile
        // header cannot exhaust memory on import.
        for (header_offset, oversized_value) in [(1usize, u32::MAX), (5, MAX_T_COST + 1)] {
            let mut oversized = backup.clone();
            oversized[header_offset..header_offset + 4]
                .copy_from_slice(&oversized_value.to_be_bytes());
            assert!(
                matches!(
                    manager.decrypt_backup(&oversized, "passphrase"),
                    Err(IdentityError::BackupParametersOutOfRange { .. })
                ),
                "header offset {header_offset} should fail the work-factor ceiling"
            );
        }
    }

    #[test]
    fn decrypt_backup_rejects_tampered_in_range_kdf_metadata() {
        let manager = manager_with_identity();
        let mut backup = manager
            .export_encrypted_backup(&mut OsRng, "passphrase", &DK_BLOB)
            .unwrap();
        backup[5..9].copy_from_slice(&(ARGON2_T_COST + 1).to_be_bytes());
        assert!(matches!(
            manager.decrypt_backup(&backup, "passphrase"),
            Err(IdentityError::DecryptionFailed)
        ));
    }

    #[test]
    fn decrypt_backup_rejects_tampered_header_field() {
        let manager = manager_with_identity();
        let backup = manager
            .export_encrypted_backup(&mut OsRng, "passphrase", &DK_BLOB)
            .unwrap();
        // Flip a salt byte: the header is the AEAD associated data, so authentication must fail.
        let mut tampered = backup.clone();
        tampered[13] ^= 0x01;
        assert!(matches!(
            manager.decrypt_backup(&tampered, "passphrase"),
            Err(IdentityError::DecryptionFailed)
        ));
    }

    #[test]
    fn decrypt_backup_with_wrong_passphrase_returns_decryption_failed() {
        let manager = manager_with_identity();
        let backup = manager
            .export_encrypted_backup(&mut OsRng, "correct-passphrase", &DK_BLOB)
            .unwrap();
        assert!(matches!(
            manager.decrypt_backup(&backup, "wrong-passphrase"),
            Err(IdentityError::DecryptionFailed)
        ));
    }

    #[test]
    fn decrypt_backup_wrong_passphrase_error_formats_are_redacted() {
        let manager = manager_with_identity();
        let backup = manager
            .export_encrypted_backup(&mut OsRng, "correct-passphrase", &DK_BLOB)
            .unwrap();
        let err = manager
            .decrypt_backup(&backup, "wrong-passphrase-secret")
            .unwrap_err();
        let display = err.to_string();
        let debug = format!("{err:?}");

        assert!(!display.contains("wrong-passphrase-secret"));
        assert!(!debug.contains("wrong-passphrase-secret"));
        assert!(!display.contains("correct-passphrase"));
        assert!(!debug.contains("correct-passphrase"));
        assert!(!display.contains("D1"));
        assert!(!debug.contains("D1"));
        assert!(!display.contains("backup plaintext"));
        assert!(!debug.contains("backup plaintext"));
    }

    #[test]
    fn decrypt_backup_tampered_ciphertext_error_formats_are_redacted() {
        let manager = manager_with_identity();
        let mut backup = manager
            .export_encrypted_backup(&mut OsRng, "correct-passphrase", &DK_BLOB)
            .unwrap();
        let last = backup.len() - 1;
        backup[last] ^= 0xAA;

        let err = manager
            .decrypt_backup(&backup, "correct-passphrase")
            .unwrap_err();
        let display = err.to_string();
        let debug = format!("{err:?}");

        assert!(!display.contains("correct-passphrase"));
        assert!(!debug.contains("correct-passphrase"));
        assert!(!display.contains("D1"));
        assert!(!debug.contains("D1"));
        assert!(!display.contains("backup plaintext"));
        assert!(!debug.contains("backup plaintext"));
    }

    #[test]
    fn normalization_form_does_not_change_derived_key() {
        let manager = manager_with_identity();
        // U+00E9 (é, NFC) and "e" + U+0301 (combining acute, NFD) normalize to the same key.
        let backup = manager
            .export_encrypted_backup(&mut OsRng, "caf\u{00e9}", &DK_BLOB)
            .unwrap();
        assert!(manager.decrypt_backup(&backup, "cafe\u{0301}").is_ok());
    }

    #[test]
    fn argon2id_derive_key_is_deterministic() {
        let salt = [0x00u8; SALT_LEN];
        let first = derive_key(
            "passphrase",
            &salt,
            ARGON2_M_COST,
            ARGON2_T_COST,
            ARGON2_P_COST,
        );
        let second = derive_key(
            "passphrase",
            &salt,
            ARGON2_M_COST,
            ARGON2_T_COST,
            ARGON2_P_COST,
        );
        assert_eq!(*first.unwrap(), *second.unwrap());
    }

    #[test]
    fn argon2id_different_passphrases_produce_different_keys() {
        let salt = [0x01u8; SALT_LEN];
        let first = derive_key(
            "passphrase-one",
            &salt,
            ARGON2_M_COST,
            ARGON2_T_COST,
            ARGON2_P_COST,
        );
        let second = derive_key(
            "passphrase-two",
            &salt,
            ARGON2_M_COST,
            ARGON2_T_COST,
            ARGON2_P_COST,
        );
        assert_ne!(*first.unwrap(), *second.unwrap());
    }
}
