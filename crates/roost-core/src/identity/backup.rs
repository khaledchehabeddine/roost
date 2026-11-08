use super::{Identity, IdentityError, IdentityManager, IdentitySecretsWire};
use crate::stored_data::{
    decode_exact, decode_versioned_prefix, encode_versioned, encode_zeroizing,
};
use argon2::{Argon2, Params};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;
use zeroize::{ZeroizeOnDrop, Zeroizing};

const BACKUP_FORMAT_VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;

// Argon2id's memory, in KiB, is the main defense against guessing, and iterations add work without
// raising memory use. The header carries the costs, so a later build can raise them.
const DEFAULT_MEMORY_KIB: u32 = 65536;
const DEFAULT_ITERATIONS: u32 = 3;
const PARALLELISM: u32 = 1;
const ARGON2_OUTPUT_LEN: usize = 32;
// The lowest costs a backup may name, fixed apart from the defaults, so raising a default never
// strands an older backup.
const MIN_MEMORY_KIB: u32 = 65536;
const MIN_ITERATIONS: u32 = 3;
// The highest costs a backup may name. Roost acts on the header before the cipher authenticates
// it, so these bound the memory a forged header can make it allocate.
const MAX_MEMORY_KIB: u32 = 1 << 20;
const MAX_ITERATIONS: u32 = 16;
// Export writes the defaults, so a default outside the import range would produce unreadable
// backups.
const _: () = assert!(
    DEFAULT_MEMORY_KIB >= MIN_MEMORY_KIB
        && DEFAULT_MEMORY_KIB <= MAX_MEMORY_KIB
        && DEFAULT_ITERATIONS >= MIN_ITERATIONS
        && DEFAULT_ITERATIONS <= MAX_ITERATIONS
);

#[derive(Deserialize, Serialize)]
struct BackupHeaderWire {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
}

#[derive(Serialize)]
struct BackupContentsWire<'a> {
    identity: IdentitySecretsWire,
    discovery_key: &'a [u8],
}

#[derive(Deserialize, ZeroizeOnDrop)]
struct DecodedBackupContentsWire {
    identity: IdentitySecretsWire,
    discovery_key: Vec<u8>,
}

impl IdentityManager {
    pub(crate) fn export_encrypted_backup<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        passphrase: &str,
        discovery_key_entry: &[u8],
    ) -> Result<Vec<u8>, IdentityError> {
        let contents = encode_zeroizing(&BackupContentsWire {
            identity: self.load_secrets()?,
            discovery_key: discovery_key_entry,
        })
        .map_err(IdentityError::BackupFormat)?;
        let header = BackupHeaderWire {
            memory_kib: DEFAULT_MEMORY_KIB,
            iterations: DEFAULT_ITERATIONS,
            parallelism: PARALLELISM,
            salt: random_bytes(rng)?,
            nonce: random_bytes(rng)?,
        };
        let associated_data = encode_versioned(BACKUP_FORMAT_VERSION, &header)
            .map_err(IdentityError::BackupFormat)?;

        let key_bytes = derive_key(
            passphrase,
            &header.salt,
            header.memory_kib,
            header.iterations,
            header.parallelism,
        )?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&*key_bytes));
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&header.nonce),
                Payload {
                    msg: &contents,
                    aad: &associated_data,
                },
            )
            .map_err(|_| IdentityError::BackupEncryption)?;

        let mut backup = Vec::with_capacity(associated_data.len() + ciphertext.len());
        backup.extend_from_slice(&associated_data);
        backup.extend_from_slice(&ciphertext);
        Ok(backup)
    }
}

// Returns the discovery key entry undecoded, so `discovery_key.rs` keeps owning its version.
pub(crate) fn decrypt_backup(
    data: &[u8],
    passphrase: &str,
) -> Result<(Identity, Zeroizing<Vec<u8>>), IdentityError> {
    let (header, ciphertext): (BackupHeaderWire, &[u8]) =
        decode_versioned_prefix(BACKUP_FORMAT_VERSION, data)
            .map_err(IdentityError::BackupFormat)?;
    // Check the costs before Argon2id spends memory on them. The floor blocks a downgrade.
    validate_import_argon2_params(header.memory_kib, header.iterations, header.parallelism)?;
    let associated_data = &data[..data.len() - ciphertext.len()];

    let key_bytes = derive_key(
        passphrase,
        &header.salt,
        header.memory_kib,
        header.iterations,
        header.parallelism,
    )?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&*key_bytes));
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&header.nonce),
                Payload {
                    msg: ciphertext,
                    aad: associated_data,
                },
            )
            .map_err(|_| IdentityError::DecryptionFailed)?,
    );
    let mut contents: DecodedBackupContentsWire =
        decode_exact(&plaintext).map_err(IdentityError::BackupFormat)?;
    Ok((
        Identity::from_wire(&contents.identity),
        Zeroizing::new(std::mem::take(&mut contents.discovery_key)),
    ))
}

fn validate_import_argon2_params(
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<(), IdentityError> {
    if !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&memory_kib)
        || !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations)
        || parallelism != PARALLELISM
    {
        return Err(IdentityError::BackupParametersOutOfRange {
            memory_kib,
            iterations,
            parallelism,
        });
    }
    Ok(())
}

// Draws with the fallible `try_fill_bytes`, so a failing generator returns `BackupRandomness`
// instead of panicking.
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
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Zeroizing<[u8; ARGON2_OUTPUT_LEN]>, IdentityError> {
    // Normalize to canonical Unicode (NFC) so the same characters typed on any platform derive the
    // same key. The normalized copy is a heap secret, so wipe it on drop.
    let normalized: Zeroizing<String> = Zeroizing::new(passphrase.nfc().collect());
    let params = Params::new(memory_kib, iterations, parallelism, Some(ARGON2_OUTPUT_LEN))
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
    use crate::stored_data::StoredDataError;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::sync::{Arc, Mutex};

    // An arbitrary opaque discovery key entry, since this module never inspects its bytes.
    const DISCOVERY_KEY_ENTRY: [u8; 8] = [0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8];

    fn manager() -> IdentityManager {
        IdentityManager::new(Arc::new(Mutex::new(Box::new(InMemorySecureStorage::new()))))
    }

    fn manager_with_identity() -> IdentityManager {
        let mut rng = ChaCha20Rng::from_seed([0x70; 32]);
        let manager = manager();
        manager.generate_identity(&mut rng).unwrap();
        manager
    }

    fn export(manager: &IdentityManager, seed: u8, passphrase: &str) -> Vec<u8> {
        manager
            .export_encrypted_backup(
                &mut ChaCha20Rng::from_seed([seed; 32]),
                passphrase,
                &DISCOVERY_KEY_ENTRY,
            )
            .unwrap()
    }

    // Returns `backup` with its header changed by `change` and its ciphertext kept.
    fn with_header(backup: &[u8], change: impl FnOnce(&mut BackupHeaderWire)) -> Vec<u8> {
        let (mut header, ciphertext): (BackupHeaderWire, &[u8]) =
            decode_versioned_prefix(BACKUP_FORMAT_VERSION, backup).unwrap();
        change(&mut header);
        let mut changed = encode_versioned(BACKUP_FORMAT_VERSION, &header)
            .unwrap()
            .to_vec();
        changed.extend_from_slice(ciphertext);
        changed
    }

    #[test]
    fn export_backup_without_identity_returns_not_found() {
        let mut rng = ChaCha20Rng::from_seed([0x71; 32]);
        let manager = manager();
        assert!(matches!(
            manager.export_encrypted_backup(&mut rng, "passphrase", &DISCOVERY_KEY_ENTRY),
            Err(IdentityError::NotFound)
        ));
    }

    #[test]
    fn each_export_uses_fresh_salt_and_nonce() {
        let mut rng = ChaCha20Rng::from_seed([0x72; 32]);
        let manager = manager_with_identity();
        let first = manager
            .export_encrypted_backup(&mut rng, "passphrase", &DISCOVERY_KEY_ENTRY)
            .unwrap();
        let second = manager
            .export_encrypted_backup(&mut rng, "passphrase", &DISCOVERY_KEY_ENTRY)
            .unwrap();
        // Nonce reuse would break XChaCha20-Poly1305 confidentiality.
        assert_ne!(first, second);
    }

    #[test]
    fn export_decrypt_round_trip_recovers_identity_and_discovery_key_entry() {
        let manager = manager_with_identity();
        let expected = manager.load_identity().unwrap();
        let backup = export(&manager, 0x73, "passphrase");
        let (identity, discovery_key_entry) = decrypt_backup(&backup, "passphrase").unwrap();
        assert_eq!(identity.public_key(), expected.public_key());
        assert_eq!(identity.verifying_key(), expected.verifying_key());
        assert_eq!(discovery_key_entry.as_slice(), &DISCOVERY_KEY_ENTRY);
    }

    #[test]
    fn decrypt_backup_rejects_an_unknown_version_before_its_header() {
        assert!(matches!(
            decrypt_backup(&[BACKUP_FORMAT_VERSION + 1], "passphrase"),
            Err(IdentityError::BackupFormat(StoredDataError::UnsupportedVersion { version }))
                if version == BACKUP_FORMAT_VERSION + 1
        ));
    }

    #[test]
    fn decrypt_backup_rejects_a_truncated_header() {
        let backup = export(&manager_with_identity(), 0x75, "passphrase");
        assert!(matches!(
            decrypt_backup(&backup[..10], "passphrase"),
            Err(IdentityError::BackupFormat(StoredDataError::Decode(_)))
        ));
    }

    #[test]
    fn decrypt_backup_rejects_parameters_outside_their_bounds() {
        let backup = export(&manager_with_identity(), 0x74, "passphrase");
        // Oversized memory or iterations must fail before Argon2id allocates, so a forged header
        // can't exhaust memory.
        let changes: [fn(&mut BackupHeaderWire); 5] = [
            |header| header.memory_kib = 1,
            |header| header.iterations = 1,
            |header| header.parallelism = 2,
            |header| header.memory_kib = u32::MAX,
            |header| header.iterations = MAX_ITERATIONS + 1,
        ];
        for change in changes {
            let (mut header, _): (BackupHeaderWire, &[u8]) =
                decode_versioned_prefix(BACKUP_FORMAT_VERSION, &backup).unwrap();
            change(&mut header);
            assert!(matches!(
                decrypt_backup(&with_header(&backup, change), "passphrase"),
                Err(IdentityError::BackupParametersOutOfRange { memory_kib, iterations, parallelism })
                    if (memory_kib, iterations, parallelism)
                        == (header.memory_kib, header.iterations, header.parallelism)
            ));
        }
    }

    #[test]
    fn decrypt_backup_rejects_tampered_in_range_kdf_metadata() {
        let backup = export(&manager_with_identity(), 0x76, "passphrase");
        let tampered = with_header(&backup, |header| header.iterations = DEFAULT_ITERATIONS + 1);
        assert!(matches!(
            decrypt_backup(&tampered, "passphrase"),
            Err(IdentityError::DecryptionFailed)
        ));
    }

    #[test]
    fn decrypt_backup_rejects_tampered_header_field() {
        let backup = export(&manager_with_identity(), 0x77, "passphrase");
        // The header is the AEAD associated data, so changing the salt must fail authentication.
        let tampered = with_header(&backup, |header| header.salt[0] ^= 0x01);
        assert!(matches!(
            decrypt_backup(&tampered, "passphrase"),
            Err(IdentityError::DecryptionFailed)
        ));
    }

    #[test]
    fn decrypt_backup_wrong_passphrase_error_formats_are_redacted() {
        let backup = export(&manager_with_identity(), 0x79, "correct-passphrase");
        let err = decrypt_backup(&backup, "wrong-passphrase-secret")
            .err()
            .unwrap();
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
        let mut backup = export(&manager_with_identity(), 0x7a, "correct-passphrase");
        let last = backup.len() - 1;
        backup[last] ^= 0xAA;

        let err = decrypt_backup(&backup, "correct-passphrase").err().unwrap();
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
    fn argon2id_different_passphrases_produce_different_keys() {
        let salt = [0x01u8; SALT_LEN];
        let first = derive_key(
            "passphrase-one",
            &salt,
            DEFAULT_MEMORY_KIB,
            DEFAULT_ITERATIONS,
            PARALLELISM,
        );
        let second = derive_key(
            "passphrase-two",
            &salt,
            DEFAULT_MEMORY_KIB,
            DEFAULT_ITERATIONS,
            PARALLELISM,
        );
        assert_ne!(*first.unwrap(), *second.unwrap());
    }

    // Uses costs far below the import floor, which only the import path enforces, to stay fast.
    #[test]
    fn argon2id_key_changes_with_the_salt_and_each_cost() {
        const MEMORY_KIB: u32 = 64;
        const ITERATIONS: u32 = 1;
        let salt = [0x01u8; SALT_LEN];
        let key = |salt: &[u8], memory_kib, iterations, parallelism| {
            *derive_key("passphrase", salt, memory_kib, iterations, parallelism).unwrap()
        };
        let expected = key(&salt, MEMORY_KIB, ITERATIONS, PARALLELISM);

        for changed in [
            key(&[0x02; SALT_LEN], MEMORY_KIB, ITERATIONS, PARALLELISM),
            key(&salt, MEMORY_KIB + 1, ITERATIONS, PARALLELISM),
            key(&salt, MEMORY_KIB, ITERATIONS + 1, PARALLELISM),
            key(&salt, MEMORY_KIB, ITERATIONS, PARALLELISM + 1),
        ] {
            assert_ne!(changed, expected);
        }
    }
}
