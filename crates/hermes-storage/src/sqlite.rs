use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use std::str::FromStr;
use zeroize::Zeroizing;

use crate::{SecureStorage, StorageError};

/// A SQLite-backed [`SecureStorage`] implementation.
///
/// Owns a single-threaded async runtime and a capped connection pool to bridge
/// sqlx's async API to the synchronous [`SecureStorage`] trait.
pub struct SqliteSecureStorage {
    pool: sqlx::SqlitePool,
    rt: tokio::runtime::Runtime,
}

impl SqliteSecureStorage {
    /// Opens (or creates) a SQLite database at `url` and runs pending migrations.
    ///
    /// `url` must be a valid SQLite connection string, e.g. `"sqlite:/path/to/db"` or
    /// `"sqlite::memory:"`.
    pub fn open(url: &str) -> Result<Self, StorageError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| StorageError::IO(e.to_string()))?;

        let opts = SqliteConnectOptions::from_str(url)
            .map_err(|e| StorageError::IO(e.to_string()))?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal);

        let pool = rt
            .block_on(
                SqlitePoolOptions::new()
                    .max_connections(1)
                    .connect_with(opts),
            )
            .map_err(|e| StorageError::IO(e.to_string()))?;

        rt.block_on(sqlx::migrate!("./migrations").run(&pool))
            .map_err(|e| StorageError::IO(e.to_string()))?;

        Ok(Self { pool, rt })
    }
}

impl SecureStorage for SqliteSecureStorage {
    fn store(&mut self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        self.rt
            .block_on(
                sqlx::query!(
                    "INSERT OR REPLACE INTO storage (key, value) VALUES (?, ?)",
                    key,
                    value
                )
                .execute(&self.pool),
            )
            .map(|_| ())
            .map_err(|e| StorageError::IO(e.to_string()))
    }

    fn load(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
        self.rt
            .block_on(
                sqlx::query!("SELECT value FROM storage WHERE key = ?", key)
                    .fetch_optional(&self.pool),
            )
            .map(|opt| opt.map(|row| Zeroizing::new(row.value)))
            .map_err(|e| StorageError::IO(e.to_string()))
    }

    fn delete(&mut self, key: &str) -> Result<(), StorageError> {
        self.rt
            .block_on(sqlx::query!("DELETE FROM storage WHERE key = ?", key).execute(&self.pool))
            .map(|_| ())
            .map_err(|e| StorageError::IO(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use hermes_crypto::generate_key_pair;

    use super::*;

    fn storage() -> SqliteSecureStorage {
        SqliteSecureStorage::open("sqlite::memory:").unwrap()
    }

    #[test]
    fn round_trips_keypair_through_sqlite() {
        let mut s = storage();
        let kp = generate_key_pair();
        let secret_bytes = *kp.to_secret_bytes();

        s.store("identity/x25519", &secret_bytes).unwrap();

        let loaded = s.load("identity/x25519").unwrap().unwrap();
        let arr: [u8; 32] = loaded.as_slice().try_into().unwrap();
        let restored = hermes_crypto::KeyPair::from_secret_bytes(arr);
        assert_eq!(kp.public.as_bytes(), restored.public.as_bytes());
    }
}
