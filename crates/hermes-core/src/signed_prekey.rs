use crate::identity::{IdentityError, IdentityManager};
use crate::storage::{SecureStorage, StorageError};
use hermes_crypto::{SignedPreKey, SignedPreKeyBundle, generate_signed_prekey};
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

pub(crate) const SPK_ROTATION_WINDOW_DAYS: u64 = 7;

const SPK_KEY: &str = "prekey/signed";
const SPK_VERSION: u8 = 1;
/// `[version(1) | secret(32) | signature(64) | created_at(8)]`
const SPK_BLOB_LEN: usize = 1 + 32 + 64 + 8;
const SECONDS_PER_DAY: u64 = 86_400;
/// Defends against clock-manipulation that would otherwise freeze rotation forever.
const FUTURE_TIMESTAMP_TOLERANCE_SECS: u64 = 30 * SECONDS_PER_DAY;

/// Errors returned by [`SignedPreKeyManager`] operations.
#[derive(Debug)]
pub enum SignedPreKeyError {
    /// System clock is before the Unix epoch — the timestamp arithmetic for SPK rotation cannot
    /// proceed.
    Clock,
    /// SPK rotation requires loading the identity's signing key. Wraps the identity's error.
    Identity(IdentityError),
    /// Stored SPK blob is malformed (wrong length or unsupported version). Inner string
    /// describes the reason.
    InvalidData(String),
    /// The internal storage lock was poisoned by a panicked thread.
    LockPoisoned,
    /// The underlying [`SecureStorage`] returned an error.
    Storage(StorageError),
}

impl fmt::Display for SignedPreKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignedPreKeyError::Clock => write!(f, "system clock is before Unix epoch"),
            SignedPreKeyError::Identity(e) => write!(f, "identity: {e}"),
            SignedPreKeyError::InvalidData(reason) => write!(f, "invalid SPK data: {reason}"),
            SignedPreKeyError::LockPoisoned => write!(f, "internal lock poisoned"),
            SignedPreKeyError::Storage(e) => write!(f, "storage: {e}"),
        }
    }
}

impl Error for SignedPreKeyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            SignedPreKeyError::Identity(e) => Some(e),
            SignedPreKeyError::Storage(e) => Some(e),
            _ => None,
        }
    }
}

impl From<IdentityError> for SignedPreKeyError {
    fn from(e: IdentityError) -> Self {
        SignedPreKeyError::Identity(e)
    }
}

impl From<StorageError> for SignedPreKeyError {
    fn from(e: StorageError) -> Self {
        SignedPreKeyError::Storage(e)
    }
}

/// Manages the local signed pre-key — generation, rotation, and persistence via
/// [`SecureStorage`].
///
/// Holds a shared handle to the [`IdentityManager`] (whose Ed25519 signing key signs each new
/// SPK). Cheap to clone — internally an `Arc`.
pub struct SignedPreKeyManager {
    storage: Arc<Mutex<Box<dyn SecureStorage>>>,
    identity: Arc<IdentityManager>,
}

impl SignedPreKeyManager {
    /// Constructs a manager backed by the given storage and identity manager. Cheap — no I/O.
    pub fn new(
        storage: Arc<Mutex<Box<dyn SecureStorage>>>,
        identity: Arc<IdentityManager>,
    ) -> Self {
        SignedPreKeyManager { storage, identity }
    }

    /// Loads the current [`SignedPreKey`] from storage. Internal — exposes the secret-bearing
    /// type, so consumers should use [`Self::current_bundle`] instead.
    ///
    /// # Errors
    /// - [`SignedPreKeyError::InvalidData`] if no SPK is stored — call
    ///   [`Self::rotate_if_stale`] first.
    /// - [`SignedPreKeyError::Storage`] on platform storage failure.
    /// - [`SignedPreKeyError::LockPoisoned`] on storage lock poisoning.
    pub(crate) fn current(&self) -> Result<SignedPreKey, SignedPreKeyError> {
        let storage = self.lock_storage()?;
        let raw = storage
            .load(SPK_KEY)?
            .ok_or_else(|| SignedPreKeyError::InvalidData("no signed prekey present".into()))?;
        Ok(decode_spk(checked_blob(&raw)?))
    }

    /// Returns the public form of the current [`SignedPreKey`] for distribution to peers.
    ///
    /// # Errors
    /// - [`SignedPreKeyError::InvalidData`] if no SPK is stored, the stored blob has the wrong
    ///   length, or its version byte is unsupported. Call
    ///   [`crate::KeyStore::rotate_signed_prekey_if_stale`] first to seed one.
    /// - [`SignedPreKeyError::Storage`] on platform storage failure.
    /// - [`SignedPreKeyError::LockPoisoned`] on storage lock poisoning.
    pub fn current_bundle(&self) -> Result<SignedPreKeyBundle, SignedPreKeyError> {
        Ok(self.current()?.bundle())
    }

    /// Returns the freshly-rotated SPK if rotation occurred, or `None` if the stored SPK is still
    /// fresh. Lets callers conditionally upload the new bundle to peers without re-fetching.
    ///
    /// Timestamp policy:
    /// - Missing → rotate.
    /// - More than [`FUTURE_TIMESTAMP_TOLERANCE_SECS`] ahead of now → rotate.
    /// - Slightly ahead of now → keep (small clock skew tolerance).
    /// - Older than [`SPK_ROTATION_WINDOW_DAYS`] → rotate.
    ///
    /// Wrong blob length or version surfaces `InvalidData` rather than silently overwrite.
    ///
    /// # Errors
    /// - [`SignedPreKeyError::Identity`] (`NotFound` / `Corrupt` / `InvalidData`) when loading
    ///   the identity fails (only when rotation is required).
    /// - [`SignedPreKeyError::InvalidData`] if the stored SPK has wrong length or version.
    /// - [`SignedPreKeyError::Storage`] on platform storage failure.
    /// - [`SignedPreKeyError::Clock`] if the system clock is before the Unix epoch.
    /// - [`SignedPreKeyError::LockPoisoned`] on storage lock poisoning.
    pub(crate) fn rotate_if_stale(&self) -> Result<Option<SignedPreKey>, SignedPreKeyError> {
        let now = now_secs()?;
        let needs_rotation = match self.read_stored_created_at()? {
            None => true,
            Some(ts) if ts > now + FUTURE_TIMESTAMP_TOLERANCE_SECS => true,
            Some(ts) if ts > now => false,
            Some(ts) => now - ts > SPK_ROTATION_WINDOW_DAYS * SECONDS_PER_DAY,
        };
        if needs_rotation {
            Ok(Some(self.rotate_now()?))
        } else {
            Ok(None)
        }
    }

    /// Applications should use [`crate::KeyStore::reset`] — it clears identity and SPK together.
    pub(crate) fn reset(&self) -> Result<(), SignedPreKeyError> {
        let mut storage = self.lock_storage()?;
        Ok(storage.delete(SPK_KEY)?)
    }

    /// Forces an immediate SPK rotation. Atomic via a single [`SecureStorage::store`] call —
    /// no partial-write window.
    ///
    /// # Errors
    /// - [`SignedPreKeyError::Identity`] (`NotFound` / `Corrupt` / `InvalidData`) when loading
    ///   the identity fails.
    /// - [`SignedPreKeyError::Storage`] on platform storage failure.
    /// - [`SignedPreKeyError::Clock`] if the system clock is before the Unix epoch.
    /// - [`SignedPreKeyError::LockPoisoned`] on storage lock poisoning.
    pub(crate) fn rotate_now(&self) -> Result<SignedPreKey, SignedPreKeyError> {
        let identity = self.identity.load_identity()?;
        let now = now_secs()?;
        let spk = generate_signed_prekey(identity.signing_key_pair(), now);
        let blob = encode_spk(&spk);
        let mut storage = self.lock_storage()?;
        storage.store(SPK_KEY, &*blob)?;
        Ok(spk)
    }

    fn read_stored_created_at(&self) -> Result<Option<u64>, SignedPreKeyError> {
        let storage = self.lock_storage()?;
        let Some(raw) = storage.load(SPK_KEY)? else {
            return Ok(None);
        };
        let blob = checked_blob(&raw)?;
        let mut ts_bytes = [0u8; 8];
        ts_bytes.copy_from_slice(&blob[97..SPK_BLOB_LEN]);
        Ok(Some(u64::from_be_bytes(ts_bytes)))
    }

    fn lock_storage(&self) -> Result<MutexGuard<'_, Box<dyn SecureStorage>>, SignedPreKeyError> {
        self.storage
            .lock()
            .map_err(|_| SignedPreKeyError::LockPoisoned)
    }
}

fn encode_spk(spk: &SignedPreKey) -> Zeroizing<[u8; SPK_BLOB_LEN]> {
    let mut buf = Zeroizing::new([0u8; SPK_BLOB_LEN]);
    buf[0] = SPK_VERSION;
    buf[1..33].copy_from_slice(&*spk.to_secret_bytes());
    buf[33..97].copy_from_slice(&spk.signature().to_bytes());
    buf[97..SPK_BLOB_LEN].copy_from_slice(&spk.created_at().to_be_bytes());
    buf
}

fn decode_spk(blob: &[u8; SPK_BLOB_LEN]) -> SignedPreKey {
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&blob[1..33]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[33..97]);
    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&blob[97..SPK_BLOB_LEN]);
    let created_at = u64::from_be_bytes(ts_bytes);
    SignedPreKey::from_secret_bytes(secret, signature, created_at)
}

fn checked_blob(raw: &[u8]) -> Result<&[u8; SPK_BLOB_LEN], SignedPreKeyError> {
    let blob: &[u8; SPK_BLOB_LEN] = raw.try_into().map_err(|_| {
        SignedPreKeyError::InvalidData(format!("expected {SPK_BLOB_LEN} bytes, got {}", raw.len()))
    })?;
    if blob[0] != SPK_VERSION {
        return Err(SignedPreKeyError::InvalidData(format!(
            "unsupported SPK format version: {}",
            blob[0]
        )));
    }
    Ok(blob)
}

fn now_secs() -> Result<u64, SignedPreKeyError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| SignedPreKeyError::Clock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::InMemorySecureStorage;
    use hermes_crypto::{generate_signing_key_pair, verify_bundle};

    fn shared_storage() -> Arc<Mutex<Box<dyn SecureStorage>>> {
        Arc::new(Mutex::new(Box::new(InMemorySecureStorage::new())))
    }

    fn manager_with_identity() -> SignedPreKeyManager {
        let storage = shared_storage();
        let identity = Arc::new(IdentityManager::new(Arc::clone(&storage)));
        identity.generate_identity().unwrap();
        SignedPreKeyManager::new(storage, identity)
    }

    fn manager_no_identity() -> SignedPreKeyManager {
        let storage = shared_storage();
        let identity = Arc::new(IdentityManager::new(Arc::clone(&storage)));
        SignedPreKeyManager::new(storage, identity)
    }

    #[test]
    fn current_without_stored_spk_returns_invalid_data() {
        let manager = manager_with_identity();
        assert!(matches!(
            manager.current(),
            Err(SignedPreKeyError::InvalidData(_))
        ));
    }

    #[test]
    fn current_returns_invalid_data_for_corrupt_blob() {
        let manager = manager_with_identity();
        manager
            .storage
            .lock()
            .unwrap()
            .store(SPK_KEY, &[0xAAu8; 50])
            .unwrap();
        assert!(matches!(
            manager.current(),
            Err(SignedPreKeyError::InvalidData(_))
        ));
    }

    #[test]
    fn current_bundle_does_not_require_identity() {
        let manager = manager_no_identity();
        let identity_signing = generate_signing_key_pair();
        let spk = generate_signed_prekey(&identity_signing, 1_700_000_000);
        let blob = encode_spk(&spk);
        manager
            .storage
            .lock()
            .unwrap()
            .store(SPK_KEY, &*blob)
            .unwrap();

        let bundle = manager.current_bundle().unwrap();
        assert_eq!(bundle.public_key.as_bytes(), spk.public().as_bytes());
    }

    #[test]
    fn rotate_if_stale_seeds_first_spk() {
        let manager = manager_with_identity();
        let rotated = manager.rotate_if_stale().unwrap().expect("first call must rotate");
        let bundle = manager.current_bundle().unwrap();
        assert_eq!(
            rotated.public().as_bytes(),
            bundle.public_key.as_bytes(),
            "returned SPK must match persisted bundle",
        );
        let identity = manager.identity.load_identity().unwrap();
        assert!(verify_bundle(&bundle, identity.verifying_key()).is_ok());
    }

    #[test]
    fn rotate_if_stale_keeps_fresh_spk() {
        let manager = manager_with_identity();
        assert!(manager.rotate_if_stale().unwrap().is_some());
        let first = manager.current_bundle().unwrap().public_key;
        let second_call = manager.rotate_if_stale().unwrap();
        assert!(second_call.is_none(), "fresh SPK must not rotate");
        let second = manager.current_bundle().unwrap().public_key;
        assert_eq!(first.as_bytes(), second.as_bytes());
    }

    #[test]
    fn rotate_if_stale_replaces_backdated_spk() {
        let manager = manager_with_identity();
        manager.rotate_if_stale().unwrap();
        let original_pk = manager.current_bundle().unwrap().public_key;

        let identity = manager.identity.load_identity().unwrap();
        let backdated_ts = now_secs().unwrap() - (SPK_ROTATION_WINDOW_DAYS + 1) * SECONDS_PER_DAY;
        let stale = generate_signed_prekey(identity.signing_key_pair(), backdated_ts);
        let blob = encode_spk(&stale);
        manager
            .storage
            .lock()
            .unwrap()
            .store(SPK_KEY, &*blob)
            .unwrap();

        let rotated = manager
            .rotate_if_stale()
            .unwrap()
            .expect("backdated SPK must trigger rotation");
        let rotated_pk = manager.current_bundle().unwrap().public_key;
        assert_eq!(
            rotated.public().as_bytes(),
            rotated_pk.as_bytes(),
            "returned SPK must match persisted bundle",
        );
        assert_ne!(rotated_pk.as_bytes(), stale.public().as_bytes());
        assert_ne!(rotated_pk.as_bytes(), original_pk.as_bytes());
    }

    #[test]
    fn future_created_at_does_not_rotate() {
        let manager = manager_with_identity();
        let identity = manager.identity.load_identity().unwrap();
        let timestamp = now_secs().unwrap() + 100_000;
        let spk = generate_signed_prekey(identity.signing_key_pair(), timestamp);
        let blob = encode_spk(&spk);
        manager
            .storage
            .lock()
            .unwrap()
            .store(SPK_KEY, &*blob)
            .unwrap();

        manager.rotate_if_stale().unwrap();
        let public_key = manager.current_bundle().unwrap().public_key;
        assert_eq!(public_key.as_bytes(), spk.public().as_bytes());
    }

    #[test]
    fn far_future_created_at_triggers_rotation() {
        let manager = manager_with_identity();
        let identity = manager.identity.load_identity().unwrap();
        let timestamp = now_secs().unwrap() + FUTURE_TIMESTAMP_TOLERANCE_SECS * 10;
        let spk = generate_signed_prekey(identity.signing_key_pair(), timestamp);
        let blob = encode_spk(&spk);
        manager
            .storage
            .lock()
            .unwrap()
            .store(SPK_KEY, &*blob)
            .unwrap();

        manager.rotate_if_stale().unwrap();
        let public_key = manager.current_bundle().unwrap().public_key;
        assert_ne!(public_key.as_bytes(), spk.public().as_bytes());
    }

    #[test]
    fn rotate_if_stale_rejects_unsupported_version() {
        let manager = manager_with_identity();
        let mut blob = [0u8; SPK_BLOB_LEN];
        blob[0] = 99;
        manager
            .storage
            .lock()
            .unwrap()
            .store(SPK_KEY, &blob)
            .unwrap();
        assert!(matches!(
            manager.rotate_if_stale(),
            Err(SignedPreKeyError::InvalidData(reason)) if reason.contains("version")
        ));
    }

    #[test]
    fn rotate_if_stale_without_identity_returns_identity_error() {
        let manager = manager_no_identity();
        assert!(matches!(
            manager.rotate_if_stale(),
            Err(SignedPreKeyError::Identity(IdentityError::NotFound))
        ));
    }

    #[test]
    fn rotate_now_without_identity_returns_identity_error() {
        let manager = manager_no_identity();
        assert!(matches!(
            manager.rotate_now(),
            Err(SignedPreKeyError::Identity(IdentityError::NotFound))
        ));
    }

    #[test]
    fn encode_decode_round_trip() {
        let identity_signing = generate_signing_key_pair();
        let original = generate_signed_prekey(&identity_signing, 1_700_000_000);
        let blob = encode_spk(&original);
        assert_eq!(blob.len(), SPK_BLOB_LEN);
        let restored = decode_spk(&blob);
        assert_eq!(restored.public().as_bytes(), original.public().as_bytes());
        assert_eq!(
            restored.signature().to_bytes(),
            original.signature().to_bytes()
        );
        assert_eq!(restored.created_at(), original.created_at());
    }

    #[test]
    fn checked_blob_rejects_short_blob() {
        assert!(matches!(
            checked_blob(&[0u8; 50]),
            Err(SignedPreKeyError::InvalidData(_))
        ));
    }

    #[test]
    fn checked_blob_rejects_long_blob() {
        assert!(matches!(
            checked_blob(&[0u8; 200]),
            Err(SignedPreKeyError::InvalidData(_))
        ));
    }

    #[test]
    fn checked_blob_rejects_unsupported_version() {
        let mut blob = [0u8; SPK_BLOB_LEN];
        blob[0] = 99;
        assert!(matches!(
            checked_blob(&blob),
            Err(SignedPreKeyError::InvalidData(reason)) if reason.contains("version")
        ));
    }

    #[test]
    fn persistence_round_trip_via_two_managers() {
        let storage = shared_storage();
        let identity = Arc::new(IdentityManager::new(Arc::clone(&storage)));
        identity.generate_identity().unwrap();

        let manager_a = SignedPreKeyManager::new(Arc::clone(&storage), Arc::clone(&identity));
        manager_a.rotate_if_stale().unwrap();
        let pk_a = manager_a.current_bundle().unwrap().public_key;
        drop(manager_a);

        let manager_b = SignedPreKeyManager::new(storage, identity);
        let pk_b = manager_b.current_bundle().unwrap().public_key;
        assert_eq!(pk_a.as_bytes(), pk_b.as_bytes());
    }
}
