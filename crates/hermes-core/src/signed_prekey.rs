use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use hermes_crypto::{PreKeyBundle, SignedPreKey, generate_signed_prekey};
use zeroize::Zeroizing;

use crate::identity::{IdentityError, IdentityManager};
use crate::storage::{SecureStorage, StorageError};

/// Default rotation window for signed prekeys, in days.
///
/// Aligned with the libsignal default. Rotation happens at app launch via
/// [`SignedPreKeyManager::rotate_if_stale`] when the stored SPK is older than this.
pub const SPK_ROTATION_WINDOW_DAYS: u64 = 7;

const SPK_KEY: &str = "prekey/signed";
const SPK_BLOB_LEN: usize = 32 + 64 + 8;
const SECONDS_PER_DAY: u64 = 86_400;

/// Errors returned by [`SignedPreKeyManager`] operations.
#[derive(Debug)]
pub enum SignedPreKeyError {
    Storage(StorageError),
    Identity(IdentityError),
    /// The stored SPK blob is malformed (wrong length, unparseable fields).
    InvalidData(String),
    /// The system clock is set before the Unix epoch.
    Clock,
    /// The internal storage lock was poisoned by a panicked thread.
    LockPoisoned,
}

impl fmt::Display for SignedPreKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignedPreKeyError::Storage(e) => write!(f, "storage: {e}"),
            SignedPreKeyError::Identity(e) => write!(f, "identity: {e}"),
            SignedPreKeyError::InvalidData(reason) => write!(f, "invalid SPK data: {reason}"),
            SignedPreKeyError::Clock => write!(f, "system clock is before Unix epoch"),
            SignedPreKeyError::LockPoisoned => write!(f, "internal lock poisoned"),
        }
    }
}

impl Error for SignedPreKeyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            SignedPreKeyError::Storage(e) => Some(e),
            SignedPreKeyError::Identity(e) => Some(e),
            _ => None,
        }
    }
}

impl From<StorageError> for SignedPreKeyError {
    fn from(e: StorageError) -> Self {
        SignedPreKeyError::Storage(e)
    }
}

impl From<IdentityError> for SignedPreKeyError {
    fn from(e: IdentityError) -> Self {
        SignedPreKeyError::Identity(e)
    }
}

/// Manages the per-device signed prekey: generation, persistence, and rotation.
///
/// Shares storage with the [`IdentityManager`] vended by the same [`crate::KeyStore`].
/// Rotation is triggered explicitly via [`Self::rotate_if_stale`] (typically once at app
/// launch); the read path ([`Self::current`], [`Self::current_bundle`]) does not touch
/// the system clock.
pub struct SignedPreKeyManager {
    storage: Arc<Mutex<Box<dyn SecureStorage>>>,
    identity: Arc<IdentityManager>,
}

impl SignedPreKeyManager {
    pub fn new(
        storage: Arc<Mutex<Box<dyn SecureStorage>>>,
        identity: Arc<IdentityManager>,
    ) -> Self {
        SignedPreKeyManager { storage, identity }
    }

    /// Returns the currently stored signed prekey.
    ///
    /// Returns [`SignedPreKeyError::InvalidData`] if no SPK is stored — call
    /// [`Self::rotate_if_stale`] first at app launch to seed one.
    pub fn current(&self) -> Result<SignedPreKey, SignedPreKeyError> {
        let storage = self.lock_storage()?;
        let blob = storage
            .load(SPK_KEY)?
            .ok_or_else(|| SignedPreKeyError::InvalidData("no signed prekey present".into()))?;
        decode_spk(&blob)
    }

    /// Returns the public-form bundle for the currently stored signed prekey.
    pub fn current_bundle(&self) -> Result<PreKeyBundle, SignedPreKeyError> {
        Ok(self.current()?.bundle())
    }

    /// Rotates the SPK if the stored issuance timestamp is older than
    /// [`SPK_ROTATION_WINDOW_DAYS`] (or no SPK is stored at all).
    ///
    /// A stored timestamp newer than `now` (clock skew) is treated as fresh — no rotation.
    /// A blob with the wrong length surfaces [`SignedPreKeyError::InvalidData`] rather than
    /// being silently replaced; the caller can decide whether to wipe and retry.
    pub fn rotate_if_stale(&self) -> Result<(), SignedPreKeyError> {
        let now = now_secs()?;
        let needs_rotation = match self.read_stored_timestamp()? {
            None => true,
            Some(ts) if ts > now => false,
            Some(ts) => now.saturating_sub(ts) > SPK_ROTATION_WINDOW_DAYS * SECONDS_PER_DAY,
        };
        if needs_rotation {
            self.rotate_now()?;
        }
        Ok(())
    }

    /// Unconditionally rotates the SPK and writes the new blob to storage.
    ///
    /// Atomic relative to `SecureStorage::store`'s overwrite semantics: the new 104-byte
    /// blob fully replaces the old entry in a single call — no `delete` precedes the
    /// `store`, so there is no partial-write window.
    pub fn rotate_now(&self) -> Result<SignedPreKey, SignedPreKeyError> {
        let identity = self.identity.load_identity()?;
        let now = now_secs()?;
        let spk = generate_signed_prekey(identity.signing_key_pair(), now);
        let blob = encode_spk(&spk);
        let mut storage = self.lock_storage()?;
        storage.store(SPK_KEY, &*blob)?;
        Ok(spk)
    }

    fn lock_storage(&self) -> Result<MutexGuard<'_, Box<dyn SecureStorage>>, SignedPreKeyError> {
        self.storage
            .lock()
            .map_err(|_| SignedPreKeyError::LockPoisoned)
    }

    /// Reads only the issuance timestamp out of the stored blob. Returns `Ok(None)` if no
    /// SPK is stored. Surfaces [`SignedPreKeyError::InvalidData`] on a length mismatch.
    fn read_stored_timestamp(&self) -> Result<Option<u64>, SignedPreKeyError> {
        let storage = self.lock_storage()?;
        let blob = match storage.load(SPK_KEY)? {
            Some(b) => b,
            None => return Ok(None),
        };
        if blob.len() != SPK_BLOB_LEN {
            return Err(SignedPreKeyError::InvalidData(format!(
                "expected {} bytes, got {}",
                SPK_BLOB_LEN,
                blob.len()
            )));
        }
        let ts_bytes: [u8; 8] = blob[96..SPK_BLOB_LEN]
            .try_into()
            .map_err(|_| SignedPreKeyError::InvalidData("timestamp slice".into()))?;
        Ok(Some(u64::from_be_bytes(ts_bytes)))
    }
}

/// Encodes a [`SignedPreKey`] into the on-disk format.
///
/// Layout: `[secret(32) | signature(64) | created_at u64 big-endian (8)]` = 104 bytes.
fn encode_spk(spk: &SignedPreKey) -> Zeroizing<[u8; SPK_BLOB_LEN]> {
    let mut buf = Zeroizing::new([0u8; SPK_BLOB_LEN]);
    buf[..32].copy_from_slice(&*spk.to_secret_bytes());
    buf[32..96].copy_from_slice(&spk.signature().to_bytes());
    buf[96..SPK_BLOB_LEN].copy_from_slice(&spk.created_at().to_be_bytes());
    buf
}

/// Decodes the on-disk format back into a [`SignedPreKey`].
fn decode_spk(blob: &[u8]) -> Result<SignedPreKey, SignedPreKeyError> {
    if blob.len() != SPK_BLOB_LEN {
        return Err(SignedPreKeyError::InvalidData(format!(
            "expected {} bytes, got {}",
            SPK_BLOB_LEN,
            blob.len()
        )));
    }
    let secret: [u8; 32] = blob[..32]
        .try_into()
        .map_err(|_| SignedPreKeyError::InvalidData("secret slice".into()))?;
    let signature: [u8; 64] = blob[32..96]
        .try_into()
        .map_err(|_| SignedPreKeyError::InvalidData("signature slice".into()))?;
    let ts_bytes: [u8; 8] = blob[96..SPK_BLOB_LEN]
        .try_into()
        .map_err(|_| SignedPreKeyError::InvalidData("timestamp slice".into()))?;
    let created_at = u64::from_be_bytes(ts_bytes);
    Ok(SignedPreKey::from_secret_bytes(
        secret, signature, created_at,
    ))
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
    fn encode_decode_round_trip() {
        let identity_signing = generate_signing_key_pair();
        let original = generate_signed_prekey(&identity_signing, 1_700_000_000);
        let blob = encode_spk(&original);
        assert_eq!(blob.len(), SPK_BLOB_LEN);
        let restored = decode_spk(&*blob).unwrap();
        assert_eq!(restored.public().as_bytes(), original.public().as_bytes());
        assert_eq!(
            restored.signature().to_bytes(),
            original.signature().to_bytes()
        );
        assert_eq!(restored.created_at(), original.created_at());
    }

    #[test]
    fn decode_rejects_short_blob() {
        let result = decode_spk(&[0u8; 50]);
        assert!(matches!(result, Err(SignedPreKeyError::InvalidData(_))));
    }

    #[test]
    fn decode_rejects_long_blob() {
        let result = decode_spk(&[0u8; 200]);
        assert!(matches!(result, Err(SignedPreKeyError::InvalidData(_))));
    }

    #[test]
    fn current_without_stored_spk_returns_invalid_data() {
        let mgr = manager_with_identity();
        assert!(matches!(
            mgr.current(),
            Err(SignedPreKeyError::InvalidData(_))
        ));
    }

    #[test]
    fn rotate_if_stale_seeds_first_spk() {
        let mgr = manager_with_identity();
        mgr.rotate_if_stale().unwrap();
        let bundle = mgr.current_bundle().unwrap();
        let identity = mgr.identity.load_identity().unwrap();
        assert!(verify_bundle(&bundle, identity.verifying_key()).is_ok());
    }

    #[test]
    fn rotate_if_stale_is_idempotent_on_fresh_spk() {
        let mgr = manager_with_identity();
        mgr.rotate_if_stale().unwrap();
        let first = mgr.current_bundle().unwrap().public_key;
        mgr.rotate_if_stale().unwrap();
        let second = mgr.current_bundle().unwrap().public_key;
        assert_eq!(first.as_bytes(), second.as_bytes());
    }

    #[test]
    fn rotate_if_stale_replaces_backdated_spk() {
        let mgr = manager_with_identity();
        mgr.rotate_if_stale().unwrap();
        let original = mgr.current_bundle().unwrap().public_key;

        // Backdoor a 30-day-old blob signed by the same identity
        let identity = mgr.identity.load_identity().unwrap();
        let backdated_ts = now_secs().unwrap() - 30 * SECONDS_PER_DAY;
        let stale = generate_signed_prekey(identity.signing_key_pair(), backdated_ts);
        let blob = encode_spk(&stale);
        mgr.storage.lock().unwrap().store(SPK_KEY, &*blob).unwrap();

        mgr.rotate_if_stale().unwrap();
        let rotated = mgr.current_bundle().unwrap().public_key;
        assert_ne!(rotated.as_bytes(), stale.public().as_bytes());
        assert_ne!(rotated.as_bytes(), original.as_bytes());
    }

    #[test]
    fn future_timestamp_does_not_rotate() {
        let mgr = manager_with_identity();
        let identity = mgr.identity.load_identity().unwrap();
        let future_ts = now_secs().unwrap() + 100_000;
        let future_spk = generate_signed_prekey(identity.signing_key_pair(), future_ts);
        let blob = encode_spk(&future_spk);
        mgr.storage.lock().unwrap().store(SPK_KEY, &*blob).unwrap();

        mgr.rotate_if_stale().unwrap();
        let after = mgr.current_bundle().unwrap().public_key;
        assert_eq!(after.as_bytes(), future_spk.public().as_bytes());
    }

    #[test]
    fn rotate_if_stale_without_identity_returns_identity_error() {
        let mgr = manager_no_identity();
        assert!(matches!(
            mgr.rotate_if_stale(),
            Err(SignedPreKeyError::Identity(IdentityError::NotFound))
        ));
    }

    #[test]
    fn rotate_now_without_identity_returns_identity_error() {
        let mgr = manager_no_identity();
        assert!(matches!(
            mgr.rotate_now(),
            Err(SignedPreKeyError::Identity(IdentityError::NotFound))
        ));
    }

    #[test]
    fn rotate_now_writes_exactly_104_bytes() {
        let mgr = manager_with_identity();
        // Pre-seed an arbitrary blob to confirm full overwrite (not append).
        mgr.storage
            .lock()
            .unwrap()
            .store(SPK_KEY, &[0xFFu8; 50])
            .unwrap();
        mgr.rotate_now().unwrap();
        let stored = mgr.storage.lock().unwrap().load(SPK_KEY).unwrap().unwrap();
        assert_eq!(stored.len(), SPK_BLOB_LEN);
    }

    #[test]
    fn persistence_round_trip_via_two_managers() {
        let storage = shared_storage();
        let identity = Arc::new(IdentityManager::new(Arc::clone(&storage)));
        identity.generate_identity().unwrap();

        let mgr_a = SignedPreKeyManager::new(Arc::clone(&storage), Arc::clone(&identity));
        mgr_a.rotate_if_stale().unwrap();
        let pk_a = mgr_a.current_bundle().unwrap().public_key;
        drop(mgr_a);

        let mgr_b = SignedPreKeyManager::new(storage, identity);
        let pk_b = mgr_b.current_bundle().unwrap().public_key;
        assert_eq!(pk_a.as_bytes(), pk_b.as_bytes());
    }

    #[test]
    fn current_returns_invalid_data_for_corrupt_blob() {
        let mgr = manager_with_identity();
        mgr.storage
            .lock()
            .unwrap()
            .store(SPK_KEY, &[0xAAu8; 50])
            .unwrap();
        assert!(matches!(
            mgr.current(),
            Err(SignedPreKeyError::InvalidData(_))
        ));
    }

    #[test]
    fn current_bundle_does_not_require_identity() {
        // current_bundle reads from storage and decodes — no identity load.
        let mgr = manager_no_identity();
        let identity_signing = generate_signing_key_pair();
        let spk = generate_signed_prekey(&identity_signing, 1_700_000_000);
        let blob = encode_spk(&spk);
        mgr.storage.lock().unwrap().store(SPK_KEY, &*blob).unwrap();

        let bundle = mgr.current_bundle().unwrap();
        assert_eq!(bundle.public_key.as_bytes(), spk.public().as_bytes());
    }
}
