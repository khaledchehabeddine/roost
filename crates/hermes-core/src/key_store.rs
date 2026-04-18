use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex};

use crate::identity::{IdentityError, IdentityManager};
use crate::signed_prekey::{SignedPreKeyError, SignedPreKeyManager};
use crate::storage::SecureStorage;

/// Errors surfaced by [`KeyStore`] facade operations.
///
/// Wraps the per-sub-manager error types. Sub-manager methods called via their `Arc`
/// handles return their own error types directly; this enum is only used by the
/// cross-cutting methods on `KeyStore` itself.
#[derive(Debug)]
pub enum KeyStoreError {
    Identity(IdentityError),
    SignedPreKey(SignedPreKeyError),
}

impl fmt::Display for KeyStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyStoreError::Identity(e) => write!(f, "identity: {e}"),
            KeyStoreError::SignedPreKey(e) => write!(f, "signed prekey: {e}"),
        }
    }
}

impl Error for KeyStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            KeyStoreError::Identity(e) => Some(e),
            KeyStoreError::SignedPreKey(e) => Some(e),
        }
    }
}

impl From<IdentityError> for KeyStoreError {
    fn from(e: IdentityError) -> Self {
        KeyStoreError::Identity(e)
    }
}

impl From<SignedPreKeyError> for KeyStoreError {
    fn from(e: SignedPreKeyError) -> Self {
        KeyStoreError::SignedPreKey(e)
    }
}

/// A single construction point for all key-managing types in `hermes-core`.
///
/// Owns one shared `Arc<Mutex<Box<dyn SecureStorage>>>` and vends Arc-wrapped sub-managers
/// ([`IdentityManager`], [`SignedPreKeyManager`]). All sub-managers obtained from the same
/// `KeyStore` see the same backing storage.
///
/// `KeyStore` itself is cheap to clone: it is a newtype around `Arc<KeyStoreInner>`.
#[derive(Clone)]
pub struct KeyStore(Arc<KeyStoreInner>);

struct KeyStoreInner {
    identity: Arc<IdentityManager>,
    signed_prekey: Arc<SignedPreKeyManager>,
}

impl KeyStore {
    /// Constructs a `KeyStore` over the given `SecureStorage` backend.
    ///
    /// The backend is wrapped in `Arc<Mutex<...>>` and shared across all sub-managers.
    pub fn new(storage: Box<dyn SecureStorage>) -> Self {
        let storage = Arc::new(Mutex::new(storage));
        let identity = Arc::new(IdentityManager::new(Arc::clone(&storage)));
        let signed_prekey = Arc::new(SignedPreKeyManager::new(storage, Arc::clone(&identity)));
        KeyStore(Arc::new(KeyStoreInner {
            identity,
            signed_prekey,
        }))
    }

    /// Returns a handle to the identity manager.
    pub fn identity(&self) -> Arc<IdentityManager> {
        Arc::clone(&self.0.identity)
    }

    /// Returns a handle to the signed prekey manager.
    pub fn signed_prekey(&self) -> Arc<SignedPreKeyManager> {
        Arc::clone(&self.0.signed_prekey)
    }

    /// Convenience: rotates the signed prekey if it is stale or missing.
    ///
    /// Equivalent to `self.signed_prekey().rotate_if_stale()` with the error type lifted
    /// into [`KeyStoreError`]. Intended to be called once at app launch.
    pub fn rotate_spk_if_stale(&self) -> Result<(), KeyStoreError> {
        self.0.signed_prekey.rotate_if_stale()?;
        Ok(())
    }

    /// Imports an encrypted identity backup, then resets the signed prekey.
    ///
    /// This is the safe import path: it ensures any stale SPK signed by the previous
    /// identity is cleared, so the next call to [`Self::rotate_spk_if_stale`] generates a
    /// fresh SPK signed by the newly-imported identity. Applications should not import
    /// the identity directly; doing so leaves an orphan SPK.
    pub fn import_encrypted_backup(
        &self,
        data: &[u8],
        passphrase: &str,
    ) -> Result<(), KeyStoreError> {
        self.0.identity.import_encrypted_backup(data, passphrase)?;
        self.0.signed_prekey.reset()?;
        Ok(())
    }

    /// Wipes all key material from storage — signed prekey first, then identity.
    ///
    /// After this returns successfully, the device has no identity and no SPK; the next
    /// launch behaves as a first launch. Used during logout flows.
    ///
    /// If the SPK delete succeeds but the identity delete fails, the partial state is
    /// recoverable: callers can retry [`Self::wipe_all`], or the next
    /// [`Self::rotate_spk_if_stale`] will regenerate the SPK against the still-present
    /// identity.
    pub fn wipe_all(&self) -> Result<(), KeyStoreError> {
        self.0.signed_prekey.reset()?;
        self.0.identity.reset()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::InMemorySecureStorage;
    use hermes_crypto::verify_bundle;

    fn store() -> KeyStore {
        KeyStore::new(Box::new(InMemorySecureStorage::new()))
    }

    #[test]
    fn identity_round_trip_via_key_store() {
        let ks = store();
        let id = ks.identity();
        let generated = id.generate_identity().unwrap();
        let loaded = id.load_identity().unwrap();
        assert_eq!(generated.public_key(), loaded.public_key());
    }

    #[test]
    fn two_identity_handles_share_storage() {
        let ks = store();
        let id_a = ks.identity();
        let id_b = ks.identity();
        let generated = id_a.generate_identity().unwrap();
        let loaded = id_b.load_identity().unwrap();
        assert_eq!(generated.public_key(), loaded.public_key());
    }

    #[test]
    fn key_store_clone_shares_storage() {
        let ks_a = store();
        let ks_b = ks_a.clone();
        ks_a.identity().generate_identity().unwrap();
        assert!(ks_b.identity().load_identity().is_ok());
    }

    #[test]
    fn rotate_spk_if_stale_seeds_first_spk() {
        let ks = store();
        ks.identity().generate_identity().unwrap();
        ks.rotate_spk_if_stale().unwrap();
        let bundle = ks.signed_prekey().current_bundle().unwrap();
        let identity = ks.identity().load_identity().unwrap();
        assert!(verify_bundle(&bundle, identity.verifying_key()).is_ok());
    }

    #[test]
    fn identity_and_spk_keys_do_not_collide() {
        let ks = store();
        ks.identity().generate_identity().unwrap();
        ks.rotate_spk_if_stale().unwrap();
        // Both sub-managers wrote to the shared backend without overwriting each other.
        assert!(ks.identity().load_identity().is_ok());
        assert!(ks.signed_prekey().current_bundle().is_ok());
    }

    #[test]
    fn import_encrypted_backup_clears_stale_spk() {
        // Setup: ks_b has its own identity + SPK
        let ks_b = store();
        ks_b.identity().generate_identity().unwrap();
        ks_b.rotate_spk_if_stale().unwrap();
        assert!(ks_b.signed_prekey().current_bundle().is_ok());

        // Setup: ks_a has a different identity, export its backup
        let ks_a = store();
        ks_a.identity().generate_identity().unwrap();
        let backup = ks_a.identity().export_encrypted_backup("pass").unwrap();

        // Importing ks_a's backup into ks_b must clear ks_b's stale SPK (signed by old id)
        ks_b.import_encrypted_backup(&backup, "pass").unwrap();
        assert!(matches!(
            ks_b.signed_prekey().current_bundle(),
            Err(SignedPreKeyError::InvalidData(_))
        ));

        // The imported identity is now active in ks_b
        let imported = ks_b.identity().load_identity().unwrap();
        let original = ks_a.identity().load_identity().unwrap();
        assert_eq!(
            imported.verifying_key().as_bytes(),
            original.verifying_key().as_bytes()
        );
    }

    #[test]
    fn import_then_rotate_yields_spk_signed_by_imported_identity() {
        let ks_b = store();
        ks_b.identity().generate_identity().unwrap();
        ks_b.rotate_spk_if_stale().unwrap();

        let ks_a = store();
        ks_a.identity().generate_identity().unwrap();
        let backup = ks_a.identity().export_encrypted_backup("pass").unwrap();

        ks_b.import_encrypted_backup(&backup, "pass").unwrap();
        ks_b.rotate_spk_if_stale().unwrap();

        let new_bundle = ks_b.signed_prekey().current_bundle().unwrap();
        let imported = ks_b.identity().load_identity().unwrap();
        assert!(verify_bundle(&new_bundle, imported.verifying_key()).is_ok());
    }

    #[test]
    fn wipe_all_clears_identity_and_spk() {
        let ks = store();
        ks.identity().generate_identity().unwrap();
        ks.rotate_spk_if_stale().unwrap();

        ks.wipe_all().unwrap();

        assert!(matches!(
            ks.identity().load_identity(),
            Err(IdentityError::NotFound)
        ));
        assert!(matches!(
            ks.signed_prekey().current_bundle(),
            Err(SignedPreKeyError::InvalidData(_))
        ));
    }

    #[test]
    fn wipe_all_is_idempotent_on_empty_store() {
        // Calling wipe_all twice (or on empty storage) must not error.
        let ks = store();
        ks.wipe_all().unwrap();
        ks.wipe_all().unwrap();
    }
}
