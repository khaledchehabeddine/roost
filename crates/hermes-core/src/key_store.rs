use crate::identity::{IdentityError, IdentityManager};
use crate::signed_prekey::{SignedPreKeyError, SignedPreKeyManager};
use crate::storage::SecureStorage;
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex};

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

struct KeyStoreInner {
    identity: Arc<IdentityManager>,
    signed_prekey: Arc<SignedPreKeyManager>,
}

/// All sub-managers vended by the same `KeyStore` share one `SecureStorage`.
#[derive(Clone)]
pub struct KeyStore(Arc<KeyStoreInner>);

impl KeyStore {
    pub fn new(storage: Box<dyn SecureStorage>) -> Self {
        let storage = Arc::new(Mutex::new(storage));
        let identity = Arc::new(IdentityManager::new(Arc::clone(&storage)));
        let signed_prekey = Arc::new(SignedPreKeyManager::new(storage, Arc::clone(&identity)));
        KeyStore(Arc::new(KeyStoreInner {
            identity,
            signed_prekey,
        }))
    }

    pub fn identity(&self) -> Arc<IdentityManager> {
        Arc::clone(&self.0.identity)
    }

    pub fn signed_prekey(&self) -> Arc<SignedPreKeyManager> {
        Arc::clone(&self.0.signed_prekey)
    }

    /// Call once at app launch.
    pub fn rotate_spk_if_stale(&self) -> Result<(), KeyStoreError> {
        Ok(self.0.signed_prekey.rotate_if_stale()?)
    }

    /// Decrypt-then-commit: a bad passphrase fails before any storage mutation. A partial
    /// failure of the commit (SPK reset succeeds, identity store fails) leaves
    /// `{no SPK, old identity}` — self-consistent, repaired by the next `rotate_if_stale`.
    pub fn import_encrypted_backup(
        &self,
        data: &[u8],
        passphrase: &str,
    ) -> Result<(), KeyStoreError> {
        let plaintext = self.0.identity.decrypt_backup(data, passphrase)?;
        self.0.signed_prekey.reset()?;
        self.0.identity.store_decrypted_identity(&plaintext)?;
        Ok(())
    }

    /// Partial-failure safe: if SPK reset succeeds but identity reset fails, retrying
    /// [`Self::reset`] completes the reset.
    pub fn reset(&self) -> Result<(), KeyStoreError> {
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
    fn key_store_clone_shares_storage() {
        let ks_a = store();
        let ks_b = ks_a.clone();
        ks_a.identity().generate_identity().unwrap();
        assert!(ks_b.identity().load_identity().is_ok());
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
    fn sub_manager_writes_do_not_collide() {
        let ks = store();
        ks.identity().generate_identity().unwrap();
        ks.rotate_spk_if_stale().unwrap();
        assert!(ks.identity().load_identity().is_ok());
        assert!(ks.signed_prekey().current_bundle().is_ok());
    }

    #[test]
    fn import_encrypted_backup_clears_stale_spk() {
        let ks_b = store();
        ks_b.identity().generate_identity().unwrap();
        ks_b.rotate_spk_if_stale().unwrap();

        let ks_a = store();
        ks_a.identity().generate_identity().unwrap();
        let backup = ks_a.identity().export_encrypted_backup("pass").unwrap();

        // Importing ks_a's backup into ks_b must clear ks_b's stale SPK (signed by old id)
        ks_b.import_encrypted_backup(&backup, "pass").unwrap();
        assert!(matches!(
            ks_b.signed_prekey().current_bundle(),
            Err(SignedPreKeyError::InvalidData(_))
        ));

        let imported = ks_b.identity().load_identity().unwrap();
        let original = ks_a.identity().load_identity().unwrap();
        assert_eq!(
            imported.verifying_key().as_bytes(),
            original.verifying_key().as_bytes()
        );
    }

    #[test]
    fn import_then_rotate_yields_spk_signed_by_imported_identity() {
        let ks_a = store();
        ks_a.identity().generate_identity().unwrap();
        ks_a.rotate_spk_if_stale().unwrap();

        let ks_b = store();
        ks_b.identity().generate_identity().unwrap();
        let backup = ks_b.identity().export_encrypted_backup("pass").unwrap();

        ks_a.import_encrypted_backup(&backup, "pass").unwrap();
        ks_a.rotate_spk_if_stale().unwrap();

        let new_bundle = ks_a.signed_prekey().current_bundle().unwrap();
        let imported = ks_a.identity().load_identity().unwrap();
        assert!(verify_bundle(&new_bundle, imported.verifying_key()).is_ok());
    }

    #[test]
    fn import_with_wrong_passphrase_does_not_disturb_existing_state() {
        let ks_a = store();
        ks_a.identity().generate_identity().unwrap();
        ks_a.rotate_spk_if_stale().unwrap();
        let original_id = ks_a.identity().load_identity().unwrap();
        let original_spk = ks_a.signed_prekey().current_bundle().unwrap().public_key;

        let ks_b = store();
        ks_b.identity().generate_identity().unwrap();
        let backup = ks_b.identity().export_encrypted_backup("right").unwrap();

        assert!(ks_a.import_encrypted_backup(&backup, "wrong").is_err());

        let id = ks_a.identity().load_identity().unwrap();
        let spk = ks_a.signed_prekey().current_bundle().unwrap().public_key;
        assert_eq!(original_id.public_key(), id.public_key());
        assert_eq!(original_spk.as_bytes(), spk.as_bytes());
    }

    #[test]
    fn reset_clears_identity_and_spk() {
        let ks = store();
        ks.identity().generate_identity().unwrap();
        ks.rotate_spk_if_stale().unwrap();

        ks.reset().unwrap();

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
    fn reset_returns_store_to_first_launch_state() {
        let ks = store();
        ks.identity().generate_identity().unwrap();
        ks.rotate_spk_if_stale().unwrap();

        ks.reset().unwrap();

        ks.identity().generate_identity().unwrap();
        ks.rotate_spk_if_stale().unwrap();
        assert!(ks.signed_prekey().current_bundle().is_ok());
    }

    #[test]
    fn reset_on_empty_store_succeeds() {
        let ks = store();
        ks.reset().unwrap();
        ks.reset().unwrap();
    }
}
