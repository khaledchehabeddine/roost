use roost_client::{IdentityContext, IdentityKey, OperationId, RoostError, SecureStorage};
use roost_crypto::SigningKeyPair;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

const CERTIFICATE_LABEL: &[u8] = b"RoostSenderCertificate-v1:";
const CERTIFICATE_VERSION: u8 = 1;
pub(crate) const DOMAIN_SIGNING_KEY_ID: &[u8] = b"relay-signing-key";
pub(crate) const RELAY_DOMAIN: &[u8] = b"relay.example";

/// Reserves and finalizes an operation, as an app does around its own commit.
pub(crate) fn complete(context: &IdentityContext, id: OperationId) {
    context.reserve_operation(id.clone()).unwrap();
    context.finalize_operation(id).unwrap();
}

/// Returns a context whose identity has a publication, as an app has before it shares a link.
pub(crate) fn published_identity() -> Arc<IdentityContext> {
    let context = IdentityContext::new(Arc::new(MemoryStorage::default()));
    let created = context.prepare_identity_creation().unwrap();
    complete(&context, created.operation_id);
    let signed_prekey = context
        .prepare_signed_prekey_rotation_and_discovery_key_cleanup()
        .unwrap();
    complete(&context, signed_prekey.operation_id);
    context
}

/// Returns the relay domain's signing key, which every test certificate names.
pub(crate) fn domain_signing_key() -> SigningKeyPair {
    SigningKeyPair::from_signing_bytes(&[0x41; 32])
}

/// Returns a sender certificate for `identity_key` that expires at `expires_at_secs`, encoded as a
/// relay's domain authority does before signing, and the domain's signature over it.
pub(crate) fn issue_certificate(
    identity_key: &IdentityKey,
    expires_at_secs: u64,
) -> (Vec<u8>, Vec<u8>) {
    let certificate = [
        CERTIFICATE_LABEL,
        &[CERTIFICATE_VERSION],
        &u32::try_from(DOMAIN_SIGNING_KEY_ID.len())
            .unwrap()
            .to_be_bytes(),
        DOMAIN_SIGNING_KEY_ID,
        &u32::try_from(RELAY_DOMAIN.len()).unwrap().to_be_bytes(),
        RELAY_DOMAIN,
        &identity_key.agreement_key,
        &identity_key.signing_key,
        &expires_at_secs.to_be_bytes(),
    ]
    .concat();
    let signature = domain_signing_key().sign(&certificate).to_bytes().to_vec();
    (certificate, signature)
}

/// Secure storage held in memory, standing in for a platform store.
#[derive(Default)]
pub(crate) struct MemoryStorage {
    entries: Mutex<BTreeMap<String, Zeroizing<Vec<u8>>>>,
    fail_next_load: AtomicBool,
}

impl MemoryStorage {
    /// Makes the next `load` fail the way a platform store reports an error.
    pub(crate) fn fail_next_load(&self) {
        self.fail_next_load.store(true, Ordering::SeqCst);
    }
}

impl SecureStorage for MemoryStorage {
    fn save(&self, key: String, value: Vec<u8>) -> Result<(), RoostError> {
        self.entries
            .lock()
            .unwrap()
            .insert(key, Zeroizing::new(value));
        Ok(())
    }

    fn load(&self, key: String) -> Result<Option<Vec<u8>>, RoostError> {
        if self.fail_next_load.swap(false, Ordering::SeqCst) {
            return Err(RoostError::Storage {
                reason: "keychain unavailable".into(),
            });
        }
        Ok(self
            .entries
            .lock()
            .unwrap()
            .get(&key)
            .map(|value| value.to_vec()))
    }

    fn remove(&self, key: String) -> Result<(), RoostError> {
        self.entries.lock().unwrap().remove(&key);
        Ok(())
    }
}
