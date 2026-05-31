//! Test helpers for reproducible crypto tests.
//!
//! Crypto operations normally draw randomness and time from the OS, so results differ each run.
//! These helpers pin both to fixed values, so identical inputs yield identical results.

use crate::clock::{Clock, ManualClock};
use crate::discovery_key::DiscoveryKeyManager;
use crate::identity::IdentityManager;
use crate::signed_prekey::SignedPreKeyManager;
use crate::storage::{InMemorySecureStorage, SecureStorage};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::{Arc, Mutex};

// Provides reproducible inputs: a seeded RNG, a fixed clock, and an in-memory store.
pub(crate) struct Sandbox {
    pub(crate) rng: ChaCha20Rng,
    clock: Arc<dyn Clock>,
    storage: Arc<Mutex<Box<dyn SecureStorage>>>,
}

impl Sandbox {
    // Builds a sandbox seeding the RNG with `seed` and pinning the clock at `now_unix_secs`.
    pub(crate) fn new(seed: [u8; 32], now_unix_secs: u64) -> Self {
        Sandbox {
            rng: ChaCha20Rng::from_seed(seed),
            clock: Arc::new(ManualClock::new(now_unix_secs)),
            storage: Arc::new(Mutex::new(Box::new(InMemorySecureStorage::new()))),
        }
    }

    // Returns identity, discovery-key, and signed-pre-key managers sharing this sandbox's storage
    // and fixed clock.
    pub(crate) fn managers(
        &self,
    ) -> (
        Arc<IdentityManager>,
        Arc<DiscoveryKeyManager>,
        SignedPreKeyManager,
    ) {
        let identity = Arc::new(IdentityManager::new(Arc::clone(&self.storage)));
        let discovery = Arc::new(DiscoveryKeyManager::new(
            Arc::clone(&self.storage),
            Arc::clone(&identity),
            Arc::clone(&self.clock),
        ));
        let signed_prekey = SignedPreKeyManager::new(
            Arc::clone(&self.storage),
            Arc::clone(&discovery),
            Arc::clone(&self.clock),
        );
        (identity, discovery, signed_prekey)
    }
}
