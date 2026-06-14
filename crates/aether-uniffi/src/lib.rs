//! UniFFI bindings for the cryptographic core.
//!
//! This crate exposes the storage-backed [`KeyStore`] API and FFI-safe record types used by SDKs.
//! Apps provide a platform [`SecureStorage`] implementation, then use one [`KeyStore`] for the app
//! lifetime to manage the local identity and publication keys.
//!
//! # Examples
//!
//! ```
//! use aether::{
//!     AetherError, InMemorySecureStorage, KeyStore, PublicationBundle, SecureStorage,
//! };
//! use std::sync::Arc;
//!
//! # fn publish(_bundle: &PublicationBundle) -> Result<(), AetherError> {
//! #     Ok(())
//! # }
//! let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
//! let store = KeyStore::new(storage);
//!
//! if !store.has_identity()? {
//!     store.generate_identity()?;
//! }
//!
//! store.rotate_signed_prekey_now()?;
//! let publication = store.current_publication_bundle()?;
//! publish(&publication)?;
//! # Ok::<(), AetherError>(())
//! ```

uniffi::setup_scaffolding!("aether");

#[cfg(all(feature = "fixture-replay", not(debug_assertions)))]
compile_error!("fixture-replay is test-only and must not be enabled for release builds");

mod error;
#[cfg(feature = "fixture-replay")]
mod fixture_replay;
mod key_store;
mod records;
mod storage;

pub use error::AetherError;
pub use key_store::KeyStore;
pub use records::{
    DiscoveryKeyBundle, Identity, OneTimePreKeyBundle, PublicationBundle, SignedPreKeyBundle,
};
pub use storage::{InMemorySecureStorage, SecureStorage};
