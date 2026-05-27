//! Application-layer key management for private messaging clients.
//!
//! This crate wraps [`aether_crypto`] primitives with persistence, identity lifecycle management,
//! and signed-pre-key rotation for Rust callers wiring the core into apps. Platform adapters
//! provide a [`SecureStorage`] implementation backed by secure storage.
//!
//! # Overview
//!
//! [`KeyStore`] is the entry point for identity setup, encrypted backup import and export, and
//! signed-pre-key publication. It serializes access to the underlying storage so callers can share
//! a cloned handle across application components.
//!
//! # Examples
//!
//! ```
//! use aether_core::{InMemorySecureStorage, KeyStore};
//!
//! # fn publish_signed_prekey_bundle(
//! #     _bundle: &aether_crypto::SignedPreKeyBundle,
//! # ) -> Result<(), Box<dyn std::error::Error>> {
//! #     Ok(())
//! # }
//! let store = KeyStore::new(Box::new(InMemorySecureStorage::new()));
//! store.generate_identity()?;
//! let bundle = match store.rotate_signed_prekey_if_stale()? {
//!     Some(bundle) => bundle,
//!     None => store.current_signed_prekey_bundle()?,
//! };
//! publish_signed_prekey_bundle(&bundle)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod identity;
mod key_store;
mod signed_prekey;
mod storage;

pub use identity::{Identity, IdentityError};
pub use key_store::{KeyStore, KeyStoreError};
pub use signed_prekey::SignedPreKeyError;
pub use storage::{InMemorySecureStorage, SecureStorage, StorageError};
