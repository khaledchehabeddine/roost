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
//! # fn publish_identity_bundle(
//! #     _identity: &aether_core::Identity,
//! #     _discovery_key: &aether_crypto::DiscoveryKeyBundle,
//! #     _signed_prekey: &aether_crypto::SignedPreKeyBundle,
//! # ) -> Result<(), Box<dyn std::error::Error>> {
//! #     Ok(())
//! # }
//! let store = KeyStore::new(Box::new(InMemorySecureStorage::new()));
//! // Generating an identity also mints its first discovery key (epoch 0).
//! let identity = store.generate_identity()?;
//! let discovery_key = store.current_discovery_key_bundle()?;
//! let signed_prekey = match store.rotate_signed_prekey_if_stale()? {
//!     Some(bundle) => bundle,
//!     None => store.current_signed_prekey_bundle()?,
//! };
//! // Publish the identity, the discovery-key bundle it signs, and the signed pre-key the
//! // discovery key signs.
//! publish_identity_bundle(&identity, &discovery_key, &signed_prekey)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod clock;
mod discovery_key;
mod identity;
mod key_store;
mod signed_prekey;
mod storage;
#[cfg(test)]
mod test_support;

pub use discovery_key::DiscoveryKeyError;
pub use identity::{Identity, IdentityError};
pub use key_store::{DiscoveryKeyRotationBundle, KeyStore, KeyStoreError};
pub use signed_prekey::SignedPreKeyError;
pub use storage::{InMemorySecureStorage, SecureStorage, StorageError};
