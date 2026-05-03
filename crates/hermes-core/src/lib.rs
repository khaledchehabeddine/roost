//! Application-layer key management for Hermes.
//!
//! Wraps the cryptographic primitives in [`hermes_crypto`] with persistence, lifecycle
//! management, and a [`SecureStorage`] trait that platforms (iOS Keychain, Android Keystore)
//! plug into.
//!
//! # Mental model
//!
//! [`KeyStore`] is the single entry point. It owns an [`IdentityManager`] (X25519 + Ed25519
//! identity keys) and a [`SignedPreKeyManager`] (rotating signed pre-key for handshake
//! initiation) and serializes their access to the underlying [`SecureStorage`].
//!
//! # Quick start
//!
//! ```
//! use hermes_core::{InMemorySecureStorage, KeyStore};
//!
//! let store = KeyStore::new(Box::new(InMemorySecureStorage::new()));
//! store.generate_identity()?;
//! let _ = store.rotate_signed_prekey_if_stale()?;
//! let bundle = store.current_signed_prekey_bundle()?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod identity;
mod key_store;
mod signed_prekey;
mod storage;

pub use identity::{Identity, IdentityError, IdentityManager};
pub use key_store::{KeyStore, KeyStoreError};
pub use signed_prekey::{SignedPreKeyError, SignedPreKeyManager};
pub use storage::{InMemorySecureStorage, SecureStorage, StorageError};
