//! UniFFI bindings for the cryptographic core.
//!
//! This crate exposes the storage-backed identity API that UniFFI projects into foreign-language
//! bindings. Consumers construct a single [`KeyStore`], provide a platform [`SecureStorage`]
//! implementation, and use the keystore to manage the local identity and signed pre-key.
//!
//! # Overview
//!
//! [`KeyStore`] is the entry point for identity and signed-pre-key operations. It delegates
//! persistence to [`SecureStorage`], which production apps must back with secure storage.
//!
//! # Examples
//!
//! ```
//! use aether::{
//!     AetherError, InMemorySecureStorage, KeyStore, SecureStorage, SignedPreKeyBundle,
//! };
//! use std::sync::Arc;
//!
//! # fn publish_signed_prekey_bundle(_bundle: &SignedPreKeyBundle) -> Result<(), AetherError> {
//! #     Ok(())
//! # }
//! let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
//! let store = KeyStore::new(storage);
//!
//! if !store.has_identity()? {
//!     store.generate_identity()?;
//! }
//!
//! if let Some(new_bundle) = store.rotate_signed_prekey_if_stale()? {
//!     publish_signed_prekey_bundle(&new_bundle)?;
//! }
//! # Ok::<(), AetherError>(())
//! ```
//!
//! # Key Concepts
//!
//! - Construct one [`KeyStore`] per app and retain it for the application lifetime.
//! - [`SecureStorage`] is the platform hook. Production builds must back it with their own secure
//!   storage implementation. [`InMemorySecureStorage`] is only for tests and prototypes.
//! - All fallible methods return [`AetherError`].

uniffi::setup_scaffolding!("aether");

mod error;
mod key_store;
mod records;
mod storage;

pub use error::AetherError;
pub use key_store::KeyStore;
pub use records::{DiscoveryKeyBundle, DiscoveryKeyRotationBundle, Identity, SignedPreKeyBundle};
pub use storage::{InMemorySecureStorage, SecureStorage};
