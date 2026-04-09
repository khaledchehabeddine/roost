//! Core domain logic for Hermes.
//!
//! [`IdentityManager`] generates, persists, and loads a local device identity (an
//! X25519 + Ed25519 key pair) and supports encrypted backup via Argon2id key
//! derivation and XChaCha20-Poly1305 encryption.
//!
//! Storage is abstracted behind the [`SecureStorage`] trait so each platform can
//! inject its own implementation. [`InMemorySecureStorage`] is provided for testing.
//! [`SecureStorage`] requires only `Send` because [`IdentityManager`] wraps the
//! backend in a `Mutex`, which lifts `Send` to `Sync`. The FFI layer in
//! `hermes-uniffi` requires `Send + Sync` because `Arc<dyn SecureStorage>` is shared
//! without an internal mutex.

pub mod identity;
pub mod storage;

pub use identity::{Identity, IdentityError, IdentityManager};
pub use storage::{InMemorySecureStorage, SecureStorage, StorageError};
