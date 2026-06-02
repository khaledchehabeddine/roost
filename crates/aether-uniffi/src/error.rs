//! Error mapping for failures crossing the UniFFI boundary.

use aether_core::{
    DiscoveryKeyError, IdentityError, KeyStoreError, SignedPreKeyError, StorageError,
};

/// Errors surfaced across the UniFFI boundary.
///
/// Variants group storage, identity, backup, and internal failures returned through generated
/// bindings. `reason` fields are diagnostic strings for logs and must not drive application
/// logic.
#[derive(Debug, uniffi::Error)]
pub enum AetherError {
    /// An identity already exists in storage.
    AlreadyExists,
    /// Encrypted backup creation failed during randomness, key derivation, or encryption.
    BackupFailed {
        /// Diagnostic failure context for logs only.
        reason: String,
    },
    /// Stored identity, discovery key, or signed pre-key material is corrupt or incomplete.
    Corrupt,
    /// Backup decryption failed because the passphrase or backup bytes did not authenticate.
    DecryptionFailed,
    /// Internal failure that does not expose a more specific failure category.
    InternalError {
        /// Diagnostic context for logging only.
        reason: String,
    },
    /// Input bytes are malformed or the wrong length.
    InvalidData {
        /// Description of what was invalid for logging only.
        reason: String,
    },
    /// Requested identity, discovery-key, or signed-pre-key material is not stored.
    NotFound,
    /// Underlying [`SecureStorage`](crate::SecureStorage) returned a platform error.
    Storage {
        /// Platform-specific error message from the underlying
        /// [`SecureStorage`](crate::SecureStorage) implementation.
        reason: String,
    },
}

impl std::error::Error for AetherError {}

impl std::fmt::Display for AetherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AetherError::AlreadyExists => write!(f, "identity already exists"),
            AetherError::BackupFailed { reason } => write!(f, "backup failed: {reason}"),
            AetherError::Corrupt => write!(f, "stored key material is corrupt"),
            AetherError::DecryptionFailed => write!(f, "decryption failed"),
            AetherError::InternalError { reason } => write!(f, "internal error: {reason}"),
            AetherError::InvalidData { reason } => write!(f, "invalid data: {reason}"),
            AetherError::NotFound => write!(f, "key material not found"),
            AetherError::Storage { reason } => write!(f, "storage error: {reason}"),
        }
    }
}

impl From<IdentityError> for AetherError {
    fn from(e: IdentityError) -> Self {
        match e {
            IdentityError::AlreadyExists => AetherError::AlreadyExists,
            IdentityError::BackupFailed(reason) => AetherError::BackupFailed { reason },
            IdentityError::Corrupt => AetherError::Corrupt,
            IdentityError::DecryptionFailed => AetherError::DecryptionFailed,
            IdentityError::InvalidData(reason) => AetherError::InvalidData { reason },
            IdentityError::LockPoisoned => AetherError::InternalError {
                reason: "internal lock poisoned".into(),
            },
            IdentityError::NotFound => AetherError::NotFound,
            IdentityError::Storage(e) => AetherError::Storage {
                reason: e.to_string(),
            },
        }
    }
}

impl From<SignedPreKeyError> for AetherError {
    fn from(e: SignedPreKeyError) -> Self {
        match e {
            SignedPreKeyError::Clock => AetherError::InternalError {
                reason: "system clock is before Unix epoch".into(),
            },
            SignedPreKeyError::Corrupt => AetherError::Corrupt,
            SignedPreKeyError::Discovery(e) => e.into(),
            SignedPreKeyError::InvalidData(reason) => AetherError::InvalidData { reason },
            SignedPreKeyError::LockPoisoned => AetherError::InternalError {
                reason: "internal lock poisoned".into(),
            },
            SignedPreKeyError::NotFound => AetherError::NotFound,
            SignedPreKeyError::Storage(e) => e.into(),
        }
    }
}

impl From<DiscoveryKeyError> for AetherError {
    fn from(e: DiscoveryKeyError) -> Self {
        match e {
            DiscoveryKeyError::Clock => AetherError::InternalError {
                reason: "system clock is before Unix epoch".into(),
            },
            DiscoveryKeyError::Corrupt => AetherError::Corrupt,
            DiscoveryKeyError::Identity(e) => e.into(),
            DiscoveryKeyError::InvalidData(reason) => AetherError::InvalidData { reason },
            DiscoveryKeyError::LockPoisoned => AetherError::InternalError {
                reason: "internal lock poisoned".into(),
            },
            DiscoveryKeyError::NotFound => AetherError::NotFound,
            DiscoveryKeyError::Storage(e) => e.into(),
        }
    }
}

impl From<StorageError> for AetherError {
    fn from(e: StorageError) -> Self {
        AetherError::Storage {
            reason: e.to_string(),
        }
    }
}

impl From<KeyStoreError> for AetherError {
    fn from(e: KeyStoreError) -> Self {
        match e {
            KeyStoreError::Discovery(e) => e.into(),
            KeyStoreError::Identity(e) => e.into(),
            KeyStoreError::SignedPreKey(e) => e.into(),
        }
    }
}
