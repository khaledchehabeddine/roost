//! Error mapping for failures crossing the UniFFI boundary.

use hermes_core::{IdentityError, KeyStoreError, SignedPreKeyError, StorageError};

/// Errors surfaced across the UniFFI boundary.
///
/// Variants group storage, identity, backup, and internal failures returned through generated
/// bindings. `reason` fields are diagnostic strings for logs and must not drive application
/// logic.
#[derive(Debug, uniffi::Error)]
pub enum HermesError {
    /// An identity already exists in storage.
    AlreadyExists,
    /// Encrypted backup creation failed during randomness, key derivation, or encryption.
    BackupFailed {
        /// Diagnostic failure context for logs only.
        reason: String,
    },
    /// Stored identity keys are incomplete.
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
    /// Requested identity or signed pre-key material is not stored.
    NotFound,
    /// Underlying [`SecureStorage`](crate::SecureStorage) returned a platform error.
    Storage {
        /// Platform-specific error message from the underlying
        /// [`SecureStorage`](crate::SecureStorage) implementation.
        reason: String,
    },
}

impl std::fmt::Display for HermesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HermesError::AlreadyExists => write!(f, "identity already exists"),
            HermesError::BackupFailed { reason } => write!(f, "backup failed: {reason}"),
            HermesError::Corrupt => write!(f, "identity data is corrupt"),
            HermesError::DecryptionFailed => write!(f, "decryption failed"),
            HermesError::InternalError { reason } => write!(f, "internal error: {reason}"),
            HermesError::InvalidData { reason } => write!(f, "invalid data: {reason}"),
            HermesError::NotFound => write!(f, "no identity found"),
            HermesError::Storage { reason } => write!(f, "storage error: {reason}"),
        }
    }
}

impl std::error::Error for HermesError {}

impl From<IdentityError> for HermesError {
    fn from(e: IdentityError) -> Self {
        match e {
            IdentityError::AlreadyExists => HermesError::AlreadyExists,
            IdentityError::BackupFailed(reason) => HermesError::BackupFailed { reason },
            IdentityError::Corrupt => HermesError::Corrupt,
            IdentityError::DecryptionFailed => HermesError::DecryptionFailed,
            IdentityError::InvalidData(reason) => HermesError::InvalidData { reason },
            IdentityError::LockPoisoned => HermesError::InternalError {
                reason: "internal lock poisoned".into(),
            },
            IdentityError::NotFound => HermesError::NotFound,
            IdentityError::Storage(e) => HermesError::Storage {
                reason: e.to_string(),
            },
        }
    }
}

impl From<SignedPreKeyError> for HermesError {
    fn from(e: SignedPreKeyError) -> Self {
        match e {
            SignedPreKeyError::Clock => HermesError::InternalError {
                reason: "system clock is before Unix epoch".into(),
            },
            SignedPreKeyError::Identity(e) => e.into(),
            SignedPreKeyError::InvalidData(reason) => HermesError::InvalidData { reason },
            SignedPreKeyError::LockPoisoned => HermesError::InternalError {
                reason: "internal lock poisoned".into(),
            },
            SignedPreKeyError::NotFound => HermesError::NotFound,
            SignedPreKeyError::Storage(e) => e.into(),
        }
    }
}

impl From<StorageError> for HermesError {
    fn from(e: StorageError) -> Self {
        HermesError::Storage {
            reason: e.to_string(),
        }
    }
}

impl From<KeyStoreError> for HermesError {
    fn from(e: KeyStoreError) -> Self {
        match e {
            KeyStoreError::Identity(e) => e.into(),
            KeyStoreError::SignedPreKey(e) => e.into(),
        }
    }
}
