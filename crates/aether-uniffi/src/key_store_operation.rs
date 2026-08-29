//! UniFFI records for recoverable KeyStore mutations.

use crate::error::AetherError;
use crate::key_store::{ContactBlock, SessionAcceptanceResult};
use crate::records::{Identity, InboxRotation, OneTimePreKeyBundle, SignedPreKeyBundle, fixed_16};
use aether_core::{
    KeyStoreOperation as CoreKeyStoreOperation,
    KeyStoreOperationIdentifier as CoreKeyStoreOperationIdentifier,
    KeyStoreOperationStatus as CoreKeyStoreOperationStatus,
    SecureStorageExpectedValue as CoreSecureStorageExpectedValue,
    SecureStoragePrecondition as CoreSecureStoragePrecondition,
    UnfinishedKeyStoreOperation as CoreUnfinishedKeyStoreOperation,
};

/// SecureStorage input that must remain unchanged before an operation commits.
#[derive(Clone, uniffi::Record)]
pub struct SecureStoragePrecondition {
    /// Stable SecureStorage entry name.
    pub key: String,
    /// Domain-separated digest of the expected value, or `None` when the entry must be absent.
    pub expected_value_digest: Option<Vec<u8>>,
}

impl From<CoreSecureStoragePrecondition> for SecureStoragePrecondition {
    fn from(precondition: CoreSecureStoragePrecondition) -> Self {
        let expected_value_digest = match precondition.expected_value {
            CoreSecureStorageExpectedValue::Absent => None,
            CoreSecureStorageExpectedValue::Digest(digest) => Some(digest.to_vec()),
        };
        Self {
            key: precondition.key,
            expected_value_digest,
        }
    }
}

/// Stable metadata for a prepared KeyStore operation.
///
/// Every returned operation must be finalized or aborted, including operations whose provisional
/// payload reports that no mutation was needed.
#[derive(Clone, uniffi::Record)]
pub struct KeyStoreOperation {
    /// Opaque 16-byte identifier to persist with the host transaction.
    pub identifier: Vec<u8>,
    /// SecureStorage inputs Core validates when the operation commits.
    pub secure_storage_preconditions: Vec<SecureStoragePrecondition>,
}

impl From<CoreKeyStoreOperation> for KeyStoreOperation {
    fn from(operation: CoreKeyStoreOperation) -> Self {
        Self {
            identifier: operation.identifier.as_bytes().to_vec(),
            secure_storage_preconditions: operation
                .secure_storage_preconditions
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    }
}

/// Durable phase of a prepared KeyStore operation.
#[derive(Clone, Copy, uniffi::Enum)]
pub enum KeyStoreOperationStatus {
    /// Secret mutations are staged and may be committed or aborted.
    Prepared,
    /// Preconditions matched and the host may commit its durable transaction.
    Committed,
    /// Secure mutations are being finalized and recovery must resume.
    Finalizing,
    /// Every secure mutation is authoritative.
    Finalized,
    /// Staged material was discarded before finalization began.
    Aborted,
}

impl From<CoreKeyStoreOperationStatus> for KeyStoreOperationStatus {
    fn from(status: CoreKeyStoreOperationStatus) -> Self {
        match status {
            CoreKeyStoreOperationStatus::Prepared => Self::Prepared,
            CoreKeyStoreOperationStatus::Committed => Self::Committed,
            CoreKeyStoreOperationStatus::Finalizing => Self::Finalizing,
            CoreKeyStoreOperationStatus::Finalized => Self::Finalized,
            CoreKeyStoreOperationStatus::Aborted => Self::Aborted,
        }
    }
}

/// An unfinished operation discovered during startup recovery.
#[derive(Clone, uniffi::Record)]
pub struct UnfinishedKeyStoreOperation {
    /// Stable operation metadata.
    pub operation: KeyStoreOperation,
    /// Durable phase that determines whether the host aborts or finalizes recovery.
    pub status: KeyStoreOperationStatus,
}

impl From<CoreUnfinishedKeyStoreOperation> for UnfinishedKeyStoreOperation {
    fn from(operation: CoreUnfinishedKeyStoreOperation) -> Self {
        Self {
            operation: operation.operation.into(),
            status: operation.status.into(),
        }
    }
}

/// Prepared identity generation result.
#[derive(uniffi::Record)]
pub struct PreparedIdentityGeneration {
    /// Recoverable operation metadata.
    pub operation: KeyStoreOperation,
    /// Provisional public identity material.
    pub identity: Identity,
}

/// Prepared one-time-prekey generation or replenishment result.
#[derive(uniffi::Record)]
pub struct PreparedOneTimePreKeys {
    /// Recoverable operation metadata.
    pub operation: KeyStoreOperation,
    /// Provisional public one-time-prekey bundles.
    pub one_time_prekeys: Vec<OneTimePreKeyBundle>,
}

/// Prepared inbox rotation result.
#[derive(uniffi::Record)]
pub struct PreparedInboxRotation {
    /// Recoverable operation metadata.
    pub operation: KeyStoreOperation,
    /// Provisional publication and capability material.
    pub rotation: InboxRotation,
}

/// Prepared signed-prekey rotation result.
#[derive(uniffi::Record)]
pub struct PreparedSignedPreKeyRotation {
    /// Recoverable operation metadata.
    pub operation: KeyStoreOperation,
    /// Provisional bundle, absent when a staleness check did not require rotation.
    pub signed_prekey: Option<SignedPreKeyBundle>,
}

/// Prepared contact-block result.
#[derive(uniffi::Record)]
pub struct PreparedContactBlock {
    /// Recoverable operation metadata.
    pub operation: KeyStoreOperation,
    /// Provisional contact update and inbox rotation.
    pub block: ContactBlock,
}

/// Prepared responder-side Session acceptance result.
#[derive(uniffi::Record)]
pub struct PreparedSessionAcceptance {
    /// Recoverable operation metadata.
    pub operation: KeyStoreOperation,
    /// Provisional plaintext, sender identity, and protocol-state updates.
    pub acceptance: SessionAcceptanceResult,
}

pub(crate) fn operation_identifier(
    identifier: &[u8],
) -> Result<CoreKeyStoreOperationIdentifier, AetherError> {
    Ok(CoreKeyStoreOperationIdentifier::from_bytes(fixed_16(
        identifier,
        "operation identifier",
    )?))
}
