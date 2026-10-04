//! UniFFI records for recoverable KeyStore mutations.

use crate::client::{ContactBlock, SessionAcceptanceResult};
use crate::error::ClientError;
use crate::records::{Identity, InboxRotation, OneTimePreKeyBundle, SignedPreKeyBundle, fixed_16};
use roost_core::{
    KeyStoreOperation as CoreKeyStoreOperation, KeyStoreOperationId as CoreKeyStoreOperationId,
    KeyStoreOperationStatus as CoreKeyStoreOperationStatus,
    SecureStorageExpectedValue as CoreSecureStorageExpectedValue,
    SecureStoragePrecondition as CoreSecureStoragePrecondition,
    UnfinishedKeyStoreOperation as CoreUnfinishedKeyStoreOperation,
};

/// Describes a SecureStorage input that must remain unchanged before an operation commits.
///
/// The digest is opaque host metadata returned by Core. A host persists the enclosing operation
/// identifier with its transaction; Core validates this precondition during `commit_operation`.
///
/// # Examples
/// ```
/// use roost_client::SecureStoragePrecondition;
///
/// let precondition = SecureStoragePrecondition {
///     key: "identity/current".into(),
///     expected_value_digest: None,
/// };
/// assert_eq!(precondition.key, "identity/current");
/// ```
#[derive(Clone, uniffi::Record)]
pub struct SecureStoragePrecondition {
    /// Stable SecureStorage entry name.
    pub key: String,
    /// Domain-separated digest of the expected value, or `None` when the entry must be absent.
    pub expected_value_digest: Option<Vec<u8>>,
}

impl SecureStoragePrecondition {
    fn from_core(precondition: CoreSecureStoragePrecondition) -> Self {
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
///
/// # Examples
/// ```
/// use roost_client::KeyStoreOperation;
///
/// let operation = KeyStoreOperation {
///     id: vec![7; 16],
///     secure_storage_preconditions: Vec::new(),
/// };
/// assert_eq!(operation.id.len(), 16);
/// ```
#[derive(Clone, uniffi::Record)]
pub struct KeyStoreOperation {
    /// Opaque 16-byte identifier to persist with the host transaction.
    pub id: Vec<u8>,
    /// SecureStorage inputs Core validates when the operation commits.
    pub secure_storage_preconditions: Vec<SecureStoragePrecondition>,
}

impl KeyStoreOperation {
    pub(crate) fn from_core(operation: CoreKeyStoreOperation) -> Self {
        Self {
            id: operation.id.as_bytes().to_vec(),
            secure_storage_preconditions: operation
                .secure_storage_preconditions
                .into_iter()
                .map(SecureStoragePrecondition::from_core)
                .collect(),
        }
    }
}

/// Reports the durable phase of a prepared KeyStore operation.
///
/// Hosts use this phase together with their transaction record to decide whether startup recovery
/// aborts an orphan or resumes finalization.
///
/// # Examples
/// ```
/// use roost_client::KeyStoreOperationStatus;
///
/// let status = KeyStoreOperationStatus::Committed;
/// assert!(matches!(status, KeyStoreOperationStatus::Committed));
/// ```
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

impl KeyStoreOperationStatus {
    pub(crate) fn from_core(status: CoreKeyStoreOperationStatus) -> Self {
        match status {
            CoreKeyStoreOperationStatus::Prepared => Self::Prepared,
            CoreKeyStoreOperationStatus::Committed => Self::Committed,
            CoreKeyStoreOperationStatus::Finalizing => Self::Finalizing,
            CoreKeyStoreOperationStatus::Finalized => Self::Finalized,
            CoreKeyStoreOperationStatus::Aborted => Self::Aborted,
        }
    }
}

/// Describes an unfinished operation discovered during startup recovery.
///
/// The host matches the identifier against its own durable transaction record before choosing
/// `finalize_operation` or `abort_operation`.
///
/// # Examples
/// ```
/// use roost_client::{KeyStoreOperation, KeyStoreOperationStatus, UnfinishedKeyStoreOperation};
///
/// let unfinished = UnfinishedKeyStoreOperation {
///     operation: KeyStoreOperation {
///         id: vec![9; 16],
///         secure_storage_preconditions: Vec::new(),
///     },
///     status: KeyStoreOperationStatus::Prepared,
/// };
/// assert_eq!(unfinished.operation.id, vec![9; 16]);
/// ```
#[derive(Clone, uniffi::Record)]
pub struct UnfinishedKeyStoreOperation {
    /// Stable operation metadata.
    pub operation: KeyStoreOperation,
    /// Durable phase that determines whether the host aborts or finalizes recovery.
    pub status: KeyStoreOperationStatus,
}

impl UnfinishedKeyStoreOperation {
    pub(crate) fn from_core(operation: CoreUnfinishedKeyStoreOperation) -> Self {
        Self {
            operation: KeyStoreOperation::from_core(operation.operation),
            status: KeyStoreOperationStatus::from_core(operation.status),
        }
    }
}

/// Carries provisional identity generation output and its recoverable operation.
///
/// Publish or persist the identity only in the host transaction associated with the operation
/// identifier, then finalize the operation.
///
/// # Examples
/// ```
/// use roost_client::PreparedIdentityGeneration;
///
/// fn host_record(prepared: &PreparedIdentityGeneration) -> (&[u8], &[u8]) {
///     (
///         &prepared.operation.id,
///         &prepared.identity.x25519_public_key,
///     )
/// }
/// ```
#[derive(uniffi::Record)]
pub struct PreparedIdentityGeneration {
    /// Recoverable operation metadata.
    pub operation: KeyStoreOperation,
    /// Provisional public identity material.
    pub identity: Identity,
}

/// Carries provisional one-time-prekey output and its recoverable operation.
///
/// The public bundles may be queued for publication in the host transaction; their secret halves
/// remain staged until finalization.
///
/// # Examples
/// ```
/// use roost_client::PreparedOneTimePreKeys;
///
/// fn publication_count(prepared: &PreparedOneTimePreKeys) -> usize {
///     prepared.one_time_prekeys.len()
/// }
/// ```
#[derive(uniffi::Record)]
pub struct PreparedOneTimePreKeys {
    /// Recoverable operation metadata.
    pub operation: KeyStoreOperation,
    /// Provisional public one-time-prekey bundles.
    pub one_time_prekeys: Vec<OneTimePreKeyBundle>,
}

/// Carries a provisional inbox rotation and its recoverable operation.
///
/// The host publishes the returned generation only with the transaction that records the operation
/// identifier; Core keeps the previous generation authoritative until finalization.
///
/// # Examples
/// ```
/// use roost_client::PreparedInboxRotation;
///
/// fn provisional_epoch(prepared: &PreparedInboxRotation) -> u32 {
///     prepared.rotation.publication.discovery_key.epoch
/// }
/// ```
#[derive(uniffi::Record)]
pub struct PreparedInboxRotation {
    /// Recoverable operation metadata.
    pub operation: KeyStoreOperation,
    /// Provisional publication and capability material.
    pub rotation: InboxRotation,
}

/// Carries a provisional signed-prekey rotation and its recoverable operation.
///
/// A `None` bundle represents a no-op staleness check, but its operation still requires finalize
/// or abort so the journal can reach a terminal state.
///
/// # Examples
/// ```
/// use roost_client::PreparedSignedPreKeyRotation;
///
/// fn needs_publication(prepared: &PreparedSignedPreKeyRotation) -> bool {
///     prepared.signed_prekey.is_some()
/// }
/// ```
#[derive(uniffi::Record)]
pub struct PreparedSignedPreKeyRotation {
    /// Recoverable operation metadata.
    pub operation: KeyStoreOperation,
    /// Provisional bundle, absent when a staleness check did not require rotation.
    pub signed_prekey: Option<SignedPreKeyBundle>,
}

/// Carries a provisional contact block and inbox rotation as one recoverable operation.
///
/// Persist the contact update and operation identifier atomically before finalizing the staged
/// SecureStorage rotation.
///
/// # Examples
/// ```
/// use roost_client::PreparedContactBlock;
///
/// fn rotates_inbox(prepared: &PreparedContactBlock) -> bool {
///     prepared.block.rotation.is_some()
/// }
/// ```
#[derive(uniffi::Record)]
pub struct PreparedContactBlock {
    /// Recoverable operation metadata.
    pub operation: KeyStoreOperation,
    /// Provisional contact update and inbox rotation.
    pub block: ContactBlock,
}

/// Carries provisional responder-side Session acceptance as a recoverable operation.
///
/// The host persists the Session updates, plaintext disposition, and operation identifier in one
/// transaction before Core finalizes staged one-time-prekey consumption.
///
/// # Examples
/// ```
/// use roost_client::PreparedSessionAcceptance;
///
/// fn authenticated_plaintext(prepared: &PreparedSessionAcceptance) -> &[u8] {
///     &prepared.acceptance.plaintext
/// }
/// ```
#[derive(uniffi::Record)]
pub struct PreparedSessionAcceptance {
    /// Recoverable operation metadata.
    pub operation: KeyStoreOperation,
    /// Provisional plaintext, sender identity, and protocol-state updates.
    pub acceptance: SessionAcceptanceResult,
}

pub(crate) fn operation_id(id: &[u8]) -> Result<CoreKeyStoreOperationId, ClientError> {
    Ok(CoreKeyStoreOperationId::from_bytes(fixed_16(
        id,
        "operation identifier",
    )?))
}
