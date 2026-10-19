//! Prepared SecureStorage operations and the records that carry their provisional output.

use crate::encoding::{hex_identifier, hex_text};
use crate::error::RoostError;
use crate::identity::Identity;
use crate::publication::{PublicOneTimePreKey, PublicSignedPreKey, PublicationBundle};
use roost_core::{
    KeyStoreOperationId as CoreKeyStoreOperationId,
    KeyStoreOperationStatus as CoreKeyStoreOperationStatus,
    UnfinishedKeyStoreOperation as CoreUnfinishedKeyStoreOperation,
};

/// Identifier of one prepared operation, which the host saves in the transaction it commits.
///
/// The value is 32 lowercase hexadecimal digits, so it compares and hashes as a plain string.
#[derive(Clone, Debug, Eq, Hash, PartialEq, uniffi::Record)]
pub struct OperationId {
    /// The identifier's canonical text.
    pub value: String,
}

impl OperationId {
    pub(crate) fn from_core(id: CoreKeyStoreOperationId) -> Self {
        Self {
            value: hex_text(id.as_bytes()),
        }
    }

    pub(crate) fn to_core(&self) -> Result<CoreKeyStoreOperationId, RoostError> {
        Ok(CoreKeyStoreOperationId::from_bytes(hex_identifier(
            &self.value,
            "operation id",
        )?))
    }
}

/// The durable phase of a prepared operation.
///
/// At startup the host compares this with its own transaction record to decide whether to
/// finalize or abort the operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum OperationStatus {
    /// Secret changes are staged and may be reserved or aborted.
    Prepared,
    /// SecureStorage still matches what the operation read, and the host may commit.
    Reserved,
    /// Secret changes are being applied, and finalization must resume after an interruption.
    Finalizing,
    /// Every secret change is applied.
    Finalized,
    /// Staged changes were discarded.
    Aborted,
}

impl OperationStatus {
    pub(crate) fn from_core(status: CoreKeyStoreOperationStatus) -> Self {
        match status {
            CoreKeyStoreOperationStatus::Prepared => Self::Prepared,
            CoreKeyStoreOperationStatus::Reserved => Self::Reserved,
            CoreKeyStoreOperationStatus::Finalizing => Self::Finalizing,
            CoreKeyStoreOperationStatus::Finalized => Self::Finalized,
            CoreKeyStoreOperationStatus::Aborted => Self::Aborted,
        }
    }
}

/// A prepared operation that is neither finalized nor aborted.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct UnfinishedOperation {
    /// The operation's identifier.
    pub id: OperationId,
    /// The operation's durable phase.
    pub status: OperationStatus,
}

impl UnfinishedOperation {
    pub(crate) fn from_core(operation: CoreUnfinishedKeyStoreOperation) -> Self {
        Self {
            id: OperationId::from_core(operation.operation.id),
            status: OperationStatus::from_core(operation.status),
        }
    }
}

/// A new identity, provisional until its operation is finalized.
#[derive(uniffi::Record)]
pub struct PreparedIdentity {
    /// The operation that makes the identity authoritative.
    pub operation_id: OperationId,
    /// The new identity's public keys.
    pub identity: Identity,
}

/// New one-time prekeys, provisional until their operation is finalized.
///
/// The host may queue the public keys for upload in the same transaction that saves the operation
/// ID, and uploads them only after finalization.
#[derive(uniffi::Record)]
pub struct PreparedOneTimePreKeys {
    /// The operation that makes the prekeys usable.
    pub operation_id: OperationId,
    /// The new public one-time prekeys, empty when the pool needed none.
    pub one_time_prekeys: Vec<PublicOneTimePreKey>,
}

/// An inbox rotation, provisional until its operation is finalized.
///
/// The previous Discovery Key stays current until finalization.
#[derive(uniffi::Record)]
pub struct PreparedInboxRotation {
    /// The operation that makes the new Discovery Key current.
    pub operation_id: OperationId,
    /// The new inbox's publication, to publish and register after finalization.
    pub publication: PublicationBundle,
}

/// A new signed prekey, provisional until its operation is finalized.
#[derive(uniffi::Record)]
pub struct PreparedSignedPreKeyRotation {
    /// The operation that makes the signed prekey current.
    pub operation_id: OperationId,
    /// The new public signed prekey, absent when the current one wasn't stale.
    pub signed_prekey: Option<PublicSignedPreKey>,
}
