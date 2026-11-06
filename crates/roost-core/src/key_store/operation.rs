use super::{KeyStore, KeyStoreError};
use crate::storage::{SecureStorage, StorageError};
use crate::stored_data::{
    StoredDataError, decode_versioned, deserialize_bounded, encode_versioned,
};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const OPERATION_JOURNAL_KEY: &str = "operation/journal";
const OPERATION_JOURNAL_VERSION: u8 = 2;
const OPERATION_ID_LEN: usize = 16;
const PRECONDITION_DIGEST_LEN: usize = 32;
const MAX_OPERATION_RECORDS: usize = 32;
const MAX_UNFINISHED_OPERATIONS: usize = 16;
const MAX_OPERATION_PRECONDITIONS: usize = 32;
const MAX_OPERATION_MUTATIONS: usize = 16;
const MAX_STORAGE_KEY_LEN: usize = 128;
const MAX_STAGED_VALUE_LEN: usize = 128 * 1024;
const MAX_OPERATION_JOURNAL_LEN: usize = 2 * 1024 * 1024;
const ID_GENERATION_ATTEMPTS: usize = 8;
const SECURE_STORAGE_PRECONDITION_CONTEXT: &str = "RoostSecureStoragePrecondition-v1";

/// Stable identifier for one prepared KeyStore operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct KeyStoreOperationId([u8; OPERATION_ID_LEN]);

impl KeyStoreOperationId {
    /// Creates an identifier from its stable byte encoding.
    pub fn from_bytes(bytes: [u8; OPERATION_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the stable byte encoding.
    pub fn as_bytes(&self) -> &[u8; OPERATION_ID_LEN] {
        &self.0
    }
}

/// An output computed from staged keys, and the operation that makes those keys authoritative.
///
/// Every returned operation must be finalized or aborted, even when its output reports that
/// nothing needed to change.
pub struct PreparedKeyStoreOperation<T> {
    /// Stable identifier the host persists with its atomic transaction.
    pub id: KeyStoreOperationId,
    /// Caller-visible result computed from the staged state.
    pub output: T,
}

/// Durable phase of a prepared KeyStore operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyStoreOperationStatus {
    /// Secret mutations are staged and may be reserved or aborted.
    Prepared,
    /// Preconditions matched and the host may commit its durable transaction.
    Reserved,
    /// Secure mutations are being made authoritative and recovery must resume finalization.
    Finalizing,
    /// Every secure mutation is authoritative.
    Finalized,
    /// Staged material was discarded before finalization began.
    Aborted,
}

/// An unfinished operation discovered during recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnfinishedKeyStoreOperation {
    /// Stable identifier the host persisted with its transaction.
    pub id: KeyStoreOperationId,
    /// Durable phase that determines whether the host aborts or finalizes recovery.
    pub status: KeyStoreOperationStatus,
}

/// Errors returned by the prepared KeyStore operation lifecycle.
#[derive(Debug, thiserror::Error)]
pub enum KeyStoreOperationError {
    /// The persisted operation journal is malformed, or can't hold a new operation.
    #[error("prepared-operation journal is corrupt")]
    Corrupt(#[from] JournalCorruption),
    /// Every generated operation identifier collided with a retained one.
    #[error("operation identifier generation kept colliding")]
    IdCollision,
    /// An operation cannot perform the requested lifecycle transition.
    #[error("cannot {action} prepared operation in {status:?} state")]
    InvalidTransition {
        /// Current durable status.
        status: KeyStoreOperationStatus,
        /// Requested lifecycle action.
        action: &'static str,
    },
    /// The in-process storage lock was poisoned.
    #[error("prepared-operation lock poisoned")]
    LockPoisoned,
    /// No retained operation has the requested identifier.
    #[error("prepared operation not found")]
    NotFound,
    /// An authoritative SecureStorage input changed after preparation.
    #[error("secure-storage precondition changed for {key}")]
    PreconditionChanged {
        /// Stable SecureStorage entry name.
        key: String,
    },
    /// The OS CSPRNG could not produce an operation identifier.
    #[error("operation identifier generation failed")]
    Randomness(#[source] rand::Error),
    /// A previously reserved operation must be finalized or aborted before more work proceeds.
    #[error("an unfinished prepared operation must be finalized or aborted first")]
    RecoveryRequired {
        /// Identifier of the unfinished operation.
        id: KeyStoreOperationId,
    },
    /// SecureStorage returned a platform failure.
    #[error("prepared-operation storage failed")]
    Storage(#[from] StorageError),
    /// The bounded unfinished-operation journal is full.
    #[error("too many unfinished prepared operations")]
    TooManyUnfinishedOperations,
}

/// A reason the prepared-operation journal can't be read, written, or hold a new operation.
#[derive(Debug, thiserror::Error)]
pub enum JournalCorruption {
    /// An operation stages the same SecureStorage entry twice.
    #[error("operation stages secure-storage entry {key} twice")]
    DuplicateMutation {
        /// Stable SecureStorage entry name.
        key: String,
    },
    /// Two operations share an identifier.
    #[error("operation journal contains duplicate identifiers")]
    DuplicateOperationIds,
    /// An operation checks the same SecureStorage entry twice.
    #[error("operation checks secure-storage entry {key} twice")]
    DuplicatePrecondition {
        /// Stable SecureStorage entry name.
        key: String,
    },
    /// Finalization progress can't advance past the largest one-byte value.
    #[error("finalization progress exceeds limit")]
    FinalizationProgressOverflow,
    /// A finalizing operation's progress is past its last mutation.
    #[error("finalization progress {next_mutation} is past the {mutations} staged mutations")]
    FinalizationProgressOutOfRange {
        /// Index of the next mutation to apply.
        next_mutation: u8,
        /// Number of staged mutations.
        mutations: usize,
    },
    /// A finalizing operation's record has a status other than finalizing.
    #[error("finalization progress has an invalid status")]
    InvalidFinalizationStatus,
    /// A SecureStorage entry name is empty or too long.
    #[error("secure-storage key length {len} is outside 1..={max}")]
    InvalidStorageKeyLength {
        /// Entry name length in bytes.
        len: usize,
        /// Longest accepted length in bytes.
        max: usize,
    },
    /// The journal is longer than its limit.
    #[error("operation journal is {len} bytes, longer than {max}")]
    JournalTooLong {
        /// Journal length in bytes.
        len: usize,
        /// Longest accepted length in bytes.
        max: usize,
    },
    /// An operation stages a SecureStorage entry it doesn't check first.
    #[error("operation stages secure-storage entry {key} without a precondition")]
    MutationWithoutPrecondition {
        /// Stable SecureStorage entry name.
        key: String,
    },
    /// An operation reads or stages the journal's own SecureStorage entry.
    #[error("operation touches the prepared-operation journal entry")]
    ReservedStorageKey,
    /// A staged SecureStorage value is longer than its limit.
    #[error("staged secure value is {len} bytes, longer than {max}")]
    StagedValueTooLong {
        /// Value length in bytes.
        len: usize,
        /// Longest accepted length in bytes.
        max: usize,
    },
    /// The journal failed to encode, or the stored one is malformed or uses an unknown version.
    #[error("operation journal failed to encode or decode")]
    StoredData(#[from] StoredDataError),
    /// A finalized or aborted operation still holds staged material.
    #[error("a finished operation still holds staged material")]
    TerminalRecordNotScrubbed,
    /// An operation stages more SecureStorage entries than the limit allows.
    #[error("operation has {count} secure-storage mutations, more than {max}")]
    TooManyMutations {
        /// Mutation count.
        count: usize,
        /// Largest accepted count.
        max: usize,
    },
    /// An operation checks more SecureStorage entries than the limit allows.
    #[error("operation has {count} secure-storage preconditions, more than {max}")]
    TooManyPreconditions {
        /// Precondition count.
        count: usize,
        /// Largest accepted count.
        max: usize,
    },
    /// The journal holds more operations than the limit allows.
    #[error("operation journal has {count} records, more than {max}")]
    TooManyRecords {
        /// Record count.
        count: usize,
        /// Largest accepted count.
        max: usize,
    },
}

#[derive(Clone, Copy)]
enum JournalStatus {
    Prepared,
    Reserved,
    Finalizing { next_mutation: u8 },
    Finalized,
    Aborted,
}

impl JournalStatus {
    fn public(self) -> KeyStoreOperationStatus {
        match self {
            Self::Prepared => KeyStoreOperationStatus::Prepared,
            Self::Reserved => KeyStoreOperationStatus::Reserved,
            Self::Finalizing { .. } => KeyStoreOperationStatus::Finalizing,
            Self::Finalized => KeyStoreOperationStatus::Finalized,
            Self::Aborted => KeyStoreOperationStatus::Aborted,
        }
    }

    fn is_unfinished(self) -> bool {
        matches!(
            self,
            Self::Prepared | Self::Reserved | Self::Finalizing { .. }
        )
    }

    fn requires_recovery(self) -> bool {
        matches!(self, Self::Reserved | Self::Finalizing { .. })
    }

    fn to_wire(self) -> JournalStatusWire {
        match self {
            Self::Prepared => JournalStatusWire::Prepared,
            Self::Reserved => JournalStatusWire::Reserved,
            Self::Finalizing { next_mutation } => JournalStatusWire::Finalizing(next_mutation),
            Self::Finalized => JournalStatusWire::Finalized,
            Self::Aborted => JournalStatusWire::Aborted,
        }
    }

    fn from_wire(wire: JournalStatusWire) -> Self {
        match wire {
            JournalStatusWire::Prepared => Self::Prepared,
            JournalStatusWire::Reserved => Self::Reserved,
            JournalStatusWire::Finalizing(next_mutation) => Self::Finalizing { next_mutation },
            JournalStatusWire::Finalized => Self::Finalized,
            JournalStatusWire::Aborted => Self::Aborted,
        }
    }
}

// The value one SecureStorage entry must still hold when an operation is reserved.
#[derive(Clone, Debug, Eq, PartialEq)]
enum SecureStorageExpectedValue {
    // The entry must not exist.
    Absent,
    // The entry's value must match this domain-separated digest.
    Digest([u8; PRECONDITION_DIGEST_LEN]),
}

// A SecureStorage entry an operation read, which must be unchanged when it is reserved.
#[derive(Clone, Debug, Eq, PartialEq)]
struct SecureStoragePrecondition {
    key: String,
    expected_value: SecureStorageExpectedValue,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct StagedMutation {
    #[zeroize(skip)]
    key: String,
    value: Option<Zeroizing<Vec<u8>>>,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct JournalRecord {
    #[zeroize(skip)]
    id: KeyStoreOperationId,
    #[zeroize(skip)]
    status: JournalStatus,
    #[zeroize(skip)]
    preconditions: Vec<SecureStoragePrecondition>,
    mutations: Vec<StagedMutation>,
}

impl JournalRecord {
    fn unfinished(&self) -> UnfinishedKeyStoreOperation {
        UnfinishedKeyStoreOperation {
            id: self.id,
            status: self.status.public(),
        }
    }

    fn scrub_staged_material(&mut self) {
        self.mutations.clear();
        self.preconditions.clear();
    }

    // Checks every limit and invariant of one record, both before it's written and after it's
    // read back.
    fn validate(&self) -> Result<(), JournalCorruption> {
        let preconditions = self.preconditions.len();
        if preconditions > MAX_OPERATION_PRECONDITIONS {
            return Err(JournalCorruption::TooManyPreconditions {
                count: preconditions,
                max: MAX_OPERATION_PRECONDITIONS,
            });
        }
        let mutations = self.mutations.len();
        if mutations > MAX_OPERATION_MUTATIONS {
            return Err(JournalCorruption::TooManyMutations {
                count: mutations,
                max: MAX_OPERATION_MUTATIONS,
            });
        }
        let mut checked = BTreeSet::new();
        for precondition in &self.preconditions {
            check_storage_key(&precondition.key)?;
            if !checked.insert(precondition.key.as_str()) {
                return Err(JournalCorruption::DuplicatePrecondition {
                    key: precondition.key.clone(),
                });
            }
        }
        let mut staged = BTreeSet::new();
        for mutation in &self.mutations {
            check_storage_key(&mutation.key)?;
            if !staged.insert(mutation.key.as_str()) {
                return Err(JournalCorruption::DuplicateMutation {
                    key: mutation.key.clone(),
                });
            }
            if !checked.contains(mutation.key.as_str()) {
                return Err(JournalCorruption::MutationWithoutPrecondition {
                    key: mutation.key.clone(),
                });
            }
            if let Some(value) = &mutation.value
                && value.len() > MAX_STAGED_VALUE_LEN
            {
                return Err(JournalCorruption::StagedValueTooLong {
                    len: value.len(),
                    max: MAX_STAGED_VALUE_LEN,
                });
            }
        }
        match self.status {
            JournalStatus::Finalizing { next_mutation }
                if usize::from(next_mutation) > mutations =>
            {
                Err(JournalCorruption::FinalizationProgressOutOfRange {
                    next_mutation,
                    mutations,
                })
            }
            JournalStatus::Finalized | JournalStatus::Aborted
                if preconditions != 0 || mutations != 0 =>
            {
                Err(JournalCorruption::TerminalRecordNotScrubbed)
            }
            JournalStatus::Prepared
            | JournalStatus::Reserved
            | JournalStatus::Finalizing { .. }
            | JournalStatus::Finalized
            | JournalStatus::Aborted => Ok(()),
        }
    }

    fn to_wire(&self) -> JournalRecordWire<'_> {
        JournalRecordWire {
            id: self.id.0,
            status: self.status.to_wire(),
            preconditions: self
                .preconditions
                .iter()
                .map(|precondition| PreconditionWire {
                    key: &precondition.key,
                    digest: match precondition.expected_value {
                        SecureStorageExpectedValue::Absent => None,
                        SecureStorageExpectedValue::Digest(digest) => Some(digest),
                    },
                })
                .collect(),
            mutations: self
                .mutations
                .iter()
                .map(|mutation| MutationWire {
                    key: &mutation.key,
                    value: mutation.value.as_deref().map(Vec::as_slice),
                })
                .collect(),
        }
    }

    fn from_wire(wire: &JournalRecordWire<'_>) -> Result<Self, JournalCorruption> {
        let record = Self {
            id: KeyStoreOperationId(wire.id),
            status: JournalStatus::from_wire(wire.status),
            preconditions: wire
                .preconditions
                .iter()
                .map(|precondition| SecureStoragePrecondition {
                    key: precondition.key.to_owned(),
                    expected_value: precondition
                        .digest
                        .map_or(SecureStorageExpectedValue::Absent, |digest| {
                            SecureStorageExpectedValue::Digest(digest)
                        }),
                })
                .collect(),
            mutations: wire
                .mutations
                .iter()
                .map(|mutation| StagedMutation {
                    key: mutation.key.to_owned(),
                    value: mutation.value.map(|value| Zeroizing::new(value.to_vec())),
                })
                .collect(),
        };
        record.validate()?;
        Ok(record)
    }
}

#[derive(Default, Zeroize, ZeroizeOnDrop)]
struct OperationJournal {
    records: Vec<JournalRecord>,
}

#[derive(Deserialize, Serialize)]
struct OperationJournalWire<'a> {
    #[serde(
        borrow,
        deserialize_with = "deserialize_bounded::<_, _, MAX_OPERATION_RECORDS>"
    )]
    records: Vec<JournalRecordWire<'a>>,
}

#[derive(Deserialize, Serialize)]
struct JournalRecordWire<'a> {
    id: [u8; OPERATION_ID_LEN],
    status: JournalStatusWire,
    #[serde(
        borrow,
        deserialize_with = "deserialize_bounded::<_, _, MAX_OPERATION_PRECONDITIONS>"
    )]
    preconditions: Vec<PreconditionWire<'a>>,
    #[serde(
        borrow,
        deserialize_with = "deserialize_bounded::<_, _, MAX_OPERATION_MUTATIONS>"
    )]
    mutations: Vec<MutationWire<'a>>,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
enum JournalStatusWire {
    Prepared,
    Reserved,
    // The index of the next mutation to apply.
    Finalizing(u8),
    Finalized,
    Aborted,
}

#[derive(Deserialize, Serialize)]
struct PreconditionWire<'a> {
    key: &'a str,
    // The digest the entry's value must match, or `None` when the entry must be absent.
    digest: Option<[u8; PRECONDITION_DIGEST_LEN]>,
}

#[derive(Deserialize, Serialize)]
struct MutationWire<'a> {
    key: &'a str,
    // The value to store, or `None` to delete the entry.
    #[serde(borrow)]
    value: Option<&'a [u8]>,
}

#[derive(Default, Zeroize, ZeroizeOnDrop)]
struct StagingState {
    #[zeroize(skip)]
    preconditions: BTreeMap<String, SecureStorageExpectedValue>,
    // BTreeMap does not implement Zeroize; every secret value is independently Zeroizing.
    #[zeroize(skip)]
    observed: BTreeMap<String, Option<Zeroizing<Vec<u8>>>>,
    // BTreeMap does not implement Zeroize; every secret value is independently Zeroizing.
    #[zeroize(skip)]
    mutations: BTreeMap<String, Option<Zeroizing<Vec<u8>>>>,
}

impl StagingState {
    fn preconditions(&self) -> Vec<SecureStoragePrecondition> {
        self.preconditions
            .iter()
            .map(|(key, expected_value)| SecureStoragePrecondition {
                key: key.clone(),
                expected_value: expected_value.clone(),
            })
            .collect()
    }

    fn mutations(&self) -> Vec<StagedMutation> {
        self.mutations
            .iter()
            .map(|(key, value)| StagedMutation {
                key: key.clone(),
                value: value.as_ref().map(|bytes| Zeroizing::new(bytes.to_vec())),
            })
            .collect()
    }
}

// SecureStorage that records what an operation reads and writes without changing the
// authoritative storage.
struct StagingSecureStorage {
    authoritative: Arc<Mutex<Box<dyn SecureStorage>>>,
    state: Arc<Mutex<StagingState>>,
}

impl StagingSecureStorage {
    fn new(authoritative: Arc<Mutex<Box<dyn SecureStorage>>>) -> (Self, Arc<Mutex<StagingState>>) {
        let state = Arc::new(Mutex::new(StagingState::default()));
        (
            Self {
                authoritative,
                state: Arc::clone(&state),
            },
            state,
        )
    }

    // Returns the staged value of `key`, reading the authoritative value and recording it as a
    // precondition the first time.
    fn observe(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
        {
            let state = lock_staging(&self.state);
            if let Some(value) = state.mutations.get(key).or_else(|| state.observed.get(key)) {
                return Ok(value.as_ref().map(|bytes| Zeroizing::new(bytes.to_vec())));
            }
        }

        let loaded = self
            .authoritative
            .lock()
            .map_err(|_| StorageError::IO("secure-storage lock poisoned".into()))?
            .load(key)?;
        let mut state = lock_staging(&self.state);
        state
            .preconditions
            .entry(key.to_owned())
            .or_insert(expected_value(loaded.as_deref().map(Vec::as_slice)));
        state.observed.insert(
            key.to_owned(),
            loaded.as_ref().map(|bytes| Zeroizing::new(bytes.to_vec())),
        );
        Ok(loaded)
    }
}

impl SecureStorage for StagingSecureStorage {
    fn store(&mut self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        self.observe(key)?;
        lock_staging(&self.state)
            .mutations
            .insert(key.to_owned(), Some(Zeroizing::new(value.to_vec())));
        Ok(())
    }

    fn load(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
        self.observe(key)
    }

    fn delete(&mut self, key: &str) -> Result<(), StorageError> {
        self.observe(key)?;
        lock_staging(&self.state)
            .mutations
            .insert(key.to_owned(), None);
        Ok(())
    }
}

// Only the thread preparing an operation holds the staging state, and a panic there ends the
// preparation, so a poisoned lock can't expose half-made changes.
fn lock_staging(state: &Mutex<StagingState>) -> MutexGuard<'_, StagingState> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

impl KeyStore {
    pub(super) fn prepare_operation<T, E>(
        &self,
        operation: impl FnOnce(&KeyStore) -> Result<T, E>,
    ) -> Result<PreparedKeyStoreOperation<T>, E>
    where
        E: From<KeyStoreOperationError>,
    {
        let _lifecycle = self.lifecycle_guard();
        self.ensure_no_recovery_required()?;

        let (staging_storage, state) = StagingSecureStorage::new(Arc::clone(&self.0.storage));
        let staged_store = KeyStore::from_shared_storage(
            Arc::new(Mutex::new(Box::new(staging_storage))),
            self.0.engine,
        );
        let output = operation(&staged_store)?;
        let state = lock_staging(&state);
        let id = self.stage_operation(state.preconditions(), state.mutations())?;
        Ok(PreparedKeyStoreOperation { id, output })
    }

    /// Returns the durable status of a retained prepared operation.
    ///
    /// Use this after an ambiguous lifecycle call or while reconciling startup state. Terminal
    /// tombstones are retained only within the bounded operation journal, so a sufficiently old
    /// finalized or aborted identifier may be unknown.
    pub fn operation_status(
        &self,
        id: KeyStoreOperationId,
    ) -> Result<KeyStoreOperationStatus, KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        let storage = self.lock_operation_storage()?;
        let journal = load_journal(&**storage)?;
        Ok(journal.records[record_index(&journal, id)?].status.public())
    }

    /// Validates secure inputs and reserves an operation for the host transaction.
    ///
    /// Calling this repeatedly after a successful reservation is idempotent. The caller must next
    /// commit the returned protocol state updates and outputs atomically, then call
    /// [`Self::finalize_operation`]. Abort only after proving the host transaction did not commit.
    /// If the host result is ambiguous, reload its operation record and reconcile it through
    /// [`Self::unfinished_operations`].
    pub fn reserve_operation(
        &self,
        id: KeyStoreOperationId,
    ) -> Result<KeyStoreOperationStatus, KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        let mut storage = self.lock_operation_storage()?;
        let mut journal = load_journal(&**storage)?;
        let index = record_index(&journal, id)?;
        let status = journal.records[index].status;
        match status {
            JournalStatus::Prepared => {
                if let Some(record) = journal
                    .records
                    .iter()
                    .find(|record| record.id != id && record.status.requires_recovery())
                {
                    return Err(KeyStoreOperationError::RecoveryRequired { id: record.id }.into());
                }
                validate_preconditions(&**storage, &journal.records[index].preconditions)?;
                journal.records[index].status = JournalStatus::Reserved;
                store_journal(&mut **storage, &journal)?;
                Ok(KeyStoreOperationStatus::Reserved)
            }
            JournalStatus::Reserved => Ok(KeyStoreOperationStatus::Reserved),
            JournalStatus::Finalizing { .. } => Ok(KeyStoreOperationStatus::Finalizing),
            JournalStatus::Finalized => Ok(KeyStoreOperationStatus::Finalized),
            JournalStatus::Aborted => Err(KeyStoreOperationError::InvalidTransition {
                status: status.public(),
                action: "reserve",
            }
            .into()),
        }
    }

    /// Makes a reserved operation's staged secure mutations authoritative.
    ///
    /// Finalization records progress after every SecureStorage mutation. Repeating the call resumes
    /// at the last durable step, and repeating it after completion is idempotent. Once finalization
    /// starts, retry a failure with this method; the operation can no longer be aborted safely.
    pub fn finalize_operation(
        &self,
        id: KeyStoreOperationId,
    ) -> Result<KeyStoreOperationStatus, KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        let mut storage = self.lock_operation_storage()?;
        let mut journal = load_journal(&**storage)?;
        let index = record_index(&journal, id)?;
        match journal.records[index].status {
            JournalStatus::Prepared | JournalStatus::Aborted => {
                return Err(KeyStoreOperationError::InvalidTransition {
                    status: journal.records[index].status.public(),
                    action: "finalize",
                }
                .into());
            }
            JournalStatus::Finalized => return Ok(KeyStoreOperationStatus::Finalized),
            JournalStatus::Reserved => {
                journal.records[index].status = JournalStatus::Finalizing { next_mutation: 0 };
                store_journal(&mut **storage, &journal)?;
            }
            JournalStatus::Finalizing { .. } => {}
        }

        loop {
            let next = match journal.records[index].status {
                JournalStatus::Finalizing { next_mutation } => usize::from(next_mutation),
                JournalStatus::Prepared
                | JournalStatus::Reserved
                | JournalStatus::Finalized
                | JournalStatus::Aborted => {
                    return Err(KeyStoreOperationError::Corrupt(
                        JournalCorruption::InvalidFinalizationStatus,
                    )
                    .into());
                }
            };
            if next == journal.records[index].mutations.len() {
                journal.records[index].scrub_staged_material();
                journal.records[index].status = JournalStatus::Finalized;
                store_journal(&mut **storage, &journal)?;
                return Ok(KeyStoreOperationStatus::Finalized);
            }

            apply_mutation(&mut **storage, &journal.records[index].mutations[next])?;
            let next_mutation = u8::try_from(next + 1)
                .map_err(|_| JournalCorruption::FinalizationProgressOverflow)
                .map_err(KeyStoreOperationError::from)?;
            journal.records[index].status = JournalStatus::Finalizing { next_mutation };
            store_journal(&mut **storage, &journal)?;
        }
    }

    /// Discards staged material before finalization starts.
    ///
    /// Prepared operations may be aborted. A reserved operation may be aborted only after the
    /// caller proves its host transaction did not commit; an ambiguous host result must be
    /// reconciled by identifier first. Repeating an abort is idempotent, while an operation that
    /// started finalizing cannot be rolled back safely.
    pub fn abort_operation(
        &self,
        id: KeyStoreOperationId,
    ) -> Result<KeyStoreOperationStatus, KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        let mut storage = self.lock_operation_storage()?;
        let mut journal = load_journal(&**storage)?;
        let index = record_index(&journal, id)?;
        match journal.records[index].status {
            JournalStatus::Prepared | JournalStatus::Reserved => {
                journal.records[index].scrub_staged_material();
                journal.records[index].status = JournalStatus::Aborted;
                store_journal(&mut **storage, &journal)?;
                Ok(KeyStoreOperationStatus::Aborted)
            }
            JournalStatus::Aborted => Ok(KeyStoreOperationStatus::Aborted),
            JournalStatus::Finalizing { .. } | JournalStatus::Finalized => {
                Err(KeyStoreOperationError::InvalidTransition {
                    status: journal.records[index].status.public(),
                    action: "abort",
                }
                .into())
            }
        }
    }

    /// Returns every prepared operation that still needs host recovery.
    ///
    /// The host matches each identifier against its durable transaction record. It aborts an
    /// orphaned Prepared or Reserved stage whose host transaction did not commit, and finalizes a
    /// Reserved or Finalizing operation whose host transaction did commit.
    pub fn unfinished_operations(&self) -> Result<Vec<UnfinishedKeyStoreOperation>, KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        let storage = self.lock_operation_storage()?;
        let journal = load_journal(&**storage)?;
        Ok(journal
            .records
            .iter()
            .filter(|record| record.status.is_unfinished())
            .map(JournalRecord::unfinished)
            .collect())
    }

    pub(super) fn ensure_no_recovery_required(&self) -> Result<(), KeyStoreOperationError> {
        let storage = self.lock_operation_storage()?;
        let journal = load_journal(&**storage)?;
        if let Some(record) = journal
            .records
            .iter()
            .find(|record| record.status.requires_recovery())
        {
            return Err(KeyStoreOperationError::RecoveryRequired { id: record.id });
        }
        Ok(())
    }

    fn stage_operation(
        &self,
        preconditions: Vec<SecureStoragePrecondition>,
        mutations: Vec<StagedMutation>,
    ) -> Result<KeyStoreOperationId, KeyStoreOperationError> {
        let mut storage = self.lock_operation_storage()?;
        let mut journal = load_journal(&**storage)?;
        prune_terminal_records(&mut journal);
        if journal
            .records
            .iter()
            .filter(|record| record.status.is_unfinished())
            .count()
            >= MAX_UNFINISHED_OPERATIONS
        {
            return Err(KeyStoreOperationError::TooManyUnfinishedOperations);
        }
        let id = generate_id(&journal)?;
        journal.records.push(JournalRecord {
            id,
            status: JournalStatus::Prepared,
            preconditions,
            mutations,
        });
        store_journal(&mut **storage, &journal)?;
        Ok(id)
    }

    fn lock_operation_storage(
        &self,
    ) -> Result<MutexGuard<'_, Box<dyn SecureStorage>>, KeyStoreOperationError> {
        self.0
            .storage
            .lock()
            .map_err(|_| KeyStoreOperationError::LockPoisoned)
    }
}

fn expected_value(value: Option<&[u8]>) -> SecureStorageExpectedValue {
    match value {
        Some(value) => SecureStorageExpectedValue::Digest(blake3::derive_key(
            SECURE_STORAGE_PRECONDITION_CONTEXT,
            value,
        )),
        None => SecureStorageExpectedValue::Absent,
    }
}

fn validate_preconditions(
    storage: &dyn SecureStorage,
    preconditions: &[SecureStoragePrecondition],
) -> Result<(), KeyStoreOperationError> {
    for precondition in preconditions {
        let actual = storage.load(&precondition.key)?;
        let matches = match (&precondition.expected_value, actual.as_deref()) {
            (SecureStorageExpectedValue::Absent, None) => true,
            (SecureStorageExpectedValue::Digest(expected), Some(value)) => {
                let actual = blake3::derive_key(SECURE_STORAGE_PRECONDITION_CONTEXT, value);
                bool::from(actual.ct_eq(expected))
            }
            _ => false,
        };
        if !matches {
            return Err(KeyStoreOperationError::PreconditionChanged {
                key: precondition.key.clone(),
            });
        }
    }
    Ok(())
}

fn apply_mutation(
    storage: &mut dyn SecureStorage,
    mutation: &StagedMutation,
) -> Result<(), KeyStoreOperationError> {
    match &mutation.value {
        Some(value) => storage.store(&mutation.key, value)?,
        None => storage.delete(&mutation.key)?,
    }
    Ok(())
}

fn generate_id(journal: &OperationJournal) -> Result<KeyStoreOperationId, KeyStoreOperationError> {
    for _ in 0..ID_GENERATION_ATTEMPTS {
        let mut bytes = [0u8; OPERATION_ID_LEN];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(KeyStoreOperationError::Randomness)?;
        let id = KeyStoreOperationId(bytes);
        if journal.records.iter().all(|record| record.id != id) {
            return Ok(id);
        }
    }
    Err(KeyStoreOperationError::IdCollision)
}

fn prune_terminal_records(journal: &mut OperationJournal) {
    while journal.records.len() >= MAX_OPERATION_RECORDS {
        if let Some(index) = journal.records.iter().position(|record| {
            matches!(
                record.status,
                JournalStatus::Finalized | JournalStatus::Aborted
            )
        }) {
            journal.records.remove(index);
        } else {
            break;
        }
    }
}

fn record_index(
    journal: &OperationJournal,
    id: KeyStoreOperationId,
) -> Result<usize, KeyStoreOperationError> {
    journal
        .records
        .iter()
        .position(|record| record.id == id)
        .ok_or(KeyStoreOperationError::NotFound)
}

fn load_journal(storage: &dyn SecureStorage) -> Result<OperationJournal, KeyStoreOperationError> {
    match storage.load(OPERATION_JOURNAL_KEY)? {
        Some(bytes) => Ok(decode_journal(&bytes)?),
        None => Ok(OperationJournal::default()),
    }
}

fn store_journal(
    storage: &mut dyn SecureStorage,
    journal: &OperationJournal,
) -> Result<(), KeyStoreOperationError> {
    let bytes = encode_journal(journal)?;
    storage.store(OPERATION_JOURNAL_KEY, &bytes)?;
    Ok(())
}

fn encode_journal(journal: &OperationJournal) -> Result<Zeroizing<Vec<u8>>, JournalCorruption> {
    check_record_count(journal.records.len())?;
    for record in &journal.records {
        record.validate()?;
    }
    let bytes = encode_versioned(
        OPERATION_JOURNAL_VERSION,
        &OperationJournalWire {
            records: journal.records.iter().map(JournalRecord::to_wire).collect(),
        },
    )?;
    check_journal_len(bytes.len())?;
    Ok(bytes)
}

fn decode_journal(bytes: &[u8]) -> Result<OperationJournal, JournalCorruption> {
    check_journal_len(bytes.len())?;
    let wire: OperationJournalWire<'_> = decode_versioned(OPERATION_JOURNAL_VERSION, bytes)?;
    let mut records: Vec<JournalRecord> = Vec::with_capacity(wire.records.len());
    for record in &wire.records {
        let record = JournalRecord::from_wire(record)?;
        if records.iter().any(|other| other.id == record.id) {
            return Err(JournalCorruption::DuplicateOperationIds);
        }
        records.push(record);
    }
    Ok(OperationJournal { records })
}

fn check_storage_key(key: &str) -> Result<(), JournalCorruption> {
    if key == OPERATION_JOURNAL_KEY {
        return Err(JournalCorruption::ReservedStorageKey);
    }
    if key.is_empty() || key.len() > MAX_STORAGE_KEY_LEN {
        return Err(JournalCorruption::InvalidStorageKeyLength {
            len: key.len(),
            max: MAX_STORAGE_KEY_LEN,
        });
    }
    Ok(())
}

fn check_record_count(count: usize) -> Result<(), JournalCorruption> {
    if count > MAX_OPERATION_RECORDS {
        return Err(JournalCorruption::TooManyRecords {
            count,
            max: MAX_OPERATION_RECORDS,
        });
    }
    Ok(())
}

fn check_journal_len(len: usize) -> Result<(), JournalCorruption> {
    if len > MAX_OPERATION_JOURNAL_LEN {
        return Err(JournalCorruption::JournalTooLong {
            len,
            max: MAX_OPERATION_JOURNAL_LEN,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn precondition_digest_changes_with_the_value() {
        let digest = |value: &[u8]| match expected_value(Some(value)) {
            SecureStorageExpectedValue::Digest(digest) => digest,
            SecureStorageExpectedValue::Absent => panic!("a present value must produce a digest"),
        };

        assert_ne!(digest(b"first value"), digest(b"second value"));
    }

    struct ChangingStorage {
        loads: Arc<AtomicUsize>,
    }

    impl SecureStorage for ChangingStorage {
        fn store(&mut self, _key: &str, _value: &[u8]) -> Result<(), StorageError> {
            Ok(())
        }

        fn load(&self, _key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
            let load = self.loads.fetch_add(1, Ordering::SeqCst);
            let value: &[u8] = if load == 0 { b"first" } else { b"changed" };
            Ok(Some(Zeroizing::new(value.to_vec())))
        }

        fn delete(&mut self, _key: &str) -> Result<(), StorageError> {
            Ok(())
        }
    }

    #[test]
    fn staging_reuses_the_first_authoritative_value_it_observes() {
        let loads = Arc::new(AtomicUsize::new(0));
        let authoritative: Arc<Mutex<Box<dyn SecureStorage>>> =
            Arc::new(Mutex::new(Box::new(ChangingStorage {
                loads: Arc::clone(&loads),
            })));
        let (staging, state) = StagingSecureStorage::new(authoritative);

        assert_eq!(
            staging
                .load("identity/current")
                .unwrap()
                .unwrap()
                .as_slice(),
            b"first"
        );
        assert_eq!(
            staging
                .load("identity/current")
                .unwrap()
                .unwrap()
                .as_slice(),
            b"first"
        );
        assert_eq!(loads.load(Ordering::SeqCst), 1);

        let state = state.lock().unwrap();
        assert_eq!(state.preconditions.len(), 1);
        assert_eq!(
            state.preconditions["identity/current"],
            expected_value(Some(b"first"))
        );
    }

    fn record(status: JournalStatus) -> JournalRecord {
        JournalRecord {
            id: KeyStoreOperationId([7; OPERATION_ID_LEN]),
            status,
            preconditions: vec![
                SecureStoragePrecondition {
                    key: "identity/current".into(),
                    expected_value: SecureStorageExpectedValue::Absent,
                },
                SecureStoragePrecondition {
                    key: "discovery/current".into(),
                    expected_value: expected_value(Some(b"discovery")),
                },
            ],
            mutations: vec![
                StagedMutation {
                    key: "identity/current".into(),
                    value: Some(Zeroizing::new(b"identity".to_vec())),
                },
                StagedMutation {
                    key: "discovery/current".into(),
                    value: None,
                },
            ],
        }
    }

    #[test]
    fn a_journal_decodes_to_the_records_it_encoded() {
        let journal = OperationJournal {
            records: vec![record(JournalStatus::Finalizing { next_mutation: 1 })],
        };

        let decoded = decode_journal(&encode_journal(&journal).unwrap()).unwrap();

        let [decoded] = decoded.records.as_slice() else {
            panic!("expected one record");
        };
        let expected = &journal.records[0];
        assert_eq!(decoded.id, expected.id);
        assert_eq!(decoded.status.public(), KeyStoreOperationStatus::Finalizing);
        assert_eq!(decoded.preconditions, expected.preconditions);
        assert_eq!(decoded.mutations.len(), expected.mutations.len());
        for (decoded, expected) in decoded.mutations.iter().zip(&expected.mutations) {
            assert_eq!(decoded.key, expected.key);
            assert_eq!(decoded.value, expected.value);
        }
    }

    #[test]
    fn a_journal_with_an_unknown_version_is_refused() {
        let mut bytes = encode_journal(&OperationJournal::default()).unwrap();
        bytes[0] = OPERATION_JOURNAL_VERSION + 1;

        assert!(matches!(
            decode_journal(&bytes),
            Err(JournalCorruption::StoredData(StoredDataError::UnsupportedVersion(version)))
                if version == OPERATION_JOURNAL_VERSION + 1
        ));
    }

    #[test]
    fn a_record_that_stages_an_unchecked_entry_is_refused() {
        let mut unchecked = record(JournalStatus::Prepared);
        unchecked.preconditions.pop();

        assert!(matches!(
            unchecked.validate(),
            Err(JournalCorruption::MutationWithoutPrecondition { key }) if key == "discovery/current"
        ));
    }

    #[test]
    fn a_record_that_touches_the_journal_entry_is_refused() {
        let mut reserved = record(JournalStatus::Prepared);
        reserved.preconditions[0].key = OPERATION_JOURNAL_KEY.into();

        assert!(matches!(
            reserved.validate(),
            Err(JournalCorruption::ReservedStorageKey)
        ));
    }

    #[test]
    fn a_finished_record_that_holds_staged_material_is_refused() {
        assert!(matches!(
            record(JournalStatus::Finalized).validate(),
            Err(JournalCorruption::TerminalRecordNotScrubbed)
        ));
    }

    #[test]
    fn finalization_progress_past_the_last_mutation_is_refused() {
        assert!(matches!(
            record(JournalStatus::Finalizing { next_mutation: 3 }).validate(),
            Err(JournalCorruption::FinalizationProgressOutOfRange {
                next_mutation: 3,
                mutations: 2
            })
        ));
    }
}
