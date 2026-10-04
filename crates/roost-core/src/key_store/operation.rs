use super::{KeyStore, KeyStoreError};
use crate::storage::{SecureStorage, StorageError};
use rand::RngCore;
use rand::rngs::OsRng;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const OPERATION_JOURNAL_KEY: &str = "operation/journal";
const OPERATION_JOURNAL_VERSION: u8 = 1;
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
const SECURE_STORAGE_PRECONDITION_CONTEXT: &str = "AetherSecureStoragePrecondition-v1";

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

/// Expected authoritative value for one SecureStorage entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecureStorageExpectedValue {
    /// The entry must not exist.
    Absent,
    /// The entry must match this domain-separated digest.
    Digest([u8; PRECONDITION_DIGEST_LEN]),
}

/// SecureStorage input that must remain unchanged before an operation commits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecureStoragePrecondition {
    /// Stable SecureStorage entry name.
    pub key: String,
    /// Expected authoritative value at commit time.
    pub expected_value: SecureStorageExpectedValue,
}

/// Public metadata for a prepared KeyStore operation.
///
/// Every returned operation must be finalized or aborted, even when its provisional output reports
/// that no mutation was needed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyStoreOperation {
    /// Stable identifier persisted by the host with its atomic transaction.
    pub id: KeyStoreOperationId,
    /// SecureStorage inputs checked before the operation is committed.
    pub secure_storage_preconditions: Vec<SecureStoragePrecondition>,
}

/// Output and recovery metadata produced without changing authoritative secure state.
pub struct PreparedKeyStoreOperation<T> {
    /// Recovery metadata for the staged secure mutation.
    pub operation: KeyStoreOperation,
    /// Caller-visible result computed from the staged state.
    pub output: T,
}

/// Durable phase of a prepared KeyStore operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyStoreOperationStatus {
    /// Secret mutations are staged and may be committed or aborted.
    Prepared,
    /// Preconditions matched and the host may commit its durable transaction.
    Committed,
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
    /// Stable operation metadata.
    pub operation: KeyStoreOperation,
    /// Durable phase that determines whether the host aborts or finalizes recovery.
    pub status: KeyStoreOperationStatus,
}

/// Errors returned by the prepared KeyStore operation lifecycle.
#[derive(Debug)]
pub enum KeyStoreOperationError {
    /// The persisted operation journal is malformed or unsupported.
    Corrupt(String),
    /// An operation cannot perform the requested lifecycle transition.
    InvalidTransition {
        /// Current durable status.
        status: KeyStoreOperationStatus,
        /// Requested lifecycle action.
        action: &'static str,
    },
    /// The in-process storage lock was poisoned.
    LockPoisoned,
    /// No retained operation has the requested identifier.
    NotFound,
    /// An authoritative SecureStorage input changed after preparation.
    PreconditionChanged {
        /// Stable SecureStorage entry name.
        key: String,
    },
    /// The OS CSPRNG could not produce an operation identifier.
    Randomness,
    /// A previously committed operation must be finalized or aborted before more work proceeds.
    RecoveryRequired {
        /// Identifier of the unfinished operation.
        id: KeyStoreOperationId,
    },
    /// SecureStorage returned a platform failure.
    Storage(StorageError),
    /// The bounded unfinished-operation journal is full.
    TooManyUnfinishedOperations,
}

impl fmt::Display for KeyStoreOperationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Corrupt(reason) => write!(f, "prepared-operation journal is corrupt: {reason}"),
            Self::InvalidTransition { status, action } => {
                write!(f, "cannot {action} prepared operation in {status:?} state")
            }
            Self::LockPoisoned => write!(f, "prepared-operation lock poisoned"),
            Self::NotFound => write!(f, "prepared operation not found"),
            Self::PreconditionChanged { key } => {
                write!(f, "secure-storage precondition changed for {key}")
            }
            Self::Randomness => write!(f, "operation identifier generation failed"),
            Self::RecoveryRequired { .. } => {
                write!(f, "prepared-operation recovery required")
            }
            Self::Storage(error) => write!(f, "prepared-operation storage: {error}"),
            Self::TooManyUnfinishedOperations => {
                write!(f, "too many unfinished prepared operations")
            }
        }
    }
}

impl std::error::Error for KeyStoreOperationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(error) => Some(error),
            _ => None,
        }
    }
}

impl From<StorageError> for KeyStoreOperationError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

#[derive(Clone, Copy, Zeroize)]
enum JournalStatus {
    Prepared,
    Committed,
    Finalizing { next_mutation: u8 },
    Finalized,
    Aborted,
}

impl JournalStatus {
    fn public(self) -> KeyStoreOperationStatus {
        match self {
            Self::Prepared => KeyStoreOperationStatus::Prepared,
            Self::Committed => KeyStoreOperationStatus::Committed,
            Self::Finalizing { .. } => KeyStoreOperationStatus::Finalizing,
            Self::Finalized => KeyStoreOperationStatus::Finalized,
            Self::Aborted => KeyStoreOperationStatus::Aborted,
        }
    }

    fn is_unfinished(self) -> bool {
        matches!(
            self,
            Self::Prepared | Self::Committed | Self::Finalizing { .. }
        )
    }

    fn requires_recovery(self) -> bool {
        matches!(self, Self::Committed | Self::Finalizing { .. })
    }
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
    status: JournalStatus,
    #[zeroize(skip)]
    preconditions: Vec<SecureStoragePrecondition>,
    mutations: Vec<StagedMutation>,
}

impl JournalRecord {
    fn public_operation(&self) -> KeyStoreOperation {
        KeyStoreOperation {
            id: self.id,
            secure_storage_preconditions: self.preconditions.clone(),
        }
    }

    fn scrub_staged_material(&mut self) {
        self.mutations.clear();
        self.preconditions.clear();
    }
}

#[derive(Default, Zeroize, ZeroizeOnDrop)]
struct OperationJournal {
    records: Vec<JournalRecord>,
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

    fn observe(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
        if key == OPERATION_JOURNAL_KEY {
            return Err(StorageError::IO(
                "reserved prepared-operation journal key".into(),
            ));
        }
        if key.len() > MAX_STORAGE_KEY_LEN {
            return Err(StorageError::IO(
                "prepared-operation storage key exceeds limit".into(),
            ));
        }

        {
            let state = self
                .state
                .lock()
                .map_err(|_| StorageError::IO("prepared-operation staging lock poisoned".into()))?;
            if let Some(value) = state.mutations.get(key) {
                return Ok(value.as_ref().map(|bytes| Zeroizing::new(bytes.to_vec())));
            }
            if let Some(value) = state.observed.get(key) {
                return Ok(value.as_ref().map(|bytes| Zeroizing::new(bytes.to_vec())));
            }
        }

        let loaded = self
            .authoritative
            .lock()
            .map_err(|_| StorageError::IO("secure-storage lock poisoned".into()))?
            .load(key)?;
        let expected_value = expected_value(loaded.as_deref().map(Vec::as_slice));
        let mut state = self
            .state
            .lock()
            .map_err(|_| StorageError::IO("prepared-operation staging lock poisoned".into()))?;
        state
            .preconditions
            .entry(key.to_owned())
            .or_insert(expected_value);
        state.observed.insert(
            key.to_owned(),
            loaded.as_ref().map(|bytes| Zeroizing::new(bytes.to_vec())),
        );
        Ok(loaded)
    }
}

impl SecureStorage for StagingSecureStorage {
    fn store(&mut self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        if value.len() > MAX_STAGED_VALUE_LEN {
            return Err(StorageError::IO("staged secure value exceeds limit".into()));
        }
        self.observe(key)?;
        self.state
            .lock()
            .map_err(|_| StorageError::IO("prepared-operation staging lock poisoned".into()))?
            .mutations
            .insert(key.to_owned(), Some(Zeroizing::new(value.to_vec())));
        Ok(())
    }

    fn load(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
        self.observe(key)
    }

    fn delete(&mut self, key: &str) -> Result<(), StorageError> {
        self.observe(key)?;
        self.state
            .lock()
            .map_err(|_| StorageError::IO("prepared-operation staging lock poisoned".into()))?
            .mutations
            .insert(key.to_owned(), None);
        Ok(())
    }
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
        let state = state
            .lock()
            .map_err(|_| KeyStoreOperationError::LockPoisoned)?;
        let operation = self.stage_operation(state.preconditions(), state.mutations())?;
        Ok(PreparedKeyStoreOperation { operation, output })
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
        Ok(find_record(&journal, id)?.status.public())
    }

    /// Validates secure inputs and reserves an operation for the host transaction.
    ///
    /// Calling this repeatedly after a successful commit is idempotent. The caller must next
    /// commit the returned Protocol State updates and outputs atomically, then call
    /// [`Self::finalize_operation`]. Abort only after proving the host transaction did not commit.
    /// If the host result is ambiguous, reload its operation record and reconcile it through
    /// [`Self::unfinished_operations`].
    pub fn commit_operation(
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
                journal.records[index].status = JournalStatus::Committed;
                store_journal(&mut **storage, &journal)?;
                Ok(KeyStoreOperationStatus::Committed)
            }
            JournalStatus::Committed => Ok(KeyStoreOperationStatus::Committed),
            JournalStatus::Finalizing { .. } => Ok(KeyStoreOperationStatus::Finalizing),
            JournalStatus::Finalized => Ok(KeyStoreOperationStatus::Finalized),
            JournalStatus::Aborted => Err(KeyStoreOperationError::InvalidTransition {
                status: status.public(),
                action: "commit",
            }
            .into()),
        }
    }

    /// Makes a committed operation's staged secure mutations authoritative.
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
            JournalStatus::Committed => {
                journal.records[index].status = JournalStatus::Finalizing { next_mutation: 0 };
                store_journal(&mut **storage, &journal)?;
            }
            JournalStatus::Finalizing { .. } => {}
        }

        loop {
            let next = match journal.records[index].status {
                JournalStatus::Finalizing { next_mutation } => usize::from(next_mutation),
                _ => {
                    return Err(KeyStoreOperationError::Corrupt(
                        "finalization progress has an invalid status".into(),
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
            let next_mutation = u8::try_from(next + 1).map_err(|_| {
                KeyStoreOperationError::Corrupt("finalization progress exceeds limit".into())
            })?;
            journal.records[index].status = JournalStatus::Finalizing { next_mutation };
            store_journal(&mut **storage, &journal)?;
        }
    }

    /// Discards staged material before finalization starts.
    ///
    /// Prepared operations may be aborted. A committed operation may be aborted only after the
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
            JournalStatus::Prepared | JournalStatus::Committed => {
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
    /// orphaned Prepared or Committed stage whose host transaction did not commit, and finalizes a
    /// Committed or Finalizing operation whose host transaction did commit.
    pub fn unfinished_operations(&self) -> Result<Vec<UnfinishedKeyStoreOperation>, KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        let storage = self.lock_operation_storage()?;
        let journal = load_journal(&**storage)?;
        Ok(journal
            .records
            .iter()
            .filter(|record| record.status.is_unfinished())
            .map(|record| UnfinishedKeyStoreOperation {
                operation: record.public_operation(),
                status: record.status.public(),
            })
            .collect())
    }

    pub(super) fn ensure_no_recovery_required(&self) -> Result<(), KeyStoreOperationError> {
        let storage = self.lock_operation_storage_raw()?;
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
    ) -> Result<KeyStoreOperation, KeyStoreOperationError> {
        if preconditions.len() > MAX_OPERATION_PRECONDITIONS {
            return Err(KeyStoreOperationError::Corrupt(
                "operation has too many secure-storage preconditions".into(),
            ));
        }
        if mutations.len() > MAX_OPERATION_MUTATIONS {
            return Err(KeyStoreOperationError::Corrupt(
                "operation has too many secure-storage mutations".into(),
            ));
        }

        let mut storage = self.lock_operation_storage_raw()?;
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
        Ok(journal
            .records
            .last()
            .ok_or_else(|| KeyStoreOperationError::Corrupt("staged record is missing".into()))?
            .public_operation())
    }

    fn lock_operation_storage(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, Box<dyn SecureStorage>>, KeyStoreError> {
        self.lock_operation_storage_raw().map_err(Into::into)
    }

    fn lock_operation_storage_raw(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, Box<dyn SecureStorage>>, KeyStoreOperationError> {
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
            .map_err(|_| KeyStoreOperationError::Randomness)?;
        let id = KeyStoreOperationId(bytes);
        if journal.records.iter().all(|record| record.id != id) {
            return Ok(id);
        }
    }
    Err(KeyStoreOperationError::Randomness)
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

fn find_record(
    journal: &OperationJournal,
    id: KeyStoreOperationId,
) -> Result<&JournalRecord, KeyStoreOperationError> {
    journal
        .records
        .iter()
        .find(|record| record.id == id)
        .ok_or(KeyStoreOperationError::NotFound)
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
        Some(bytes) => decode_journal(&bytes),
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

fn encoded_journal_len(journal: &OperationJournal) -> Result<usize, KeyStoreOperationError> {
    if journal.records.len() > MAX_OPERATION_RECORDS {
        return Err(KeyStoreOperationError::Corrupt(
            "operation journal exceeds record limit".into(),
        ));
    }

    let mut len = 2usize;
    for record in &journal.records {
        if record.preconditions.len() > MAX_OPERATION_PRECONDITIONS {
            return Err(KeyStoreOperationError::Corrupt(
                "operation has too many secure-storage preconditions".into(),
            ));
        }
        if record.mutations.len() > MAX_OPERATION_MUTATIONS {
            return Err(KeyStoreOperationError::Corrupt(
                "operation has too many secure-storage mutations".into(),
            ));
        }

        // Identifier, status, progress, and precondition count.
        len = checked_journal_len(len, OPERATION_ID_LEN + 3)?;
        for precondition in &record.preconditions {
            let key_len = storage_key_len(&precondition.key)?;
            let digest_len = match &precondition.expected_value {
                SecureStorageExpectedValue::Absent => 0,
                SecureStorageExpectedValue::Digest(_) => PRECONDITION_DIGEST_LEN,
            };
            // Key length, key, expected-value tag, and optional digest.
            len = checked_journal_len(len, 1 + key_len + 1 + digest_len)?;
        }

        // Mutation count.
        len = checked_journal_len(len, 1)?;
        for mutation in &record.mutations {
            let key_len = storage_key_len(&mutation.key)?;
            // Key length, key, and value tag.
            len = checked_journal_len(len, 1 + key_len + 1)?;
            if let Some(value) = &mutation.value {
                if value.len() > MAX_STAGED_VALUE_LEN {
                    return Err(KeyStoreOperationError::Corrupt(
                        "staged secure value exceeds limit".into(),
                    ));
                }
                // Value length and secret bytes.
                len = checked_journal_len(len, 4 + value.len())?;
            }
        }
    }

    if len > MAX_OPERATION_JOURNAL_LEN {
        return Err(KeyStoreOperationError::Corrupt(
            "operation journal exceeds byte limit".into(),
        ));
    }
    Ok(len)
}

fn encode_journal(
    journal: &OperationJournal,
) -> Result<Zeroizing<Vec<u8>>, KeyStoreOperationError> {
    let encoded_len = encoded_journal_len(journal)?;
    // Allocate once so capacity growth cannot release earlier secret-bearing buffers unwiped.
    let mut encoded = Zeroizing::new(Vec::with_capacity(encoded_len));
    encoded.push(OPERATION_JOURNAL_VERSION);
    push_u8(
        &mut encoded,
        journal.records.len(),
        "operation record count",
    )?;
    for record in &journal.records {
        encoded.extend_from_slice(record.id.as_bytes());
        let (status, progress) = match record.status {
            JournalStatus::Prepared => (0, 0),
            JournalStatus::Committed => (1, 0),
            JournalStatus::Finalizing { next_mutation } => (2, next_mutation),
            JournalStatus::Finalized => (3, 0),
            JournalStatus::Aborted => (4, 0),
        };
        encoded.push(status);
        encoded.push(progress);
        push_u8(
            &mut encoded,
            record.preconditions.len(),
            "secure-storage precondition count",
        )?;
        for precondition in &record.preconditions {
            push_key(&mut encoded, &precondition.key)?;
            match &precondition.expected_value {
                SecureStorageExpectedValue::Absent => encoded.push(0),
                SecureStorageExpectedValue::Digest(digest) => {
                    encoded.push(1);
                    encoded.extend_from_slice(digest);
                }
            }
        }
        push_u8(
            &mut encoded,
            record.mutations.len(),
            "secure-storage mutation count",
        )?;
        for mutation in &record.mutations {
            push_key(&mut encoded, &mutation.key)?;
            match &mutation.value {
                None => encoded.push(0),
                Some(value) => {
                    if value.len() > MAX_STAGED_VALUE_LEN {
                        return Err(KeyStoreOperationError::Corrupt(
                            "staged secure value exceeds limit".into(),
                        ));
                    }
                    encoded.push(1);
                    let len = u32::try_from(value.len()).map_err(|_| {
                        KeyStoreOperationError::Corrupt(
                            "staged secure value length is invalid".into(),
                        )
                    })?;
                    encoded.extend_from_slice(&len.to_be_bytes());
                    encoded.extend_from_slice(value);
                }
            }
        }
    }
    if encoded.len() != encoded_len {
        return Err(KeyStoreOperationError::Corrupt(
            "operation journal encoded length is inconsistent".into(),
        ));
    }
    Ok(encoded)
}

fn checked_journal_len(len: usize, additional: usize) -> Result<usize, KeyStoreOperationError> {
    len.checked_add(additional)
        .ok_or_else(|| KeyStoreOperationError::Corrupt("operation journal length overflow".into()))
}

fn decode_journal(bytes: &[u8]) -> Result<OperationJournal, KeyStoreOperationError> {
    if bytes.len() > MAX_OPERATION_JOURNAL_LEN {
        return Err(KeyStoreOperationError::Corrupt(
            "operation journal exceeds byte limit".into(),
        ));
    }
    let mut decoder = JournalDecoder::new(bytes);
    let version = decoder.u8()?;
    if version != OPERATION_JOURNAL_VERSION {
        return Err(KeyStoreOperationError::Corrupt(format!(
            "unsupported operation journal version {version}"
        )));
    }
    let record_count = usize::from(decoder.u8()?);
    if record_count > MAX_OPERATION_RECORDS {
        return Err(KeyStoreOperationError::Corrupt(
            "operation journal exceeds record limit".into(),
        ));
    }
    let mut records = Vec::with_capacity(record_count);
    for _ in 0..record_count {
        let id = KeyStoreOperationId(decoder.array()?);
        if records.iter().any(|record: &JournalRecord| record.id == id) {
            return Err(KeyStoreOperationError::Corrupt(
                "operation journal contains duplicate identifiers".into(),
            ));
        }
        let status_tag = decoder.u8()?;
        let progress = decoder.u8()?;
        let precondition_count = usize::from(decoder.u8()?);
        if precondition_count > MAX_OPERATION_PRECONDITIONS {
            return Err(KeyStoreOperationError::Corrupt(
                "operation has too many secure-storage preconditions".into(),
            ));
        }
        let mut preconditions = Vec::with_capacity(precondition_count);
        for _ in 0..precondition_count {
            let key = decoder.key()?;
            if preconditions
                .iter()
                .any(|precondition: &SecureStoragePrecondition| precondition.key == key)
            {
                return Err(KeyStoreOperationError::Corrupt(
                    "operation contains duplicate secure-storage preconditions".into(),
                ));
            }
            let expected_value = match decoder.u8()? {
                0 => SecureStorageExpectedValue::Absent,
                1 => SecureStorageExpectedValue::Digest(decoder.array()?),
                _ => {
                    return Err(KeyStoreOperationError::Corrupt(
                        "operation contains an unknown precondition".into(),
                    ));
                }
            };
            preconditions.push(SecureStoragePrecondition {
                key,
                expected_value,
            });
        }
        let mutation_count = usize::from(decoder.u8()?);
        if mutation_count > MAX_OPERATION_MUTATIONS {
            return Err(KeyStoreOperationError::Corrupt(
                "operation has too many secure-storage mutations".into(),
            ));
        }
        let mut mutations = Vec::with_capacity(mutation_count);
        for _ in 0..mutation_count {
            let key = decoder.key()?;
            if mutations
                .iter()
                .any(|mutation: &StagedMutation| mutation.key == key)
            {
                return Err(KeyStoreOperationError::Corrupt(
                    "operation contains duplicate secure-storage mutations".into(),
                ));
            }
            if !preconditions
                .iter()
                .any(|precondition| precondition.key == key)
            {
                return Err(KeyStoreOperationError::Corrupt(
                    "secure-storage mutation has no precondition".into(),
                ));
            }
            let value = match decoder.u8()? {
                0 => None,
                1 => Some(decoder.secret_value()?),
                _ => {
                    return Err(KeyStoreOperationError::Corrupt(
                        "operation contains an unknown secure-storage mutation".into(),
                    ));
                }
            };
            mutations.push(StagedMutation { key, value });
        }
        let status = match status_tag {
            0 if progress == 0 => JournalStatus::Prepared,
            1 if progress == 0 => JournalStatus::Committed,
            2 if usize::from(progress) <= mutations.len() => JournalStatus::Finalizing {
                next_mutation: progress,
            },
            3 if progress == 0 && preconditions.is_empty() && mutations.is_empty() => {
                JournalStatus::Finalized
            }
            4 if progress == 0 && preconditions.is_empty() && mutations.is_empty() => {
                JournalStatus::Aborted
            }
            _ => {
                return Err(KeyStoreOperationError::Corrupt(
                    "operation contains invalid lifecycle state".into(),
                ));
            }
        };
        records.push(JournalRecord {
            id,
            status,
            preconditions,
            mutations,
        });
    }
    if !decoder.is_finished() {
        return Err(KeyStoreOperationError::Corrupt(
            "operation journal contains trailing bytes".into(),
        ));
    }
    Ok(OperationJournal { records })
}

fn push_u8(encoded: &mut Vec<u8>, value: usize, label: &str) -> Result<(), KeyStoreOperationError> {
    let value = u8::try_from(value)
        .map_err(|_| KeyStoreOperationError::Corrupt(format!("{label} exceeds limit")))?;
    encoded.push(value);
    Ok(())
}

fn push_key(encoded: &mut Vec<u8>, key: &str) -> Result<(), KeyStoreOperationError> {
    let key_len = storage_key_len(key)?;
    push_u8(encoded, key_len, "secure-storage key length")?;
    encoded.extend_from_slice(key.as_bytes());
    Ok(())
}

fn storage_key_len(key: &str) -> Result<usize, KeyStoreOperationError> {
    if key.is_empty() || key.len() > MAX_STORAGE_KEY_LEN {
        return Err(KeyStoreOperationError::Corrupt(
            "secure-storage key length is invalid".into(),
        ));
    }
    Ok(key.len())
}

struct JournalDecoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> JournalDecoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn u8(&mut self) -> Result<u8, KeyStoreOperationError> {
        Ok(self.take(1)?[0])
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], KeyStoreOperationError> {
        self.take(N)?.try_into().map_err(|_| {
            KeyStoreOperationError::Corrupt("operation journal field length is invalid".into())
        })
    }

    fn key(&mut self) -> Result<String, KeyStoreOperationError> {
        let len = usize::from(self.u8()?);
        if len == 0 || len > MAX_STORAGE_KEY_LEN {
            return Err(KeyStoreOperationError::Corrupt(
                "secure-storage key length is invalid".into(),
            ));
        }
        String::from_utf8(self.take(len)?.to_vec())
            .map_err(|_| KeyStoreOperationError::Corrupt("secure-storage key is not UTF-8".into()))
    }

    fn secret_value(&mut self) -> Result<Zeroizing<Vec<u8>>, KeyStoreOperationError> {
        let len = u32::from_be_bytes(self.array()?) as usize;
        if len > MAX_STAGED_VALUE_LEN {
            return Err(KeyStoreOperationError::Corrupt(
                "staged secure value exceeds limit".into(),
            ));
        }
        Ok(Zeroizing::new(self.take(len)?.to_vec()))
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], KeyStoreOperationError> {
        let end = self.cursor.checked_add(len).ok_or_else(|| {
            KeyStoreOperationError::Corrupt("operation journal length overflow".into())
        })?;
        let value = self.bytes.get(self.cursor..end).ok_or_else(|| {
            KeyStoreOperationError::Corrupt("operation journal is truncated".into())
        })?;
        self.cursor = end;
        Ok(value)
    }

    fn is_finished(&self) -> bool {
        self.cursor == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const SECURE_STORAGE_PRECONDITION_KAT_EXPECTED: &str =
        "1057a0c66b56f08caa9cc9623796774f165575324362504f1626f534e4090c1a";

    /// Source: `lukechampine.com/blake3` v1.4.1's independent Go implementation, using its
    /// `DeriveKey(subKey, ctx, srcKey)` API under Go 1.27.0.
    ///
    /// Inputs: context `AetherSecureStoragePrecondition-v1` and the exact UTF-8 bytes
    /// `fixture secure value` (no trailing newline).
    ///
    /// Derivation:
    /// ```text
    /// output := make([]byte, 32)
    /// blake3.DeriveKey(
    ///     output,
    ///     "AetherSecureStoragePrecondition-v1",
    ///     []byte("fixture secure value"),
    /// )
    /// hex.EncodeToString(output)
    /// ```
    ///
    /// Output: `SECURE_STORAGE_PRECONDITION_KAT_EXPECTED`.
    #[test]
    fn secure_storage_precondition_digest_known_answer() {
        let SecureStorageExpectedValue::Digest(digest) =
            expected_value(Some(b"fixture secure value"))
        else {
            panic!("present values must produce a digest");
        };
        assert_eq!(
            hex::encode(digest),
            SECURE_STORAGE_PRECONDITION_KAT_EXPECTED
        );
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
}
