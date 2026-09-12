//! Identity-scoped Client and focused interfaces sharing one Core context.

use crate::SecureStorage;
use crate::certificate::{
    SenderCertificateValidation, domain_signing_keys_to_core, revocation_state_to_core,
    revoked_identity_keys_to_core,
};
use crate::error::ClientError;
use crate::key_store_operation::{
    KeyStoreOperation, KeyStoreOperationStatus, PreparedContactBlock, PreparedIdentityGeneration,
    PreparedInboxRotation, PreparedOneTimePreKeys, PreparedSessionAcceptance,
    PreparedSignedPreKeyRotation, UnfinishedKeyStoreOperation, operation_identifier,
};
use crate::message::{Message, SenderIdentityMaterial};
use crate::protocol::{
    AcknowledgmentOutcome, ContactStateChange, IdentityKey as FfiIdentityKey,
    InboundMessageOutcome, OutboundMessageResult, ProtocolStateEntry, ProtocolStateUpdate,
    protocol_key, snapshot_input_from_entries, updates_from_core,
};
use crate::records::{
    DiscoveryKeyBundle, Identity, InboxRotation, OneTimePreKeyBundle, PublicationBundle,
    SignedPreKeyBundle, fixed_16, fixed_32,
};
use crate::storage::SecureStorageAdapter;
use crate::transport_binding::{PreKeySelection, TransportBinding};
use roost_core::{
    AcknowledgmentProcessing, InboundSenderCertificateValidation, KeyStore as CoreKeyStore,
    MessageDecryption, MessageEncryption,
    PreparedKeyStoreOperation as CorePreparedKeyStoreOperation,
    ProtocolStateEngine as CoreProtocolStateEngine, ProtocolStateKey, SessionAcceptance,
    SessionInitiation,
};
use roost_protocol::MessageId;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Largest authentication transcript this keystore will sign, in bytes.
///
/// A relay authentication transcript is 159 bytes for the HTTP form and 120 for the WebSocket
/// form, so this leaves room for long request targets while keeping the export from doubling as a
/// bulk document signer.
const MAX_AUTHENTICATION_TRANSCRIPT_LEN: usize = 4096;

/// ASCII prefix reserved for preimages Aether signs or verifies itself.
///
/// Every context and domain tag in `docs/domain-separation.md` starts with these bytes, so
/// refusing them keeps [`IdentityOperations::sign_authentication_transcript`] disjoint from the whole
/// registry. Matched case-insensitively to cover the lowercase hash-domain convention as well.
const RESERVED_AETHER_DOMAIN_PREFIX: &[u8] = b"Aether";

/// Identity-scoped entry point for Identity, Messaging, and Contact operations.
///
/// Keep one Client for each identity namespace. All focused interfaces share its storage and
/// immutable configuration. The host must serialize each identity's complete load, operation,
/// and conditional host commit, including across app and extension processes. For prepared
/// operations, hold that serialization until finalization, abort, or reconciliation after an
/// ambiguous host commit.
///
/// # Examples
/// ```
/// # use roost_client::{Client, ClientError, InMemorySecureStorage};
/// # use std::sync::Arc;
/// let client = Client::new(Arc::new(InMemorySecureStorage::new()));
/// assert!(!client.identity().has_identity()?);
/// assert!(client.contacts().contact_states(Vec::new())?.is_empty());
/// # Ok::<(), ClientError>(())
/// ```
#[derive(uniffi::Object)]
pub struct Client {
    inner: Arc<CoreKeyStore>,
}

/// Identity lifecycle and public key material for one Client.
///
/// Obtain this handle from [`Client::identity`]. It retains the Client's context and uses its
/// prepared-operation journal; constructing another storage adapter is unnecessary.
///
/// # Examples
/// ```
/// # use roost_client::{Client, ClientError, InMemorySecureStorage};
/// # use std::sync::Arc;
/// let client = Client::new(Arc::new(InMemorySecureStorage::new()));
/// assert!(!client.identity().has_identity()?);
/// # Ok::<(), ClientError>(())
/// ```
#[derive(uniffi::Object)]
pub struct IdentityOperations {
    pub(crate) inner: Arc<CoreKeyStore>,
}

/// Session, message, acknowledgment, and retry operations for one Client.
///
/// Obtain this handle from [`Client::messaging`]. The host supplies snapshots and exact Transport
/// Binding bytes, then commits returned updates together with their associated application effects.
///
/// # Examples
/// ```
/// # use roost_client::{Client, InMemorySecureStorage};
/// # use std::sync::Arc;
/// let client = Client::new(Arc::new(InMemorySecureStorage::new()));
/// let limits = client.messaging().hardening_limits();
/// assert!(limits.deduplication_capacity > 0);
/// ```
#[derive(uniffi::Object)]
pub struct Messaging {
    pub(crate) inner: Arc<CoreKeyStore>,
}

/// Contact identity, trust, blocking, and inbox authorization for one Client.
///
/// Obtain this handle from [`Client::contacts`]. Queries project host-owned snapshots; state changes
/// become visible when the host commits and refreshes its store.
///
/// # Examples
/// ```
/// # use roost_client::{Client, ClientError, InMemorySecureStorage};
/// # use std::sync::Arc;
/// let client = Client::new(Arc::new(InMemorySecureStorage::new()));
/// assert!(client.contacts().contact_states(Vec::new())?.is_empty());
/// # Ok::<(), ClientError>(())
/// ```
#[derive(uniffi::Object)]
pub struct Contacts {
    pub(crate) inner: Arc<CoreKeyStore>,
}

/// Immutable protocol policy shared by every interface of a Client.
///
/// Pass this record to [`Client::with_configuration`] before starting work. Prepared operations
/// retain the same configuration while staging secure mutations.
///
/// # Examples
/// ```
/// # use roost_client::{BlockedContactAcknowledgmentPolicy, ClientConfiguration};
/// let configuration = ClientConfiguration {
///     deduplication_capacity: 64,
///     blocked_contact_acknowledgment_policy: BlockedContactAcknowledgmentPolicy::SilentReceipt,
/// };
/// assert_eq!(configuration.deduplication_capacity, 64);
/// ```
#[derive(uniffi::Record)]
pub struct ClientConfiguration {
    /// Number of received message digests retained for this identity, within Core's hard cap.
    pub deduplication_capacity: u64,
    /// Whether a blocked sender receives an acknowledgment.
    pub blocked_contact_acknowledgment_policy: crate::BlockedContactAcknowledgmentPolicy,
}

/// Result of starting a Session through X3DH.
#[derive(uniffi::Record)]
pub struct SessionInitiationResult {
    /// X3DH first Message to send after host commit.
    pub message: Message,
    /// Opaque protocol-state updates to commit.
    pub state_updates: Vec<ProtocolStateUpdate>,
}

/// Result of blocking a contact.
#[derive(uniffi::Record)]
pub struct ContactBlock {
    /// Contact state change to commit durably, then emit.
    pub contact: ContactStateChange,
    /// The inbox rotation the block performed, absent when the contact was already blocked.
    ///
    /// Present means every remaining contact now holds a stale delivery capability and must be
    /// given the new one before it can reach this inbox again. The blocked contact is deliberately
    /// not among them — that is what makes the block bite at the relay rather than only locally.
    pub rotation: Option<InboxRotation>,
}

/// Result of accepting a Session through X3DH.
#[derive(uniffi::Record)]
pub struct SessionAcceptanceResult {
    /// Decrypted first-message plaintext.
    pub plaintext: Vec<u8>,
    /// Sender identity material decoded after authentication.
    pub sender_identity: SenderIdentityMaterial,
    /// Opaque protocol-state updates to commit.
    pub state_updates: Vec<ProtocolStateUpdate>,
}

#[uniffi::export]
impl Client {
    /// Creates one identity context backed by platform SecureStorage with the default policy.
    ///
    /// Construction performs no storage I/O. Keep the Client and its interfaces for the identity's
    /// lifetime. The host serializes operations and commits across every process sharing storage.
    ///
    /// # Examples
    /// ```
    /// use roost_client::{Client, InMemorySecureStorage};
    /// use std::sync::Arc;
    /// let client = Client::new(Arc::new(InMemorySecureStorage::new()));
    /// assert!(!client.identity().has_identity()?);
    /// # Ok::<(), roost_client::ClientError>(())
    /// ```
    #[uniffi::constructor]
    pub fn new(storage: Arc<dyn SecureStorage>) -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(CoreKeyStore::new(Box::new(SecureStorageAdapter::new(
                storage,
            )))),
        })
    }

    /// Creates one identity context with immutable protocol configuration.
    ///
    /// Every interface and prepared operation uses this policy. `deduplication_capacity` must be
    /// between 64 and 2048 inclusive. See [`Client`] for serialization and recovery requirements.
    ///
    /// # Examples
    /// ```
    /// use roost_client::{Client, ClientConfiguration, BlockedContactAcknowledgmentPolicy, InMemorySecureStorage};
    /// use std::sync::Arc;
    /// let client = Client::with_configuration(Arc::new(InMemorySecureStorage::new()), ClientConfiguration {
    ///     deduplication_capacity: 64,
    ///     blocked_contact_acknowledgment_policy: BlockedContactAcknowledgmentPolicy::Unreachable,
    /// })?;
    /// # Ok::<(), roost_client::ClientError>(())
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::InvalidData`] if the capacity is outside that range.
    #[uniffi::constructor]
    pub fn with_configuration(
        storage: Arc<dyn SecureStorage>,
        configuration: ClientConfiguration,
    ) -> Result<Arc<Self>, ClientError> {
        let capacity = usize::try_from(configuration.deduplication_capacity).map_err(|_| {
            ClientError::InvalidData {
                reason: "deduplication capacity exceeds platform range".into(),
            }
        })?;
        let engine = CoreProtocolStateEngine::with_deduplication_capacity(capacity)?
            .with_blocked_contact_acknowledgment_policy(
                configuration.blocked_contact_acknowledgment_policy.into(),
            );
        Ok(Arc::new(Self {
            inner: Arc::new(CoreKeyStore::with_protocol_engine(
                Box::new(SecureStorageAdapter::new(storage)),
                engine,
            )),
        }))
    }

    /// Returns the identity interface sharing this Client's storage and lifecycle.
    ///
    /// The interface retains the context even after the root handle is released.
    ///
    /// # Examples
    /// ```
    /// # use roost_client::{Client, InMemorySecureStorage};
    /// # use std::sync::Arc;
    /// let client = Client::new(Arc::new(InMemorySecureStorage::new()));
    /// let identity = client.identity();
    /// assert!(!identity.has_identity()?);
    /// # Ok::<(), roost_client::ClientError>(())
    /// ```
    pub fn identity(&self) -> Arc<IdentityOperations> {
        Arc::new(IdentityOperations {
            inner: Arc::clone(&self.inner),
        })
    }

    /// Returns the messaging interface using this Client's identity and protocol policy.
    ///
    /// Pass committed host snapshots to operations and atomically persist updates and effects.
    ///
    /// # Examples
    /// ```
    /// # use roost_client::{Client, InMemorySecureStorage};
    /// # use std::sync::Arc;
    /// let client = Client::new(Arc::new(InMemorySecureStorage::new()));
    /// let update = client.messaging().initialize_deduplication_set(vec![1; 16])?;
    /// # Ok::<(), roost_client::ClientError>(())
    /// ```
    pub fn messaging(&self) -> Arc<Messaging> {
        Arc::new(Messaging {
            inner: Arc::clone(&self.inner),
        })
    }

    /// Returns the contacts interface sharing this Client's identity and protocol policy.
    ///
    /// Reload committed host snapshots for queries, including after another process commits.
    ///
    /// # Examples
    /// ```
    /// # use roost_client::{Client, InMemorySecureStorage};
    /// # use std::sync::Arc;
    /// let client = Client::new(Arc::new(InMemorySecureStorage::new()));
    /// let contacts = client.contacts().contact_states(Vec::new())?;
    /// # Ok::<(), roost_client::ClientError>(())
    /// ```
    pub fn contacts(&self) -> Arc<Contacts> {
        Arc::new(Contacts {
            inner: Arc::clone(&self.inner),
        })
    }
}

#[uniffi::export]
impl Client {
    /// Returns the durable status of a retained prepared operation.
    ///
    /// Use this after an ambiguous lifecycle call or while reconciling startup state. Terminal
    /// tombstones are retained only within the bounded operation journal, so a sufficiently old
    /// finalized or aborted identifier may return [`ClientError::NotFound`].
    ///
    /// # Examples
    /// ```
    /// # use roost_client::{ClientError, InMemorySecureStorage, Client, KeyStoreOperationStatus, SecureStorage};
    /// # use std::sync::Arc;
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = Client::new(storage);
    /// let prepared = store.identity().prepare_generate_identity()?;
    /// let status = store.operation_status(prepared.operation.identifier)?;
    /// assert!(matches!(status, KeyStoreOperationStatus::Prepared));
    /// # Ok::<(), ClientError>(())
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::InvalidData`] if `identifier` is not 16 bytes.
    /// - [`ClientError::NotFound`] if the operation is no longer retained.
    /// - [`ClientError::Corrupt`] | [`ClientError::InternalError`] |
    ///   [`ClientError::Storage`] if the operation journal cannot be read.
    pub fn operation_status(
        &self,
        identifier: Vec<u8>,
    ) -> Result<KeyStoreOperationStatus, ClientError> {
        Ok(self
            .inner
            .operation_status(operation_identifier(&identifier)?)?
            .into())
    }

    /// Validates SecureStorage preconditions and reserves an operation for the host transaction.
    ///
    /// After this succeeds, commit the provisional protocol-state updates and outputs atomically.
    /// Call [`Self::finalize_operation`] after that host commit. Abort only after proving the host
    /// transaction did not commit. If the commit result is ambiguous, reload the host operation
    /// record by identifier and reconcile it through [`Self::unfinished_operations`].
    ///
    /// # Examples
    /// ```
    /// # use roost_client::{ClientError, InMemorySecureStorage, Client, KeyStoreOperationStatus, SecureStorage};
    /// # use std::sync::Arc;
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = Client::new(storage);
    /// let prepared = store.identity().prepare_generate_identity()?;
    /// let status = store.commit_operation(prepared.operation.identifier.clone())?;
    /// assert!(matches!(status, KeyStoreOperationStatus::Committed));
    /// // Atomically persist host-owned output and the identifier here.
    /// store.finalize_operation(prepared.operation.identifier)?;
    /// # Ok::<(), ClientError>(())
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::InvalidData`] if `identifier` is not 16 bytes.
    /// - [`ClientError::NotFound`] if the operation is no longer retained.
    /// - [`ClientError::OperationConflict`] if the operation cannot be committed in its current
    ///   state.
    /// - [`ClientError::OperationRecoveryRequired`] if another committed operation needs recovery.
    /// - [`ClientError::SecureStoragePreconditionChanged`] if authoritative input changed after
    ///   preparation.
    /// - [`ClientError::Corrupt`] | [`ClientError::InternalError`] |
    ///   [`ClientError::Storage`] if the operation journal cannot be updated.
    pub fn commit_operation(
        &self,
        identifier: Vec<u8>,
    ) -> Result<KeyStoreOperationStatus, ClientError> {
        Ok(self
            .inner
            .commit_operation(operation_identifier(&identifier)?)?
            .into())
    }

    /// Makes a committed operation's staged SecureStorage mutations authoritative.
    ///
    /// Repeating this call resumes interrupted finalization or returns `Finalized` again.
    ///
    /// # Examples
    /// ```
    /// # use roost_client::{ClientError, InMemorySecureStorage, Client, KeyStoreOperationStatus, SecureStorage};
    /// # use std::sync::Arc;
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = Client::new(storage);
    /// let prepared = store.identity().prepare_generate_identity()?;
    /// store.commit_operation(prepared.operation.identifier.clone())?;
    /// // The host transaction committed before finalization.
    /// let status = store.finalize_operation(prepared.operation.identifier)?;
    /// assert!(matches!(status, KeyStoreOperationStatus::Finalized));
    /// # Ok::<(), ClientError>(())
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::InvalidData`] if `identifier` is not 16 bytes.
    /// - [`ClientError::NotFound`] if the operation is no longer retained.
    /// - [`ClientError::OperationConflict`] if the operation has not committed or was aborted.
    /// - [`ClientError::Corrupt`] | [`ClientError::InternalError`] |
    ///   [`ClientError::Storage`] if staged mutations cannot be resumed.
    pub fn finalize_operation(
        &self,
        identifier: Vec<u8>,
    ) -> Result<KeyStoreOperationStatus, ClientError> {
        Ok(self
            .inner
            .finalize_operation(operation_identifier(&identifier)?)?
            .into())
    }

    /// Discards staged SecureStorage mutations before finalization starts.
    ///
    /// A committed operation may be aborted only after proving its host transaction did not commit.
    /// Reconcile an ambiguous result by identifier instead.
    ///
    /// # Examples
    /// ```
    /// # use roost_client::{ClientError, InMemorySecureStorage, Client, KeyStoreOperationStatus, SecureStorage};
    /// # use std::sync::Arc;
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = Client::new(storage);
    /// let prepared = store.identity().prepare_generate_identity()?;
    /// let status = store.abort_operation(prepared.operation.identifier)?;
    /// assert!(matches!(status, KeyStoreOperationStatus::Aborted));
    /// # Ok::<(), ClientError>(())
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::InvalidData`] if `identifier` is not 16 bytes.
    /// - [`ClientError::NotFound`] if the operation is no longer retained.
    /// - [`ClientError::OperationConflict`] if finalization already started or completed.
    /// - [`ClientError::Corrupt`] | [`ClientError::InternalError`] |
    ///   [`ClientError::Storage`] if the operation journal cannot be updated.
    pub fn abort_operation(
        &self,
        identifier: Vec<u8>,
    ) -> Result<KeyStoreOperationStatus, ClientError> {
        Ok(self
            .inner
            .abort_operation(operation_identifier(&identifier)?)?
            .into())
    }

    /// Returns prepared operations that still need startup recovery.
    ///
    /// Match each identifier against the host transaction log. Finalize operations whose host
    /// transaction committed; abort an orphan only after proving that it did not commit.
    ///
    /// # Examples
    /// ```
    /// # use roost_client::{ClientError, InMemorySecureStorage, Client, KeyStoreOperationStatus, SecureStorage};
    /// # use std::sync::Arc;
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = Client::new(storage);
    /// let prepared = store.identity().prepare_generate_identity()?;
    /// let unfinished = store.unfinished_operations()?;
    /// assert_eq!(unfinished[0].operation.identifier, prepared.operation.identifier);
    /// assert!(matches!(unfinished[0].status, KeyStoreOperationStatus::Prepared));
    /// # Ok::<(), ClientError>(())
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::Corrupt`] | [`ClientError::InternalError`] |
    ///   [`ClientError::Storage`] if the operation journal cannot be read.
    pub fn unfinished_operations(&self) -> Result<Vec<UnfinishedKeyStoreOperation>, ClientError> {
        Ok(self
            .inner
            .unfinished_operations()?
            .into_iter()
            .map(Into::into)
            .collect())
    }
}

#[uniffi::export]
impl IdentityOperations {
    /// Prepares fresh identity material without changing authoritative key entries.
    ///
    /// The secret material is staged in Core's recoverable [`SecureStorage`] journal. Commit the
    /// operation, persist any host-owned output, then finalize it before using the identity.
    ///
    /// # Examples
    /// ```
    /// # use roost_client::{Client, ClientError, Identity, InMemorySecureStorage, IdentityOperations, SecureStorage};
    /// # use std::sync::Arc;
    /// # fn publish_identity(_identity: &Identity) -> Result<(), ClientError> { Ok(()) }
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let client = Client::new(storage);
    /// let store = client.identity();
    /// let prepared = store.prepare_generate_identity()?;
    /// client.commit_operation(prepared.operation.identifier.clone())?;
    /// client.finalize_operation(prepared.operation.identifier.clone())?;
    /// publish_identity(&prepared.identity)?;
    /// # Ok::<(), ClientError>(())
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::AlreadyExists`] if complete identity and discovery-key material already
    ///   exist.
    /// - [`ClientError::Corrupt`] if stored identity key material is incomplete.
    /// - [`ClientError::InternalError`] on storage lock poisoning or system clock anomaly.
    /// - [`ClientError::InvalidData`] if stored discovery-key or identity bytes are malformed.
    /// - [`ClientError::TooManyUnfinishedOperations`] if the unfinished-operation limit is reached.
    /// - [`ClientError::OperationRecoveryRequired`] if a committed operation needs recovery.
    /// - [`ClientError::Storage`] if platform storage returns an error.
    pub fn prepare_generate_identity(&self) -> Result<PreparedIdentityGeneration, ClientError> {
        let (operation, identity) = convert_prepared(
            &self.inner,
            self.inner.prepare_generate_identity()?,
            |identity| Ok(Identity::from_core(identity)?),
        )?;
        Ok(PreparedIdentityGeneration {
            operation,
            identity,
        })
    }

    /// Loads the stored identity's public material.
    ///
    /// # Examples
    /// ```
    /// # use roost_client::{Client, ClientError, InMemorySecureStorage, IdentityOperations, SecureStorage};
    /// # use std::sync::Arc;
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let client = Client::new(storage);
    /// let store = client.identity();
    /// # let prepared = store.prepare_generate_identity()?;
    /// # client.commit_operation(prepared.operation.identifier.clone())?;
    /// # client.finalize_operation(prepared.operation.identifier)?;
    /// let identity = store.load_identity()?;
    /// # Ok::<(), ClientError>(())
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::Corrupt`] if only one of the two key parts is present.
    /// - [`ClientError::InternalError`] on storage lock poisoning.
    /// - [`ClientError::InvalidData`] if a stored key has the wrong byte length.
    /// - [`ClientError::NotFound`] if no identity is stored.
    /// - [`ClientError::OperationRecoveryRequired`] if a committed operation needs recovery.
    /// - [`ClientError::Storage`] on platform storage failure.
    pub fn load_identity(&self) -> Result<Identity, ClientError> {
        Ok(Identity::from_core(self.inner.load_identity()?)?)
    }

    /// Returns `true` when this keystore has identity data in storage.
    ///
    /// This is a presence check only. Use [`Self::load_identity`] to read and validate the public
    /// identity.
    ///
    /// # Examples
    /// ```
    /// # use roost_client::{Client, ClientError, InMemorySecureStorage, IdentityOperations, SecureStorage};
    /// # use std::sync::Arc;
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let client = Client::new(storage);
    /// let store = client.identity();
    /// if !store.has_identity()? {
    ///     let prepared = store.prepare_generate_identity()?;
    ///     client.commit_operation(prepared.operation.identifier.clone())?;
    ///     client.finalize_operation(prepared.operation.identifier)?;
    /// }
    /// # Ok::<(), ClientError>(())
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::InternalError`] on storage lock poisoning.
    /// - [`ClientError::OperationRecoveryRequired`] if a committed operation needs recovery.
    /// - [`ClientError::Storage`] on platform storage failure.
    pub fn has_identity(&self) -> Result<bool, ClientError> {
        Ok(self.inner.has_identity()?)
    }

    /// Signs a caller-built authentication transcript with the identity key's Ed25519 half.
    ///
    /// The transcript is signed exactly as given — no context is prepended. Callers own their own
    /// domain separation and put it inside the transcript, which is what a relay authentication
    /// transcript already does: `Relay-HTTP-Auth-v1` and `Relay-WebSocket-Auth-v1` are literal
    /// prefixes of the bytes the relay rebuilds and verifies. Prepending a second context here
    /// would produce a preimage no verifier ever reconstructs, so this operation deliberately does
    /// not. Aether defines neither the transcript layout nor the verifier, and never inspects the
    /// fields.
    ///
    /// What Aether does enforce is that the result can never be mistaken for one of its own
    /// signatures. A transcript starting with the reserved ASCII prefix `Aether`, matched
    /// case-insensitively, is refused, because every preimage Aether signs or verifies begins with
    /// a context from `docs/domain-separation.md` and every one of those begins with those bytes.
    /// Without the check this export would be a signing oracle able to mint an identity binding, a
    /// discovery-to-identity binding, or a message-transcript signature under the local identity
    /// key from bytes the caller — or whoever supplies the caller — chose.
    ///
    /// Returns the 64 signature bytes. Ed25519 signing is deterministic, so an identical
    /// transcript always yields an identical signature.
    ///
    /// # Examples
    /// ```
    /// # use roost_client::{Client, ClientError, InMemorySecureStorage, IdentityOperations, SecureStorage};
    /// # use std::sync::Arc;
    /// # fn challenge_nonce() -> [u8; 32] { [0x22; 32] }
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let client = Client::new(storage);
    /// let store = client.identity();
    /// # let prepared = store.prepare_generate_identity()?;
    /// # client.commit_operation(prepared.operation.identifier.clone())?;
    /// # client.finalize_operation(prepared.operation.identifier)?;
    /// let identity = store.load_identity()?;
    ///
    /// // The caller builds the whole preimage, context included.
    /// let mut transcript = b"Relay-WebSocket-Auth-v1".to_vec();
    /// transcript.extend_from_slice(&1u16.to_be_bytes());
    /// transcript.extend_from_slice(&challenge_nonce());
    /// transcript.extend_from_slice(&identity.ed25519_verifying_key);
    ///
    /// let signature = store.sign_authentication_transcript(transcript)?;
    /// assert_eq!(signature.len(), 64);
    /// # Ok::<(), ClientError>(())
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::Corrupt`] if only one of the two stored identity key parts is present.
    /// - [`ClientError::InternalError`] on storage lock poisoning.
    /// - [`ClientError::InvalidData`] if the transcript is empty, longer than 4096 bytes, starts
    ///   with the reserved `Aether` prefix, or a stored identity key has the wrong byte length.
    /// - [`ClientError::NotFound`] if no identity is stored.
    /// - [`ClientError::OperationRecoveryRequired`] if a committed operation needs recovery.
    /// - [`ClientError::Storage`] on platform storage failure.
    pub fn sign_authentication_transcript(
        &self,
        transcript: Vec<u8>,
    ) -> Result<Vec<u8>, ClientError> {
        let transcript = Zeroizing::new(transcript);
        check_signable_transcript(&transcript)?;
        Ok(self
            .inner
            .load_identity()?
            .sign(&transcript)
            .to_bytes()
            .to_vec())
    }

    /// Returns the currently stored signed pre-key bundle.
    ///
    /// Hand this to peers asking for the bundle they need to start a session.
    ///
    /// # Examples
    /// ```
    /// # use roost_client::{Client,
    /// #     ClientError, InMemorySecureStorage, IdentityOperations, SecureStorage, SignedPreKeyBundle,
    /// # };
    /// # use std::sync::Arc;
    /// # fn send_bundle_to_peer(_bundle: &SignedPreKeyBundle) -> Result<(), ClientError> {
    /// #     Ok(())
    /// # }
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let client = Client::new(storage);
    /// let store = client.identity();
    /// # let identity = store.prepare_generate_identity()?;
    /// # client.commit_operation(identity.operation.identifier.clone())?;
    /// # client.finalize_operation(identity.operation.identifier)?;
    /// # let signed_prekey = store.prepare_rotate_signed_prekey_if_stale()?;
    /// # client.commit_operation(signed_prekey.operation.identifier.clone())?;
    /// # client.finalize_operation(signed_prekey.operation.identifier)?;
    /// let bundle = store.current_signed_prekey_bundle()?;
    /// send_bundle_to_peer(&bundle)?;
    /// # Ok::<(), ClientError>(())
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::InboxRotationRequired`] after backup restore and before inbox rotation.
    /// - [`ClientError::InternalError`] on storage lock poisoning.
    /// - [`ClientError::InvalidData`] if the stored blob has the wrong length or unsupported
    ///   version.
    /// - [`ClientError::NotFound`] if no signed pre-key is stored.
    /// - [`ClientError::OperationRecoveryRequired`] if a committed operation needs recovery.
    /// - [`ClientError::Storage`] on platform storage failure.
    pub fn current_signed_prekey_bundle(&self) -> Result<SignedPreKeyBundle, ClientError> {
        Ok(self.inner.current_signed_prekey_bundle()?.into())
    }

    /// Returns the current discovery-key bundle, verified against the identity key.
    ///
    /// Publish this alongside the signed pre-key bundle so peers can verify the trust chain.
    ///
    /// # Examples
    /// ```
    /// # use roost_client::{Client,
    /// #     ClientError, DiscoveryKeyBundle, InMemorySecureStorage, IdentityOperations, SecureStorage
    /// # };
    /// # use std::sync::Arc;
    /// # fn send_to_peer(_bundle: &DiscoveryKeyBundle) -> Result<(), ClientError> {
    /// #     Ok(())
    /// # }
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let client = Client::new(storage);
    /// let store = client.identity();
    /// # let prepared = store.prepare_generate_identity()?;
    /// # client.commit_operation(prepared.operation.identifier.clone())?;
    /// # client.finalize_operation(prepared.operation.identifier)?;
    /// let bundle = store.current_discovery_key_bundle()?;
    /// send_to_peer(&bundle)?;
    /// # Ok::<(), ClientError>(())
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::Corrupt`] if the stored discovery key does not verify or identity keys are
    ///   incomplete.
    /// - [`ClientError::InternalError`] on storage lock poisoning.
    /// - [`ClientError::InvalidData`] if stored discovery-key or identity bytes are malformed.
    /// - [`ClientError::NotFound`] if no identity or discovery key is stored.
    /// - [`ClientError::OperationRecoveryRequired`] if a committed operation needs recovery.
    /// - [`ClientError::Storage`] on platform storage failure.
    pub fn current_discovery_key_bundle(&self) -> Result<DiscoveryKeyBundle, ClientError> {
        Ok(self.inner.current_discovery_key_bundle()?.into())
    }

    /// Returns the current publishable pair (discovery-key bundle + signed pre-key), atomically.
    ///
    /// Returns caller-created bundles that verify as a chain. Prefer this over reading the
    /// discovery-key and signed-pre-key bundles separately, which can race a concurrent rotation
    /// into a pair the peer rejects. Publish both bundles together.
    ///
    /// # Examples
    /// ```
    /// # use roost_client::{Client,
    /// #     ClientError, InMemorySecureStorage, IdentityOperations, PublicationBundle, SecureStorage
    /// # };
    /// # use std::sync::Arc;
    /// # fn publish(_bundle: &PublicationBundle) -> Result<(), ClientError> {
    /// #     Ok(())
    /// # }
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let client = Client::new(storage);
    /// let store = client.identity();
    /// # let identity = store.prepare_generate_identity()?;
    /// # client.commit_operation(identity.operation.identifier.clone())?;
    /// # client.finalize_operation(identity.operation.identifier)?;
    /// # let signed_prekey = store.prepare_rotate_signed_prekey_now()?;
    /// # client.commit_operation(signed_prekey.operation.identifier.clone())?;
    /// # client.finalize_operation(signed_prekey.operation.identifier)?;
    /// let publication = store.current_publication_bundle()?;
    /// publish(&publication)?;
    /// # Ok::<(), ClientError>(())
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::Corrupt`] if stored key material does not verify as a chain.
    /// - [`ClientError::InboxRotationRequired`] after backup restore and before inbox rotation.
    /// - [`ClientError::InternalError`] on storage lock poisoning or system clock anomaly.
    /// - [`ClientError::InvalidData`] if stored discovery-key, signed-pre-key, or identity bytes
    ///   are malformed.
    /// - [`ClientError::NotFound`] if no identity, discovery key, or signed pre-key is stored.
    /// - [`ClientError::OperationRecoveryRequired`] if a committed operation needs recovery.
    /// - [`ClientError::Storage`] on platform storage failure.
    pub fn current_publication_bundle(&self) -> Result<PublicationBundle, ClientError> {
        Ok(self.inner.current_publication_bundle()?.into())
    }

    /// Returns the recipient delivery capability for the current inbox generation. Always 32
    /// bytes.
    ///
    /// This is a bearer secret. Give it only to authorized contacts over an encrypted channel and
    /// persist it in platform secure storage. Register
    /// [`PublicationBundle::recipient_delivery_verifier`] with the relay instead. Roost never
    /// registers, validates, or transmits a capability.
    ///
    /// # Examples
    /// ```
    /// # use roost_client::{Client, ClientError, InMemorySecureStorage};
    /// # use std::sync::Arc;
    /// let client = Client::new(Arc::new(InMemorySecureStorage::new()));
    /// let prepared = client.identity().prepare_generate_identity()?;
    /// client.commit_operation(prepared.operation.identifier.clone())?;
    /// // Commit the host's identity record and operation identifier before finalizing.
    /// client.finalize_operation(prepared.operation.identifier)?;
    /// let capability = client.identity().current_delivery_capability()?;
    /// // Send only to authorized contacts through an encrypted channel.
    /// assert_eq!(capability.len(), 32);
    /// # Ok::<(), ClientError>(())
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::InternalError`] on storage lock poisoning.
    /// - [`ClientError::InvalidData`] if the stored discovery-key blob is malformed.
    /// - [`ClientError::NotFound`] if no discovery key is stored.
    /// - [`ClientError::OperationRecoveryRequired`] if a committed operation needs recovery.
    /// - [`ClientError::Storage`] on platform storage failure.
    pub fn current_delivery_capability(&self) -> Result<Vec<u8>, ClientError> {
        Ok(self
            .inner
            .current_delivery_capability()?
            .to_bytes()
            .to_vec())
    }

    /// Prepares exactly `batch_size` one-time pre-keys for the current discovery-key epoch.
    ///
    /// The returned records contain only public material. The secret halves remain securely staged
    /// in the recoverable operation journal and become authoritative only on finalization.
    ///
    /// # Examples
    /// ```
    /// # use roost_client::{Client, ClientError, InMemorySecureStorage, IdentityOperations, SecureStorage};
    /// # use std::sync::Arc;
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let client = Client::new(storage);
    /// let store = client.identity();
    /// # let identity = store.prepare_generate_identity()?;
    /// # client.commit_operation(identity.operation.identifier.clone())?;
    /// # client.finalize_operation(identity.operation.identifier)?;
    /// let prepared = store.prepare_generate_one_time_prekeys(8)?;
    /// assert_eq!(prepared.one_time_prekeys.len(), 8);
    /// client.commit_operation(prepared.operation.identifier.clone())?;
    /// // Atomically queue the public bundles and persist the identifier here.
    /// client.finalize_operation(prepared.operation.identifier)?;
    /// # Ok::<(), ClientError>(())
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::InboxRotationRequired`] after backup restore and before inbox rotation.
    /// - [`ClientError::InternalError`] on storage lock poisoning or system clock anomaly.
    /// - [`ClientError::InvalidData`] if stored one-time-pre-key data is malformed or the batch
    ///   exceeds capacity.
    /// - [`ClientError::NotFound`] if no identity or discovery key is stored.
    /// - [`ClientError::TooManyUnfinishedOperations`] if the unfinished-operation limit is reached.
    /// - [`ClientError::OperationRecoveryRequired`] if a committed operation needs recovery.
    /// - [`ClientError::Storage`] on platform storage failure.
    pub fn prepare_generate_one_time_prekeys(
        &self,
        batch_size: u32,
    ) -> Result<PreparedOneTimePreKeys, ClientError> {
        let (operation, one_time_prekeys) = convert_prepared(
            &self.inner,
            self.inner
                .prepare_generate_one_time_prekeys(batch_size as usize)?,
            |one_time_prekeys| Ok(one_time_prekeys.into_iter().map(Into::into).collect()),
        )?;
        Ok(PreparedOneTimePreKeys {
            operation,
            one_time_prekeys,
        })
    }

    /// Prepares one-time-prekey pool replenishment when it falls below the threshold.
    ///
    /// Returns an empty provisional list when the current pool is already above the threshold. The
    /// returned no-op operation must still be finalized or aborted.
    ///
    /// # Examples
    /// ```
    /// # use roost_client::{Client, ClientError, InMemorySecureStorage, IdentityOperations, SecureStorage};
    /// # use std::sync::Arc;
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let client = Client::new(storage);
    /// let store = client.identity();
    /// # let identity = store.prepare_generate_identity()?;
    /// # client.commit_operation(identity.operation.identifier.clone())?;
    /// # client.finalize_operation(identity.operation.identifier)?;
    /// let prepared = store.prepare_replenish_one_time_prekeys()?;
    /// client.commit_operation(prepared.operation.identifier.clone())?;
    /// // Finalize even when `one_time_prekeys` is empty.
    /// client.finalize_operation(prepared.operation.identifier)?;
    /// # Ok::<(), ClientError>(())
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::InboxRotationRequired`] after backup restore and before inbox rotation.
    /// - [`ClientError::InternalError`] on storage lock poisoning or system clock anomaly.
    /// - [`ClientError::InvalidData`] if stored one-time-prekey data is malformed.
    /// - [`ClientError::NotFound`] if no identity or discovery key is stored.
    /// - [`ClientError::TooManyUnfinishedOperations`] if the unfinished-operation limit is reached.
    /// - [`ClientError::OperationRecoveryRequired`] if a committed operation needs recovery.
    /// - [`ClientError::Storage`] on platform storage failure.
    pub fn prepare_replenish_one_time_prekeys(
        &self,
    ) -> Result<PreparedOneTimePreKeys, ClientError> {
        let (operation, one_time_prekeys) = convert_prepared(
            &self.inner,
            self.inner.prepare_replenish_one_time_prekeys()?,
            |one_time_prekeys| Ok(one_time_prekeys.into_iter().map(Into::into).collect()),
        )?;
        Ok(PreparedOneTimePreKeys {
            operation,
            one_time_prekeys,
        })
    }

    /// Prepares a discovery-key, capability, and prekey rotation as one operation.
    ///
    /// The discovery-key and signed-pre-key rotations are one operation. Stored one-time pre-keys
    /// are cleared before the discovery-key epoch advances. Publish both returned bundles together
    /// so peers can verify the full trust chain.
    ///
    /// # Examples
    /// ```
    /// # use roost_client::{Client,
    /// #     ClientError, PublicationBundle, InMemorySecureStorage, IdentityOperations, SecureStorage,
    /// # };
    /// # use std::sync::Arc;
    /// # fn publish_rotation(_bundle: &PublicationBundle) -> Result<(), ClientError> {
    /// #     Ok(())
    /// # }
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let client = Client::new(storage);
    /// let store = client.identity();
    /// # let identity = store.prepare_generate_identity()?;
    /// # client.commit_operation(identity.operation.identifier.clone())?;
    /// # client.finalize_operation(identity.operation.identifier)?;
    /// let prepared = store.prepare_rotate_inbox_now()?;
    /// client.commit_operation(prepared.operation.identifier.clone())?;
    /// client.finalize_operation(prepared.operation.identifier.clone())?;
    /// publish_rotation(&prepared.rotation.publication)?;
    /// # Ok::<(), ClientError>(())
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::Corrupt`] if the discovery key cannot be verified while creating the
    ///   signed pre-key.
    /// - [`ClientError::InternalError`] on storage lock poisoning or system clock anomaly.
    /// - [`ClientError::InvalidData`] if stored discovery-key or identity bytes are malformed.
    /// - [`ClientError::NotFound`] if no identity is stored.
    /// - [`ClientError::TooManyUnfinishedOperations`] if the unfinished-operation limit is reached.
    /// - [`ClientError::OperationRecoveryRequired`] if a committed operation needs recovery.
    /// - [`ClientError::Storage`] on platform storage failure.
    pub fn prepare_rotate_inbox_now(&self) -> Result<PreparedInboxRotation, ClientError> {
        let (operation, rotation) = convert_prepared(
            &self.inner,
            self.inner.prepare_rotate_inbox_now()?,
            |rotation| Ok(inbox_rotation_from_core(rotation)),
        )?;
        Ok(PreparedInboxRotation {
            operation,
            rotation,
        })
    }

    /// Prepares signed-prekey rotation if the stored one is missing or stale.
    ///
    /// Returns the new bundle when rotation occurred, `None` when the stored signed pre-key is
    /// still fresh. The returned no-op operation must still be finalized or aborted.
    ///
    /// Call once at app launch. The returned signed pre-key is signed by the current discovery
    /// key, so publish it together with that discovery-key bundle. Prefer
    /// [`Self::current_publication_bundle`] when publishing both keys. `None` means the stored
    /// signed pre-key is unchanged.
    ///
    /// # Examples
    /// ```
    /// # use roost_client::{Client,
    /// #     ClientError, InMemorySecureStorage, IdentityOperations, SecureStorage, SignedPreKeyBundle,
    /// # };
    /// # use std::sync::Arc;
    /// # fn publish_signed_prekey_bundle(_bundle: &SignedPreKeyBundle) -> Result<(), ClientError> {
    /// #     Ok(())
    /// # }
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let client = Client::new(storage);
    /// let store = client.identity();
    /// # let identity = store.prepare_generate_identity()?;
    /// # client.commit_operation(identity.operation.identifier.clone())?;
    /// # client.finalize_operation(identity.operation.identifier)?;
    /// let prepared = store.prepare_rotate_signed_prekey_if_stale()?;
    /// client.commit_operation(prepared.operation.identifier.clone())?;
    /// client.finalize_operation(prepared.operation.identifier)?;
    /// if let Some(new_bundle) = prepared.signed_prekey {
    ///     publish_signed_prekey_bundle(&new_bundle)?;
    /// }
    /// # Ok::<(), ClientError>(())
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::Corrupt`] if the discovery key does not verify or identity keys are
    ///   incomplete.
    /// - [`ClientError::InboxRotationRequired`] after backup restore and before inbox rotation.
    /// - [`ClientError::InternalError`] on storage lock poisoning or system clock anomaly.
    /// - [`ClientError::InvalidData`] if stored signed-pre-key, discovery-key, or identity bytes are
    ///   malformed.
    /// - [`ClientError::NotFound`] if no identity or discovery key is stored.
    /// - [`ClientError::TooManyUnfinishedOperations`] if the unfinished-operation limit is reached.
    /// - [`ClientError::OperationRecoveryRequired`] if a committed operation needs recovery.
    /// - [`ClientError::Storage`] on platform storage failure.
    pub fn prepare_rotate_signed_prekey_if_stale(
        &self,
    ) -> Result<PreparedSignedPreKeyRotation, ClientError> {
        let (operation, signed_prekey) = convert_prepared(
            &self.inner,
            self.inner.prepare_rotate_signed_prekey_if_stale()?,
            |signed_prekey| Ok(signed_prekey.map(Into::into)),
        )?;
        Ok(PreparedSignedPreKeyRotation {
            operation,
            signed_prekey,
        })
    }

    /// Prepares immediate signed-prekey rotation regardless of staleness.
    ///
    /// Use when the caller needs a fresh bundle independent of the rotation window.
    ///
    /// # Examples
    /// ```
    /// # use roost_client::{Client,
    /// #     ClientError, InMemorySecureStorage, IdentityOperations, SecureStorage, SignedPreKeyBundle,
    /// # };
    /// # use std::sync::Arc;
    /// # fn publish_signed_prekey_bundle(_bundle: &SignedPreKeyBundle) -> Result<(), ClientError> {
    /// #     Ok(())
    /// # }
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let client = Client::new(storage);
    /// let store = client.identity();
    /// # let identity = store.prepare_generate_identity()?;
    /// # client.commit_operation(identity.operation.identifier.clone())?;
    /// # client.finalize_operation(identity.operation.identifier)?;
    /// let prepared = store.prepare_rotate_signed_prekey_now()?;
    /// client.commit_operation(prepared.operation.identifier.clone())?;
    /// client.finalize_operation(prepared.operation.identifier)?;
    /// if let Some(new_bundle) = prepared.signed_prekey {
    ///     publish_signed_prekey_bundle(&new_bundle)?;
    /// }
    /// # Ok::<(), ClientError>(())
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::Corrupt`] if the discovery key does not verify or identity keys are
    ///   incomplete.
    /// - [`ClientError::InboxRotationRequired`] after backup restore and before inbox rotation.
    /// - [`ClientError::InternalError`] on storage lock poisoning or system clock anomaly.
    /// - [`ClientError::InvalidData`] if stored discovery-key or identity bytes are malformed.
    /// - [`ClientError::NotFound`] if no identity or discovery key is stored.
    /// - [`ClientError::TooManyUnfinishedOperations`] if the unfinished-operation limit is reached.
    /// - [`ClientError::OperationRecoveryRequired`] if a committed operation needs recovery.
    /// - [`ClientError::Storage`] on platform storage failure.
    pub fn prepare_rotate_signed_prekey_now(
        &self,
    ) -> Result<PreparedSignedPreKeyRotation, ClientError> {
        let (operation, signed_prekey) = convert_prepared(
            &self.inner,
            self.inner.prepare_rotate_signed_prekey_now()?,
            |signed_prekey| Ok(Some(signed_prekey.into())),
        )?;
        Ok(PreparedSignedPreKeyRotation {
            operation,
            signed_prekey,
        })
    }

    /// Exports the current identity and discovery key as a passphrase-encrypted blob.
    ///
    /// The blob is portable across devices: pass it to another keystore's
    /// [`Self::prepare_import_encrypted_backup`] with the same `passphrase` to restore the same identity
    /// and discovery-epoch lineage.
    ///
    /// Requires a stored discovery key; if it is missing, regenerate the identity with
    /// [`Self::prepare_generate_identity`] (which repairs the discovery key) before exporting.
    ///
    /// # Examples
    /// ```
    /// # use roost_client::{Client, ClientError, InMemorySecureStorage, IdentityOperations, SecureStorage};
    /// # use std::sync::Arc;
    /// # fn persist_backup_blob(_blob: &[u8]) -> Result<(), ClientError> { Ok(()) }
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let client = Client::new(storage);
    /// let store = client.identity();
    /// # let prepared = store.prepare_generate_identity()?;
    /// # client.commit_operation(prepared.operation.identifier.clone())?;
    /// # client.finalize_operation(prepared.operation.identifier)?;
    /// let blob = store.export_encrypted_backup("strong passphrase".into())?;
    /// persist_backup_blob(&blob)?;
    /// # Ok::<(), ClientError>(())
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::BackupFailed`] on randomness failure, Argon2id derivation error, or
    ///   authenticated encryption failure.
    /// - [`ClientError::Corrupt`] if identity keys are incomplete or the discovery key does not
    ///   verify against the current identity.
    /// - [`ClientError::InternalError`] on storage lock poisoning.
    /// - [`ClientError::InvalidData`] if a stored identity key has the wrong byte length.
    /// - [`ClientError::NotFound`] if no identity or discovery key is stored.
    /// - [`ClientError::OperationRecoveryRequired`] if a committed operation needs recovery.
    /// - [`ClientError::Storage`] on platform storage failure when loading an identity.
    ///
    /// # Performance
    /// The backup blob is about 274 bytes: a versioned header carrying the Argon2id parameters,
    /// followed by the encrypted identity and discovery keys. Each call runs one Argon2id password
    /// hashing step using 64 MiB memory and 3 iterations.
    pub fn export_encrypted_backup(&self, passphrase: String) -> Result<Vec<u8>, ClientError> {
        let passphrase = Zeroizing::new(passphrase);
        Ok(self.inner.export_encrypted_backup(&passphrase)?)
    }

    /// Prepares restoration of an encrypted identity backup.
    ///
    /// The backup is decrypted and the restored discovery key is validated against the restored
    /// identity before staging changes, so a wrong passphrase or malformed blob leaves the
    /// existing identity untouched. Commit the operation, atomically wipe or replace host-owned
    /// Session, deduplication, and pending-acknowledgment state, then finalize. Prekey use stays
    /// blocked until [`Self::prepare_rotate_inbox_now`] advances the restored identity to a fresh
    /// inbox generation. This prevents reuse of prekey identifiers that the backed-up generation
    /// may already have published.
    ///
    /// # Examples
    /// ```
    /// # use roost_client::{Client, ClientError, InMemorySecureStorage, IdentityOperations, SecureStorage};
    /// # use std::sync::Arc;
    /// // Source keystore: generate an identity and export an encrypted backup.
    /// let source: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// let source_store = Client::new(source);
    /// let identity = source_store.identity().prepare_generate_identity()?;
    /// source_store.commit_operation(identity.operation.identifier.clone())?;
    /// source_store.finalize_operation(identity.operation.identifier)?;
    /// let blob = source_store.identity().export_encrypted_backup("strong passphrase".into())?;
    ///
    /// // Restored keystore: import the blob into a fresh store.
    /// let destination: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// let destination_store = Client::new(destination);
    /// let operation = destination_store.identity().prepare_import_encrypted_backup(
    ///     blob,
    ///     "strong passphrase".into(),
    /// )?;
    /// destination_store.commit_operation(operation.identifier.clone())?;
    /// // Atomically wipe host-owned protocol state here.
    /// destination_store.finalize_operation(operation.identifier)?;
    /// let rotation = destination_store.identity().prepare_rotate_inbox_now()?;
    /// destination_store.commit_operation(rotation.operation.identifier.clone())?;
    /// // Publish `rotation.rotation.publication` and persist the identifier atomically.
    /// destination_store.finalize_operation(rotation.operation.identifier)?;
    /// # Ok::<(), ClientError>(())
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::BackupFailed`] on Argon2id derivation failure.
    /// - [`ClientError::DecryptionFailed`] on wrong passphrase or backup authentication failure.
    /// - [`ClientError::InternalError`] on storage lock poisoning.
    /// - [`ClientError::Corrupt`] if the backup's discovery key is not signed by the backup's
    ///   identity key.
    /// - [`ClientError::InvalidData`] on a malformed header, authenticated unsupported version,
    ///   out-of-range Argon2id parameters, or a malformed discovery-key blob.
    /// - [`ClientError::TooManyUnfinishedOperations`] if the unfinished-operation limit is reached.
    /// - [`ClientError::OperationRecoveryRequired`] if a committed operation needs recovery.
    /// - [`ClientError::Storage`] on platform storage failure during commit.
    ///
    /// # Performance
    /// The backup blob is about 274 bytes: a versioned header carrying the Argon2id parameters,
    /// followed by the encrypted identity and discovery keys. Each call runs one Argon2id password
    /// hashing step using 64 MiB memory and 3 iterations.
    pub fn prepare_import_encrypted_backup(
        &self,
        data: Vec<u8>,
        passphrase: String,
    ) -> Result<KeyStoreOperation, ClientError> {
        let data = Zeroizing::new(data);
        let passphrase = Zeroizing::new(passphrase);
        Ok(self
            .inner
            .prepare_import_encrypted_backup(data.as_slice(), passphrase.as_str())?
            .operation
            .into())
    }

    /// Prepares deletion of all stored prekeys, discovery-key, and identity material.
    ///
    /// Commit the operation, atomically wipe host-owned protocol state, then finalize. Calling this
    /// on an empty store still produces an idempotent recoverable operation.
    ///
    /// # Examples
    /// ```
    /// # use roost_client::{Client, ClientError, InMemorySecureStorage, IdentityOperations, SecureStorage};
    /// # use std::sync::Arc;
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let client = Client::new(storage);
    /// let store = client.identity();
    /// let operation = store.prepare_reset()?;
    /// client.commit_operation(operation.identifier.clone())?;
    /// // Atomically wipe host-owned protocol state here.
    /// client.finalize_operation(operation.identifier)?;
    /// # Ok::<(), ClientError>(())
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::InternalError`] on storage lock poisoning.
    /// - [`ClientError::TooManyUnfinishedOperations`] if the unfinished-operation limit is reached.
    /// - [`ClientError::OperationRecoveryRequired`] if a committed operation needs recovery.
    /// - [`ClientError::Storage`] on platform storage failure.
    pub fn prepare_reset(&self) -> Result<KeyStoreOperation, ClientError> {
        Ok(self.inner.prepare_reset()?.operation.into())
    }
}

#[uniffi::export]
impl Messaging {
    /// Starts a new Session while authenticating a caller-owned Transport Binding.
    ///
    /// Commit the returned state updates atomically with the returned Message and retain the exact
    /// binding for transport retry. Aether does not interpret, transmit, or store the binding.
    ///
    /// # Examples
    /// ```
    /// use roost_client::{
    ///     ClientError, Identity, Messaging, OneTimePreKeyBundle, PublicationBundle, TransportBinding,
    ///     SessionInitiationResult,
    /// };
    ///
    /// fn initiate(
    ///     store: &Messaging,
    ///     responder_identity: Identity,
    ///     responder_publication: PublicationBundle,
    ///     responder_one_time_prekey: Option<OneTimePreKeyBundle>,
    ///     transport_binding: TransportBinding,
    /// ) -> Result<SessionInitiationResult, ClientError> {
    ///     store.initiate_session(
    ///         vec![0x11; 16],
    ///         responder_identity,
    ///         responder_publication,
    ///         responder_one_time_prekey,
    ///         Vec::new(),
    ///         Vec::new(),
    ///         b"hello".to_vec(),
    ///         transport_binding,
    ///     )
    /// }
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::AuthenticationFailed`] if X3DH, sealed-frame, sender-proof, or AEAD work
    ///   fails.
    /// - [`ClientError::Corrupt`] if stored Identity or Discovery Key material is incomplete or
    ///   fails its binding checks.
    /// - [`ClientError::InternalError`] on storage lock poisoning.
    /// - [`ClientError::InvalidData`] if key, Message, certificate, prekey, or Transport Binding
    ///   inputs are malformed.
    /// - [`ClientError::NotFound`] if local Identity or Discovery Key material is missing.
    /// - [`ClientError::OperationRecoveryRequired`] if a committed operation needs recovery.
    /// - [`ClientError::ProtocolStateFault`] if install state cannot be encoded.
    /// - [`ClientError::Storage`] on platform storage failure.
    /// - [`ClientError::UnsupportedVersion`] if a prekey bundle, Message, or stored key version is
    ///   unsupported.
    #[expect(
        clippy::too_many_arguments,
        reason = "flat UniFFI export preserves generated binding shape"
    )]
    pub fn initiate_session(
        &self,
        session_key: Vec<u8>,
        responder_identity: Identity,
        responder_publication: PublicationBundle,
        responder_one_time_prekey: Option<OneTimePreKeyBundle>,
        sender_certificate: Vec<u8>,
        sender_signature: Vec<u8>,
        plaintext: Vec<u8>,
        transport_binding: TransportBinding,
    ) -> Result<SessionInitiationResult, ClientError> {
        let sender_certificate = Zeroizing::new(sender_certificate);
        let sender_signature = Zeroizing::new(sender_signature);
        let plaintext = Zeroizing::new(plaintext);
        let transport_binding = transport_binding.into_core()?;
        let result = self.inner.initiate_session_with_transport_binding(
            SessionInitiation {
                session_key: ProtocolStateKey::from_bytes(session_key)?,
                responder_identity_key: responder_identity.to_core()?,
                responder_discovery_to_identity: responder_publication
                    .discovery_to_identity_signature()?,
                responder_prekey_bundle: responder_publication
                    .to_prekey_bundle(responder_one_time_prekey)?,
                sender_certificate: &sender_certificate,
                sender_signature: &sender_signature,
                plaintext: &plaintext,
            },
            &transport_binding,
        )?;
        Ok(SessionInitiationResult {
            message: Message::from_core(result.message),
            state_updates: updates_from_core(result.state_updates)?,
        })
    }

    /// Reads who sent an X3DH first Message while authenticating its Transport Binding.
    ///
    /// This operation consumes no one-time prekey. Pass the same binding and prekey selection to
    /// [`Self::prepare_accept_session`] after deriving the host Session key.
    ///
    /// # Examples
    /// ```
    /// use roost_client::{ClientError, Identity, Messaging, Message, PreKeySelection, TransportBinding};
    ///
    /// fn inspect_sender(
    ///     store: &Messaging,
    ///     message: Message,
    ///     transport_binding: TransportBinding,
    ///     prekey_selection: PreKeySelection,
    /// ) -> Result<Identity, ClientError> {
    ///     store.initiator_identity_hint(
    ///         message,
    ///         transport_binding,
    ///         prekey_selection,
    ///     )
    /// }
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::AuthenticationFailed`] if the frame is not sealed to this Discovery Key
    ///   and Transport Binding, the selected one-time-prekey identifier does not match the
    ///   Message, or the named identity's binding signature does not verify.
    /// - [`ClientError::Corrupt`] if stored Identity or Discovery Key material is incomplete or
    ///   fails its binding checks.
    /// - [`ClientError::InboxRotationRequired`] after backup restore and before inbox rotation.
    /// - [`ClientError::InternalError`] on storage lock poisoning.
    /// - [`ClientError::InvalidData`] if the Message or Transport Binding is malformed.
    /// - [`ClientError::NotFound`] if local Discovery Key or referenced signed-prekey material is
    ///   missing.
    /// - [`ClientError::OperationRecoveryRequired`] if a committed operation needs recovery.
    /// - [`ClientError::Storage`] on platform storage failure.
    /// - [`ClientError::UnsupportedVersion`] if the Message or stored prekey version is unsupported.
    pub fn initiator_identity_hint(
        &self,
        message: Message,
        transport_binding: TransportBinding,
        prekey_selection: PreKeySelection,
    ) -> Result<Identity, ClientError> {
        let core_message = message.to_core()?;
        let transport_binding = transport_binding.into_core()?;
        let bundle = self.inner.initiator_identity_hint_with_transport_binding(
            &core_message,
            &transport_binding,
            prekey_selection.to_core(),
        )?;
        Ok(Identity {
            x25519_public_key: bundle.public_key.as_bytes().to_vec(),
            ed25519_verifying_key: bundle.verifying_key.as_bytes().to_vec(),
            identity_binding_signature: bundle.binding_signature.to_bytes().to_vec(),
        })
    }

    /// Prepares responder-side Session acceptance while authenticating a Transport Binding.
    ///
    /// For a retained superseded signed prekey, the host must first validate that its transport
    /// accepted the item before supersession. Commit the operation, atomically persist the returned
    /// state updates and operation identifier, then finalize SecureStorage.
    ///
    /// # Examples
    /// ```
    /// use roost_client::{
    ///     ClientError, Messaging, Message, PreKeySelection, PreparedSessionAcceptance,
    ///     TransportBinding,
    /// };
    ///
    /// fn prepare_acceptance(
    ///     store: &Messaging,
    ///     session_key: Vec<u8>,
    ///     message: Message,
    ///     transport_binding: TransportBinding,
    ///     prekey_selection: PreKeySelection,
    /// ) -> Result<PreparedSessionAcceptance, ClientError> {
    ///     store.prepare_accept_session(
    ///         session_key,
    ///         None,
    ///         message,
    ///         transport_binding,
    ///         prekey_selection,
    ///     )
    /// }
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::AuthenticationFailed`] if X3DH, sealed-frame, sender-proof, or AEAD work
    ///   fails.
    /// - [`ClientError::Corrupt`] if stored Identity or Discovery Key material is incomplete or
    ///   fails its binding checks.
    /// - [`ClientError::InboxRotationRequired`] after backup restore and before inbox rotation.
    /// - [`ClientError::InternalError`] on storage lock poisoning or operation identifier
    ///   generation failure.
    /// - [`ClientError::InvalidData`] if the Message, key, prekey, or Transport Binding inputs are
    ///   malformed.
    /// - [`ClientError::NotFound`] if required local Identity, Discovery Key, signed-prekey, or
    ///   one-time-prekey material is missing.
    /// - [`ClientError::TooManyUnfinishedOperations`] if the unfinished-operation limit is reached.
    /// - [`ClientError::OperationRecoveryRequired`] if a committed operation needs recovery.
    /// - [`ClientError::ProtocolStateFault`] if install state cannot be encoded.
    /// - [`ClientError::Storage`] on platform storage failure.
    /// - [`ClientError::UnsupportedVersion`] if the Message, stored prekey, or protocol-state
    ///   version is unsupported.
    pub fn prepare_accept_session(
        &self,
        session_key: Vec<u8>,
        initiator_identity: Option<Identity>,
        message: Message,
        transport_binding: TransportBinding,
        prekey_selection: PreKeySelection,
    ) -> Result<PreparedSessionAcceptance, ClientError> {
        let core_message = message.to_core()?;
        let initiator_identity_key = initiator_identity
            .map(|identity| identity.to_core())
            .transpose()?;
        let transport_binding = transport_binding.into_core()?;
        let prepared = self.inner.prepare_accept_session_with_transport_binding(
            SessionAcceptance {
                session_key: ProtocolStateKey::from_bytes(session_key)?,
                initiator_identity_key,
                message: &core_message,
            },
            &transport_binding,
            prekey_selection.to_core(),
        )?;
        let (operation, acceptance) = convert_prepared(&self.inner, prepared, |result| {
            let state_updates = updates_from_core(result.state_updates)?;
            Ok(SessionAcceptanceResult {
                plaintext: result.plaintext.to_vec(),
                sender_identity: SenderIdentityMaterial::from_core(result.sender_identity),
                state_updates,
            })
        })?;
        Ok(PreparedSessionAcceptance {
            operation,
            acceptance,
        })
    }

    /// Encrypts an established-session Message while authenticating a Transport Binding.
    ///
    /// Commit the returned state updates atomically with the returned Message and retain the exact
    /// binding for retransmission.
    ///
    /// # Examples
    /// ```
    /// use roost_client::{
    ///     ClientError, IdentityKey, Messaging, OutboundMessageResult, ProtocolStateEntry,
    ///     TransportBinding,
    /// };
    ///
    /// fn encrypt(
    ///     store: &Messaging,
    ///     snapshot: Vec<ProtocolStateEntry>,
    ///     contact: IdentityKey,
    ///     transport_binding: TransportBinding,
    /// ) -> Result<OutboundMessageResult, ClientError> {
    ///     store.encrypt_message(
    ///         snapshot,
    ///         vec![0x11; 16],
    ///         vec![0x22; 16],
    ///         contact,
    ///         vec![0x33; 32],
    ///         1_700_000_000_000,
    ///         Vec::new(),
    ///         Vec::new(),
    ///         b"hello".to_vec(),
    ///         transport_binding,
    ///     )
    /// }
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::ContactNotAccepted`] if the peer contact is still pending.
    /// - [`ClientError::TerminalSessionRecovery`] if the Session requires replacement.
    /// - [`ClientError::BlockedContact`] if the contact is locally blocked.
    /// - [`ClientError::Corrupt`] if stored Identity material is incomplete.
    /// - [`ClientError::InternalError`] on storage lock poisoning.
    /// - [`ClientError::InvalidData`] if Message identifiers, keys, Message fields, or the
    ///   Transport Binding are malformed.
    /// - [`ClientError::NotFound`] if local Identity material is missing.
    /// - [`ClientError::OperationRecoveryRequired`] if a committed operation needs recovery.
    /// - [`ClientError::ProtocolStateFault`] if required blobs are missing or malformed.
    /// - [`ClientError::Storage`] on platform storage failure.
    /// - [`ClientError::UnsupportedVersion`] if a stored protocol-state version is unsupported.
    #[expect(
        clippy::too_many_arguments,
        reason = "flat UniFFI export preserves generated binding shape"
    )]
    pub fn encrypt_message(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        session_key: Vec<u8>,
        message_id: Vec<u8>,
        contact_identity_key: FfiIdentityKey,
        recipient_public_key: Vec<u8>,
        timestamp_millis: u64,
        sender_certificate: Vec<u8>,
        sender_signature: Vec<u8>,
        plaintext: Vec<u8>,
        transport_binding: TransportBinding,
    ) -> Result<OutboundMessageResult, ClientError> {
        let sender_certificate = Zeroizing::new(sender_certificate);
        let sender_signature = Zeroizing::new(sender_signature);
        let plaintext = Zeroizing::new(plaintext);
        let snapshot = snapshot_input_from_entries(snapshot)?;
        let transport_binding = transport_binding.into_core()?;
        OutboundMessageResult::from_core(self.inner.encrypt_message_with_transport_binding(
            MessageEncryption {
                snapshot: &snapshot,
                session_key: protocol_key(session_key)?,
                message_id: MessageId::from_bytes(fixed_16(&message_id, "message id")?),
                contact_identity_key: contact_identity_key.to_core()?,
                recipient_public_key: fixed_32(&recipient_public_key, "recipient public key")?,
                timestamp_millis,
                sender_certificate: &sender_certificate,
                sender_signature: &sender_signature,
                plaintext: &plaintext,
            },
            &transport_binding,
        )?)
    }

    /// Decrypts an established-session Message while authenticating its Transport Binding and the
    /// binding used for the returned acknowledgment.
    ///
    /// Unique Messages require `sender_certificate_validation`; duplicates can return before
    /// validation because they surface no plaintext. Retain `acknowledgment_transport_binding`
    /// with any returned acknowledgment Message.
    ///
    /// # Examples
    /// ```
    /// use roost_client::{
    ///     ClientError, InboundMessageOutcome, Messaging, Message, ProtocolStateEntry, TransportBinding,
    /// };
    ///
    /// fn decrypt(
    ///     store: &Messaging,
    ///     snapshot: Vec<ProtocolStateEntry>,
    ///     message: Message,
    ///     message_transport_binding: TransportBinding,
    ///     acknowledgment_transport_binding: TransportBinding,
    /// ) -> Result<InboundMessageOutcome, ClientError> {
    ///     store.decrypt_message(
    ///         snapshot,
    ///         vec![0x11; 16],
    ///         b"deduplication".to_vec(),
    ///         message,
    ///         vec![0x22; 16],
    ///         vec![0x33; 32],
    ///         1_700_000_000_000,
    ///         Vec::new(),
    ///         Vec::new(),
    ///         None,
    ///         message_transport_binding,
    ///         acknowledgment_transport_binding,
    ///     )
    /// }
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::AuthenticationFailed`] if sealed-sender, ratchet, transcript, or AEAD
    ///   authentication fails.
    /// - [`ClientError::CertificateRejected`] if sender-certificate validation rejects the sender.
    /// - [`ClientError::Corrupt`] if stored Identity or Discovery Key material is incomplete or
    ///   fails its binding checks.
    /// - [`ClientError::InternalError`] on storage lock poisoning.
    /// - [`ClientError::InvalidData`] if Message identifiers, keys, Message fields, or either
    ///   Transport Binding is malformed.
    /// - [`ClientError::NotFound`] if local Identity or Discovery Key material is missing.
    /// - [`ClientError::OperationRecoveryRequired`] if a committed operation needs recovery.
    /// - [`ClientError::ProtocolStateFault`] if required blobs are missing or malformed.
    /// - [`ClientError::Storage`] on platform storage failure.
    /// - [`ClientError::UnsupportedVersion`] if the Message or a stored protocol-state version is
    ///   unsupported.
    #[expect(
        clippy::too_many_arguments,
        reason = "flat UniFFI export preserves generated binding shape"
    )]
    pub fn decrypt_message(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        session_key: Vec<u8>,
        deduplication_key: Vec<u8>,
        message: Message,
        acknowledgment_id: Vec<u8>,
        acknowledgment_recipient_public_key: Vec<u8>,
        acknowledgment_timestamp_millis: u64,
        acknowledgment_sender_certificate: Vec<u8>,
        acknowledgment_sender_signature: Vec<u8>,
        sender_certificate_validation: Option<SenderCertificateValidation>,
        message_transport_binding: TransportBinding,
        acknowledgment_transport_binding: TransportBinding,
    ) -> Result<InboundMessageOutcome, ClientError> {
        let acknowledgment_sender_certificate = Zeroizing::new(acknowledgment_sender_certificate);
        let acknowledgment_sender_signature = Zeroizing::new(acknowledgment_sender_signature);
        let snapshot = snapshot_input_from_entries(snapshot)?;
        let message = message.to_core()?;
        let message_transport_binding = message_transport_binding.into_core()?;
        let acknowledgment_transport_binding = acknowledgment_transport_binding.into_core()?;

        let validation_storage = if let Some(validation) = &sender_certificate_validation {
            Some((
                domain_signing_keys_to_core(&validation.domain_signing_keys)?,
                revoked_identity_keys_to_core(&validation.revocation_state)?,
            ))
        } else {
            None
        };
        let core_validation = sender_certificate_validation
            .as_ref()
            .zip(validation_storage.as_ref())
            .map(
                |(validation, (domain_signing_keys, revoked_identity_keys))| {
                    InboundSenderCertificateValidation {
                        domain_signing_keys,
                        expected_relay_domain: &validation.expected_relay_domain,
                        revocation_state: revocation_state_to_core(
                            &validation.revocation_state,
                            revoked_identity_keys,
                        ),
                        reference_timestamp_secs: validation.reference_timestamp_secs,
                        grace_window_secs: validation.grace_window_secs,
                    }
                },
            );

        InboundMessageOutcome::from_core(self.inner.decrypt_message_with_transport_bindings(
            MessageDecryption {
                snapshot: &snapshot,
                session_key: protocol_key(session_key)?,
                deduplication_key: protocol_key(deduplication_key)?,
                message: &message,
                acknowledgment_id: MessageId::from_bytes(fixed_16(
                    &acknowledgment_id,
                    "acknowledgment id",
                )?),
                acknowledgment_recipient_public_key: fixed_32(
                    &acknowledgment_recipient_public_key,
                    "acknowledgment recipient public key",
                )?,
                acknowledgment_timestamp_millis,
                acknowledgment_sender_certificate: &acknowledgment_sender_certificate,
                acknowledgment_sender_signature: &acknowledgment_sender_signature,
                sender_certificate_validation: core_validation,
            },
            &message_transport_binding,
            &acknowledgment_transport_binding,
        )?)
    }

    /// Processes an encrypted acknowledgment while authenticating its Transport Binding.
    ///
    /// Commit returned updates before clearing local transport retry state.
    ///
    /// # Examples
    /// ```
    /// use roost_client::{
    ///     AcknowledgmentOutcome, ClientError, Messaging, Message, ProtocolStateEntry, TransportBinding,
    /// };
    ///
    /// fn process(
    ///     store: &Messaging,
    ///     snapshot: Vec<ProtocolStateEntry>,
    ///     message: Message,
    ///     transport_binding: TransportBinding,
    /// ) -> Result<AcknowledgmentOutcome, ClientError> {
    ///     store.process_acknowledgment(
    ///         snapshot,
    ///         vec![0x11; 16],
    ///         message,
    ///         transport_binding,
    ///     )
    /// }
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::AuthenticationFailed`] if sealed-sender, ratchet, transcript, or AEAD
    ///   authentication fails.
    /// - [`ClientError::Corrupt`] if stored Identity or Discovery Key material is incomplete or
    ///   fails its binding checks.
    /// - [`ClientError::InternalError`] on storage lock poisoning.
    /// - [`ClientError::InvalidData`] if Message fields or the Transport Binding are malformed.
    /// - [`ClientError::NotFound`] if local Identity or Discovery Key material is missing.
    /// - [`ClientError::OperationRecoveryRequired`] if a committed operation needs recovery.
    /// - [`ClientError::ProtocolStateFault`] if required blobs are missing or malformed.
    /// - [`ClientError::Storage`] on platform storage failure.
    /// - [`ClientError::UnsupportedVersion`] if the Message or a stored protocol-state version is
    ///   unsupported.
    pub fn process_acknowledgment(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        session_key: Vec<u8>,
        message: Message,
        transport_binding: TransportBinding,
    ) -> Result<AcknowledgmentOutcome, ClientError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        let message = message.to_core()?;
        let transport_binding = transport_binding.into_core()?;
        AcknowledgmentOutcome::from_core(self.inner.process_acknowledgment_with_transport_binding(
            AcknowledgmentProcessing {
                snapshot: &snapshot,
                session_key: protocol_key(session_key)?,
                message: &message,
            },
            &transport_binding,
        )?)
    }
}

#[uniffi::export]
impl Contacts {
    /// Prepares a contact block and inbox rotation so both cross one host commit boundary.
    ///
    /// Blocking stops this device sending and surfacing the contact's messages and rotates the
    /// local inbox to invalidate the contact's delivery capability. Rotation also invalidates
    /// every other contact's copy:
    /// when `PreparedContactBlock.block.rotation` is present, each remaining contact must receive
    /// the new capability before it can deliver again.
    /// [`Self::contacts_needing_inbox_authorization`] returns that list and excludes the blocked
    /// contact.
    ///
    /// Blocking an already-blocked contact performs no rotation, so repeating the call does not
    /// churn every contact's capability. Its no-op operation must still be finalized or aborted.
    ///
    /// Commit the operation, atomically persist `PreparedContactBlock.block.contact` and any
    /// host-owned publication work, then finalize the staged SecureStorage rotation. Abort only
    /// after proving the host transaction did not commit.
    ///
    /// # Examples
    /// ```
    /// use roost_client::{Client, ClientError, IdentityKey, Contacts, ProtocolStateEntry};
    ///
    /// fn block(
    ///     client: &Client,
    ///     snapshot: Vec<ProtocolStateEntry>,
    ///     identity_key: IdentityKey,
    /// ) -> Result<(), ClientError> {
    ///     let prepared = client.contacts().prepare_block_contact(snapshot, identity_key)?;
    ///     client.commit_operation(prepared.operation.identifier.clone())?;
    ///     // Persist `prepared.block.contact`, publication work, and the identifier atomically.
    ///     client.finalize_operation(prepared.operation.identifier)?;
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Errors
    /// - [`ClientError::InvalidData`] if `identity_key` has the wrong length.
    /// - [`ClientError::InternalError`] on storage lock poisoning or system clock anomaly.
    /// - [`ClientError::TooManyUnfinishedOperations`] if the unfinished-operation limit is reached.
    /// - [`ClientError::OperationRecoveryRequired`] if a committed operation needs recovery.
    /// - [`ClientError::ProtocolStateFault`] if no contact is stored for `identity_key`, or its
    ///   blob is malformed.
    /// - [`ClientError::Storage`] on platform storage failure.
    pub fn prepare_block_contact(
        &self,
        snapshot: Vec<ProtocolStateEntry>,
        identity_key: FfiIdentityKey,
    ) -> Result<PreparedContactBlock, ClientError> {
        let snapshot = snapshot_input_from_entries(snapshot)?;
        let prepared = self
            .inner
            .prepare_block_contact(&snapshot, identity_key.to_core()?)?;
        let (operation, block) = convert_prepared(&self.inner, prepared, |blocked| {
            Ok(ContactBlock {
                contact: ContactStateChange::from_core(blocked.contact)?,
                rotation: blocked.rotation.map(inbox_rotation_from_core),
            })
        })?;
        Ok(PreparedContactBlock { operation, block })
    }
}

fn convert_prepared<T, U>(
    store: &CoreKeyStore,
    prepared: CorePreparedKeyStoreOperation<T>,
    convert: impl FnOnce(T) -> Result<U, ClientError>,
) -> Result<(KeyStoreOperation, U), ClientError> {
    let identifier = prepared.operation.identifier;
    let operation = prepared.operation.into();
    match convert(prepared.output) {
        Ok(output) => Ok((operation, output)),
        // A conversion failure hides the prepared output from the host. Abort its journal record,
        // or return the identifier so the host can reconcile an uncertain cleanup after restart.
        Err(error) => match store.abort_operation(identifier) {
            Ok(_) => Err(error),
            Err(abort_error) => Err(ClientError::OperationRecoveryRequired {
                operation_identifier: identifier.as_bytes().to_vec(),
                reason: format!(
                    "prepared output conversion failed and cleanup also failed: {abort_error}"
                ),
            }),
        },
    }
}
fn inbox_rotation_from_core(rotation: roost_core::InboxRotation) -> InboxRotation {
    InboxRotation {
        publication: rotation.publication.into(),
        capability: rotation.capability.to_bytes().to_vec(),
    }
}

// Bounds what the identity key will sign for a caller-defined purpose. The prefix rule is the
// security-relevant half: it keeps this export's preimages disjoint from every context in
// docs/domain-separation.md, so no signature it produces can satisfy an Aether verifier.
fn check_signable_transcript(transcript: &[u8]) -> Result<(), ClientError> {
    if transcript.is_empty() {
        return Err(ClientError::InvalidData {
            reason: "authentication transcript is empty".into(),
        });
    }
    if transcript.len() > MAX_AUTHENTICATION_TRANSCRIPT_LEN {
        return Err(ClientError::InvalidData {
            reason: format!(
                "authentication transcript exceeds {MAX_AUTHENTICATION_TRANSCRIPT_LEN} bytes"
            ),
        });
    }
    let reserved = RESERVED_AETHER_DOMAIN_PREFIX.len();
    if transcript.len() >= reserved
        && transcript[..reserved].eq_ignore_ascii_case(RESERVED_AETHER_DOMAIN_PREFIX)
    {
        return Err(ClientError::InvalidData {
            reason: "authentication transcript starts with the reserved Aether domain prefix"
                .into(),
        });
    }
    Ok(())
}

#[cfg(test)]
impl Client {
    fn complete_prepared<T>(
        &self,
        operation: KeyStoreOperation,
        output: T,
    ) -> Result<T, ClientError> {
        self.commit_operation(operation.identifier.clone())?;
        self.finalize_operation(operation.identifier)?;
        Ok(output)
    }

    pub(crate) fn generate_identity(&self) -> Result<Identity, ClientError> {
        let prepared = self.identity().prepare_generate_identity()?;
        self.complete_prepared(prepared.operation, prepared.identity)
    }

    pub(crate) fn generate_one_time_prekeys(
        &self,
        batch_size: u32,
    ) -> Result<Vec<OneTimePreKeyBundle>, ClientError> {
        let prepared = self
            .identity()
            .prepare_generate_one_time_prekeys(batch_size)?;
        self.complete_prepared(prepared.operation, prepared.one_time_prekeys)
    }

    pub(crate) fn replenish_one_time_prekeys(
        &self,
    ) -> Result<Vec<OneTimePreKeyBundle>, ClientError> {
        let prepared = self.identity().prepare_replenish_one_time_prekeys()?;
        self.complete_prepared(prepared.operation, prepared.one_time_prekeys)
    }

    pub(crate) fn rotate_inbox_now(&self) -> Result<InboxRotation, ClientError> {
        let prepared = self.identity().prepare_rotate_inbox_now()?;
        self.complete_prepared(prepared.operation, prepared.rotation)
    }

    pub(crate) fn rotate_signed_prekey_if_stale(
        &self,
    ) -> Result<Option<SignedPreKeyBundle>, ClientError> {
        let prepared = self.identity().prepare_rotate_signed_prekey_if_stale()?;
        self.complete_prepared(prepared.operation, prepared.signed_prekey)
    }

    pub(crate) fn rotate_signed_prekey_now(&self) -> Result<SignedPreKeyBundle, ClientError> {
        let prepared = self.identity().prepare_rotate_signed_prekey_now()?;
        let signed_prekey = prepared.signed_prekey.ok_or(ClientError::InternalError {
            reason: "forced signed-prekey rotation returned no bundle".into(),
        })?;
        self.complete_prepared(prepared.operation, signed_prekey)
    }

    pub(crate) fn accept_session(
        &self,
        session_key: Vec<u8>,
        initiator_identity: Option<Identity>,
        message: Message,
    ) -> Result<SessionAcceptanceResult, ClientError> {
        let selection = crate::PreKeySelection {
            signed_prekey_identifier: self.identity().current_signed_prekey_bundle()?.identifier,
            one_time_prekey_identifier: message
                .prekey_reference
                .as_ref()
                .and_then(|p| p.one_time_prekey_identifier),
        };
        let prepared = self.messaging().prepare_accept_session(
            session_key,
            initiator_identity,
            message,
            crate::TransportBinding {
                bytes: b"test-route".to_vec(),
            },
            selection,
        )?;
        self.complete_prepared(prepared.operation, prepared.acceptance)
    }
}

#[cfg(test)]
mod tests {
    use super::{Client, KeyStoreOperationStatus, MAX_AUTHENTICATION_TRANSCRIPT_LEN};
    use crate::{
        ClientError, InMemorySecureStorage, SecureStorage,
        protocol::{
            ContactDiscoveryKey, ContactIdentity, IdentityKey, ProtocolStateEntry,
            ProtocolStateKind, ProtocolStateUpdate,
        },
        records::{
            DiscoveryKeyBundle as FfiDiscoveryKeyBundle, Identity as FfiIdentity,
            OneTimePreKeyBundle as FfiOneTimePreKeyBundle,
            PublicationBundle as FfiPublicationBundle, SignedPreKeyBundle as FfiSignedPreKeyBundle,
        },
    };
    use roost_core::test_support::{
        DiscoveryKeyBundle as CryptoDiscoveryKeyBundle,
        IdentityKeyBundle as CryptoIdentityKeyBundle, PublicKey,
        RecipientDeliveryCapability as CryptoCapability, Signature,
        SignedPreKeyBundle as CryptoSignedPreKeyBundle, SigningKeyPair, VerifyingKey,
        verify_discovery_key_bundle, verify_discovery_to_identity_binding,
        verify_identity_key_bundle, verify_signed_prekey_bundle,
    };
    use roost_protocol::verify_with_context;
    use std::sync::Arc;

    /// Every Ed25519 signature context and canonical-encoding domain tag in
    /// `docs/domain-separation.md`, plus the one lowercase hash domain, as of v0.11.0.
    const AETHER_DOMAIN_REGISTRY: [&str; 10] = [
        "AetherIKBinding-v1:",
        "AetherDK-v1:",
        "AetherDKToIK-v1:",
        "AetherSPK-v1:",
        "AetherMessageTranscript-v1:",
        "AetherIK-v1:",
        "AetherSafetyNumber-v1:",
        "AetherSenderCertificate-v2:",
        "AetherProtocolStateCommit-v1:",
        "aether-recipient-delivery-capability-v1",
    ];

    const RELAY_HTTP_AUTH_CONTEXT: &[u8] = b"Relay-HTTP-Auth-v1";
    const RELAY_PROTOCOL_VERSION: u16 = 1;
    const REL_RLY_18_KAT_IDENTITY_SIGNING_SECRET: [u8; 32] = [0x11; 32];
    const REL_RLY_18_KAT_CHALLENGE_NONCE: [u8; 32] = [0x22; 32];
    const REL_RLY_18_KAT_RELAY_DOMAIN: &[u8] = b"relay.example";
    const REL_RLY_18_KAT_METHOD: &[u8] = b"POST";
    const REL_RLY_18_KAT_REQUEST_TARGET: &[u8] = b"/v1/prekeys?count=10";
    const REL_RLY_18_KAT_BODY_DIGEST_HEX: &str =
        "5e7ea43567be4f0a65821dcdfa31d2d92cb0d0d666df62b7f6cdaacac19d4047";
    const REL_RLY_18_KAT_TRANSCRIPT_LEN: usize = 159;
    const REL_RLY_18_KAT_EXPECTED_VERIFYING_HEX: &str =
        "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
    const REL_RLY_18_KAT_EXPECTED_SIGNATURE_HEX: &str = "7925dfac93637e618b5fad03a236f2c1\
         f0a913b252c79ac594123a40a00a2929\
         951d1a452bafccc602baf9072ff42105\
         07e53969e62220f2e2fea9d9713d340c";

    fn hex32(hex: &str) -> [u8; 32] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    fn push_length_prefixed(transcript: &mut Vec<u8>, field: &[u8]) {
        transcript.extend_from_slice(&(field.len() as u16).to_be_bytes());
        transcript.extend_from_slice(field);
    }

    // REL-RLY-16: concat("Relay-HTTP-Auth-v1", protocol_version_u16_be, challenge_nonce,
    // identity_signing_key, len_u16_be(relay_domain), relay_domain, len_u16_be(method), method,
    // len_u16_be(request_target), request_target, SHA-256(request_body)). Fixed-width fields and
    // the context itself carry no length prefix, and nothing separates the context from what
    // follows it.
    fn relay_http_transcript(identity_signing_key: &[u8], body_digest: &[u8; 32]) -> Vec<u8> {
        let mut transcript = RELAY_HTTP_AUTH_CONTEXT.to_vec();
        transcript.extend_from_slice(&RELAY_PROTOCOL_VERSION.to_be_bytes());
        transcript.extend_from_slice(&REL_RLY_18_KAT_CHALLENGE_NONCE);
        transcript.extend_from_slice(identity_signing_key);
        push_length_prefixed(&mut transcript, REL_RLY_18_KAT_RELAY_DOMAIN);
        push_length_prefixed(&mut transcript, REL_RLY_18_KAT_METHOD);
        push_length_prefixed(&mut transcript, REL_RLY_18_KAT_REQUEST_TARGET);
        transcript.extend_from_slice(body_digest);
        transcript
    }

    fn signature_from(bytes: &[u8]) -> Signature {
        Signature::from_bytes(&<[u8; 64]>::try_from(bytes).unwrap())
    }

    /// Known-answer test for the REL-RLY-16 authentication transcript and the signature over it.
    ///
    /// Source: Relay REL-RLY-18 published vector (`relay/docs/auth-transcript.md`), produced by
    /// the relay's own transcript encoder and `ed25519-dalek` verifier, which share no code with
    /// this crate. Matching the expected signature pins all 159 transcript bytes, because any
    /// difference in field order, length prefixing, or separators changes the signature.
    ///
    /// Inputs:
    /// - `identity_signing_secret = REL_RLY_18_KAT_IDENTITY_SIGNING_SECRET`
    /// - `challenge_nonce = REL_RLY_18_KAT_CHALLENGE_NONCE`
    /// - `relay_domain = REL_RLY_18_KAT_RELAY_DOMAIN`
    /// - `protocol_version = RELAY_PROTOCOL_VERSION`
    /// - `method = REL_RLY_18_KAT_METHOD`
    /// - `request_target = REL_RLY_18_KAT_REQUEST_TARGET`
    /// - `body_digest = REL_RLY_18_KAT_BODY_DIGEST_HEX` (SHA-256 of `b"vector-body"`)
    ///
    /// Derivation:
    /// ```text
    /// transcript = concat("Relay-HTTP-Auth-v1", protocol_version, challenge_nonce,
    ///                     identity_signing_key, len(relay_domain), relay_domain, len(method),
    ///                     method, len(request_target), request_target, body_digest)
    /// signature = Ed25519-Sign(identity_signing_secret, transcript)
    /// ```
    ///
    /// Output:
    /// - `identity_signing_key = REL_RLY_18_KAT_EXPECTED_VERIFYING_HEX`
    /// - `signature = REL_RLY_18_KAT_EXPECTED_SIGNATURE_HEX`
    #[test]
    fn relay_http_authentication_transcript_signature_known_answer() {
        let signing = SigningKeyPair::from_signing_bytes(REL_RLY_18_KAT_IDENTITY_SIGNING_SECRET);
        assert_eq!(
            hex::encode(signing.verifying.to_bytes()),
            REL_RLY_18_KAT_EXPECTED_VERIFYING_HEX
        );

        let transcript = relay_http_transcript(
            signing.verifying.as_bytes(),
            &hex32(REL_RLY_18_KAT_BODY_DIGEST_HEX),
        );

        assert_eq!(transcript.len(), REL_RLY_18_KAT_TRANSCRIPT_LEN);
        assert_eq!(
            hex::encode(signing.sign(&transcript).to_bytes()),
            REL_RLY_18_KAT_EXPECTED_SIGNATURE_HEX
        );
    }

    /// The signature must cover the transcript bytes and nothing else.
    ///
    /// The relay rebuilds the transcript alone and calls bare Ed25519 verify, so a context
    /// prepended on this side — what `sign_with_context` would do — yields a preimage the relay
    /// never reconstructs. That failure is silent at the boundary and only shows up as a signature
    /// that verifies nowhere, which is why it is pinned here rather than left to the caller.
    #[test]
    fn signed_authentication_transcript_verifies_bare_and_is_not_context_prefixed() {
        let store = key_store();
        let identity = store.generate_identity().unwrap();
        let transcript = relay_http_transcript(
            &identity.ed25519_verifying_key,
            &hex32(REL_RLY_18_KAT_BODY_DIGEST_HEX),
        );

        let signature_bytes = store
            .identity()
            .sign_authentication_transcript(transcript.clone())
            .unwrap();

        assert_eq!(signature_bytes.len(), 64);
        let signature = signature_from(&signature_bytes);
        let verifying = verifying_key(&identity);
        assert!(verifying.verify_strict(&transcript, &signature).is_ok());
        // Re-prepending the transcript's own context is the exact shape a contextual signature
        // would have had. It must not verify, or this export would be signing the wrong preimage.
        assert!(
            verify_with_context(&verifying, RELAY_HTTP_AUTH_CONTEXT, &transcript, &signature)
                .is_err()
        );
        for context in AETHER_DOMAIN_REGISTRY {
            assert!(
                verify_with_context(&verifying, context.as_bytes(), &transcript, &signature)
                    .is_err()
            );
        }
        // Ed25519 is deterministic, so a host retrying the same challenge resends the same proof.
        assert_eq!(
            store
                .identity()
                .sign_authentication_transcript(transcript)
                .unwrap(),
            signature_bytes
        );
    }

    /// An unrestricted "sign these bytes with the identity key" export would be a signing oracle
    /// over Aether's own preimages: the identity key is what signs identity bindings,
    /// discovery-key bindings, and message transcripts. Every context Aether signs or verifies
    /// under starts with `Aether`, so refusing that prefix makes the two preimage sets disjoint.
    #[test]
    fn sign_authentication_transcript_refuses_reserved_aether_preimages() {
        let store = key_store();
        let identity = store.generate_identity().unwrap();

        for context in AETHER_DOMAIN_REGISTRY {
            let mut preimage = context.as_bytes().to_vec();
            preimage.extend_from_slice(&identity.x25519_public_key);
            preimage.extend_from_slice(&identity.ed25519_verifying_key);
            match store.identity().sign_authentication_transcript(preimage) {
                Err(ClientError::InvalidData { .. }) => {}
                Err(error) => panic!("expected InvalidData for {context}, got {error}"),
                Ok(_) => panic!("expected InvalidData for {context}"),
            }
        }
    }

    #[test]
    fn sign_authentication_transcript_bounds_transcript_length() {
        let store = key_store();
        store.generate_identity().unwrap();

        match store.identity().sign_authentication_transcript(Vec::new()) {
            Err(ClientError::InvalidData { .. }) => {}
            other => panic!("expected InvalidData for an empty transcript, got {other:?}"),
        }
        match store.identity().sign_authentication_transcript(vec![
            0x41;
            MAX_AUTHENTICATION_TRANSCRIPT_LEN
                + 1
        ]) {
            Err(ClientError::InvalidData { .. }) => {}
            other => panic!("expected InvalidData past the length cap, got {other:?}"),
        }
        assert!(
            store
                .identity()
                .sign_authentication_transcript(vec![0x41; MAX_AUTHENTICATION_TRANSCRIPT_LEN])
                .is_ok()
        );
    }

    #[test]
    fn sign_authentication_transcript_requires_a_stored_identity() {
        let store = key_store();

        match store
            .identity()
            .sign_authentication_transcript(b"Relay-HTTP-Auth-v1".to_vec())
        {
            Err(ClientError::NotFound) => {}
            other => panic!("expected NotFound without an identity, got {other:?}"),
        }
    }

    fn key_store() -> Arc<Client> {
        let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
        Client::new(storage)
    }

    #[test]
    fn prepared_identity_lifecycle_crosses_the_uniffi_boundary() {
        let store = key_store();
        let prepared = store.identity().prepare_generate_identity().unwrap();
        let identifier = prepared.operation.identifier.clone();

        assert_eq!(identifier.len(), 16);
        assert!(!prepared.operation.secure_storage_preconditions.is_empty());
        assert!(matches!(
            store.operation_status(identifier.clone()).unwrap(),
            KeyStoreOperationStatus::Prepared
        ));
        assert!(!store.identity().has_identity().unwrap());

        assert!(matches!(
            store.commit_operation(identifier.clone()).unwrap(),
            KeyStoreOperationStatus::Committed
        ));
        assert!(matches!(
            store.identity().has_identity(),
            Err(ClientError::OperationRecoveryRequired {
                operation_identifier,
                ..
            }) if operation_identifier == identifier
        ));

        assert!(matches!(
            store.finalize_operation(identifier.clone()).unwrap(),
            KeyStoreOperationStatus::Finalized
        ));
        assert!(matches!(
            store.finalize_operation(identifier).unwrap(),
            KeyStoreOperationStatus::Finalized
        ));
        assert_eq!(
            store.identity().load_identity().unwrap().x25519_public_key,
            prepared.identity.x25519_public_key
        );
    }

    fn verifying_key(identity: &FfiIdentity) -> VerifyingKey {
        VerifyingKey::from_bytes(
            &<[u8; 32]>::try_from(identity.ed25519_verifying_key.as_slice()).unwrap(),
        )
        .unwrap()
    }

    fn identity_bundle(identity: &FfiIdentity) -> CryptoIdentityKeyBundle {
        CryptoIdentityKeyBundle::from_bytes(
            &identity.x25519_public_key,
            &identity.ed25519_verifying_key,
            &identity.identity_binding_signature,
        )
        .unwrap()
    }

    fn discovery_bundle(bundle: &FfiDiscoveryKeyBundle) -> CryptoDiscoveryKeyBundle {
        CryptoDiscoveryKeyBundle::from_bytes(
            &bundle.public_key,
            &bundle.verifying_key,
            bundle.epoch,
            bundle.created_at,
            &bundle.signature,
        )
        .unwrap()
    }

    fn signed_prekey_bundle(bundle: &FfiSignedPreKeyBundle) -> CryptoSignedPreKeyBundle {
        CryptoSignedPreKeyBundle {
            id: bundle.identifier,
            public_key: PublicKey::from(
                <[u8; 32]>::try_from(bundle.public_key.as_slice()).unwrap(),
            ),
            signature: Signature::from_bytes(
                &<[u8; 64]>::try_from(bundle.signature.as_slice()).unwrap(),
            ),
            epoch: bundle.epoch,
            created_at: bundle.created_at,
        }
    }

    fn assert_discovery_key_verifies(
        identity: &FfiIdentity,
        discovery: &FfiDiscoveryKeyBundle,
    ) -> CryptoDiscoveryKeyBundle {
        let crypto_discovery = discovery_bundle(discovery);
        assert!(verify_discovery_key_bundle(&crypto_discovery, &verifying_key(identity)).is_ok());
        crypto_discovery
    }

    fn assert_signed_prekey_verifies(
        signed_prekey: &FfiSignedPreKeyBundle,
        discovery: &CryptoDiscoveryKeyBundle,
    ) {
        let crypto_prekey = signed_prekey_bundle(signed_prekey);
        assert!(verify_signed_prekey_bundle(&crypto_prekey, &discovery.verifying_key).is_ok());
    }

    fn assert_discovery_to_identity_verifies(
        identity: &FfiIdentity,
        publication: &FfiPublicationBundle,
        discovery: &CryptoDiscoveryKeyBundle,
    ) {
        let signature = Signature::from_bytes(
            &<[u8; 64]>::try_from(publication.discovery_to_identity.as_slice()).unwrap(),
        );
        assert!(
            verify_discovery_to_identity_binding(
                &identity_bundle(identity),
                &discovery.verifying_key,
                &signature,
            )
            .is_ok()
        );
    }

    fn assert_publication_verifies(identity: &FfiIdentity, publication: &FfiPublicationBundle) {
        assert_eq!(
            publication.version,
            roost_core::test_support::PREKEY_BUNDLE_VERSION
        );
        let discovery = assert_discovery_key_verifies(identity, &publication.discovery_key);
        assert_signed_prekey_verifies(&publication.signed_prekey, &discovery);
        assert_discovery_to_identity_verifies(identity, publication, &discovery);
    }

    /// The host registers the verifier and shares the capability only with authorized contacts, so
    /// both must cross the FFI boundary and the verifier must commit to the capability actually in
    /// storage (AE-IDN-10).
    #[test]
    fn publication_verifier_commits_to_the_capability_across_ffi() {
        let key_store = key_store();
        key_store.generate_identity().unwrap();
        key_store.rotate_signed_prekey_now().unwrap();

        let publication = key_store.identity().current_publication_bundle().unwrap();
        let capability = key_store.identity().current_delivery_capability().unwrap();

        assert_eq!(publication.recipient_delivery_verifier.len(), 32);
        assert_eq!(capability.len(), 32);
        // The capability is the secret; publishing it instead of the verifier would be the whole
        // bug this separation exists to prevent.
        assert_ne!(publication.recipient_delivery_verifier, capability);

        let expected =
            CryptoCapability::from_bytes(<[u8; 32]>::try_from(capability.as_slice()).unwrap());
        assert_eq!(
            publication.recipient_delivery_verifier,
            expected.verifier().as_bytes().to_vec()
        );
    }

    /// The DK→IK binding must survive the FFI boundary as 64 usable bytes, not merely exist on the
    /// Rust side. A host reads this field straight out of the generated record to populate
    /// `relay.cloud.v1.KeyBindingSignatures.discovery_to_identity`.
    #[test]
    fn publication_bundle_carries_discovery_to_identity_binding_across_ffi() {
        let key_store = key_store();
        let identity = key_store.generate_identity().unwrap();
        key_store.rotate_signed_prekey_now().unwrap();

        let publication = key_store.identity().current_publication_bundle().unwrap();

        assert_eq!(publication.discovery_to_identity.len(), 64);
        assert_ne!(publication.discovery_to_identity, vec![0u8; 64]);
        assert_publication_verifies(&identity, &publication);
    }

    fn assert_one_time_prekey_record(bundle: &FfiOneTimePreKeyBundle, epoch: u32) {
        assert_eq!(bundle.public_key.len(), 32);
        assert_eq!(bundle.epoch, epoch);
    }

    fn identity_key(identity: &FfiIdentity) -> IdentityKey {
        IdentityKey {
            x25519_public_key: identity.x25519_public_key.clone(),
            ed25519_verifying_key: identity.ed25519_verifying_key.clone(),
        }
    }

    fn contact_identity(
        identity: &FfiIdentity,
        publication: &FfiPublicationBundle,
    ) -> ContactIdentity {
        ContactIdentity {
            identity_key: identity_key(identity),
            discovery_key: ContactDiscoveryKey {
                x25519_public_key: publication.discovery_key.public_key.clone(),
                ed25519_verifying_key: publication.discovery_key.verifying_key.clone(),
                epoch: publication.discovery_key.epoch,
                created_at: publication.discovery_key.created_at,
                identity_signature: publication.discovery_key.signature.clone(),
            },
        }
    }

    fn same_protocol_state_kind(left: ProtocolStateKind, right: ProtocolStateKind) -> bool {
        matches!(
            (left, right),
            (
                ProtocolStateKind::RatchetSession,
                ProtocolStateKind::RatchetSession
            ) | (
                ProtocolStateKind::DeduplicationSet,
                ProtocolStateKind::DeduplicationSet
            ) | (
                ProtocolStateKind::PendingAcknowledgments,
                ProtocolStateKind::PendingAcknowledgments
            ) | (
                ProtocolStateKind::ContactState,
                ProtocolStateKind::ContactState
            ) | (
                ProtocolStateKind::PeerInboxAuthorization,
                ProtocolStateKind::PeerInboxAuthorization
            ) | (
                ProtocolStateKind::LocalInboxAuthorization,
                ProtocolStateKind::LocalInboxAuthorization
            )
        )
    }

    fn assert_protocol_state_kind(actual: ProtocolStateKind, expected: ProtocolStateKind) {
        assert!(same_protocol_state_kind(actual, expected));
    }

    fn apply_updates(entries: &mut Vec<ProtocolStateEntry>, updates: Vec<ProtocolStateUpdate>) {
        for update in updates {
            entries.retain(|entry| {
                !same_protocol_state_kind(entry.kind, update.kind) || entry.key != update.key
            });
            if let Some(blob) = update.blob {
                entries.push(ProtocolStateEntry {
                    kind: update.kind,
                    key: update.key,
                    blob,
                });
            }
        }
    }

    #[test]
    fn wipe_returns_only_active_protocol_state_kinds() {
        let engine = Client::new(Arc::new(InMemorySecureStorage::new())).messaging();

        let updates = engine.wipe(Vec::new(), vec![0x44; 16]).unwrap();

        assert_eq!(updates.len(), 6);
        assert_protocol_state_kind(updates[0].kind, ProtocolStateKind::RatchetSession);
        assert_protocol_state_kind(updates[1].kind, ProtocolStateKind::DeduplicationSet);
        assert_protocol_state_kind(updates[2].kind, ProtocolStateKind::PendingAcknowledgments);
        assert_protocol_state_kind(updates[3].kind, ProtocolStateKind::ContactState);
        // A wipe must reach the peer's delivery capability too, or session replacement leaves a
        // stale bearer secret behind with nothing left that uses it.
        assert_protocol_state_kind(updates[4].kind, ProtocolStateKind::PeerInboxAuthorization);
        assert_protocol_state_kind(updates[5].kind, ProtocolStateKind::LocalInboxAuthorization);
        assert!(updates.iter().all(|update| update.blob.is_none()));
    }

    fn copy_snapshot(entries: &[ProtocolStateEntry]) -> Vec<ProtocolStateEntry> {
        entries
            .iter()
            .map(|entry| ProtocolStateEntry {
                kind: entry.kind,
                key: entry.key.clone(),
                blob: entry.blob.clone(),
            })
            .collect()
    }

    #[test]
    fn generate_identity_returns_ffi_safe_public_keys() {
        let store = key_store();
        let identity = store.generate_identity().unwrap();
        assert_eq!(identity.x25519_public_key.len(), 32);
        assert_eq!(identity.ed25519_verifying_key.len(), 32);
        assert_eq!(identity.identity_binding_signature.len(), 64);
        verifying_key(&identity);
        assert!(verify_identity_key_bundle(&identity_bundle(&identity)).is_ok());
    }

    #[test]
    fn rotate_signed_prekey_if_stale_returns_verifiable_record() {
        let store = key_store();
        let identity = store.generate_identity().unwrap();
        let signed_prekey = store
            .rotate_signed_prekey_if_stale()
            .unwrap()
            .expect("first rotate must produce a bundle");
        let discovery = store.identity().current_discovery_key_bundle().unwrap();
        let crypto_discovery = assert_discovery_key_verifies(&identity, &discovery);
        assert_signed_prekey_verifies(&signed_prekey, &crypto_discovery);
    }

    #[test]
    fn current_publication_bundle_returns_verifiable_records() {
        let store = key_store();
        let identity = store.generate_identity().unwrap();
        store.rotate_signed_prekey_now().unwrap();
        let publication = store.identity().current_publication_bundle().unwrap();
        assert_publication_verifies(&identity, &publication);
    }

    #[test]
    fn generate_one_time_prekeys_returns_public_records() {
        let store = key_store();
        store.generate_identity().unwrap();
        let discovery = store.identity().current_discovery_key_bundle().unwrap();
        let bundles = store.generate_one_time_prekeys(3).unwrap();

        assert_eq!(bundles.len(), 3);
        assert_eq!(
            bundles
                .iter()
                .map(|bundle| bundle.identifier)
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        for bundle in &bundles {
            assert_one_time_prekey_record(bundle, discovery.epoch);
        }
    }

    #[test]
    fn rotate_inbox_now_advances_epoch_and_returns_verifiable_records() {
        let store = key_store();
        let identity = store.generate_identity().unwrap();
        let initial_discovery = store.identity().current_discovery_key_bundle().unwrap();
        let rotation = store.rotate_inbox_now().unwrap();
        assert_eq!(
            rotation.publication.discovery_key.epoch,
            initial_discovery.epoch + 1
        );
        assert_publication_verifies(&identity, &rotation.publication);
        // The capability returned by the rotation is the one the new verifier commits to.
        assert_eq!(rotation.capability.len(), 32);
        assert_eq!(
            rotation.capability,
            store.identity().current_delivery_capability().unwrap()
        );
    }

    #[test]
    fn replenish_one_time_prekeys_returns_public_records() {
        let store = key_store();
        store.generate_identity().unwrap();
        let discovery = store.identity().current_discovery_key_bundle().unwrap();
        let bundles = store.replenish_one_time_prekeys().unwrap();

        assert_eq!(bundles.len(), 100);
        for bundle in &bundles {
            assert_one_time_prekey_record(bundle, discovery.epoch);
        }
        assert!(store.replenish_one_time_prekeys().unwrap().is_empty());
    }

    #[test]
    fn session_establishment_round_trips_first_message_through_ffi_records() {
        let alice = key_store();
        let bob = key_store();
        let alice_identity = alice.generate_identity().unwrap();
        let bob_identity = bob.generate_identity().unwrap();
        bob.rotate_signed_prekey_now().unwrap();
        let bob_publication = bob.identity().current_publication_bundle().unwrap();
        let bob_one_time_prekey = bob.generate_one_time_prekeys(1).unwrap().remove(0);

        let session_key = vec![0x44; 16];
        let initiation = alice
            .messaging()
            .initiate_session(
                session_key.clone(),
                bob_identity,
                bob_publication,
                Some(bob_one_time_prekey),
                b"alice certificate".to_vec(),
                b"alice signature".to_vec(),
                b"hello bob".to_vec(),
                crate::TransportBinding {
                    bytes: b"test-route".to_vec(),
                },
            )
            .unwrap();

        assert!(initiation.message.prekey_reference.is_some());
        assert_eq!(initiation.state_updates.len(), 2);

        let acceptance = bob
            .accept_session(session_key, Some(alice_identity), initiation.message)
            .unwrap();

        assert_eq!(acceptance.plaintext, b"hello bob".to_vec());
        assert_eq!(
            acceptance.sender_identity.certificate,
            b"alice certificate".to_vec()
        );
        assert_eq!(acceptance.state_updates.len(), 2);
    }

    #[test]
    fn encrypt_message_returns_message_and_pending_state_update() {
        let alice = key_store();
        let bob = key_store();
        let alice_identity = alice.generate_identity().unwrap();
        let bob_identity = bob.generate_identity().unwrap();
        bob.rotate_signed_prekey_now().unwrap();
        let bob_publication = bob.identity().current_publication_bundle().unwrap();
        let bob_one_time_prekey = bob.generate_one_time_prekeys(1).unwrap().remove(0);
        let session_key = vec![0x55; 16];
        let initiation = alice
            .messaging()
            .initiate_session(
                session_key.clone(),
                bob_identity.clone(),
                bob_publication.clone(),
                Some(bob_one_time_prekey),
                b"alice certificate".to_vec(),
                b"alice signature".to_vec(),
                b"hello bob".to_vec(),
                crate::TransportBinding {
                    bytes: b"test-route".to_vec(),
                },
            )
            .unwrap();
        let acceptance = bob
            .accept_session(
                session_key.clone(),
                Some(alice_identity),
                initiation.message.clone(),
            )
            .unwrap();

        let engine = Client::new(Arc::new(InMemorySecureStorage::new())).messaging();
        let mut alice_snapshot = Vec::new();
        apply_updates(&mut alice_snapshot, initiation.state_updates);
        let change = alice
            .contacts()
            .record_contact(
                Vec::new(),
                contact_identity(&bob_identity, &bob_publication),
            )
            .unwrap();
        apply_updates(&mut alice_snapshot, change.state_updates);
        let accepted = alice
            .contacts()
            .accept_contact(copy_snapshot(&alice_snapshot), identity_key(&bob_identity))
            .unwrap();
        apply_updates(&mut alice_snapshot, accepted.state_updates);

        let outbound = alice
            .messaging()
            .encrypt_message(
                copy_snapshot(&alice_snapshot),
                session_key.clone(),
                vec![0x77; 16],
                identity_key(&bob_identity),
                bob_publication.discovery_key.public_key,
                42,
                b"alice certificate".to_vec(),
                b"alice signature".to_vec(),
                b"follow-up".to_vec(),
                crate::TransportBinding {
                    bytes: b"test-route".to_vec(),
                },
            )
            .unwrap();

        assert_eq!(outbound.message_id, vec![0x77; 16]);
        assert_eq!(outbound.state_updates.len(), 2);
        apply_updates(&mut alice_snapshot, outbound.state_updates);
        let pending = engine
            .pending_acknowledgments(alice_snapshot, session_key)
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(acceptance.plaintext, b"hello bob".to_vec());
    }

    #[test]
    fn decrypt_message_requires_certificate_validation_for_unique_message() {
        let alice = key_store();
        let bob = key_store();
        let alice_identity = alice.generate_identity().unwrap();
        let bob_identity = bob.generate_identity().unwrap();
        alice.rotate_signed_prekey_now().unwrap();
        bob.rotate_signed_prekey_now().unwrap();
        let alice_publication = alice.identity().current_publication_bundle().unwrap();
        let bob_publication = bob.identity().current_publication_bundle().unwrap();
        let bob_one_time_prekey = bob.generate_one_time_prekeys(1).unwrap().remove(0);
        let session_key = vec![0x66; 16];
        let initiation = alice
            .messaging()
            .initiate_session(
                session_key.clone(),
                bob_identity.clone(),
                bob_publication.clone(),
                Some(bob_one_time_prekey),
                b"alice certificate".to_vec(),
                b"alice signature".to_vec(),
                b"hello bob".to_vec(),
                crate::TransportBinding {
                    bytes: b"test-route".to_vec(),
                },
            )
            .unwrap();
        let acceptance = bob
            .accept_session(
                session_key.clone(),
                Some(alice_identity.clone()),
                initiation.message,
            )
            .unwrap();

        let engine = Client::new(Arc::new(InMemorySecureStorage::new())).messaging();
        let mut alice_snapshot = Vec::new();
        apply_updates(&mut alice_snapshot, initiation.state_updates);
        let change = alice
            .contacts()
            .record_contact(
                Vec::new(),
                contact_identity(&bob_identity, &bob_publication),
            )
            .unwrap();
        apply_updates(&mut alice_snapshot, change.state_updates);
        let accepted = alice
            .contacts()
            .accept_contact(copy_snapshot(&alice_snapshot), identity_key(&bob_identity))
            .unwrap();
        apply_updates(&mut alice_snapshot, accepted.state_updates);
        let outbound = alice
            .messaging()
            .encrypt_message(
                alice_snapshot,
                session_key.clone(),
                vec![0x88; 16],
                identity_key(&bob_identity),
                bob_publication.discovery_key.public_key,
                43,
                b"alice certificate".to_vec(),
                b"alice signature".to_vec(),
                b"follow-up".to_vec(),
                crate::TransportBinding {
                    bytes: b"test-route".to_vec(),
                },
            )
            .unwrap();

        let mut bob_snapshot = Vec::new();
        apply_updates(&mut bob_snapshot, acceptance.state_updates);
        let deduplication_key = b"bob-dedup".to_vec();
        apply_updates(
            &mut bob_snapshot,
            vec![
                engine
                    .initialize_deduplication_set(deduplication_key.clone())
                    .unwrap(),
            ],
        );
        let result = bob.messaging().decrypt_message(
            bob_snapshot,
            session_key,
            deduplication_key,
            outbound.message,
            vec![0x99; 16],
            alice_publication.discovery_key.public_key,
            44,
            b"bob certificate".to_vec(),
            b"bob signature".to_vec(),
            None,
            crate::TransportBinding {
                bytes: b"test-route".to_vec(),
            },
            crate::TransportBinding {
                bytes: b"test-route".to_vec(),
            },
        );

        match result {
            Err(ClientError::InvalidData { .. }) => {}
            Err(error) => panic!("expected InvalidData, got {error}"),
            Ok(_) => panic!("expected InvalidData"),
        }
    }
}
