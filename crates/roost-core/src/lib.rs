//! Identity lifecycle, messaging and transitions over host-owned protocol state.
//!
//! This implementation crate coordinates [`roost_crypto`] operations with caller-owned storage.
//! Mobile consumers use `roost-client`. Platform adapters provide [`SecureStorage`] for keys and
//! the host owns durable Protocol State Blob transactions.
//!
//! [`KeyStore`] coordinates identity setup, encrypted backups, publication keys and one configured
//! [`ProtocolStateEngine`]. The host serializes each identity's complete operation and commit,
//! including prepared-operation recovery across instances and processes. See [`KeyStore`] and
//! [`ProtocolStateSnapshot`] for the storage and commit contracts.
//!
//! # Secret handling
//!
//! Identity does not implement `Debug`.
//!
//! ```compile_fail
//! use roost_core::Identity;
//!
//! fn assert_debug<T: std::fmt::Debug>() {}
//!
//! assert_debug::<Identity>();
//! ```
//!
//! Protocol-state blobs do not implement `Debug`.
//!
//! ```compile_fail
//! use roost_core::ProtocolStateBlob;
//!
//! fn assert_debug<T: std::fmt::Debug>() {}
//!
//! assert_debug::<ProtocolStateBlob>();
//! ```
//!
//! Secret-owning public result types do not implement caller-visible `Clone`.
//!
//! ```compile_fail
//! use roost_core::InboundMessageResult;
//!
//! fn assert_clone<T: Clone>() {}
//!
//! assert_clone::<InboundMessageResult>();
//! ```

mod contact;
mod discovery_key;
mod hardening;
mod identity;
mod key_store;
mod message;
mod one_time_prekey;
mod prekey_state;
mod protocol_state;
mod safety_number;
mod signed_prekey;
mod storage;
mod transport_binding;

use roost_protocol::{MessageId, PayloadKind};

pub use contact::{
    ContactDiscoveryKey, ContactEvent, ContactIdentity, ContactIdentityKey,
    ContactSafetyNumberConfirmation, ContactState, ContactStateChange, ContactTrustState,
    PeerInboxAuthorization,
};
pub use discovery_key::DiscoveryKeyError;
pub use hardening::{
    DEFAULT_DEDUPLICATION_CAPACITY, MAX_DEDUPLICATION_CAPACITY, MIN_DEDUPLICATION_CAPACITY,
    ProtocolHardeningLimits,
};
pub use identity::{Identity, IdentityError};
pub use key_store::{
    AcknowledgmentProcessing, ContactBlock, InboxRotation, JournalCorruption, KeyStore,
    KeyStoreError, KeyStoreOperation, KeyStoreOperationError, KeyStoreOperationId,
    KeyStoreOperationStatus, MessageDecryption, MessageEncryption, MessageOperationError,
    PreparedKeyStoreOperation, PublicationBundle, SecureStorageExpectedValue,
    SecureStoragePrecondition, SessionAcceptance, SessionEstablishmentError, SessionInitiation,
    UnfinishedKeyStoreOperation,
};
pub use message::{Message, MessageError};
pub use one_time_prekey::OneTimePreKeyError;
pub use protocol_state::{
    AcknowledgmentOutcome, BlockedContactAcknowledgmentPolicy, BlockedInboundMessageResult,
    ClearedAcknowledgment, InboundAcknowledgmentMessage, InboundEncryptedMessage,
    InboundMessageOutcome, InboundMessageResult, InboundSenderCertificateValidation,
    InboundSessionStart, LocalSender, MAX_PROTOCOL_STATE_ENTRIES, OutboundAcknowledgment,
    OutboundMessageResult, OutboundPlaintext, OutboundSessionStart, PendingAcknowledgment,
    ProtocolStateAddress, ProtocolStateBlob, ProtocolStateCommitCondition, ProtocolStateEngine,
    ProtocolStateError, ProtocolStateKey, ProtocolStateKind, ProtocolStateSnapshot,
    ProtocolStateUpdate, RetryInstruction, RetryInstructionResult, SenderIdentityMaterial,
    SessionAcceptanceOutcome, SessionAcceptanceResult, SessionEvent, SessionInitiationResult,
    SessionUnrecoverableReason, SessionUnrecoverableResult, protocol_state_blob_digest,
};
pub use roost_crypto::{
    HandshakeError, PreKeyBundle, PublicDiscoveryKey, PublicIdentityKey, PublicKey, PublicKeyError,
    PublicOneTimePreKey, PublicSignedPreKey, RatchetError, RatchetStateError,
    RecipientDeliveryCapability, SealedFrameError, SealedFramePreKeyReference, Signature,
    verify_discovery_to_identity_binding, verify_public_identity_key,
};
pub use roost_protocol::SessionId;
pub use safety_number::{IdentityKey, SafetyNumber, SafetyNumberError, derive_safety_number};
pub use signed_prekey::SignedPreKeyError;
pub use storage::{InMemorySecureStorage, SecureStorage, StorageError};
pub use transport_binding::{PreKeySelection, TransportBinding, TransportBindingError};
