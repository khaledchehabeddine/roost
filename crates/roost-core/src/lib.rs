//! Identity lifecycle, messaging and transitions over host-owned protocol state.
//!
//! This implementation crate coordinates [`roost_crypto`] operations with caller-owned storage.
//! Mobile consumers use `roost-client`. Platform adapters provide [`SecureStorage`] for keys and
//! the host owns durable Protocol State Blob transactions.
//!
//! [`KeyStore`] coordinates identity setup, encrypted backups, publication keys and the
//! [`ProtocolStateEngine`], and starts each [`MessageEncryption`] and [`MessageDecryption`]. A
//! Message Operation asks the host for exact records and returns [`StateChanges`] the host commits
//! only while every Commit Condition holds. The host serializes each identity's complete operation
//! and commit, including prepared-operation recovery across instances and processes. See
//! [`KeyStore`] and [`StateChanges`] for the storage and commit contracts.
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
mod one_time_prekey;
mod protocol_state;
mod safety_number;
mod signed_prekey;
mod storage;
mod stored_data;
mod transport_binding;

pub use contact::{
    ContactDiscoveryKey, ContactIdentityKey, ContactSafetyNumberConfirmation, ContactState,
    ContactTrustState,
};
pub use discovery_key::DiscoveryKeyError;
pub use hardening::ProtocolHardeningLimits;
pub use identity::{Identity, IdentityError};
pub use key_store::{
    ContactBlock, JournalCorruption, KeyStore, KeyStoreError, KeyStoreOperationError,
    KeyStoreOperationId, KeyStoreOperationStatus, MessageStartError, PreparedKeyStoreOperation,
    PublicationBundle, UnfinishedKeyStoreOperation,
};
pub use one_time_prekey::OneTimePreKeyError;
pub use protocol_state::{
    AcknowledgmentResult, AdmissionRequest, BlockedContactAcknowledgmentPolicy,
    BlockedInboundMessageResult, DeliveryCheck, DeliveryCheckResult, DeliveryCheckStep,
    GrantUpdateResult, InboundMessageOutcome, InboundMessageResult,
    InboundSenderCertificateValidation, IncomingMessage, KnownDomainSigningKey,
    MAX_PROTOCOL_STATE_ENTRIES, MessageDecryption, MessageDecryptionStep, MessageDestination,
    MessageEncryption, MessageEncryptionStep, MessageOperationError, MessageRecovery,
    MessageRecoveryStep, OutboundMessageResult, OutgoingGrantUpdate, OutgoingMessage,
    OutgoingRecovery, PeerPreKeyBundle, PendingAcknowledgment, ProtocolStateAddress,
    ProtocolStateBlob, ProtocolStateCommitCondition, ProtocolStateEngine, ProtocolStateError,
    ProtocolStateKey, ProtocolStateKind, ProtocolStateSnapshot, ProtocolStateUpdate,
    ReceiveSettings, RetryInstruction, SenderIdentityMaterial, SignedSenderCertificate,
    StateChanges, StateEntryError, WithheldInboundMessageResult, commit_conditions_match,
};
pub use roost_crypto::{
    HandshakeError, OneTimePreKeyReference, PreKeyBundle, PublicDiscoveryKey, PublicIdentityKey,
    PublicKey, PublicKeyError, PublicOneTimePreKey, PublicSignedPreKey, RatchetError,
    RatchetStateError, SealedFrame, SealedFrameError, SealedFramePreKeyReference, Signature,
    verify_discovery_to_identity_binding, verify_public_identity_key,
};
pub use roost_protocol::SessionId;
pub use safety_number::{IdentityKey, SafetyNumber, SafetyNumberError, derive_safety_number};
pub use signed_prekey::SignedPreKeyError;
pub use storage::{SecureStorage, StorageError};
pub use stored_data::StoredDataError;
pub use transport_binding::{TransportBinding, TransportBindingError};
