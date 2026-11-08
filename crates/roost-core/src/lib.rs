//! Identity lifecycle, messaging, and state changes over protocol state the app holds.
//!
//! This crate coordinates [`roost_crypto`] operations with storage the app owns, and apps call it
//! through `roost-client`. The app provides [`SecureStorage`] for keys and owns the transactions
//! that store protocol state blobs.
//!
//! [`KeyStore`] coordinates identity setup, encrypted backups, publication keys, and the
//! [`ProtocolStateEngine`], and starts each [`MessageEncryption`] and [`MessageDecryption`]. A
//! message operation asks the app for exact records and returns [`StateChanges`] the app commits
//! only while every commit condition holds. The app holds one identity lock across every instance
//! and process sharing an identity, from an operation's first call until its commit is resolved,
//! and while it resolves unfinished prepared operations. See [`KeyStore`] and [`StateChanges`] for
//! the storage and commit contracts.
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
//! Public result types that hold secrets don't implement `Clone`.
//!
//! ```compile_fail
//! use roost_core::InboundMessageResult;
//!
//! fn assert_clone<T: Clone>() {}
//!
//! assert_clone::<InboundMessageResult>();
//! ```

mod contact;
mod contact_publication;
mod discovery_key;
mod hardening;
mod identity;
mod key_store;
mod one_time_prekey;
mod protocol_state;
mod retention;
mod safety_number;
mod signed_prekey;
mod storage;
mod stored_data;

pub use contact::{
    ContactDiscoveryKey, ContactSafetyNumberConfirmation, ContactState, ContactTrustState,
};
pub use contact_publication::{ContactPublication, ContactPublicationError};
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
    GrantUpdateResult, InboundMessageOutcome, InboundMessageResult, IncomingMessage,
    MessageDecryption, MessageDecryptionStep, MessageDestination, MessageEncryption,
    MessageEncryptionStep, MessageOperationError, MessageRecovery, MessageRecoveryStep,
    OutboundMessageResult, OutgoingGrantUpdate, OutgoingMessage, OutgoingRecovery,
    PeerPreKeyBundle, PendingAcknowledgment, ProtocolStateAddress, ProtocolStateBlob,
    ProtocolStateCommitCondition, ProtocolStateEngine, ProtocolStateError, ProtocolStateKey,
    ProtocolStateKind, ProtocolStateUpdate, ReceiveSettings, SenderIdentityMaterial,
    SignedSenderCertificate, StateChanges, StateEntryError, WithheldInboundMessageResult,
    commit_conditions_match, is_newer_discovery_key,
};
pub use roost_crypto::{
    HandshakeError, OneTimePreKeyReference, PreKeyBundle, PublicDiscoveryKey, PublicIdentityKey,
    PublicKey, PublicKeyError, PublicOneTimePreKey, PublicSignedPreKey, RatchetError,
    RatchetStateError, SealedFrame, SealedFrameError, SealedFramePreKeyReference, Signature,
    verify_discovery_to_identity_binding, verify_public_identity_key,
};
pub use roost_protocol::{
    DomainSigningKey, IdentityKey, RevocationState, SenderCertificateValidation, SessionId,
    TransportBinding, TransportBindingError,
};
pub use safety_number::{SafetyNumber, SafetyNumberError, derive_safety_number};
pub use signed_prekey::SignedPreKeyError;
pub use storage::{SecureStorage, StorageError};
pub use stored_data::StoredDataError;
