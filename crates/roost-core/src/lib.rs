//! Identity lifecycle, messaging and transitions over host-owned protocol state.
//!
//! This implementation crate coordinates [`roost_crypto`] operations with caller-owned storage.
//! Mobile consumers use `roost-client`; backends use `roost-server`. Platform adapters provide
//! [`SecureStorage`] for keys and the host owns durable Protocol State Blob transactions.
//!
//! # Overview
//!
//! [`KeyStore`] coordinates identity setup, encrypted backups, publication keys and one configured
//! [`ProtocolStateEngine`]. The host serializes each identity's complete operation and commit,
//! including prepared-operation recovery across instances and processes. See [`KeyStore`] and
//! [`ProtocolStateSnapshot`] for the storage and commit contracts.
//!
//! # Examples
//!
//! ```
//! use roost_core::{InMemorySecureStorage, KeyStore};
//!
//! # fn publish_identity_bundle(
//! #     _identity: &roost_core::Identity,
//! #     _discovery_key: &roost_crypto::DiscoveryKeyBundle,
//! #     _signed_prekey: &roost_crypto::SignedPreKeyBundle,
//! # ) -> Result<(), Box<dyn std::error::Error>> {
//! #     Ok(())
//! # }
//! let store = KeyStore::new(Box::new(InMemorySecureStorage::new()));
//! let identity = store.prepare_generate_identity()?;
//! store.commit_operation(identity.operation.identifier)?;
//! // Commit any host-owned output atomically here, then finalize SecureStorage.
//! store.finalize_operation(identity.operation.identifier)?;
//! // Publish the identity with a matching discovery-key + signed-pre-key pair.
//! let signed_prekey = store.prepare_rotate_signed_prekey_now()?;
//! store.commit_operation(signed_prekey.operation.identifier)?;
//! store.finalize_operation(signed_prekey.operation.identifier)?;
//! let publication = store.current_publication_bundle()?;
//! publish_identity_bundle(
//!     &identity.output,
//!     &publication.discovery_key,
//!     &publication.signed_prekey,
//! )?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
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

mod clock;
mod contact;
#[cfg(feature = "development-certificates")]
mod development_certificate;
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
#[cfg(feature = "development-certificates")]
pub use development_certificate::{
    DevelopmentCertificateAuthority, DevelopmentCertificateError, DevelopmentSenderCertificate,
};
pub use discovery_key::DiscoveryKeyError;
pub use hardening::{
    DEFAULT_DEDUPLICATION_CAPACITY, MAX_DEDUPLICATION_CAPACITY, MIN_DEDUPLICATION_CAPACITY,
    ProtocolHardeningLimits,
};
pub use identity::{Identity, IdentityError};
pub use key_store::{
    AcknowledgmentProcessing, ContactBlock, InboxRotation, KeyStore, KeyStoreError,
    KeyStoreOperation, KeyStoreOperationError, KeyStoreOperationIdentifier,
    KeyStoreOperationStatus, MessageDecryption, MessageEncryption, MessageOperationError,
    PreparedKeyStoreOperation, PublicationBundle, SecureStorageExpectedValue,
    SecureStoragePrecondition, SessionAcceptance, SessionAcceptanceResult,
    SessionEstablishmentError, SessionInitiation, SessionInitiationResult,
    UnfinishedKeyStoreOperation,
};
pub use message::{Message, MessageError};
pub use one_time_prekey::OneTimePreKeyError;
pub use protocol_state::{
    AcknowledgmentOutcome, BlockedContactAcknowledgmentPolicy, BlockedInboundMessageResult,
    ClearedAcknowledgment, InboundAcknowledgmentMessage, InboundEncryptedMessage,
    InboundMessageOutcome, InboundMessageResult, InboundSenderCertificateValidation,
    MAX_PROTOCOL_STATE_ENTRIES, OutboundAcknowledgment, OutboundMessageResult, OutboundPlaintext,
    PendingAcknowledgment, ProtocolStateAddress, ProtocolStateBlob, ProtocolStateCommitCondition,
    ProtocolStateEngine, ProtocolStateError, ProtocolStateKey, ProtocolStateKind,
    ProtocolStateSnapshot, ProtocolStateUpdate, RetryInstruction, RetryInstructionResult,
    SessionEvent, SessionId, SessionUnrecoverableReason, SessionUnrecoverableResult,
    protocol_state_blob_digest,
};
pub use roost_crypto::{
    CryptoError, DiscoveryKeyBundle, IdentityKeyBundle, OneTimePreKeyBundle, PreKeyBundle,
    PublicKey, RecipientDeliveryCapability, SealedFramePreKeyReference, SenderIdentityMaterial,
    Signature, SignedPreKeyBundle, verify_discovery_to_identity_binding,
    verify_identity_key_bundle,
};
pub use safety_number::{IdentityKey, SafetyNumber, SafetyNumberError, derive_safety_number};
pub use signed_prekey::SignedPreKeyError;
pub use storage::{InMemorySecureStorage, SecureStorage, StorageError};
pub use transport_binding::{PreKeySelection, TransportBinding, TransportBindingError};

/// Crypto inputs used by Client's Rust adapter tests.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub mod test_support {
    pub use roost_crypto::{
        DiscoveryKeyBundle, IdentityKeyBundle, KeyPair, PREKEY_BUNDLE_VERSION, PublicKey,
        RecipientDeliveryCapability, Signature, SignedPreKeyBundle, SigningKeyPair, VerifyingKey,
        sign_identity_key_binding, verify_discovery_key_bundle,
        verify_discovery_to_identity_binding, verify_identity_key_bundle,
        verify_signed_prekey_bundle,
    };
}
