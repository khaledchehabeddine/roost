//! Application-layer key management for private messaging clients.
//!
//! This crate wraps [`aether_crypto`] primitives with persistence, identity lifecycle management,
//! and signed-pre-key rotation for Rust callers wiring the core into apps. Platform adapters
//! provide a [`SecureStorage`] implementation backed by secure storage.
//!
//! # Overview
//!
//! [`KeyStore`] is the entry point for identity setup, encrypted backup import and export, and
//! signed-pre-key publication. It serializes access to the underlying storage so callers can share
//! a cloned handle across application components.
//!
//! # Examples
//!
//! ```
//! use aether_core::{InMemorySecureStorage, KeyStore};
//!
//! # fn publish_identity_bundle(
//! #     _identity: &aether_core::Identity,
//! #     _discovery_key: &aether_crypto::DiscoveryKeyBundle,
//! #     _signed_prekey: &aether_crypto::SignedPreKeyBundle,
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
//! use aether_core::Identity;
//!
//! fn assert_debug<T: std::fmt::Debug>() {}
//!
//! assert_debug::<Identity>();
//! ```
//!
//! Protocol-state blobs do not implement `Debug`.
//!
//! ```compile_fail
//! use aether_core::ProtocolStateBlob;
//!
//! fn assert_debug<T: std::fmt::Debug>() {}
//!
//! assert_debug::<ProtocolStateBlob>();
//! ```
//!
//! Secret-owning public result types do not implement caller-visible `Clone`.
//!
//! ```compile_fail
//! use aether_core::InboundMessageResult;
//!
//! fn assert_clone<T: Clone>() {}
//!
//! assert_clone::<InboundMessageResult>();
//! ```

mod clock;
mod contact;
mod discovery_key;
mod events;
mod evidence;
mod hardening;
mod identity;
mod key_encoding;
mod key_store;
mod message;
mod one_time_prekey;
mod prekey_state;
mod protocol_state;
mod safety_number;
mod sender_certificate;
mod signed_prekey;
mod storage;
mod transport_binding;

pub use aether_crypto::SenderIdentityMaterial;
pub use contact::{
    ContactDiscoveryKey, ContactEvent, ContactEventStream, ContactIdentity, ContactIdentityKey,
    ContactSafetyNumberConfirmation, ContactState, ContactStateChange, ContactTrustState,
    PeerInboxAuthorization,
};
pub use discovery_key::DiscoveryKeyError;
pub use events::{
    DEFAULT_OBSERVER_CAPACITY, EventEnvelope, EventId, EventObserver, EventStream,
    EventStreamError, EventStreamItem, EventStreamSnapshot, MAX_OBSERVER_CAPACITY,
};
pub use evidence::{
    EvidenceBundle, EvidenceProfile, EvidenceVerificationError, EvidenceVerificationInput,
    MAX_EVIDENCE_DOMAIN_SIGNING_KEYS, MAX_EVIDENCE_GRACE_WINDOW_SECS, VerifiedEvidenceBundle,
    verify_evidence_bundle,
};
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
pub use message::{Message, MessageError, MessageId, PayloadKind};
pub use one_time_prekey::OneTimePreKeyError;
pub use protocol_state::{
    AcknowledgmentOutcome, BlockedContactAcknowledgmentPolicy, BlockedInboundMessageResult,
    ClearedAcknowledgment, InboundAcknowledgmentMessage, InboundEncryptedMessage,
    InboundMessageOutcome, InboundMessageResult, InboundSenderCertificateValidation,
    OutboundAcknowledgment, OutboundMessageResult, OutboundPlaintext, PendingAcknowledgment,
    ProtocolStateAddress, ProtocolStateBlob, ProtocolStateEngine, ProtocolStateError,
    ProtocolStateKey, ProtocolStateKind, ProtocolStateSnapshot, ProtocolStateUpdate,
    RetryInstruction, RetryInstructionResult, SessionEvent, SessionId, SessionUnrecoverableReason,
    SessionUnrecoverableResult,
};
pub use safety_number::{IdentityKey, SafetyNumber, SafetyNumberError, derive_safety_number};
#[cfg(feature = "development-certificates")]
pub use sender_certificate::{
    DevelopmentCertificateAuthority, DevelopmentCertificateError, DevelopmentSenderCertificate,
};
pub use sender_certificate::{
    DomainSigningKey, DomainSigningKeyStatus, RevocationState, SenderCertificateDiscoveryKey,
    SenderCertificateIdentityKey, SenderCertificateValidationError,
    SenderCertificateValidationInput, ValidatedSenderCertificate, validate_sender_certificate,
};
pub use signed_prekey::SignedPreKeyError;
pub use storage::{InMemorySecureStorage, SecureStorage, StorageError};
pub use transport_binding::{PreKeySelection, TransportBinding, TransportBindingError};

#[cfg(fuzzing)]
#[doc(hidden)]
pub mod fuzzing {
    pub use crate::discovery_key::fuzz_decode_discovery_key_blob;
    pub use crate::one_time_prekey::fuzz_decode_one_time_prekey_pool;
    pub use crate::protocol_state::{
        fuzz_decode_protocol_state_blob, fuzz_decode_sealed_sender_envelope,
        fuzz_deduplication_digest, fuzz_unpad_sealed_payload,
    };
    pub use crate::signed_prekey::fuzz_decode_signed_prekey_blob;
}
