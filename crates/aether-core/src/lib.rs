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
//! let identity = store.generate_identity()?;
//! // Publish the identity with a matching discovery-key + signed-pre-key pair.
//! store.rotate_signed_prekey_now()?;
//! let publication = store.current_publication_bundle()?;
//! publish_identity_bundle(&identity, &publication.discovery_key, &publication.signed_prekey)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod clock;
mod contact;
mod discovery_key;
mod events;
mod identity;
mod key_encoding;
mod key_store;
mod message;
mod one_time_prekey;
mod protocol_state;
mod safety_number;
mod sender_certificate;
mod signed_prekey;
mod storage;

pub use aether_crypto::SenderIdentityMaterial;
pub use contact::{
    ContactDiscoveryKey, ContactEvent, ContactEventStream, ContactIdentity, ContactIdentityKey,
    ContactSafetyNumberConfirmation, ContactState, ContactStateChange, ContactTrustState,
};
pub use discovery_key::DiscoveryKeyError;
pub use events::{
    DEFAULT_OBSERVER_CAPACITY, EventEnvelope, EventId, EventObserver, EventStream,
    EventStreamError, EventStreamItem, EventStreamSnapshot, MAX_OBSERVER_CAPACITY,
};
pub use identity::{Identity, IdentityError};
pub use key_store::{KeyStore, KeyStoreError, PublicationBundle};
pub use message::{Message, MessageError, MessageId, PayloadKind};
pub use one_time_prekey::OneTimePreKeyError;
pub use protocol_state::{
    AcknowledgmentOutcome, BlockedInboundMessageResult, ClearedAcknowledgment,
    DEFAULT_DEDUPLICATION_CAPACITY, InboundAcknowledgmentMessage, InboundEncryptedMessage,
    InboundMessageOutcome, InboundMessageResult, InboundSenderCertificateValidation,
    MAX_DEDUPLICATION_CAPACITY, MIN_DEDUPLICATION_CAPACITY, OutboundAcknowledgment,
    OutboundMessageResult, OutboundPlaintext, PendingAcknowledgment, ProtocolStateAddress,
    ProtocolStateBlob, ProtocolStateEngine, ProtocolStateError, ProtocolStateKey,
    ProtocolStateKind, ProtocolStateSnapshot, ProtocolStateUpdate, RetryInstruction,
    RetryInstructionResult, SessionEvent, SessionId, SessionUnrecoverableReason,
    SessionUnrecoverableResult,
};
pub use safety_number::{IdentityKey, SafetyNumber, SafetyNumberError, derive_safety_number};
pub use sender_certificate::{
    DomainSigningKey, DomainSigningKeyStatus, RevocationState, SenderCertificateDiscoveryKey,
    SenderCertificateIdentityKey, SenderCertificateValidationError,
    SenderCertificateValidationInput, ValidatedSenderCertificate, validate_sender_certificate,
};
pub use signed_prekey::SignedPreKeyError;
pub use storage::{InMemorySecureStorage, SecureStorage, StorageError};
